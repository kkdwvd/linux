// SPDX-License-Identifier: GPL-2.0
/*
 * Memory workloads for evaluating the BPF proactive reclaimer: a hot or
 * cold anonymous working set, a page cache working set, a streaming reader
 * and an allocator growing at a rate, each reporting its own throughput and
 * chunk latency once a second so that reclaim done to it shows up in its
 * own numbers.
 *
 * Usage: workload anon --size MB [--threads N] [--pass-ms N] [--once] [--fill PCT]
 *        workload file --path P --size MB [--offset MB] [--pass-ms N]
 *        workload file --path P --size MB [--offset MB] --stream --rate MB/s
 *                      [--rate-max MB/s --ramp S]
 *        workload grow --rate MB/s --limit MB [--threads N] [--rate-max MB/s --ramp S]
 *                      [--fill PCT]
 *        with --seconds S to stop after S seconds.
 *
 * anon walks an anonymous working set of --size MB in 1 MB chunks, writing
 * a word per page, over and over; --pass-ms is the least time one pass may
 * take, so it sets the touch rate, and --once touches the set a single time
 * and then idles, a cold set. file does the same with pread() over --size MB
 * of --path from --offset, a page cache working set, or with --stream reads
 * through that range once at --rate, a streaming reader whose cache is cold
 * as soon as it is read. grow faults in anonymous memory at --rate MB/s up
 * to --limit MB and then holds it, an allocator that the reclaimer has to
 * keep up with. A rate ramps linearly from --rate to --rate-max over --ramp
 * seconds. --fill makes that many percent of each page random on its first
 * touch, so swapping it costs the compressor real work; the rest is zero.
 * --threads splits a set or a growth, and its rate, over that many threads;
 * one thread faults in memory at a few hundred megabytes a second in a
 * guest, so a fast allocator needs several.
 *
 * Every second prints "t=<s> mb=<MB> p99_us=<N> max_us=<N>": the megabytes
 * touched or read in that second and the chunk latency percentiles, which
 * is where refaults, direct reclaim and memory.high throttling show up.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define CHUNK (1UL << 20)
#define PAGE 4096UL
#define MAX_SAMPLES 65536

static volatile sig_atomic_t stop_requested;

struct opts {
	const char *mode;
	const char *path;
	unsigned long size_mb;
	unsigned long offset_mb;
	unsigned long limit_mb;
	unsigned long rate_mb;
	unsigned long rate_max_mb;
	unsigned long ramp_s;
	unsigned long pass_ms;
	unsigned int threads;
	unsigned int seconds;
	unsigned int fill_pct;
	int once;
	int stream;
};

struct worker {
	pthread_t thread;
	pthread_mutex_t lock;
	unsigned int *samples;
	unsigned int nr_samples;
	unsigned long bytes;
	char *base;
	size_t len;
	int fd;
	off_t offset;
	uint64_t rng;
	const struct opts *o;
};

static void on_signal(int sig)
{
	stop_requested = 1;
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void sleep_until(uint64_t when)
{
	uint64_t now = now_ns();
	struct timespec ts;

	if (when <= now)
		return;
	ts.tv_sec = (when - now) / 1000000000ULL;
	ts.tv_nsec = (when - now) % 1000000000ULL;
	nanosleep(&ts, NULL);
}

/*
 * The rate at time t since the start, ramping from --rate to --rate-max,
 * for one of the threads sharing it.
 */
static uint64_t rate_bytes(const struct opts *o, uint64_t t_ns)
{
	uint64_t rate = o->rate_mb << 20;

	if (o->rate_max_mb > o->rate_mb && o->ramp_s) {
		uint64_t ramp_ns = o->ramp_s * 1000000000ULL;

		if (t_ns > ramp_ns)
			t_ns = ramp_ns;
		rate += ((o->rate_max_mb - o->rate_mb) << 20) * t_ns / ramp_ns;
	}
	rate /= o->threads;
	return rate ? rate : 1;
}

static void record(struct worker *w, uint64_t start, unsigned long bytes)
{
	unsigned int us = (now_ns() - start) / 1000;

	pthread_mutex_lock(&w->lock);
	w->bytes += bytes;
	if (w->nr_samples < MAX_SAMPLES)
		w->samples[w->nr_samples++] = us;
	pthread_mutex_unlock(&w->lock);
}

static inline uint64_t xorshift(uint64_t *s)
{
	uint64_t x = *s;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	return *s = x;
}

/* A word per page keeps a page from being zero and cheap to compress. */
static void touch(char *p, size_t len, unsigned long tag)
{
	for (size_t off = 0; off < len; off += PAGE)
		*(volatile unsigned long *)(p + off) = tag + off;
}

/* The first touch: --fill percent of each page random, the rest zero. */
static void fill(struct worker *w, char *p, size_t len, unsigned long tag)
{
	size_t random = PAGE * w->o->fill_pct / 100 & ~7UL;

	if (!random) {
		touch(p, len, tag);
		return;
	}
	for (size_t off = 0; off < len; off += PAGE) {
		uint64_t *words = (uint64_t *)(p + off);

		for (size_t i = 0; i < random / 8; i++)
			words[i] = xorshift(&w->rng);
	}
}

static void *anon_worker(void *arg)
{
	struct worker *w = arg;
	unsigned long pass = 0;

	while (!stop_requested) {
		uint64_t pass_start = now_ns();

		for (size_t off = 0; off < w->len && !stop_requested; off += CHUNK) {
			size_t len = w->len - off < CHUNK ? w->len - off : CHUNK;
			uint64_t start = now_ns();

			if (pass)
				touch(w->base + off, len, pass);
			else
				fill(w, w->base + off, len, pass);
			record(w, start, len);
		}
		pass++;
		if (w->o->once)
			break;
		if (w->o->pass_ms)
			sleep_until(pass_start + w->o->pass_ms * 1000000ULL);
	}
	while (!stop_requested)
		sleep_until(now_ns() + 100000000ULL);
	return NULL;
}

static void *file_worker(void *arg)
{
	struct worker *w = arg;
	char *buf = malloc(CHUNK);

	if (!buf)
		return NULL;
	while (!stop_requested) {
		uint64_t pass_start = now_ns();

		for (off_t off = 0; off < (off_t)w->len && !stop_requested; off += CHUNK) {
			size_t len = w->len - off < CHUNK ? w->len - off : CHUNK;
			uint64_t start = now_ns();
			ssize_t got = pread(w->fd, buf, len, w->offset + off);

			if (got <= 0)
				break;
			record(w, start, got);
		}
		if (w->o->pass_ms)
			sleep_until(pass_start + w->o->pass_ms * 1000000ULL);
	}
	free(buf);
	return NULL;
}

/* Reads through the range once at the paced rate, then idles. */
static void *stream_worker(void *arg)
{
	struct worker *w = arg;
	char *buf = malloc(CHUNK);
	uint64_t t0 = now_ns(), due = t0;
	off_t off = 0;

	if (!buf)
		return NULL;
	while (!stop_requested && off < (off_t)w->len) {
		size_t len = w->len - off < CHUNK ? w->len - off : CHUNK;
		uint64_t start;
		ssize_t got;

		sleep_until(due);
		start = now_ns();
		got = pread(w->fd, buf, len, w->offset + off);
		if (got <= 0)
			break;
		record(w, start, got);
		off += got;
		/* The next chunk is due when the rate allows it. */
		due += (uint64_t)got * 1000000000ULL / rate_bytes(w->o, start - t0);
		if (due < start)
			due = start;
	}
	free(buf);
	while (!stop_requested)
		sleep_until(now_ns() + 100000000ULL);
	return NULL;
}

static void *grow_worker(void *arg)
{
	struct worker *w = arg;
	uint64_t t0 = now_ns(), due = t0;
	size_t off = 0;

	while (!stop_requested && off < w->len) {
		size_t len = w->len - off < CHUNK ? w->len - off : CHUNK;
		uint64_t start;

		sleep_until(due);
		start = now_ns();
		fill(w, w->base + off, len, off);
		record(w, start, len);
		off += len;
		due += (uint64_t)len * 1000000000ULL / rate_bytes(w->o, start - t0);
		if (due < start)
			due = start;
	}
	while (!stop_requested)
		sleep_until(now_ns() + 100000000ULL);
	return NULL;
}

static int cmp_uint(const void *a, const void *b)
{
	unsigned int x = *(const unsigned int *)a, y = *(const unsigned int *)b;

	return x < y ? -1 : x > y;
}

static void report(struct worker *ws, unsigned int n, unsigned int t)
{
	static unsigned int all[MAX_SAMPLES];
	unsigned int total = 0, i;
	unsigned long bytes = 0;

	for (i = 0; i < n; i++) {
		struct worker *w = &ws[i];
		unsigned int take;

		pthread_mutex_lock(&w->lock);
		take = w->nr_samples;
		if (total + take > MAX_SAMPLES)
			take = MAX_SAMPLES - total;
		memcpy(all + total, w->samples, take * sizeof(*all));
		total += take;
		bytes += w->bytes;
		w->nr_samples = 0;
		w->bytes = 0;
		pthread_mutex_unlock(&w->lock);
	}
	if (total)
		qsort(all, total, sizeof(*all), cmp_uint);
	printf("t=%u mb=%.1f p99_us=%u max_us=%u\n", t, bytes / (1024.0 * 1024.0),
	       total ? all[(total * 99) / 100] : 0, total ? all[total - 1] : 0);
	fflush(stdout);
}

int main(int argc, char **argv)
{
	static const struct option lopts[] = {
		{ "size", required_argument, NULL, 's' },
		{ "offset", required_argument, NULL, 'O' },
		{ "limit", required_argument, NULL, 'l' },
		{ "rate", required_argument, NULL, 'r' },
		{ "rate-max", required_argument, NULL, 'R' },
		{ "ramp", required_argument, NULL, 'a' },
		{ "path", required_argument, NULL, 'p' },
		{ "pass-ms", required_argument, NULL, 'm' },
		{ "threads", required_argument, NULL, 't' },
		{ "seconds", required_argument, NULL, 'S' },
		{ "fill", required_argument, NULL, 'f' },
		{ "once", no_argument, NULL, 'o' },
		{ "stream", no_argument, NULL, 'w' },
		{},
	};
	struct sigaction sa = { .sa_handler = on_signal };
	struct opts o = { .threads = 1 };
	struct worker *ws;
	void *(*fn)(void *);
	size_t total;
	char *base = NULL;
	int fd = -1, opt;
	unsigned int i, t;

	if (argc < 2)
		goto usage;
	o.mode = argv[1];
	optind = 2;
	while ((opt = getopt_long(argc, argv, "s:O:l:r:R:a:p:m:t:S:f:ow", lopts, NULL)) != -1) {
		switch (opt) {
		case 's':
			o.size_mb = strtoul(optarg, NULL, 0);
			break;
		case 'O':
			o.offset_mb = strtoul(optarg, NULL, 0);
			break;
		case 'l':
			o.limit_mb = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			o.rate_mb = strtoul(optarg, NULL, 0);
			break;
		case 'R':
			o.rate_max_mb = strtoul(optarg, NULL, 0);
			break;
		case 'a':
			o.ramp_s = strtoul(optarg, NULL, 0);
			break;
		case 'p':
			o.path = optarg;
			break;
		case 'm':
			o.pass_ms = strtoul(optarg, NULL, 0);
			break;
		case 't':
			o.threads = strtoul(optarg, NULL, 0);
			break;
		case 'S':
			o.seconds = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			o.fill_pct = strtoul(optarg, NULL, 0);
			if (o.fill_pct > 100)
				o.fill_pct = 100;
			break;
		case 'o':
			o.once = 1;
			break;
		case 'w':
			o.stream = 1;
			break;
		default:
			goto usage;
		}
	}
	if (!o.threads)
		o.threads = 1;

	if (!strcmp(o.mode, "anon")) {
		if (!o.size_mb)
			goto usage;
		total = o.size_mb << 20;
		fn = anon_worker;
	} else if (!strcmp(o.mode, "file")) {
		if (!o.size_mb || !o.path || (o.stream && !o.rate_mb))
			goto usage;
		total = o.size_mb << 20;
		fd = open(o.path, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "%s: %s\n", o.path, strerror(errno));
			return 1;
		}
		fn = o.stream ? stream_worker : file_worker;
		if (o.stream)
			o.threads = 1;
	} else if (!strcmp(o.mode, "grow")) {
		if (!o.rate_mb || !o.limit_mb)
			goto usage;
		total = o.limit_mb << 20;
		fn = grow_worker;
	} else {
		goto usage;
	}

	if (fd < 0) {
		base = mmap(NULL, total, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
		if (base == MAP_FAILED) {
			fprintf(stderr, "mmap %zu bytes: %s\n", total, strerror(errno));
			return 1;
		}
		/* Base pages, so reclaim and the counters see 4K units. */
		madvise(base, total, MADV_NOHUGEPAGE);
	}

	ws = calloc(o.threads, sizeof(*ws));
	if (!ws)
		return 1;
	for (i = 0; i < o.threads; i++) {
		struct worker *w = &ws[i];
		size_t share = total / o.threads;

		w->o = &o;
		w->samples = calloc(MAX_SAMPLES, sizeof(*w->samples));
		if (!w->samples)
			return 1;
		pthread_mutex_init(&w->lock, NULL);
		w->base = base ? base + i * share : NULL;
		w->offset = (off_t)(o.offset_mb << 20) + i * share;
		w->len = i == o.threads - 1 ? total - i * share : share;
		w->fd = fd;
		w->rng = 0x9e3779b97f4a7c15ULL ^ (i + 1) ^ ((uint64_t)getpid() << 32);
	}

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	for (i = 0; i < o.threads; i++)
		if (pthread_create(&ws[i].thread, NULL, fn, &ws[i])) {
			fprintf(stderr, "pthread_create: %s\n", strerror(errno));
			return 1;
		}

	for (t = 1; !stop_requested && (!o.seconds || t <= o.seconds); t++) {
		uint64_t due = now_ns() + 1000000000ULL;

		sleep_until(due);
		report(ws, o.threads, t);
	}
	stop_requested = 1;
	for (i = 0; i < o.threads; i++)
		pthread_join(ws[i].thread, NULL);
	return 0;
usage:
	fprintf(stderr, "usage: workload anon --size MB [--threads N] [--pass-ms N] [--once] [--fill PCT]\n"
		"       workload file --path P --size MB [--threads N] [--offset MB] [--pass-ms N]\n"
		"       workload file --path P --size MB [--offset MB] --stream --rate MB/s\n"
		"                     [--rate-max MB/s --ramp S]\n"
		"       workload grow --rate MB/s --limit MB [--threads N] [--rate-max MB/s --ramp S]\n"
		"                     [--fill PCT]\n"
		"       ... [--seconds S]\n");
	return 2;
}
