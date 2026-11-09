// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/*
 * bpf_reclaim: keep a buffer of free memory with a pool of BPF kthreads.
 *
 * Loads reclaim.bpf.c with the band and the target cgroup, starts the
 * controller and the workers, and prints what they did every interval until
 * SIGINT, SIGTERM or --duration.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "reclaim.h"
#include "reclaim.bpf.skel.h"

#define CGROOT "/sys/fs/cgroup"

static struct {
	const char *target;
	const char *pool;
	const char *csv;
	__u64 low_mb, high_mb;
	__u64 tick_us;
	__u64 chunk_kb;
	__u64 floor_kb;
	__u64 interval_ms;
	__u64 duration_s;
	int swappiness;
	int workers;
} opt = {
	.tick_us = 1000,
	.chunk_kb = 256,
	.floor_kb = 32,
	.interval_ms = 1000,
	.swappiness = -1,
	.workers = 4,
};

static volatile sig_atomic_t stop;

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "bpf_reclaim: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static __u64 now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* A cgroup's ID is the inode number of its directory on cgroup2. */
static __u64 cgroup_id(const char *path)
{
	char abs[PATH_MAX];
	struct stat st;

	if (path[0] == '/' && strncmp(path, CGROOT, strlen(CGROOT)))
		snprintf(abs, sizeof(abs), "%s%s", CGROOT, path);
	else if (path[0] == '/')
		snprintf(abs, sizeof(abs), "%s", path);
	else
		snprintf(abs, sizeof(abs), "%s/%s", CGROOT, path);
	if (stat(abs, &st) || !S_ISDIR(st.st_mode))
		die("no cgroup %s", abs);
	return st.st_ino;
}

static int nr_possible_nodes(void)
{
	int lo, hi, n = 1;
	FILE *in;

	in = fopen("/sys/devices/system/node/possible", "r");
	if (!in)
		return 1;
	if (fscanf(in, "%d-%d", &lo, &hi) == 2)
		n = hi + 1;
	fclose(in);
	return n > RECLAIM_MAX_NODES ? RECLAIM_MAX_NODES : n;
}

static int run_thread_prog(struct bpf_program *prog, __u32 idx, __u64 pool_cgid)
{
	struct reclaim_thread_args args = { .idx = idx, .pool_cgid = pool_cgid };
	LIBBPF_OPTS(bpf_test_run_opts, o, .ctx_in = &args, .ctx_size_in = sizeof(args));
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &o);
	return err ?: (int)o.retval;
}

static void on_signal(int sig)
{
	stop = 1;
}

static void usage(void)
{
	fprintf(stderr,
"Usage: bpf_reclaim [OPTIONS] --low MB TARGET_CGROUP\n"
"\n"
"Keep free memory between --low and --high by reclaiming from TARGET_CGROUP\n"
"(relative to " CGROOT ") with a pool of BPF kthreads.\n"
"\n"
"  -l, --low MB            start reclaiming when free memory is below this\n"
"  -H, --high MB           stop when it is back at this (default: low * 5 / 4)\n"
"  -w, --workers N         worker threads (default 4)\n"
"  -t, --tick-us N         controller period (default 1000)\n"
"  -c, --chunk-kb N        bytes per reclaim call, at most 256 (default 256)\n"
"  -f, --floor-kb N        KiB the pool must free per ms of worker time,\n"
"                          judged every 100 ms of work, or it pauses (default 32)\n"
"  -s, --swappiness N      reclaim swappiness, -1 for the cgroup's (default -1)\n"
"  -p, --pool-cgroup PATH  run the threads in this cgroup\n"
"  -i, --interval-ms N     status interval (default 1000)\n"
"  -o, --csv FILE          write the status lines to FILE as CSV instead\n"
"  -d, --duration S        stop after S seconds\n");
	exit(2);
}

static void parse_args(int argc, char **argv)
{
	static const struct option longopts[] = {
		{ "low", required_argument, NULL, 'l' },
		{ "high", required_argument, NULL, 'H' },
		{ "workers", required_argument, NULL, 'w' },
		{ "tick-us", required_argument, NULL, 't' },
		{ "chunk-kb", required_argument, NULL, 'c' },
		{ "floor-kb", required_argument, NULL, 'f' },
		{ "swappiness", required_argument, NULL, 's' },
		{ "pool-cgroup", required_argument, NULL, 'p' },
		{ "interval-ms", required_argument, NULL, 'i' },
		{ "csv", required_argument, NULL, 'o' },
		{ "duration", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	int c;

	while ((c = getopt_long(argc, argv, "l:H:w:t:c:f:s:p:i:o:d:h", longopts, NULL)) != -1) {
		switch (c) {
		case 'l': opt.low_mb = strtoull(optarg, NULL, 0); break;
		case 'H': opt.high_mb = strtoull(optarg, NULL, 0); break;
		case 'w': opt.workers = atoi(optarg); break;
		case 't': opt.tick_us = strtoull(optarg, NULL, 0); break;
		case 'c': opt.chunk_kb = strtoull(optarg, NULL, 0); break;
		case 'f': opt.floor_kb = strtoull(optarg, NULL, 0); break;
		case 's': opt.swappiness = atoi(optarg); break;
		case 'p': opt.pool = optarg; break;
		case 'i': opt.interval_ms = strtoull(optarg, NULL, 0); break;
		case 'o': opt.csv = optarg; break;
		case 'd': opt.duration_s = strtoull(optarg, NULL, 0); break;
		default: usage();
		}
	}
	if (optind != argc - 1 || !opt.low_mb)
		usage();
	opt.target = argv[optind];
	if (!opt.high_mb)
		opt.high_mb = opt.low_mb * 5 / 4;
	if (opt.high_mb <= opt.low_mb)
		die("--high must be above --low");
	if (opt.workers < 1 || opt.workers > RECLAIM_MAX_WORKERS)
		die("--workers must be 1 to %d", RECLAIM_MAX_WORKERS);
	if (opt.chunk_kb < 4 || opt.chunk_kb > 256)
		die("--chunk-kb must be 4 to 256");
	if (!opt.tick_us || !opt.interval_ms)
		usage();
}

static void report(FILE *out, struct reclaim_bpf *skel, struct reclaim_stats *prev,
		   __u64 t, __u64 dt)
{
	struct reclaim_stats s = skel->bss->stats;
	double secs = dt / 1e9;

	if (out)
		fprintf(out, "%.3f,%llu,%u,%llu,%llu,%.1f,%.1f,%llu,%llu,%llu\n", t / 1e9,
			skel->bss->free_now * 4096 >> 20, skel->bss->active,
			s.episodes - prev->episodes, s.calls - prev->calls,
			(s.reclaimed - prev->reclaimed) / 1048576.0 / secs,
			100.0 * (s.busy_ns - prev->busy_ns) / dt / opt.workers,
			s.backoffs - prev->backoffs, s.wakeups - prev->wakeups,
			s.errors - prev->errors);
	else
		printf("%7.1fs free %6llu MB %s  %6.1f MB/s  %6llu calls  busy %5.1f%%  "
		       "backoffs %llu wakeups %llu\n", t / 1e9,
		       skel->bss->free_now * 4096 >> 20, skel->bss->active ? "reclaiming" : "idle      ",
		       (s.reclaimed - prev->reclaimed) / 1048576.0 / secs, s.calls - prev->calls,
		       100.0 * (s.busy_ns - prev->busy_ns) / dt / opt.workers,
		       s.backoffs - prev->backoffs, s.wakeups - prev->wakeups);
	fflush(out ?: stdout);
	*prev = s;
}

int main(int argc, char **argv)
{
	__u64 pool_cgid = 0, t0, last, now;
	struct reclaim_stats prev = {};
	struct reclaim_bpf *skel;
	FILE *csv = NULL;
	int i, err;

	parse_args(argc, argv);
	skel = reclaim_bpf__open();
	if (!skel)
		die("open BPF object: %s", strerror(errno));
	skel->rodata->target_cgid = cgroup_id(opt.target);
	skel->rodata->low_pages = (opt.low_mb << 20) / 4096;
	skel->rodata->high_pages = (opt.high_mb << 20) / 4096;
	skel->rodata->tick_ns = opt.tick_us * 1000;
	skel->rodata->nr_workers = opt.workers;
	skel->rodata->chunk_bytes = opt.chunk_kb << 10;
	skel->rodata->floor_bytes_per_ms = opt.floor_kb << 10;
	skel->rodata->swappiness = opt.swappiness;
	skel->rodata->nr_nodes = nr_possible_nodes();
	if (opt.pool)
		pool_cgid = cgroup_id(opt.pool);

	err = reclaim_bpf__load(skel);
	if (err)
		die("load BPF object: %s", strerror(-err));
	err = reclaim_bpf__attach(skel);
	if (err)
		die("attach: %s", strerror(-err));

	/* Workers first, so that the controller's first wake finds them. */
	for (i = 1; i <= opt.workers; i++) {
		err = run_thread_prog(skel->progs.create_thread, i, pool_cgid);
		if (err)
			die("create worker %d: %s", i, strerror(-err));
	}
	err = run_thread_prog(skel->progs.create_thread, RECLAIM_CONTROLLER, pool_cgid);
	if (err)
		die("create controller: %s", strerror(-err));

	if (opt.csv) {
		csv = fopen(opt.csv, "w");
		if (!csv)
			die("open %s: %s", opt.csv, strerror(errno));
		fprintf(csv, "t,free_mb,active,episodes,calls,reclaim_mbs,busy_pct,backoffs,"
			"wakeups,errors\n");
	}
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	t0 = last = now_ns();
	while (!stop) {
		struct timespec nap = { .tv_nsec = 10 * 1000000 };

		nanosleep(&nap, NULL);
		now = now_ns();
		if (now - last >= opt.interval_ms * 1000000ULL) {
			report(csv, skel, &prev, now - t0, now - last);
			last = now;
		}
		if (opt.duration_s && now - t0 >= opt.duration_s * 1000000000ULL)
			break;
	}

	run_thread_prog(skel->progs.stop_thread, RECLAIM_CONTROLLER, 0);
	for (i = 1; i <= opt.workers; i++)
		run_thread_prog(skel->progs.stop_thread, i, 0);
	now = now_ns();
	prev = skel->bss->stats;
	fprintf(stderr, "total: %.1f s, %llu episodes, %llu calls, %.1f MB reclaimed, %.2f s busy, "
		"%llu backoffs, %llu wakeups, %llu errors\n", (now - t0) / 1e9, prev.episodes,
		prev.calls, prev.reclaimed / 1048576.0, prev.busy_ns / 1e9, prev.backoffs,
		prev.wakeups, prev.errors);
	if (csv)
		fclose(csv);
	reclaim_bpf__destroy(skel);
	return 0;
}
