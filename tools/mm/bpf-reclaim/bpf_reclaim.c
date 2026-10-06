// SPDX-License-Identifier: GPL-2.0
/*
 * Run the BPF proactive reclaimer over the children of a cgroup.
 *
 * Usage: bpf_reclaim [options] ROOT_CGROUP
 *
 * Loads the reclaim program, creates the worker pool and the controller,
 * prints "ready" and then a status block every --status-ms until SIGTERM or
 * SIGINT. On exit it stops the threads and prints the totals as key=value
 * lines. The policy keeps --buffer MB of memory free by reclaiming from the
 * children of ROOT_CGROUP, never taking one below --floor MB and never while
 * its refaults show the reclaim eating its working set, alone or with its
 * PSI memory "some" pressure above --target, in percent of wall time.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
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

#define MB (1024.0 * 1024.0)

static volatile sig_atomic_t stop_requested;

/* A child of the root, with its last sample for the rates. */
struct child {
	char name[256];
	int fd;
	struct bpf_reclaim_cgroup last;
	int seen;
};

static void on_signal(int sig)
{
	stop_requested = 1;
}

static int verbose_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	return vfprintf(stderr, fmt, args);
}

static int run_prog(struct bpf_program *prog, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (err) {
		fprintf(stderr, "%s: run failed: %s\n", name, strerror(errno));
		return err;
	}
	if ((int)opts.retval) {
		fprintf(stderr, "%s: returned %d (%s)\n", name, (int)opts.retval,
			strerror(-(int)opts.retval));
		return (int)opts.retval;
	}
	return 0;
}

/* The cgroup ID is the kernfs inode number, which the file handle carries. */
static unsigned long long cgroup_id(const char *path)
{
	struct {
		struct file_handle fh;
		unsigned char bytes[8];
	} h = { .fh.handle_bytes = 8 };
	unsigned long long id;
	int mount_id;

	if (name_to_handle_at(AT_FDCWD, path, &h.fh, &mount_id, 0) || h.fh.handle_bytes != 8)
		return 0;
	memcpy(&id, h.bytes, sizeof(id));
	return id;
}

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static unsigned long long total_ram(void)
{
	long pages = sysconf(_SC_PHYS_PAGES), size = sysconf(_SC_PAGESIZE);

	if (pages < 0 || size < 0)
		return 0;
	return (unsigned long long)pages * size;
}

/*
 * Refresh the list of children from the root directory, keeping the entries
 * that are still there so their last samples survive, and adding new ones
 * with an open directory fd, which is the key for the cgroup storage map.
 */
static int scan_children(const char *root, struct child *kids, int max)
{
	struct dirent *de;
	struct stat st;
	char path[PATH_MAX];
	int i, n = 0;
	DIR *dir;

	for (i = 0; i < max; i++)
		kids[i].seen = 0;
	dir = opendir(root);
	if (!dir)
		return 0;
	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s", root, de->d_name);
		if (stat(path, &st) || !S_ISDIR(st.st_mode))
			continue;
		for (i = 0; i < max; i++)
			if (kids[i].fd >= 0 && !strcmp(kids[i].name, de->d_name))
				break;
		if (i == max) {
			for (i = 0; i < max; i++)
				if (kids[i].fd < 0)
					break;
			if (i == max)
				continue;
			snprintf(kids[i].name, sizeof(kids[i].name), "%s", de->d_name);
			memset(&kids[i].last, 0, sizeof(kids[i].last));
			kids[i].fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
			if (kids[i].fd < 0)
				continue;
		}
		kids[i].seen = 1;
	}
	closedir(dir);
	for (i = 0; i < max; i++) {
		if (kids[i].fd >= 0 && !kids[i].seen) {
			close(kids[i].fd);
			kids[i].fd = -1;
		}
		if (kids[i].fd >= 0)
			n++;
	}
	return n;
}

static int child_state(struct reclaim *skel, struct child *kid, struct bpf_reclaim_cgroup *cg)
{
	return bpf_map__lookup_elem(skel->maps.cgroups, &kid->fd, sizeof(kid->fd), cg,
				    sizeof(*cg), 0);
}

static void print_status(struct reclaim *skel, struct child *kids, int max, double t,
			 double dt, struct bpf_reclaim_control *pc)
{
	struct bpf_reclaim_control c;
	struct bpf_reclaim_cgroup cg;
	unsigned int zero = 0;
	double reclaimed = 0;
	int i;

	if (bpf_map__lookup_elem(skel->maps.control, &zero, sizeof(zero), &c, sizeof(c), 0))
		return;
	for (i = 0; i < max; i++)
		if (kids[i].fd >= 0 && !child_state(skel, &kids[i], &cg))
			reclaimed += cg.reclaimed - kids[i].last.reclaimed;
	printf("t=%.1f free=%.0fM deficit=%.0fM demand=%.1fM/tick awake=%u cgroups=%u "
	       "reclaimed=%.1fM/s\n",
	       t, c.free / MB,
	       c.free < skel->bss->cfg.buffer ? (skel->bss->cfg.buffer - c.free) / MB : 0.0,
	       c.demand / MB, c.awake, c.nr_cgroups, reclaimed / MB / dt);
	*pc = c;
	for (i = 0; i < max; i++) {
		if (kids[i].fd < 0 || child_state(skel, &kids[i], &cg))
			continue;
		printf("  cg=%s usage=%.0fM pressure=%.2f%% refault=%.1fM/s undone=%.1fM/s "
		       "growth=%+.1fM/s cold=%.0f%% headroom=%.0fM reclaimed=%.1fM/s cpu=%.0f%% "
		       "eff=%.0fM/s refaults=%llu calls=%llu empty=%llu%s%s\n",
		       kids[i].name, cg.usage / MB, cg.pressure_ppm / 1e4, cg.refault_rate / MB,
		       cg.undone_rate / MB, cg.growth / MB,
		       100.0 * cg.coldness / BPF_RECLAIM_COLD_MAX, cg.headroom / MB,
		       (cg.reclaimed - kids[i].last.reclaimed) / MB / dt, cg.busy_ppm / 1e4,
		       cg.efficiency / MB,
		       (unsigned long long)(cg.refaults_total - kids[i].last.refaults_total),
		       (unsigned long long)(cg.calls - kids[i].last.calls),
		       (unsigned long long)(cg.empty - kids[i].last.empty),
		       cg.gated ? " gated" : "", cg.rest ? " resting" : "");
		kids[i].last = cg;
	}
	fflush(stdout);
}

static void print_totals(struct reclaim *skel, struct child *kids, int max, unsigned int threads)
{
	struct bpf_reclaim_control c;
	struct bpf_reclaim_cgroup cg;
	struct bpf_reclaim_thread t;
	unsigned int zero = 0, i;

	if (!bpf_map__lookup_elem(skel->maps.control, &zero, sizeof(zero), &c, sizeof(c), 0))
		printf("control ticks=%llu deficit_ticks=%llu free_min=%llu wakeups=%llu\n",
		       (unsigned long long)c.ticks, (unsigned long long)c.deficit_ticks,
		       (unsigned long long)c.free_min, (unsigned long long)c.wakeups);
	for (i = 0; i < threads; i++) {
		if (bpf_map__lookup_elem(skel->maps.threads, &i, sizeof(i), &t, sizeof(t), 0))
			continue;
		printf("thread=%u rounds=%llu claims=%llu reclaimed=%llu busy_ms=%llu sleeps=%llu\n",
		       t.index, (unsigned long long)t.rounds, (unsigned long long)t.claims,
		       (unsigned long long)t.reclaimed, (unsigned long long)(t.busy_ns / 1000000),
		       (unsigned long long)t.sleeps);
	}
	for (i = 0; i < (unsigned int)max; i++) {
		if (kids[i].fd < 0 || child_state(skel, &kids[i], &cg))
			continue;
		printf("cgroup=%s reclaimed=%llu calls=%llu empty=%llu quota_given=%llu "
		       "busy_ms=%llu refaults=%llu undone=%llu gated_ticks=%llu expensive_ticks=%llu "
		       "budget_hits=%llu scanned=%llu stolen=%llu coldness=%llu usage=%llu\n",
		       kids[i].name, (unsigned long long)cg.reclaimed,
		       (unsigned long long)cg.calls, (unsigned long long)cg.empty,
		       (unsigned long long)cg.quota_given,
		       (unsigned long long)(cg.busy_ns / 1000000),
		       (unsigned long long)cg.refaults_total, (unsigned long long)cg.undone_total,
		       (unsigned long long)cg.gated_ticks, (unsigned long long)cg.expensive_ticks,
		       (unsigned long long)cg.budget_hits, (unsigned long long)cg.scanned_total,
		       (unsigned long long)cg.stolen_total, (unsigned long long)cg.coldness,
		       (unsigned long long)cg.usage);
	}
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "buffer", required_argument, NULL, 'b' },
		{ "interval-ms", required_argument, NULL, 'i' },
		{ "pool", required_argument, NULL, 'P' },
		{ "chunk", required_argument, NULL, 'c' },
		{ "floor", required_argument, NULL, 'f' },
		{ "target", required_argument, NULL, 't' },
		{ "cpu-budget", required_argument, NULL, 'C' },
		{ "min-efficiency", required_argument, NULL, 'e' },
		{ "swappiness", required_argument, NULL, 'w' },
		{ "status-ms", required_argument, NULL, 's' },
		{ "verbose", no_argument, NULL, 'v' },
		{},
	};
	static struct child kids[BPF_RECLAIM_MAX_CGROUPS];
	struct bpf_reclaim_cfg cfg = {
		.interval_ns = 100 * 1000 * 1000ULL,
		.chunk = 2ULL << 20,
		.target_ppm = 10000,
		.min_efficiency = 16ULL << 20,
		.pool = 2,
		.swappiness = -1,
	};
	struct bpf_reclaim_control pc = {};
	struct sigaction sa = { .sa_handler = on_signal };
	struct reclaim *skel;
	const char *root;
	double status_s = 1.0, target_pct = 1.0, start, last;
	int opt, i, err = 1;

	cfg.buffer = total_ram() / 8;
	while ((opt = getopt_long(argc, argv, "b:i:P:c:f:t:C:e:w:s:v", opts, NULL)) != -1) {
		switch (opt) {
		case 'b':
			cfg.buffer = strtoull(optarg, NULL, 0) << 20;
			break;
		case 'i':
			cfg.interval_ns = strtoull(optarg, NULL, 0) * 1000000ULL;
			break;
		case 'P':
			cfg.pool = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			cfg.chunk = strtoull(optarg, NULL, 0) << 20;
			break;
		case 'f':
			cfg.floor = strtoull(optarg, NULL, 0) << 20;
			break;
		case 't':
			target_pct = atof(optarg);
			cfg.target_ppm = target_pct * 10000;
			break;
		case 'C':
			cfg.cpu_budget_ppm = atof(optarg) * 10000;
			break;
		case 'e':
			cfg.min_efficiency = strtoull(optarg, NULL, 0) << 20;
			break;
		case 'w':
			cfg.swappiness = !strcmp(optarg, "anon") ? BPF_RECLAIM_SWAPPINESS_ANON_ONLY
							       : atoi(optarg);
			break;
		case 's':
			status_s = strtoul(optarg, NULL, 0) / 1000.0;
			break;
		case 'v':
			libbpf_set_print(verbose_print);
			break;
		default:
			goto usage;
		}
	}
	if (optind != argc - 1)
		goto usage;
	root = argv[optind];
	if (!cfg.pool || cfg.pool > BPF_RECLAIM_MAX_THREADS) {
		fprintf(stderr, "the pool must have 1 to %d threads\n", BPF_RECLAIM_MAX_THREADS);
		return 1;
	}
	if (!cfg.interval_ns || cfg.chunk < BPF_RECLAIM_PAGE_SIZE) {
		fprintf(stderr, "the interval and the chunk must not be zero\n");
		return 1;
	}
	/* By default a child may have the whole pool; the budget bounds waste, not work. */
	if (!cfg.cpu_budget_ppm)
		cfg.cpu_budget_ppm = cfg.pool * 1000000ULL;
	cfg.root_cgroup_id = cgroup_id(root);
	if (!cfg.root_cgroup_id) {
		fprintf(stderr, "%s: not a cgroup: %s\n", root, strerror(errno));
		return 1;
	}
	for (i = 0; i < BPF_RECLAIM_MAX_CGROUPS; i++)
		kids[i].fd = -1;

	skel = reclaim__open();
	if (!skel) {
		fprintf(stderr, "failed to open the reclaim object: %s\n", strerror(errno));
		return 1;
	}
	skel->bss->cfg = cfg;
	if (reclaim__load(skel)) {
		fprintf(stderr, "failed to load the reclaim object: %s\n", strerror(errno));
		goto out;
	}

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	if (run_prog(skel->progs.reclaim_setup, "setup")) {
		run_prog(skel->progs.reclaim_teardown, "teardown");
		goto out;
	}
	printf("ready root=%s buffer=%.0fM pool=%u interval=%.0fms chunk=%.0fM floor=%.0fM "
	       "target=%.2f%% cpu_budget=%.0f%% min_efficiency=%.0fM/s\n",
	       root, cfg.buffer / MB, cfg.pool, cfg.interval_ns / 1e6, cfg.chunk / MB,
	       cfg.floor / MB, target_pct, cfg.cpu_budget_ppm / 1e4, cfg.min_efficiency / MB);
	fflush(stdout);

	start = last = now_s();
	while (!stop_requested) {
		struct timespec ts = { .tv_nsec = 50 * 1000 * 1000 };
		double t;

		nanosleep(&ts, NULL);
		t = now_s();
		if (status_s > 0 && t - last >= status_s) {
			scan_children(root, kids, BPF_RECLAIM_MAX_CGROUPS);
			print_status(skel, kids, BPF_RECLAIM_MAX_CGROUPS, t - start, t - last, &pc);
			last = t;
		}
	}

	err = run_prog(skel->progs.reclaim_teardown, "teardown");
	scan_children(root, kids, BPF_RECLAIM_MAX_CGROUPS);
	print_totals(skel, kids, BPF_RECLAIM_MAX_CGROUPS, cfg.pool);
	fflush(stdout);
out:
	reclaim__destroy(skel);
	return err ? 1 : 0;
usage:
	fprintf(stderr, "usage: %s [-v] [--buffer MB] [--interval-ms N] [--pool N] [--chunk MB]\n"
		"          [--floor MB] [--target PCT] [--cpu-budget PCT] [--min-efficiency MB/s]\n"
		"          [--swappiness N|anon] [--status-ms N] ROOT_CGROUP\n",
		basename(argv[0]));
	return 2;
}
