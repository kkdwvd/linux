// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Timer NMI Concurrency Tester
 *
 * Tests timer operations interleaving between normal and NMI context.
 * Follows the pattern from bpf_test_rqspinlock.c kernel module.
 *
 * Scenarios:
 * 1. Normal: start,        NMI: cancel_async
 * 2. Normal: cancel_async, NMI: start
 * 3. Normal: start,        NMI: start (callback interleave)
 * 4. Normal: cancel_sync,  NMI: start
 * 5. Normal: cancel_sync,  NMI: cancel_async
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <linux/types.h>
#include <linux/perf_event.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "timer_conctest.skel.h"

/* Simple coordination - like rqspinlock kmod */
static volatile int skip;

struct thread_arg {
	int prog_fd;
	int cpu;
};

static int pin_to_cpu(int cpu)
{
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	return pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

static int open_perf_event(int cpu, int sample_period)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.size = sizeof(attr),
		.sample_period = sample_period,
		.pinned = 1,
		.disabled = 0,
	};

	return syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
}

/*
 * Worker thread - runs BPF program in loop until skip is set.
 * Pattern from res_spin_lock.c spin_lock_thread().
 */
static void *worker_thread(void *arg)
{
	struct thread_arg *ta = arg;
	struct bpf_test_run_opts opts = {
		.sz = sizeof(struct bpf_test_run_opts),
	};
	int err;

	if (pin_to_cpu(ta->cpu)) {
		fprintf(stderr, "Failed to pin to CPU %d\n", ta->cpu);
		pthread_exit(arg);
	}

	while (!skip) {
		err = bpf_prog_test_run_opts(ta->prog_fd, &opts);
		if (err) {
			fprintf(stderr, "bpf_prog_test_run_opts error: %d (errno=%d, prog_fd=%d)\n",
				err, errno, ta->prog_fd);
			break;
		}
	}

	pthread_exit(arg);
}

/*
 * Timing stats for a single operation type
 */
struct op_timing {
	__u64 total_ns;
	__u64 max_ns;
	__u64 count;
	__u64 over_1ms;
	__u64 over_10ms;
	__u64 over_100ms;
};

/*
 * Aggregate per-CPU stats
 */
struct stats {
	__u64 start_attempts, start_success;
	__u64 cancel_attempts, cancel_success;
	__u64 cancel_sync_attempts, cancel_sync_success;
	__u64 callback_executions;
	__u64 nmi_hits;
	__u64 nmi_start_attempts, nmi_start_success;
	__u64 nmi_cancel_attempts, nmi_cancel_success;
	__u64 nmi_during_start, nmi_during_cancel, nmi_during_cancel_sync;
	__u64 nmi_during_callback;
	/* Timing stats */
	struct op_timing start_timing;
	struct op_timing cancel_timing;
	struct op_timing cancel_sync_timing;
	struct op_timing callback_timing;
	struct op_timing nmi_start_timing;
	struct op_timing nmi_cancel_timing;
};

static int read_stats(struct timer_conctest *skel, struct stats *out)
{
	int ncpus = libbpf_num_possible_cpus();
	void *per_cpu;
	size_t value_size;
	int key = 0;
	int err, i;

	/* Get the per-CPU array value size from map */
	value_size = bpf_map__value_size(skel->maps.stats_map);
	per_cpu = calloc(ncpus, value_size);
	if (!per_cpu)
		return -ENOMEM;

	err = bpf_map__lookup_elem(skel->maps.stats_map, &key, sizeof(key),
				   per_cpu, ncpus * value_size, 0);
	if (err) {
		free(per_cpu);
		return err;
	}

	memset(out, 0, sizeof(*out));

	/* Sum across CPUs - access raw bytes matching BPF struct layout */
	for (i = 0; i < ncpus; i++) {
		__u64 *vals = (__u64 *)((char *)per_cpu + i * value_size);
		/* Fields match timer_conctest_stats layout (all __u64) */
		out->start_attempts += vals[0];
		out->start_success += vals[1];
		/* vals[2] = start_failure */
		out->cancel_attempts += vals[3];
		out->cancel_success += vals[4];
		/* vals[5] = cancel_failure */
		out->cancel_sync_attempts += vals[6];
		out->cancel_sync_success += vals[7];
		/* vals[8] = cancel_sync_failure */
		out->callback_executions += vals[9];
		/* vals[10] = callback_restarts */
		out->nmi_start_attempts += vals[11];
		out->nmi_start_success += vals[12];
		/* vals[13] = nmi_start_failure */
		out->nmi_cancel_attempts += vals[14];
		out->nmi_cancel_success += vals[15];
		out->nmi_during_start += vals[16];
		out->nmi_during_cancel += vals[17];
		out->nmi_during_cancel_sync += vals[18];
		out->nmi_during_callback += vals[19];
		out->nmi_hits += vals[20];

		/* Timing stats - each op_timing is 6 __u64 fields */
		/* start_timing at vals[21-26] */
		out->start_timing.total_ns += vals[21];
		if (vals[22] > out->start_timing.max_ns)
			out->start_timing.max_ns = vals[22];
		out->start_timing.count += vals[23];
		out->start_timing.over_1ms += vals[24];
		out->start_timing.over_10ms += vals[25];
		out->start_timing.over_100ms += vals[26];

		/* cancel_timing at vals[27-32] */
		out->cancel_timing.total_ns += vals[27];
		if (vals[28] > out->cancel_timing.max_ns)
			out->cancel_timing.max_ns = vals[28];
		out->cancel_timing.count += vals[29];
		out->cancel_timing.over_1ms += vals[30];
		out->cancel_timing.over_10ms += vals[31];
		out->cancel_timing.over_100ms += vals[32];

		/* cancel_sync_timing at vals[33-38] */
		out->cancel_sync_timing.total_ns += vals[33];
		if (vals[34] > out->cancel_sync_timing.max_ns)
			out->cancel_sync_timing.max_ns = vals[34];
		out->cancel_sync_timing.count += vals[35];
		out->cancel_sync_timing.over_1ms += vals[36];
		out->cancel_sync_timing.over_10ms += vals[37];
		out->cancel_sync_timing.over_100ms += vals[38];

		/* callback_timing at vals[39-44] */
		out->callback_timing.total_ns += vals[39];
		if (vals[40] > out->callback_timing.max_ns)
			out->callback_timing.max_ns = vals[40];
		out->callback_timing.count += vals[41];
		out->callback_timing.over_1ms += vals[42];
		out->callback_timing.over_10ms += vals[43];
		out->callback_timing.over_100ms += vals[44];

		/* nmi_start_timing at vals[45-50] */
		out->nmi_start_timing.total_ns += vals[45];
		if (vals[46] > out->nmi_start_timing.max_ns)
			out->nmi_start_timing.max_ns = vals[46];
		out->nmi_start_timing.count += vals[47];
		out->nmi_start_timing.over_1ms += vals[48];
		out->nmi_start_timing.over_10ms += vals[49];
		out->nmi_start_timing.over_100ms += vals[50];

		/* nmi_cancel_timing at vals[51-56] */
		out->nmi_cancel_timing.total_ns += vals[51];
		if (vals[52] > out->nmi_cancel_timing.max_ns)
			out->nmi_cancel_timing.max_ns = vals[52];
		out->nmi_cancel_timing.count += vals[53];
		out->nmi_cancel_timing.over_1ms += vals[54];
		out->nmi_cancel_timing.over_10ms += vals[55];
		out->nmi_cancel_timing.over_100ms += vals[56];
	}

	free(per_cpu);
	return 0;
}

static void print_timing(const char *name, struct op_timing *t)
{
	__u64 avg_ns = t->count ? t->total_ns / t->count : 0;

	if (t->count == 0)
		return;

	printf("    %s: count=%llu avg=%llu ns max=%llu ns",
	       name, t->count, avg_ns, t->max_ns);

	if (t->over_1ms || t->over_10ms || t->over_100ms)
		printf(" [ABERRATIONS: >1ms=%llu >10ms=%llu >100ms=%llu]",
		       t->over_1ms, t->over_10ms, t->over_100ms);
	printf("\n");
}

static void print_stats(struct stats *s)
{
	printf("Results:\n");
	printf("  Normal context:\n");
	printf("    start: %llu/%llu\n", s->start_success, s->start_attempts);
	printf("    cancel_async: %llu/%llu\n", s->cancel_success, s->cancel_attempts);
	printf("    cancel_sync: %llu/%llu\n", s->cancel_sync_success, s->cancel_sync_attempts);
	printf("    callbacks: %llu\n", s->callback_executions);
	printf("  NMI context:\n");
	printf("    hits: %llu\n", s->nmi_hits);
	printf("    start: %llu/%llu\n", s->nmi_start_success, s->nmi_start_attempts);
	printf("    cancel: %llu/%llu\n", s->nmi_cancel_success, s->nmi_cancel_attempts);
	printf("  Interleaving:\n");
	printf("    nmi_during: start=%llu cancel_async=%llu cancel_sync=%llu callback=%llu\n",
	       s->nmi_during_start, s->nmi_during_cancel,
	       s->nmi_during_cancel_sync, s->nmi_during_callback);
	printf("  Timing:\n");
	print_timing("start", &s->start_timing);
	print_timing("cancel_async", &s->cancel_timing);
	print_timing("cancel_sync", &s->cancel_sync_timing);
	print_timing("callback", &s->callback_timing);
	print_timing("nmi_start", &s->nmi_start_timing);
	print_timing("nmi_cancel", &s->nmi_cancel_timing);
}

struct scenario {
	int normal_op;  /* 0=start, 1=cancel_async, 2=cancel_sync */
	int nmi_op;     /* 0=start, 1=cancel_async */
	const char *desc;
};

static struct scenario scenarios[] = {
	{ 0, 1, "Normal: start, NMI: cancel_async" },
	{ 1, 0, "Normal: cancel_async, NMI: start" },
	{ 0, 0, "Normal: start, NMI: start (callback)" },
	{ 2, 0, "Normal: cancel_sync, NMI: start" },
	{ 2, 1, "Normal: cancel_sync, NMI: cancel_async" },
};
#define NUM_SCENARIOS (sizeof(scenarios) / sizeof(scenarios[0]))

static int run_test(int scenario_idx, int cpu, int duration_secs, int sample_period)
{
	struct timer_conctest *skel = NULL;
	struct bpf_link *nmi_link = NULL;
	struct thread_arg ta = { 0 };
	pthread_t thread;
	int pmu_fd = -1;
	struct stats stats;
	struct bpf_test_run_opts opts = {
		.sz = sizeof(struct bpf_test_run_opts),
	};
	struct scenario *sc = &scenarios[scenario_idx];
	void *ret;
	int err;

	printf("\n=== Scenario %d: %s ===\n", scenario_idx + 1, sc->desc);
	printf("Running on CPU %d for %d seconds...\n", cpu, duration_secs);

	WRITE_ONCE(skip, 0);

	skel = timer_conctest__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load skeleton\n");
		return -1;
	}

	/* Initialize timer */
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.init_timer), &opts);
	if (err || opts.retval) {
		fprintf(stderr, "Failed to init timer: err=%d errno=%d retval=%d\n",
			err, errno, opts.retval);
		goto out;
	}

	pmu_fd = open_perf_event(cpu, sample_period);
	if (pmu_fd < 0) {
		if (errno == ENOENT || errno == EOPNOTSUPP) {
			printf("SKIP: no hardware perf events\n");
			err = 0;
			goto out;
		}
		fprintf(stderr, "Failed to open perf event: %s\n", strerror(errno));
		err = -1;
		goto out;
	}

	nmi_link = bpf_program__attach_perf_event(skel->progs.nmi_timer_op, pmu_fd);
	if (!nmi_link) {
		fprintf(stderr, "Failed to attach perf event\n");
		err = -1;
		goto out;
	}
	pmu_fd = -1;

	/* Configure scenario */
	skel->bss->nmi_op = sc->nmi_op;
	skel->data->restart_timer = 1;
	skel->bss->enabled = 1;

	/* Start initial timer */
	bpf_prog_test_run_opts(bpf_program__fd(skel->progs.do_start), &opts);

	/* Select worker program */
	switch (sc->normal_op) {
	case 0:
		ta.prog_fd = bpf_program__fd(skel->progs.do_start);
		break;
	case 1:
		ta.prog_fd = bpf_program__fd(skel->progs.do_cancel);
		break;
	case 2:
		ta.prog_fd = bpf_program__fd(skel->progs.do_cancel_sync);
		break;
	}
	ta.cpu = cpu;

	/* Start worker thread */
	err = pthread_create(&thread, NULL, worker_thread, &ta);
	if (err) {
		fprintf(stderr, "Failed to create thread: %s\n", strerror(err));
		goto out;
	}

	/* Let it run - simple sleep like rqspinlock kmod */
	sleep(duration_secs);

	/* Stop - set flags first, then join */
	printf("Stopping...\n");
	skel->bss->enabled = 0;
	skel->data->restart_timer = 0;
	WRITE_ONCE(skip, 1);

	/* Destroy NMI link before joining to stop interference */
	bpf_link__destroy(nmi_link);
	nmi_link = NULL;

	/* Join worker */
	pthread_join(thread, &ret);

	/* Read and print stats */
	if (read_stats(skel, &stats) == 0)
		print_stats(&stats);

	err = (stats.nmi_hits > 0) ? 0 : -1;
	printf("Result: %s\n", err == 0 ? "PASS" : "FAIL (no NMI hits)");

out:
	bpf_link__destroy(nmi_link);
	if (pmu_fd >= 0)
		close(pmu_fd);
	timer_conctest__destroy(skel);
	return err;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -t, --test <1-%zu>   Run specific scenario (default: all)\n", NUM_SCENARIOS);
	fprintf(stderr, "  -c, --cpu <n>        Target CPU (default: 1)\n");
	fprintf(stderr, "  -d, --duration <s>   Duration in seconds (default: 5)\n");
	fprintf(stderr, "  -f, --freq <n>       Perf sample period (default: 10000)\n");
	fprintf(stderr, "  -h, --help           Show this help\n");
	fprintf(stderr, "\nScenarios:\n");
	for (size_t i = 0; i < NUM_SCENARIOS; i++)
		fprintf(stderr, "  %zu. %s\n", i + 1, scenarios[i].desc);
}

int main(int argc, char **argv)
{
	static struct option long_options[] = {
		{"test", required_argument, 0, 't'},
		{"cpu", required_argument, 0, 'c'},
		{"duration", required_argument, 0, 'd'},
		{"freq", required_argument, 0, 'f'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	int cpu = 1;
	int duration = 5;
	int sample_period = 10000;
	int scenario = -1;
	int opt;
	int failed = 0;

	while ((opt = getopt_long(argc, argv, "t:c:d:f:h", long_options, NULL)) != -1) {
		switch (opt) {
		case 't':
			scenario = atoi(optarg) - 1;
			if (scenario < 0 || scenario >= (int)NUM_SCENARIOS) {
				fprintf(stderr, "Invalid scenario\n");
				return 1;
			}
			break;
		case 'c':
			cpu = atoi(optarg);
			break;
		case 'd':
			duration = atoi(optarg);
			break;
		case 'f':
			sample_period = atoi(optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (get_nprocs() < 2) {
		fprintf(stderr, "Need at least 2 CPUs\n");
		return 0;
	}

	if (cpu < 0 || cpu >= get_nprocs()) {
		fprintf(stderr, "Invalid CPU %d\n", cpu);
		return 1;
	}

	printf("Timer NMI Concurrency Tester\n");
	printf("============================\n");

	if (scenario >= 0) {
		return run_test(scenario, cpu, duration, sample_period) ? 1 : 0;
	}

	/* Run all scenarios */
	for (size_t i = 0; i < NUM_SCENARIOS; i++) {
		if (run_test(i, cpu, duration, sample_period) != 0)
			failed++;
	}

	printf("\n=== Summary: %d/%zu passed ===\n",
	       (int)NUM_SCENARIOS - failed, NUM_SCENARIOS);
	return failed > 0 ? 1 : 0;
}
