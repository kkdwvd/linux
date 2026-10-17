// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <network_helpers.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#include "res_spin_lock.skel.h"
#include "res_spin_lock_fail.skel.h"

void test_res_spin_lock_failure(void)
{
	RUN_TESTS(res_spin_lock_fail);
}

static volatile int skip;

static void *spin_lock_thread(void *arg)
{
	int err, prog_fd = *(u32 *) arg;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 10000,
	);

	while (!READ_ONCE(skip)) {
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		if (err || topts.retval) {
			ASSERT_OK(err, "test_run");
			ASSERT_OK(topts.retval, "test_run retval");
			break;
		}
	}
	pthread_exit(arg);
}

void test_res_spin_lock_success(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct res_spin_lock *skel;
	pthread_t thread_id[16];
	int prog_fd, i, err;
	void *ret;

	if (get_nprocs() < 2) {
		test__skip();
		return;
	}

	skel = res_spin_lock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "res_spin_lock__open_and_load"))
		return;
	/* AA deadlock */
	prog_fd = bpf_program__fd(skel->progs.res_spin_lock_test);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "error");
	ASSERT_OK(topts.retval, "retval");

	prog_fd = bpf_program__fd(skel->progs.res_spin_lock_test_held_lock_max);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "error");
	ASSERT_OK(topts.retval, "retval");

	/* Multi-threaded ABBA deadlock. */

	WRITE_ONCE(skip, false);
	prog_fd = bpf_program__fd(skel->progs.res_spin_lock_test_AB);
	for (i = 0; i < 16; i++) {
		int err;

		err = pthread_create(&thread_id[i], NULL, &spin_lock_thread, &prog_fd);
		if (!ASSERT_OK(err, "pthread_create"))
			goto end;
	}

	topts.retval = 0;
	topts.repeat = 1000;
	int fd = bpf_program__fd(skel->progs.res_spin_lock_test_BA);
	while (!topts.retval && !err && !READ_ONCE(skel->bss->err)) {
		err = bpf_prog_test_run_opts(fd, &topts);
	}

	WRITE_ONCE(skip, true);

	for (i = 0; i < 16; i++) {
		if (!ASSERT_OK(pthread_join(thread_id[i], &ret), "pthread_join"))
			goto end;
		if (!ASSERT_EQ(ret, &prog_fd, "ret == prog_fd"))
			goto end;
	}

	ASSERT_EQ(READ_ONCE(skel->bss->err), -EDEADLK, "deadlock err");
	ASSERT_OK(err, "err");
	ASSERT_EQ(topts.retval, -EDEADLK, "deadlock retval");
end:
	res_spin_lock__destroy(skel);
	return;
}

void serial_test_res_spin_lock_stress(void)
{
	struct perf_event_attr attr = {
		.size = sizeof(attr),
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};
	static const char * const modes[] = { "AA", "ABBA" };
	char params[32];
	int pmu_fd;

	if (get_nprocs() < 3) {
		test__skip();
		return;
	}

	pmu_fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
	if (pmu_fd < 0) {
		if (errno == ENOENT || errno == EOPNOTSUPP) {
			test__skip();
			return;
		}
		ASSERT_OK(-errno, "perf_event_open pmu probe");
		return;
	}
	close(pmu_fd);

	for (int mode = 0; mode < ARRAY_SIZE(modes); mode++) {
		if (!test__start_subtest(modes[mode]))
			continue;
		snprintf(params, sizeof(params), "test_mode=%d", mode);
		if (!ASSERT_OK(load_module_params("bpf_test_rqspinlock.ko", params, false),
			       "load module"))
			continue;
		sleep(5);
		ASSERT_OK(unload_module("bpf_test_rqspinlock", false), "unload module");
	}
	/*
	 * Insert bpf_test_rqspinlock.ko manually with test_mode=2 to test ABBCCA.
	 */
}
