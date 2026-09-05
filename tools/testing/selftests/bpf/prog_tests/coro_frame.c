// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "coro_frame.skel.h"

static void run_prog(struct bpf_program *prog, int expected)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(opts.retval, expected, "retval");
}

static __u32 prog_id(struct bpf_program *prog)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	if (!ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &len), "prog_info"))
		return 0;
	return info.id;
}

/* Is the program with @id freed within two seconds? The kernel frees it in the background. */
static bool prog_freed(__u32 id)
{
	int i, fd;

	for (i = 0; i < 200; i++) {
		fd = bpf_prog_get_fd_by_id(id);
		if (fd < 0)
			return errno == ENOENT;
		close(fd);
		usleep(10000);
	}
	return false;
}

/* A new skeleton, which loads program @name, and program @also if it is not NULL */
static struct coro_frame *load_one(const char *name, const char *also)
{
	struct bpf_program *prog;
	struct coro_frame *skel;

	skel = coro_frame__open();
	if (!ASSERT_OK_PTR(skel, "coro_frame__open"))
		return NULL;
	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, !strcmp(bpf_program__name(prog), name) ||
						(also && !strcmp(bpf_program__name(prog), also)));
	if (!ASSERT_OK(coro_frame__load(skel), "coro_frame__load")) {
		coro_frame__destroy(skel);
		return NULL;
	}
	return skel;
}

/* The frames that a program frees give back its reference */
static void test_prog_put(void)
{
	struct coro_frame *skel;
	__u32 id;
	int i;

	skel = load_one("coro_frame_sum", NULL);
	if (!skel)
		return;
	for (i = 0; i < 4; i++)
		run_prog(skel->progs.coro_frame_sum, 42);
	id = prog_id(skel->progs.coro_frame_sum);
	coro_frame__destroy(skel);
	ASSERT_TRUE(id && prog_freed(id), "prog_freed");
}

void test_coro_frame(void)
{
	struct coro_frame *skel;

	skel = coro_frame__open_and_load();
	if (!ASSERT_OK_PTR(skel, "coro_frame__open_and_load"))
		return;

	if (test__start_subtest("sum"))
		run_prog(skel->progs.coro_frame_sum, 42);
	if (test__start_subtest("odd_size"))
		run_prog(skel->progs.coro_frame_odd_size, 6);
	if (test__start_subtest("prog_put"))
		test_prog_put();
	coro_frame__destroy(skel);
}
