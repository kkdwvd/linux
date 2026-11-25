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

/* The ids of the frames that bpf_testmod keeps, see bpf_testmod.c */
#define KEPT_RESUMED	10
#define KEPT_FREED	11

/* What became of the resume of the kept frame: wait two seconds at most */
static int kept_result(struct coro_frame *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int i;

	for (i = 0; i < 200; i++) {
		if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.coro_frame_result),
						      &opts), "coro_frame_result"))
			return -1;
		if (opts.retval != -EINPROGRESS)
			return opts.retval;
		usleep(10000);
	}
	return -EINPROGRESS;
}

/*
 * bpf_testmod keeps a frame of a program whose fd is closed, and holds the program for it.
 * Another program has the frame resumed, and the continuation runs and frees it, or has
 * bpf_testmod free it, with interrupts off: the program goes with it.
 */
static void test_kept(bool resume)
{
	struct coro_frame *keeper, *other;
	int fd, bss_fd = -1, zero = 0;
	struct coro_frame__bss bss;
	__u32 id;

	keeper = load_one("coro_frame_keep", NULL);
	if (!keeper)
		return;
	other = load_one(resume ? "coro_frame_resume_kept" : "coro_frame_free_kept",
			 "coro_frame_result");
	if (!other)
		goto out_keeper;
	keeper->bss->kept_id = other->bss->kept_id = resume ? KEPT_RESUMED : KEPT_FREED;
	run_prog(keeper->progs.coro_frame_keep, 0);
	id = prog_id(keeper->progs.coro_frame_keep);
	/* what the continuation leaves in the program's globals */
	bss_fd = dup(bpf_map__fd(keeper->maps.bss));
	coro_frame__destroy(keeper);

	fd = bpf_prog_get_fd_by_id(id);
	if (ASSERT_GE(fd, 0, "kept prog"))
		close(fd);
	run_prog(resume ? other->progs.coro_frame_resume_kept : other->progs.coro_frame_free_kept,
		 0);
	if (resume)
		ASSERT_EQ(kept_result(other), 0, "not unwound");
	if (ASSERT_GE(bss_fd, 0, "bss_fd") &&
	    ASSERT_OK(bpf_map_lookup_elem(bss_fd, &zero, &bss), "bss"))
		ASSERT_EQ(bss.kept_ran, resume, "kept_ran");
	if (bss_fd >= 0)
		close(bss_fd);
	ASSERT_TRUE(id && prog_freed(id), "prog_freed");
	coro_frame__destroy(other);
	return;
out_keeper:
	coro_frame__destroy(keeper);
}

void test_coro_frame(void)
{
	struct coro_frame *skel;

	skel = coro_frame__open();
	if (!ASSERT_OK_PTR(skel, "coro_frame__open"))
		return;
	/* the programs that bpf_testmod keeps a frame for, see test_kept() */
	bpf_program__set_autoload(skel->progs.coro_frame_keep, false);
	bpf_program__set_autoload(skel->progs.coro_frame_resume_kept, false);
	bpf_program__set_autoload(skel->progs.coro_frame_free_kept, false);
	bpf_program__set_autoload(skel->progs.coro_frame_result, false);
	if (!ASSERT_OK(coro_frame__load(skel), "coro_frame__load"))
		goto out;

	if (test__start_subtest("sum"))
		run_prog(skel->progs.coro_frame_sum, 42);
	if (test__start_subtest("odd_size"))
		run_prog(skel->progs.coro_frame_odd_size, 6);
	if (test__start_subtest("prog_put"))
		test_prog_put();
	if (env.has_testmod && test__start_subtest("kept_resumed"))
		test_kept(true);
	if (env.has_testmod && test__start_subtest("kept_freed"))
		test_kept(false);
out:
	coro_frame__destroy(skel);
}
