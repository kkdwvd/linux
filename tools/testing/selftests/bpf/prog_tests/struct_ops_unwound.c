// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "testing_helpers.h"
#include "struct_ops_unwound.skel.h"
#include "struct_ops_unwound_module.skel.h"

static int call_test_1(struct struct_ops_unwound *skel, struct bpf_map *map, __u64 arg)
{
	__u64 args[2] = { arg };
	LIBBPF_OPTS(bpf_test_run_opts, opts, .ctx_in = args, .ctx_size_in = sizeof(args));
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);

	if (!ASSERT_OK(bpf_map_get_info_by_fd(bpf_map__fd(map), &info, &len), "info"))
		return -1;
	args[1] = info.id;
	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.call_test_1), &opts), "run");
	return opts.retval;
}

static int unwound_cnt(struct struct_ops_unwound *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.unwound_cnt), &opts), "cnt");
	return opts.retval;
}

/*
 * The operator of @map arms a timer and returns 7. The callback is unwound, possibly before the
 * kfunc is back: the struct_ops is told once, and not a second time later.
 */
static void timer_cb_unwound(struct struct_ops_unwound *skel, struct bpf_map *map, const char *name)
{
	int cnt, i;

	cnt = unwound_cnt(skel);
	ASSERT_EQ(call_test_1(skel, map, 0) & 0xffff, 7, "timer armed");
	for (i = 0; i < 100 && unwound_cnt(skel) == cnt; i++)
		usleep(10000);
	usleep(20000);
	ASSERT_EQ(unwound_cnt(skel), cnt + 1, name);
}

/*
 * The operator of @map arms a timer whose callback leaves with unwind_exit of the prog, or calls
 * what does. It runs once, and the struct_ops is told @told times.
 */
static void timer_cb_unwinds(struct struct_ops_unwound *skel, struct bpf_map *map, int told,
			     const char *name)
{
	volatile int *runs = &skel->bss->own_unwinds;
	int cnt, was, i;

	cnt = unwound_cnt(skel);
	was = *runs;
	ASSERT_EQ(call_test_1(skel, map, 0) & 0xffff, 7, "timer armed");
	for (i = 0; i < 100 && *runs == was; i++)
		usleep(10000);
	usleep(20000);
	ASSERT_EQ(*runs, was + 1, "callback ran");
	ASSERT_EQ(unwound_cnt(skel), cnt + told, name);
}

void test_struct_ops_unwound(void)
{
	struct struct_ops_unwound *skel;

	skel = struct_ops_unwound__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (!ASSERT_OK(struct_ops_unwound__attach(skel), "attach"))
		goto out;

	ASSERT_EQ(call_test_1(skel, skel->maps.st_ops_map, 0), 7, "returns");
	ASSERT_EQ(call_test_1(skel, skel->maps.st_ops_map, 1), 1 << 16 | 5, "bpf_throw");

	/* the kernel enters a landing pad of the prog on the way: told once, behind the pad */
	ASSERT_EQ(call_test_1(skel, skel->maps.st_ops_pad, 0), 7, "pad returns");
	ASSERT_EQ(call_test_1(skel, skel->maps.st_ops_pad, 1), 1 << 16 | 5, "pad, bpf_throw");

	/* the exception callback throws too: one invocation, told once */
	ASSERT_EQ(call_test_1(skel, skel->maps.st_ops_exception_cb, 0), 7, "exception_cb returns");
	ASSERT_EQ(call_test_1(skel, skel->maps.st_ops_exception_cb, 1), 1 << 16 | 6,
		  "exception_cb throws");

	/* a callback that only the kernel calls, with a pad that ends in kexit */
	timer_cb_unwound(skel, skel->maps.st_ops_timer, "timer callback");

	/* a callback that the prog calls too: told once in each role */
	ASSERT_EQ(call_test_1(skel, skel->maps.st_ops_timer_called, 1), 1 << 16 | 8,
		  "callback is called");
	timer_cb_unwound(skel, skel->maps.st_ops_timer_called, "timer callback that is called too");

	/* a callback that calls itself: the kernel unwinds its frames, the first one tells */
	timer_cb_unwound(skel, skel->maps.st_ops_timer_recursive, "recursive timer callback");
	ASSERT_EQ(skel->bss->second_frames, 1, "second_frames");

	/* a callback with a landing pad of the prog that the kernel enters: told behind the pad */
	timer_cb_unwound(skel, skel->maps.st_ops_timer_pad, "timer callback with a landing pad");
	ASSERT_EQ(skel->bss->cb_pad_runs, 1, "cb_pad_runs");

	/* unwind_exit of the prog in the frame that the kernel called: nobody is told */
	ASSERT_EQ(call_test_1(skel, skel->maps.st_ops_unwinds, 0), 9, "unwind_exit of the prog");
	timer_cb_unwinds(skel, skel->maps.st_ops_timer_unwinds, 0,
			 "unwind_exit of a timer callback");

	/*
	 * unwind_exit below a call without unwind_goto: the pad of the verifier that ends the
	 * invocation tells, also about an unwind of the prog's own
	 */
	ASSERT_EQ(call_test_1(skel, skel->maps.st_ops_callee_unwinds, 0), 1 << 16,
		  "unwind_exit of a callee");
	timer_cb_unwinds(skel, skel->maps.st_ops_timer_callee_unwinds, 1,
			 "unwind_exit of a callee of a timer callback");

	/*
	 * the same in a callback that can leave unwound: its pad ends in unwind_exit, which tells
	 * nobody where the kernel called, and goes to the pad of the operator where that did
	 */
	timer_cb_unwinds(skel, skel->maps.st_ops_called_timer_callee_unwinds, 0,
			 "unwind_exit of a callee of a timer callback that is called too");
	ASSERT_EQ(call_test_1(skel, skel->maps.st_ops_called_timer_callee_unwinds, 1), 1 << 16,
		  "unwind_exit of a callee of a callback that the operator calls");
out:
	struct_ops_unwound__destroy(skel);
}

/*
 * A prog of a struct_ops of a module keeps the module, with or without ->unwound(): the kernel
 * looks at the struct_ops when the prog is unwound and when an extension of it is loaded, and the
 * map that kept the module can be gone by then. Serial: where it fails, the module is unloaded.
 */
void serial_test_struct_ops_unwound_module(void)
{
	struct struct_ops_unwound_module *skel;
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	struct bpf_link *link;
	int prog_fd, fd, i;

	skel = struct_ops_unwound_module__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	/* the map takes its progs here */
	link = bpf_map__attach_struct_ops(skel->maps.testmod_ops);
	if (!ASSERT_OK_PTR(link, "attach")) {
		struct_ops_unwound_module__destroy(skel);
		return;
	}
	ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.test_2), &info, &len), "info");
	prog_fd = dup(bpf_program__fd(skel->progs.test_1));
	ASSERT_GE(prog_fd, 0, "dup");
	bpf_link__destroy(link);
	struct_ops_unwound_module__destroy(skel);

	/* the map lets go of the module before it lets go of its progs: wait until test_2 is gone */
	for (i = 0; i < 500; i++) {
		fd = bpf_prog_get_fd_by_id(info.id);
		if (fd < 0)
			break;
		close(fd);
		usleep(10000);
	}
	ASSERT_LT(fd, 0, "map is gone");

	/* test_1 is all that is left */
	if (!ASSERT_ERR(try_unload_module("bpf_testmod", 1, false), "try_unload_module"))
		ASSERT_OK(load_bpf_testmod(false), "load_bpf_testmod");
	close(prog_fd);
}
