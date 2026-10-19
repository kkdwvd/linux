// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "linked_jumptables.skel.h"

/*
 * The jump tables of the functions of linked_jumptables2.c, which the static
 * linker placed behind those of linked_jumptables1.c in .text and in the
 * section of the programs.
 */
static void run(struct bpf_program *prog, __u64 x)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &x,
		.ctx_size_in = sizeof(x),
	);

	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run");
}

void test_linked_jumptables(void)
{
	static const __u64 ret1[] = {
		1, 11, 21, 31, 41, 51, 61, 71, 81, 91, 101, 111, 121, 131, 141, 151,
		1001,
	};
	static const __u64 sub_ret1[] = {
		301, 311, 321, 331, 341, 351, 361, 371, 381, 391, 401, 411, 421, 431,
		441, 451, 1301,
	};
	static const __u64 ret2[] = {
		2, 12, 22, 32, 42, 52, 62, 72, 82, 92, 102, 112, 122, 132, 142, 152,
		1002,
	};
	static const __u64 sub_ret2[] = {
		302, 312, 322, 332, 342, 352, 362, 372, 382, 392, 402, 412, 422, 432,
		442, 452, 1302,
	};
	struct linked_jumptables *skel;
	__u64 x;

	skel = linked_jumptables__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (skel->data->skip) {
		test__skip();
		goto out;
	}

	for (x = 0; x < ARRAY_SIZE(ret1); x++) {
		run(skel->progs.jt1, x);
		ASSERT_EQ(skel->bss->ret1, ret1[x], "ret1");
		ASSERT_EQ(skel->bss->sub_ret1, sub_ret1[x], "sub_ret1");
		run(skel->progs.jt2, x);
		ASSERT_EQ(skel->bss->ret2, ret2[x], "ret2");
		ASSERT_EQ(skel->bss->sub_ret2, sub_ret2[x], "sub_ret2");
	}
out:
	linked_jumptables__destroy(skel);
}
