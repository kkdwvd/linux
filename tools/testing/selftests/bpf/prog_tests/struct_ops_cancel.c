// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

#include "struct_ops_cancel.skel.h"

/* Attach @map, whose operator runs with a reference to the current task, and expect one release. */
static void run_ref_op(struct struct_ops_cancel *skel, struct bpf_map *map, const char *name)
{
	struct bpf_link *link;

	if (!test__start_subtest(name))
		return;
	skel->bss->task_released = 0;
	link = bpf_map__attach_struct_ops(map);
	if (!ASSERT_OK_PTR(link, "attach struct_ops with a __ref argument"))
		return;
	ASSERT_EQ(skel->bss->task_released, 1, "task released once");
	bpf_link__destroy(link);
}

/*
 * A struct_ops operator that the kernel cancels returns 0, releases what it
 * holds, and the struct_ops is told through its cancel hook.
 */
void test_struct_ops_cancel(void)
{
	struct struct_ops_cancel *skel;
	struct bpf_link *link;

	skel = struct_ops_cancel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	/* The hooks have to be in place before the operators run at attach. */
	bpf_map__set_autoattach(skel->maps.testmod_cancel, false);
	bpf_map__set_autoattach(skel->maps.testmod_ctx_ref, false);
	bpf_map__set_autoattach(skel->maps.testmod_ctx_ref_unloaded, false);
	bpf_map__set_autoattach(skel->maps.testmod_ctx_ref_loaded, false);
	bpf_map__set_autoattach(skel->maps.testmod_ctx_ref_callee, false);
	if (!ASSERT_OK(struct_ops_cancel__attach(skel), "attach hooks"))
		goto out;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_cancel);
	if (!ASSERT_OK_PTR(link, "attach struct_ops"))
		goto out;

	ASSERT_NEQ(skel->bss->acquired, 0, "acquired");
	ASSERT_EQ(skel->bss->released, skel->bss->acquired, "released");
	ASSERT_EQ(skel->bss->cancelled, 1, "cancelled");
	bpf_link__destroy(link);

	/*
	 * The operators with a __ref argument are unwound holding it: the
	 * reference the kernel handed them is released once, by the unwinder.
	 */
	run_ref_op(skel, skel->maps.testmod_ctx_ref, "subprog releases or throws");
	run_ref_op(skel, skel->maps.testmod_ctx_ref_unloaded, "throws before the load");
	run_ref_op(skel, skel->maps.testmod_ctx_ref_loaded, "throws after the load");
	run_ref_op(skel, skel->maps.testmod_ctx_ref_callee, "callee throws with the context");
out:
	struct_ops_cancel__destroy(skel);
}
