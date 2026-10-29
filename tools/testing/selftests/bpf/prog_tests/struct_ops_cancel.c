// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

#include "struct_ops_cancel.skel.h"

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
	/* The hooks have to be in place before the operator runs at attach. */
	bpf_map__set_autoattach(skel->maps.testmod_cancel, false);
	if (!ASSERT_OK(struct_ops_cancel__attach(skel), "attach hooks"))
		goto out;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_cancel);
	if (!ASSERT_OK_PTR(link, "attach struct_ops"))
		goto out;

	ASSERT_NEQ(skel->bss->acquired, 0, "acquired");
	ASSERT_EQ(skel->bss->released, skel->bss->acquired, "released");
	ASSERT_EQ(skel->bss->cancelled, 1, "cancelled");
	bpf_link__destroy(link);
out:
	struct_ops_cancel__destroy(skel);
}
