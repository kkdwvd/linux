// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/pkt_cls.h>

#include "irq_flags_mirror.skel.h"

/*
 * A program saves IRQ flags into one slot at two instructions, on two paths,
 * and is cancelled where it holds no pointer to the slot: the unwinder
 * restores the flags whichever path saved them.
 */
void test_irq_flags_mirror(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct irq_flags_mirror *skel;
	int fd, which;

	skel = irq_flags_mirror__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (!ASSERT_OK(irq_flags_mirror__attach(skel), "attach"))
		goto out;

	fd = bpf_program__fd(skel->progs.irq_flags_saved_twice);
	for (which = 0; which < 2; which++) {
		skel->bss->param = which;
		skel->bss->restored = 0;
		if (!ASSERT_OK(bpf_prog_test_run_opts(fd, &topts), "test_run"))
			break;
		ASSERT_EQ(topts.retval, TC_ACT_SHOT, "cancelled");
		ASSERT_NEQ(skel->bss->flags_slot, 0, "flags saved");
		ASSERT_EQ(skel->bss->restored, skel->bss->flags_slot, "flags restored");
	}
out:
	irq_flags_mirror__destroy(skel);
}
