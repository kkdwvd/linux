// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void bpf_local_irq_save(unsigned long *) __ksym;
extern void bpf_local_irq_restore(unsigned long *) __ksym;

/* Saves IRQ flags around a cancellation point, the timed may_goto of the loop. */
static __noinline int spin_with_irqs_off(int n)
{
	unsigned long flags;
	int i = 0;

	bpf_local_irq_save(&flags);
	while (i < n && can_loop)
		i++;
	bpf_local_irq_restore(&flags);
	return i;
}

/*
 * The subprog saves its flags under a caller's saved flags on one path and
 * under none on the other. What the subprog's frame holds at the may_goto is
 * the same either way: its own flags, in its own slot.
 */
SEC("tc")
__description("frame_desc: a subprog saving irq flags under a caller's flags and without")
__success __retval(3)
int irq_flags_rank_differs_by_caller(struct __sk_buff *skb)
{
	unsigned long flags;
	int r;

	if (skb->len > 100) {
		bpf_local_irq_save(&flags);
		r = spin_with_irqs_off(3);
		bpf_local_irq_restore(&flags);
	} else {
		r = spin_with_irqs_off(3);
	}
	return r;
}

char _license[] SEC("license") = "GPL";
