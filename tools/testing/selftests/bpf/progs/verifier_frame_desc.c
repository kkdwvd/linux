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

/*
 * A socket cast to its struct by a helper carries the reference of the
 * socket a lookup acquired: a site reached with the cast pointer live
 * releases the socket from it.
 */
SEC("tc")
__description("frame_desc: a throw with a socket cast to tcp_sock live")
__success
int sock_cast_at_throw(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	struct tcp_sock *tp;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		bpf_sk_release(sk);
		return 0;
	}
	if (skb->len > 100)
		bpf_throw(0);
	bpf_sk_release((struct bpf_sock *)tp);
	return 1;
}

char _license[] SEC("license") = "GPL";
