// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "bpf_qdisc_common.h"

char _license[] SEC("license") = "GPL";

/*
 * A fifo whose ->enqueue() the kernel unwinds when user space says so, while the prog holds the
 * packet: the landing pad frees the packet, and the operator returns NET_XMIT_DROP. 0 would tell
 * the sender that the packet is in the queue.
 */
struct skb_node {
	struct sk_buff __kptr * skb;
	struct bpf_list_node node;
};

private(A) struct bpf_spin_lock q_lock;
private(A) struct bpf_list_head q __contains(skb_node, node);

/* set by user space: the kernel unwinds each ->enqueue() */
bool unwind;
/* how many calls of ->enqueue() got to the recursion, and how many got behind it */
int went_down, went_on;
/* the same for ->init(): unwound, it returns -ECANCELED, and the qdisc is not taken for set up */
bool unwind_init;
int init_went_down, init_went_on;

/* A recursion without an end: the kernel unwinds it when the stack has no room for one more frame */
__naked __noinline __used
static unsigned long goes_down(void)
{
	asm volatile (
		"r1 = 0;"
		"call goes_down;"
		"exit;"
		::: __clobber_all);
}

SEC("struct_ops/bpf_unwound_enqueue")
int BPF_PROG(bpf_unwound_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	struct skb_node *skbn;
	u32 pkt_len;

	if (unwind) {
		went_down++;
		goes_down();
		went_on++;
	}

	if (sch->q.qlen == sch->limit)
		goto drop;

	skbn = bpf_obj_new(typeof(*skbn));
	if (!skbn)
		goto drop;

	pkt_len = qdisc_pkt_len(skb);

	sch->q.qlen++;
	skb = bpf_kptr_xchg(&skbn->skb, skb);
	if (skb)
		bpf_qdisc_skb_drop(skb, to_free);

	bpf_spin_lock(&q_lock);
	bpf_list_push_back(&q, &skbn->node);
	bpf_spin_unlock(&q_lock);

	sch->qstats.backlog += pkt_len;
	return NET_XMIT_SUCCESS;
drop:
	bpf_qdisc_skb_drop(skb, to_free);
	return NET_XMIT_DROP;
}

SEC("struct_ops/bpf_unwound_dequeue")
struct sk_buff *BPF_PROG(bpf_unwound_dequeue, struct Qdisc *sch)
{
	struct bpf_list_node *node;
	struct sk_buff *skb = NULL;
	struct skb_node *skbn;

	bpf_spin_lock(&q_lock);
	node = bpf_list_pop_front(&q);
	bpf_spin_unlock(&q_lock);
	if (!node)
		return NULL;

	skbn = container_of(node, struct skb_node, node);
	skb = bpf_kptr_xchg(&skbn->skb, skb);
	bpf_obj_drop(skbn);
	if (!skb)
		return NULL;

	sch->qstats.backlog -= qdisc_pkt_len(skb);
	bpf_qdisc_bstats_update(sch, skb);
	sch->q.qlen--;

	return skb;
}

SEC("struct_ops/bpf_unwound_init")
int BPF_PROG(bpf_unwound_init, struct Qdisc *sch, struct nlattr *opt,
	     struct netlink_ext_ack *extack)
{
	if (unwind_init) {
		init_went_down++;
		goes_down();
		init_went_on++;
	}

	sch->limit = 1000;
	return 0;
}

SEC("struct_ops/bpf_unwound_reset")
void BPF_PROG(bpf_unwound_reset, struct Qdisc *sch)
{
	struct bpf_list_node *node;
	struct skb_node *skbn;
	int i;

	bpf_for(i, 0, sch->q.qlen) {
		struct sk_buff *skb = NULL;

		bpf_spin_lock(&q_lock);
		node = bpf_list_pop_front(&q);
		bpf_spin_unlock(&q_lock);

		if (!node)
			break;

		skbn = container_of(node, struct skb_node, node);
		skb = bpf_kptr_xchg(&skbn->skb, skb);
		if (skb)
			bpf_kfree_skb(skb);
		bpf_obj_drop(skbn);
	}
	sch->q.qlen = 0;
}

SEC("struct_ops")
void BPF_PROG(bpf_unwound_destroy, struct Qdisc *sch)
{
}

SEC(".struct_ops")
struct Qdisc_ops unwound = {
	.enqueue   = (void *)bpf_unwound_enqueue,
	.dequeue   = (void *)bpf_unwound_dequeue,
	.init      = (void *)bpf_unwound_init,
	.reset     = (void *)bpf_unwound_reset,
	.destroy   = (void *)bpf_unwound_destroy,
	.id        = "bpf_unwound",
};
