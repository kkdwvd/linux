// SPDX-License-Identifier: GPL-2.0
/*
 * An extension on the path of a packet, see net/core/napi_bpf.c. The path is a coroutine by
 * hand: its frame is in the head of the packet, the entry offers the packet to GRO, and
 * where GRO holds it the kernel resumes the continuation at the flush, which puts the
 * packet on the batch. With what tells the test whether the packets went the kernel's way:
 * a program at the device's ingress, and one where the kernel delivers a batch. See
 * prog_tests/rx_ext.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "rx_ext.h"

extern void *bpf_coro_frame_alloc_skb(__u64 size, struct sk_buff *skb) __ksym;
extern bool bpf_rx_gro(void *frame) __ksym;
extern void bpf_rx_batch(struct sk_buff *skb) __ksym;
extern void bpf_rx_native(struct sk_buff *skb) __ksym;

char _license[] SEC("license") = "GPL";

/* set by the test */
int mode;
int ifindex;

/* by the extension: what came, what GRO took and did not, what was resumed, what had no frame */
__u64 arrived, taken, declined, resumed, native, no_frame;
/* the last frame, behind the head of its packet */
__s64 frame_off;

/* by the observers: what the stack got, in order, and the lists that it got them in */
struct rx_seen seen[RX_SEEN];
__u64 nr_seen, nr_lists;

unsigned long frames;

/* It calls itself until the stack has no room, which has the kernel unwind the program */
__naked __noinline __used
static unsigned long dives(void)
{
	asm volatile (
		"r1 = %[frames] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"*(u64 *)(r10 - 128) = r2;"
		"call dives;"
		"exit;"
		:
		: __imm_addr(frames)
		: __clobber_all
	);
}

/* The continuation: GRO flushes the packet that it held. The batch is the end of the frame. */
static __noinline __used void flush_fn(void *frame)
{
	__u64 *f = frame;

	__sync_fetch_and_add(&resumed, 1);
	if (f[3] == MODE_DIVES)
		dives();
	bpf_rx_batch((struct sk_buff *)f[2]);
}

SEC("struct_ops/arrive")
void BPF_PROG(arrive, struct sk_buff *skb)
{
	__u64 *f;

	__sync_fetch_and_add(&arrived, 1);
	if (mode == MODE_NATIVE) {
		__sync_fetch_and_add(&native, 1);
		bpf_rx_native(skb);
		return;
	}
	if (mode == MODE_PAST_GRO) {
		bpf_rx_batch(skb);
		return;
	}
	f = bpf_coro_frame_alloc_skb(32, skb);
	if (!f) {
		__sync_fetch_and_add(&no_frame, 1);
		bpf_rx_native(skb);
		return;
	}
	frame_off = (long)f - (long)skb->head;
	f[0] = (__u64)flush_fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	f[3] = mode;
	if (mode == MODE_ENTRY_DIVES)
		dives();
	if (bpf_rx_gro(f)) {
		__sync_fetch_and_add(&taken, 1);
		return;
	}
	__sync_fetch_and_add(&declined, 1);
	bpf_rx_batch(skb);
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_ext = {
	.arrive = (void *)arrive,
};

/* The null extension, and nothing else: what the path costs as code of an extension */
static __noinline __used void flush_null_fn(void *frame)
{
	__u64 *f = frame;

	bpf_rx_batch((struct sk_buff *)f[2]);
}

SEC("struct_ops/arrive")
void BPF_PROG(arrive_null, struct sk_buff *skb)
{
	__u64 *f = bpf_coro_frame_alloc_skb(24, skb);

	if (!f) {
		bpf_rx_native(skb);
		return;
	}
	f[0] = (__u64)flush_null_fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	if (!bpf_rx_gro(f))
		bpf_rx_batch(skb);
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_null = {
	.arrive = (void *)arrive_null,
};

/* And less: the entry alone, which leaves every packet to the kernel */
SEC("struct_ops/arrive")
void BPF_PROG(arrive_native, struct sk_buff *skb)
{
	bpf_rx_native(skb);
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_entry = {
	.arrive = (void *)arrive_native,
};

/*
 * A slot for each packet, on whichever CPU the stack gets it: under a lock, since the value
 * of an atomic add is not there for every CPU version that the programs are built for.
 */
SEC(".data.seen") __hidden __attribute__((aligned(8))) struct bpf_spin_lock seen_lock;

/* What the stack gets of the device, one after the other */
SEC("tc")
int ingress(struct __sk_buff *ctx)
{
	struct sk_buff *skb = bpf_cast_to_kern_ctx(ctx);
	struct skb_shared_info *shinfo;
	struct rx_seen *s;
	__u64 n;

	bpf_spin_lock(&seen_lock);
	n = nr_seen++;
	bpf_spin_unlock(&seen_lock);
	if (n >= RX_SEEN)
		return 0;
	s = &seen[n];
	shinfo = bpf_core_cast(skb->head + skb->end, struct skb_shared_info);
	s->len = skb->len;
	s->data_len = skb->data_len;
	s->hash = skb->hash;
	s->l4_hash = skb->l4_hash;
	s->ip_summed = skb->ip_summed;
	s->csum_level = skb->csum_level;
	s->gso_size = shinfo->gso_size;
	s->gso_segs = shinfo->gso_segs;
	s->gso_type = shinfo->gso_type;
	s->nr_frags = shinfo->nr_frags;
	s->frag_list = !!shinfo->frag_list;
	s->list = nr_lists;
	return 0;
}

/* A batch of the device goes up as a list */
SEC("fentry/netif_receive_skb_list_internal")
int BPF_PROG(list, struct list_head *head)
{
	struct sk_buff *skb = container_of(BPF_CORE_READ(head, next), struct sk_buff, list);

	if (BPF_CORE_READ(skb, dev, ifindex) == ifindex)
		__sync_fetch_and_add(&nr_lists, 1);
	return 0;
}
