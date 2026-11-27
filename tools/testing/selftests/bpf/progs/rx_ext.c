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
extern __u32 bpf_rx_offer(struct sk_buff *skb) __ksym;
extern bool bpf_rx_hold(void *frame) __ksym;
extern bool bpf_rx_pass(struct sk_buff *skb) __ksym;
extern bool bpf_rx_backlog(void *frame, __u32 cpu) __ksym;
extern void bpf_rx_deliver(struct sk_buff *skb) __ksym;
extern void bpf_rx_set_state(struct sk_buff *skb, __u64 state) __ksym;
extern __u64 bpf_rx_state(struct sk_buff *skb) __ksym;
extern void bpf_rx_batch(struct sk_buff *skb) __ksym;
extern void bpf_rx_native(struct sk_buff *skb) __ksym;

char _license[] SEC("license") = "GPL";

/* set by the test */
int mode;
int ifindex;

/* by the extension: what came, what GRO took and did not, what was resumed, what had no frame */
__u64 arrived, taken, declined, resumed, native, no_frame;
/* by the ones that offer with no frame: what GRO held, and what refused a merged packet */
__u64 held, merged_refused;
/* by the continuation that loops */
__u64 looped;
/* by the one that passes: what GRO did not hold */
__u64 passed;
/* the last frame, behind the head of its packet */
__s64 frame_off;
/* by the one with state: the merges, and the state of every packet that went onto a batch */
__u64 merges, state_sum;
/*
 * by the one that steers: the CPU, the packets whose backlog took them and did not, and
 * those that went on there, on that CPU and with the state that they left with
 */
__u32 steer_cpu;
__u64 steered, not_steered, delivered, on_cpu, state_kept;

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
	/* a loop with a time slice: the kernel resumes this program as an invocation of its own */
	if (f[3] == MODE_LOOPS) {
		__u64 i;

		for (i = 0; i < 16 && can_loop; i++)
			__sync_fetch_and_add(&looped, 1);
	}
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

/*
 * The same path with a frame only where one is needed: GRO sees the packet first, and the
 * one that it holds gets a frame, for the flush. The others never had one.
 */
SEC("struct_ops/arrive")
void BPF_PROG(arrive_lean, struct sk_buff *skb)
{
	__u32 got;
	__u64 *f;

	__sync_fetch_and_add(&arrived, 1);
	got = bpf_rx_offer(skb);
	if (got == GRO_NORMAL) {
		__sync_fetch_and_add(&declined, 1);
		bpf_rx_batch(skb);
		return;
	}
	__sync_fetch_and_add(&taken, 1);
	/* a second offer is none, to GRO */
	if (bpf_rx_offer(skb) != GRO_NORMAL)
		__sync_fetch_and_add(&no_frame, 1);
	if (got != GRO_HELD || mode == MODE_NO_FRAME) {
		bpf_rx_batch(skb);
		return;
	}
	f = bpf_coro_frame_alloc_skb(32, skb);
	if (!f) {
		__sync_fetch_and_add(&no_frame, 1);
		bpf_rx_batch(skb);
		return;
	}
	frame_off = (long)f - (long)skb->head;
	f[0] = (__u64)flush_fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	f[3] = mode;
	if (bpf_rx_hold(f)) {
		__sync_fetch_and_add(&held, 1);
		return;
	}
	__sync_fetch_and_add(&no_frame, 1);
	bpf_rx_batch(skb);
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_lean = {
	.arrive = (void *)arrive_lean,
};

/*
 * An extension with state: each packet starts as one segment, and where GRO merges two the
 * segments add up. What goes onto the batches is what arrived.
 */
static __noinline __used void flush_state_fn(void *frame)
{
	__u64 *f = frame;
	struct sk_buff *skb = (struct sk_buff *)f[2];

	__sync_fetch_and_add(&resumed, 1);
	__sync_fetch_and_add(&state_sum, bpf_rx_state(skb));
	bpf_rx_batch(skb);
}

SEC("struct_ops/arrive")
void BPF_PROG(arrive_state, struct sk_buff *skb)
{
	__u64 *f;

	__sync_fetch_and_add(&arrived, 1);
	f = bpf_coro_frame_alloc_skb(24, skb);
	if (!f) {
		__sync_fetch_and_add(&no_frame, 1);
		bpf_rx_native(skb);
		return;
	}
	f[0] = (__u64)flush_state_fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	bpf_rx_set_state(skb, 1);
	if (bpf_rx_gro(f)) {
		__sync_fetch_and_add(&taken, 1);
		return;
	}
	__sync_fetch_and_add(&declined, 1);
	__sync_fetch_and_add(&state_sum, bpf_rx_state(skb));
	bpf_rx_batch(skb);
}

SEC("struct_ops/merge")
__u64 BPF_PROG(merge, __u64 into, __u64 from)
{
	__sync_fetch_and_add(&merges, 1);
	return into + from;
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_state = {
	.arrive = (void *)arrive_state,
	.merge = (void *)merge,
};

/* The same with one call for a packet that GRO does not hold: bpf_rx_pass() */
SEC("struct_ops/arrive")
void BPF_PROG(arrive_pass, struct sk_buff *skb)
{
	__u64 *f;

	__sync_fetch_and_add(&arrived, 1);
	if (bpf_rx_pass(skb)) {
		__sync_fetch_and_add(&passed, 1);
		return;
	}
	/* held, and a second pass is none */
	if (bpf_rx_pass(skb)) {
		__sync_fetch_and_add(&no_frame, 1);
		return;
	}
	f = bpf_coro_frame_alloc_skb(32, skb);
	if (!f || mode == MODE_NO_FRAME) {
		if (!f)
			__sync_fetch_and_add(&no_frame, 1);
		bpf_rx_batch(skb);
		return;
	}
	frame_off = (long)f - (long)skb->head;
	f[0] = (__u64)flush_fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	f[3] = mode;
	if (bpf_rx_hold(f)) {
		__sync_fetch_and_add(&held, 1);
		return;
	}
	__sync_fetch_and_add(&no_frame, 1);
	bpf_rx_batch(skb);
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_pass = {
	.arrive = (void *)arrive_pass,
};

/*
 * With state: the packet that GRO holds starts as one segment, and one that is merged into
 * it had no frame and no word, which the fold sees as 0.
 */
SEC("struct_ops/arrive")
void BPF_PROG(arrive_lean_state, struct sk_buff *skb)
{
	__u32 got;
	__u64 *f;

	__sync_fetch_and_add(&arrived, 1);
	got = bpf_rx_offer(skb);
	if (got != GRO_HELD) {
		if (got == GRO_NORMAL) {
			__sync_fetch_and_add(&declined, 1);
			__sync_fetch_and_add(&state_sum, 1);
		}
		bpf_rx_batch(skb);
		return;
	}
	f = bpf_coro_frame_alloc_skb(24, skb);
	if (!f) {
		__sync_fetch_and_add(&no_frame, 1);
		bpf_rx_batch(skb);
		return;
	}
	f[0] = (__u64)flush_state_fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	bpf_rx_set_state(skb, 1);
	if (!bpf_rx_hold(f)) {
		__sync_fetch_and_add(&no_frame, 1);
		bpf_rx_batch(skb);
	}
}

SEC("struct_ops/merge")
__u64 BPF_PROG(merge_lean, __u64 into, __u64 from)
{
	__sync_fetch_and_add(&merges, 1);
	return into + (from ?: 1);
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_lean_state = {
	.arrive = (void *)arrive_lean_state,
	.merge = (void *)merge_lean,
};

/*
 * An extension that steers: a packet that comes out of GRO goes to the backlog of a CPU, as
 * RPS has it, and on to the stack from there. Where the backlog does not take it, onto the
 * batch. The frame says where the coroutine is: 0 in GRO, 1 in the backlog.
 */
static __always_inline void steer(__u64 *f, struct sk_buff *skb)
{
	f[3] = 1;
	bpf_rx_set_state(skb, 0x5eed);
	if (bpf_rx_backlog(f, steer_cpu)) {
		__sync_fetch_and_add(&steered, 1);
		return;
	}
	__sync_fetch_and_add(&not_steered, 1);
	bpf_rx_batch(skb);
}

static __noinline __used void steer_fn(void *frame)
{
	__u64 *f = frame;
	struct sk_buff *skb = (struct sk_buff *)f[2];

	if (f[3]) {
		__sync_fetch_and_add(&delivered, 1);
		if (bpf_get_smp_processor_id() == steer_cpu)
			__sync_fetch_and_add(&on_cpu, 1);
		if (bpf_rx_state(skb) == 0x5eed)
			__sync_fetch_and_add(&state_kept, 1);
		bpf_rx_deliver(skb);
		return;
	}
	__sync_fetch_and_add(&resumed, 1);
	steer(f, skb);
}

SEC("struct_ops/arrive")
void BPF_PROG(arrive_steer, struct sk_buff *skb)
{
	__u64 *f;

	__sync_fetch_and_add(&arrived, 1);
	f = bpf_coro_frame_alloc_skb(32, skb);
	if (!f) {
		__sync_fetch_and_add(&no_frame, 1);
		bpf_rx_native(skb);
		return;
	}
	f[0] = (__u64)steer_fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	f[3] = 0;
	if (bpf_rx_gro(f)) {
		__sync_fetch_and_add(&taken, 1);
		return;
	}
	__sync_fetch_and_add(&declined, 1);
	steer(f, skb);
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_steer = {
	.arrive = (void *)arrive_steer,
};

/*
 * And one that steers what it offered with no frame: the packet that GRO has no use for
 * gets a frame for the backlog, the one that GRO holds gets one for the flush and the
 * backlog behind it, and one that is part of another packet now is no backlog's.
 */
SEC("struct_ops/arrive")
void BPF_PROG(arrive_lean_steer, struct sk_buff *skb)
{
	__u32 got;
	__u64 *f;

	__sync_fetch_and_add(&arrived, 1);
	got = bpf_rx_offer(skb);
	f = bpf_coro_frame_alloc_skb(32, skb);
	if (!f) {
		__sync_fetch_and_add(&no_frame, 1);
		bpf_rx_batch(skb);
		return;
	}
	f[0] = (__u64)steer_fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	f[3] = 0;
	if (got == GRO_NORMAL) {
		__sync_fetch_and_add(&declined, 1);
		steer(f, skb);
		return;
	}
	__sync_fetch_and_add(&taken, 1);
	if (got == GRO_HELD && bpf_rx_hold(f))
		return;
	if (got == GRO_HELD)
		__sync_fetch_and_add(&no_frame, 1);
	f[3] = 1;
	if (bpf_rx_backlog(f, steer_cpu))
		return;
	__sync_fetch_and_add(&merged_refused, 1);
	bpf_rx_batch(skb);
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_lean_steer = {
	.arrive = (void *)arrive_lean_steer,
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

/* The null extension that offers first: a frame for the packet that GRO holds, and no other */
SEC("struct_ops/arrive")
void BPF_PROG(arrive_lean_null, struct sk_buff *skb)
{
	__u64 *f;

	if (bpf_rx_offer(skb) == GRO_HELD) {
		f = bpf_coro_frame_alloc_skb(24, skb);
		if (f) {
			f[0] = (__u64)flush_null_fn;
			f[1] = 0;
			f[2] = (__u64)skb;
			if (bpf_rx_hold(f))
				return;
		}
	}
	bpf_rx_batch(skb);
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_lean_null = {
	.arrive = (void *)arrive_lean_null,
};

/*
 * And the one that passes: one call for a packet that GRO does not hold, and a frame for
 * the one that it does.
 */
SEC("struct_ops/arrive")
void BPF_PROG(arrive_pass_null, struct sk_buff *skb)
{
	__u64 *f;

	if (bpf_rx_pass(skb))
		return;
	f = bpf_coro_frame_alloc_skb(24, skb);
	if (f) {
		f[0] = (__u64)flush_null_fn;
		f[1] = 0;
		f[2] = (__u64)skb;
		if (bpf_rx_hold(f))
			return;
	}
	bpf_rx_batch(skb);
}

SEC(".struct_ops.link")
struct bpf_rx_ops rx_pass_null = {
	.arrive = (void *)arrive_pass_null,
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
