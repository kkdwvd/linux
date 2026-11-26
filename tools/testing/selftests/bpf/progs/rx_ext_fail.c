// SPDX-License-Identifier: GPL-2.0
/*
 * Extensions on the path of a packet that are not loaded, one struct_ops map each, see
 * prog_tests/rx_ext.c: code that keeps its packet, or has it after GRO took it, and frames
 * that the kernel could not keep or end.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void *bpf_coro_frame_alloc_skb(__u64 size, struct sk_buff *skb) __ksym;
extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern bool bpf_rx_gro(void *frame) __ksym;
extern void bpf_rx_batch(struct sk_buff *skb) __ksym;
extern void bpf_rx_native(struct sk_buff *skb) __ksym;
extern __u64 bpf_rx_state(struct sk_buff *skb) __ksym;

char _license[] SEC("license") = "GPL";

__u64 sum;

static __noinline __used void flush_fn(void *frame)
{
	__u64 *f = frame;

	bpf_rx_batch((struct sk_buff *)f[2]);
}

#define EXT(name, entry)						\
	SEC(".struct_ops.link")						\
	struct bpf_rx_ops name = {					\
		.arrive = (void *)entry,				\
		.ifindex = 1,						\
	}

static __always_inline __u64 *frame_of(struct sk_buff *skb, void *fn)
{
	__u64 *f = bpf_coro_frame_alloc_skb(32, skb);

	if (!f)
		return NULL;
	f[0] = (__u64)fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	f[3] = 0;
	return f;
}

/* The entry returns with the packet */
SEC("struct_ops/arrive")
void BPF_PROG(keeps, struct sk_buff *skb)
{
	sum += skb->len;
}
EXT(ext_keeps, keeps);

/* GRO has no use for the packet, and the entry returns with it */
SEC("struct_ops/arrive")
void BPF_PROG(keeps_declined, struct sk_buff *skb)
{
	__u64 *f = frame_of(skb, flush_fn);

	if (!f) {
		bpf_rx_native(skb);
		return;
	}
	bpf_rx_gro(f);
}
EXT(ext_keeps_declined, keeps_declined);

/* GRO took the packet, and the entry puts it on the batch */
SEC("struct_ops/arrive")
void BPF_PROG(batches_taken, struct sk_buff *skb)
{
	__u64 *f = frame_of(skb, flush_fn);

	if (!f) {
		bpf_rx_native(skb);
		return;
	}
	bpf_rx_gro(f);
	bpf_rx_batch(skb);
}
EXT(ext_batches_taken, batches_taken);

/* GRO took the packet, and the entry looks at the frame, which may be gone with the head */
SEC("struct_ops/arrive")
void BPF_PROG(reads_taken, struct sk_buff *skb)
{
	__u64 *f = frame_of(skb, flush_fn);

	if (!f) {
		bpf_rx_native(skb);
		return;
	}
	if (bpf_rx_gro(f)) {
		sum += f[3];
		return;
	}
	bpf_rx_batch(skb);
}
EXT(ext_reads_taken, reads_taken);

/* The continuation does not put the packet on the batch */
static __noinline __used void no_batch_fn(void *frame)
{
	__u64 *f = frame;

	sum += f[3];
}

SEC("struct_ops/arrive")
void BPF_PROG(cont_keeps, struct sk_buff *skb)
{
	__u64 *f = frame_of(skb, no_batch_fn);

	if (!f) {
		bpf_rx_native(skb);
		return;
	}
	if (!bpf_rx_gro(f))
		bpf_rx_batch(skb);
}
EXT(ext_cont_keeps, cont_keeps);

/* The continuation offers the packet to GRO again */
static __noinline __used void again_fn(void *frame)
{
	__u64 *f = frame;

	if (!bpf_rx_gro(f))
		bpf_rx_batch((struct sk_buff *)f[2]);
}

SEC("struct_ops/arrive")
void BPF_PROG(cont_offers, struct sk_buff *skb)
{
	__u64 *f = frame_of(skb, again_fn);

	if (!f) {
		bpf_rx_native(skb);
		return;
	}
	if (!bpf_rx_gro(f))
		bpf_rx_batch(skb);
}
EXT(ext_cont_offers, cont_offers);

/* A frame that is larger than what the head of a packet has for one */
SEC("struct_ops/arrive")
void BPF_PROG(too_big, struct sk_buff *skb)
{
	__u64 *f = bpf_coro_frame_alloc_skb(72, skb);

	if (f)
		f[0] = 0;
	bpf_rx_native(skb);
}
EXT(ext_too_big, too_big);

/* The frame is offered without its packet */
SEC("struct_ops/arrive")
void BPF_PROG(no_host, struct sk_buff *skb)
{
	__u64 *f = bpf_coro_frame_alloc_skb(32, skb);

	if (!f) {
		bpf_rx_native(skb);
		return;
	}
	f[0] = (__u64)flush_fn;
	f[1] = 0;
	f[2] = 0;
	f[3] = 0;
	bpf_rx_gro(f);
	bpf_rx_native(skb);
}
EXT(ext_no_host, no_host);

/* A frame that the kernel would have to call the program for, to end it */
static __noinline __used void holds_fn(void *frame)
{
	__u64 *f = frame;

	bpf_task_release((struct task_struct *)f[3]);
	bpf_rx_batch((struct sk_buff *)f[2]);
}

SEC("struct_ops/arrive")
void BPF_PROG(holds, struct sk_buff *skb)
{
	struct task_struct *task;
	__u64 *f;

	f = bpf_coro_frame_alloc_skb(32, skb);
	if (!f) {
		bpf_rx_native(skb);
		return;
	}
	task = bpf_task_from_pid(1);
	if (!task) {
		bpf_rx_native(skb);
		return;
	}
	f[0] = (__u64)holds_fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	f[3] = (__u64)task;
	if (bpf_rx_gro(f))
		return;
	bpf_task_release(task);
	bpf_rx_batch(skb);
}
EXT(ext_holds, holds);

/* A frame from the cache of the program is not in the packet for the kernel to keep it there */
SEC("struct_ops/arrive")
void BPF_PROG(cached, struct sk_buff *skb)
{
	__u64 *f = bpf_coro_frame_alloc(32, NULL);

	if (!f) {
		bpf_rx_native(skb);
		return;
	}
	f[0] = (__u64)flush_fn;
	f[1] = 0;
	f[2] = (__u64)skb;
	f[3] = 0;
	if (!bpf_rx_gro(f))
		bpf_rx_batch(skb);
}
EXT(ext_cached, cached);

/* A merge that asks for the state of a packet: it has the two words, and no packet */
SEC("struct_ops/arrive")
void BPF_PROG(arrives, struct sk_buff *skb)
{
	bpf_rx_native(skb);
}

SEC("struct_ops/merge")
__u64 BPF_PROG(merge_calls, __u64 into, __u64 from)
{
	return into + bpf_rx_state((struct sk_buff *)from);
}

SEC(".struct_ops.link")
struct bpf_rx_ops ext_merge_calls = {
	.arrive = (void *)arrives,
	.merge = (void *)merge_calls,
	.ifindex = 1,
};
