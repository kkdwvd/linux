// SPDX-License-Identifier: GPL-2.0
/* What the verifier allows around a frame taken with bpf_xdp_frame_steal(). */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_misc.h"

struct frame_node {
	struct bpf_rb_node node;
	struct xdp_frame __kptr *frame;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct xdp_frame __kptr *stash;

SEC("xdp")
__description("a stolen frame can be released")
__success
int steal_then_release(struct xdp_md *ctx)
{
	struct xdp_frame *f = bpf_xdp_frame_steal(ctx);

	if (!f)
		return XDP_PASS;
	bpf_xdp_frame_release(f);
	return XDP_CONSUME;
}

SEC("xdp")
__description("a stolen frame can be stored in a kptr field")
__success
int steal_then_store(struct xdp_md *ctx)
{
	struct xdp_frame *f = bpf_xdp_frame_steal(ctx);

	if (!f)
		return XDP_PASS;
	f = bpf_kptr_xchg(&stash, f);
	if (f)
		bpf_xdp_frame_release(f);
	return XDP_CONSUME;
}

SEC("xdp")
__description("a stolen frame goes into an allocated object")
__success
int steal_then_node(struct xdp_md *ctx)
{
	struct xdp_frame *f = bpf_xdp_frame_steal(ctx);
	struct frame_node *n;

	if (!f)
		return XDP_PASS;
	n = bpf_obj_new(typeof(*n));
	if (!n) {
		bpf_xdp_frame_release(f);
		return XDP_CONSUME;
	}
	f = bpf_kptr_xchg(&n->frame, f);
	if (f)
		bpf_xdp_frame_release(f);
	bpf_obj_drop(n);
	return XDP_CONSUME;
}

SEC("xdp")
__description("a stolen frame must be released or stored")
__failure __msg("Unreleased reference")
int steal_then_leak(struct xdp_md *ctx)
{
	struct xdp_frame *f = bpf_xdp_frame_steal(ctx);

	return f ? XDP_CONSUME : XDP_PASS;
}

SEC("xdp")
__description("the context is consumed by the steal")
__failure __msg("expected=ctx")
int ctx_after_steal(struct xdp_md *ctx)
{
	struct xdp_frame *f = bpf_xdp_frame_steal(ctx);

	if (!f)
		return XDP_PASS;
	bpf_xdp_frame_release(f);
	return bpf_xdp_adjust_meta(ctx, 0) ? XDP_ABORTED : XDP_CONSUME;
}

SEC("xdp")
__description("packet pointers do not survive the steal")
__failure __msg("invalid mem access")
int pkt_after_steal(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct xdp_frame *f;
	__u8 b;

	if (data + 1 > data_end)
		return XDP_DROP;
	f = bpf_xdp_frame_steal(ctx);
	if (!f)
		return XDP_PASS;
	b = *(volatile __u8 *)data;
	bpf_xdp_frame_release(f);
	return b ? XDP_CONSUME : XDP_ABORTED;
}

SEC("xdp")
__description("an xdp dynptr does not survive the steal")
__failure __msg("Expected an initialized dynptr")
int dynptr_after_steal(struct xdp_md *ctx)
{
	struct bpf_dynptr ptr;
	struct xdp_frame *f;
	__u8 buf[4];

	bpf_dynptr_from_xdp(ctx, 0, &ptr);
	f = bpf_xdp_frame_steal(ctx);
	if (!f)
		return XDP_PASS;
	bpf_xdp_frame_release(f);
	return bpf_dynptr_read(buf, sizeof(buf), &ptr, 0, 0) ? XDP_ABORTED : XDP_CONSUME;
}

SEC("xdp")
__description("a frame dynptr does not survive the release")
__failure __msg("Expected an initialized dynptr")
int frame_dynptr_after_release(struct xdp_md *ctx)
{
	struct bpf_dynptr ptr;
	struct xdp_frame *f;
	__u8 buf[4];

	f = bpf_xdp_frame_steal(ctx);
	if (!f)
		return XDP_PASS;
	bpf_dynptr_from_xdp_frame(f, 0, &ptr);
	bpf_xdp_frame_release(f);
	return bpf_dynptr_read(buf, sizeof(buf), &ptr, 0, 0) ? XDP_ABORTED : XDP_CONSUME;
}

SEC("xdp")
__description("a frame dynptr does not survive the frame being stored")
__failure __msg("Expected an initialized dynptr")
int frame_dynptr_after_store(struct xdp_md *ctx)
{
	struct bpf_dynptr ptr;
	struct xdp_frame *f;
	__u8 buf[4];

	f = bpf_xdp_frame_steal(ctx);
	if (!f)
		return XDP_PASS;
	bpf_dynptr_from_xdp_frame(f, 0, &ptr);
	f = bpf_kptr_xchg(&stash, f);
	if (f)
		bpf_xdp_frame_release(f);
	return bpf_dynptr_read(buf, sizeof(buf), &ptr, 0, 0) ? XDP_ABORTED : XDP_CONSUME;
}

SEC("xdp")
__description("a slice of a frame dynptr does not survive the release")
__failure __msg("invalid mem access")
int frame_slice_after_release(struct xdp_md *ctx)
{
	struct bpf_dynptr ptr;
	struct xdp_frame *f;
	__u32 buf, *p = NULL;

	f = bpf_xdp_frame_steal(ctx);
	if (!f)
		return XDP_PASS;
	if (!bpf_dynptr_from_xdp_frame(f, 0, &ptr))
		p = bpf_dynptr_slice(&ptr, 0, &buf, sizeof(buf));
	bpf_xdp_frame_release(f);
	return p ? *p : XDP_CONSUME;
}

SEC("xdp")
__description("a frame is not an allocated object")
__failure __msg("type=trusted_ptr_ expected=ptr_")
int obj_drop_frame(struct xdp_md *ctx)
{
	struct xdp_frame *f = bpf_xdp_frame_steal(ctx);

	if (!f)
		return XDP_PASS;
	bpf_obj_drop(f);
	return XDP_CONSUME;
}

__noinline int steal_in_global(struct xdp_md *ctx)
{
	struct xdp_frame *f = bpf_xdp_frame_steal(ctx);

	if (!f)
		return XDP_PASS;
	bpf_xdp_frame_release(f);
	return XDP_CONSUME;
}

SEC("xdp")
__description("a global function cannot consume its caller's context")
__failure __msg("cannot be called from a global function")
int steal_from_global(struct xdp_md *ctx)
{
	return steal_in_global(ctx);
}

SEC("tc")
__description("only XDP programs steal frames")
__failure __msg("not allowed")
int steal_from_tc(struct __sk_buff *skb)
{
	struct xdp_frame *f = bpf_xdp_frame_steal((void *)skb);

	if (f)
		bpf_xdp_frame_release(f);
	return 0;
}

char _license[] SEC("license") = "GPL";
