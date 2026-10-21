// SPDX-License-Identifier: GPL-2.0
/* Constraints on the TCP kfuncs that hold whatever a program does around them. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"
#include "bpf_misc.h"

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock lock;
private(A) struct sock __kptr *held_sock;

static __always_inline int stale_view(struct xdp_md *ctx, bool slice, bool clone)
{
	struct bpf_xdp_tcp_info info = {};
	struct bpf_dynptr ptr, copy;
	struct xdp_frame *frame;
	struct sock *sk;
	char data, *p;
	int err;

	sk = bpf_xdp_tcp_recv(ctx, &info);
	if (!sk)
		return XDP_PASS;
	frame = bpf_xdp_frame_steal(ctx);
	if (!frame) {
		bpf_xdp_tcp_release(sk);
		return XDP_PASS;
	}
	bpf_dynptr_from_xdp_frame(frame, 0, &ptr);
	if (clone)
		bpf_dynptr_clone(&ptr, &copy);
	p = bpf_dynptr_slice_rdwr(&ptr, 0, &data, sizeof(data));
	bpf_xdp_tcp_hold(sk, frame);
	if (slice) {
		if (p)
			*p = 0;
		err = 0;
	} else {
		err = bpf_dynptr_write(clone ? &copy : &ptr, 0, &data, sizeof(data), 0);
	}
	bpf_xdp_frame_release(frame);
	bpf_xdp_tcp_release(sk);
	return err ? XDP_ABORTED : XDP_CONSUME;
}

SEC("xdp")
__description("TCP admission invalidates prior frame dynptrs")
__failure __msg("Expected an initialized dynptr")
int tcp_stale_dynptr(struct xdp_md *ctx)
{
	return stale_view(ctx, false, false);
}

SEC("xdp")
__description("TCP admission invalidates cloned frame dynptrs")
__failure __msg("Expected an initialized dynptr")
int tcp_stale_clone(struct xdp_md *ctx)
{
	return stale_view(ctx, false, true);
}

SEC("xdp")
__description("TCP admission invalidates prior writable slices")
__failure __msg("invalid mem access")
int tcp_stale_slice(struct xdp_md *ctx)
{
	return stale_view(ctx, true, false);
}

SEC("xdp")
__description("TCP admission permits fresh frame views")
__success
int tcp_fresh_dynptr(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_info info = {};
	struct bpf_dynptr ptr;
	struct xdp_frame *frame;
	struct sock *sk;
	char data;

	sk = bpf_xdp_tcp_recv(ctx, &info);
	if (!sk)
		return XDP_PASS;
	frame = bpf_xdp_frame_steal(ctx);
	if (!frame) {
		bpf_xdp_tcp_release(sk);
		return XDP_PASS;
	}
	bpf_xdp_tcp_hold(sk, frame);
	bpf_dynptr_from_xdp_frame(frame, 0, &ptr);
	bpf_dynptr_read(&data, sizeof(data), &ptr, 0, 0);
	bpf_xdp_frame_release(frame);
	bpf_xdp_tcp_release(sk);
	return XDP_CONSUME;
}

SEC("xdp")
__description("TCP operations cannot run under a BPF spinlock")
__failure __msg("is not allowed")
int tcp_under_lock(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_info info = {};
	struct sock *sk = bpf_xdp_tcp_recv(ctx, &info);

	if (!sk)
		return XDP_PASS;
	bpf_spin_lock(&lock);
	bpf_xdp_tcp_ack_pending(sk);
	bpf_spin_unlock(&lock);
	bpf_xdp_tcp_release(sk);
	return XDP_PASS;
}

SEC("fentry/tcp_rcv_space_adjust")
__description("tracing cannot recursively lock a TCP socket")
__failure __msg("calling kernel function bpf_xdp_tcp_ack_pending is not allowed")
int BPF_PROG(tcp_from_tracing, struct sock *ignored)
{
	struct sock *sk = bpf_kptr_xchg(&held_sock, NULL);

	if (!sk)
		return 0;
	bpf_xdp_tcp_ack_pending(sk);
	bpf_xdp_tcp_release(sk);
	return 0;
}

SEC("xdp")
__description("TCP socket references must be released")
__failure __msg("Unreleased reference")
int tcp_leak(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_info info = {};
	struct sock *sk = bpf_xdp_tcp_recv(ctx, &info);

	return sk ? XDP_DROP : XDP_PASS;
}

SEC("xdp")
__description("TCP socket references cannot be used after release")
__failure __msg("expected=ptr_")
int tcp_after_release(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_info info = {};
	struct sock *sk = bpf_xdp_tcp_recv(ctx, &info);

	if (!sk)
		return XDP_PASS;
	bpf_xdp_tcp_release(sk);
	bpf_xdp_tcp_ack_pending(sk);
	return XDP_PASS;
}

SEC("xdp")
__description("frame flags cannot be written directly")
__failure __msg("only read is supported")
int tcp_clear_flags(struct xdp_md *ctx)
{
	struct xdp_frame *frame = bpf_xdp_frame_steal(ctx);

	if (!frame)
		return XDP_PASS;
	frame->flags = 0;
	bpf_xdp_frame_release(frame);
	return XDP_CONSUME;
}

char _license[] SEC("license") = "GPL";
