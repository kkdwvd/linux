// SPDX-License-Identifier: GPL-2.0
/*
 * A program that is cancelled while it holds a connection of the XDP TCP
 * kfuncs, and the frame it took, or that throws then. dives() calls itself
 * until the stack has no room, which cancels the program at once; bpf_throw()
 * jumps to the pad of its site. The pads that the verifier generates release
 * what the program holds, through the release kfuncs registered for struct
 * sock and struct xdp_frame. Programs on the entry of those kfuncs tell the
 * test which handles they got.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

/* Take the frame as well as the connection */
int steal;
/* Throw instead of running out of stack */
int throws;

/* The frames of the recursion, and how many times code behind a call of it ran */
__u64 frames;
__u64 behind;

/* What the program held, by address, and how many times a release got it */
__u64 held_sk;
__u64 held_frame;
int released_sk;
int released_frame;

/* The references to the connection, the probe's among them */
int sock_refcnt;

/* The cookie of the throw, how many times the exception callback ran and what it got */
#define COOKIE	7
int callbacks;
__u64 thrown_cookie;

/* @var++ in assembly, with r1 and r2 */
#define COUNT(var)				\
	"r1 = %[" #var "] ll;"			\
	"r2 = *(u64 *)(r1 + 0);"		\
	"r2 += 1;"				\
	"*(u64 *)(r1 + 0) = r2;"

/* It calls itself until the stack has no room */
__naked __noinline __used
static unsigned long dives(void)
{
	asm volatile (
		COUNT(frames)
		"*(u64 *)(r10 - 128) = r2;"
		"call dives;"
		COUNT(behind)
		"exit;"
		:
		: __imm_addr(frames),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* Leave while holding what was taken: by a cancellation, or by a throw */
static __always_inline void leave(void)
{
	if (throws)
		bpf_throw(COOKIE);
	else
		dives();
}

/* It runs behind all pads. A cancelled program returns XDP_ABORTED without it. */
__noinline int thrown(u64 c)
{
	callbacks++;
	thrown_cookie = c;
	return XDP_DROP;
}

/*
 * The split lookup finds the connection of an in-order segment and takes
 * nothing, so the segment can be sent again once the program is gone.
 */
SEC("xdp")
__exception_cb(thrown)
int xdp_tcp_cancel(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_info info = {};
	struct xdp_frame *frame;
	struct sock *sk;

	sk = bpf_xdp_tcp_lookup(ctx, &info, sizeof(info));
	if (!sk)
		return XDP_PASS;
	held_sk = (__u64)sk;
	if (!steal) {
		leave();
		behind++;
		bpf_xdp_tcp_release(sk);
		return XDP_PASS;
	}
	frame = bpf_xdp_frame_steal(ctx);
	if (!frame) {
		bpf_xdp_tcp_release(sk);
		return XDP_PASS;
	}
	held_frame = (__u64)frame;
	leave();
	behind++;
	bpf_xdp_frame_release(frame);
	bpf_xdp_tcp_release(sk);
	return XDP_CONSUME;
}

SEC("xdp")
int probe_sock(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_info info = {};
	struct sock *sk;

	sk = bpf_xdp_tcp_lookup(ctx, &info, sizeof(info));
	if (!sk)
		return XDP_PASS;
	sock_refcnt = sk->__sk_common.skc_refcnt.refs.counter;
	bpf_xdp_tcp_release(sk);
	return XDP_PASS;
}

SEC("fentry/bpf_xdp_tcp_release")
int BPF_PROG(on_sock_release, struct sock *sk)
{
	if (held_sk && (__u64)sk == held_sk)
		released_sk++;
	return 0;
}

SEC("fentry/bpf_xdp_frame_release")
int BPF_PROG(on_frame_release, struct xdp_frame *frame)
{
	if (held_frame && (__u64)frame == held_frame)
		released_frame++;
	return 0;
}
