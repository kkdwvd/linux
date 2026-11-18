// SPDX-License-Identifier: GPL-2.0
/*
 * Programs that the kernel unwinds, or that throw, while they hold a
 * connection of the XDP TCP kfuncs, the frame they took and a dynptr over
 * that frame. The landing pads that the verifier emits release what the
 * program holds, through the release kfuncs that it finds for struct sock and
 * struct xdp_frame. A dynptr over a frame goes with the frame. Programs on the
 * entry of those kfuncs, and of what a frame goes through once the program
 * has returned, tell the test what happened to each handle.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

/* Where the program is unwound, as prog_tests/xdp_tcp.c names them */
enum {
	SITE_STACK,	/* the stack check of a recursion that has no room left */
	SITE_GUARD,	/* a loop that the verifier adds may_goto to is out of time */
	SITE_MAY_GOTO,	/* may_goto of the program is out of time */
	SITE_CALLEE,	/* the same in a function that the program calls */
	SITE_FAULT,	/* an access to arena faults */
	SITE_THROW,	/* bpf_throw() */
};

int site;
/* Take the frame as well as the connection, and read the frame through a dynptr */
int steal;
int view;

/* The verifier does not know that it stays 1 */
unsigned long one = 1;

/* The frames of the recursion, and how many times code behind a site ran */
__u64 frames;
__u64 behind;

/* What the program held, by address, and how many times a release got it */
__u64 held_sk;
__u64 held_frame;
int released_sk;
int released_frame;

/*
 * What became of the buffer of the frame once the program returned: the
 * redirect that drops the driver's reference, a return of the buffer by the
 * driver, which it no longer owns, and the puts of the two references to
 * the frame, with the count that the last one found.
 */
__u32 watched_prog;
int redirected;
int buff_returned;
int frame_puts;
int last_put_refs;

/* The references to the connection, the probe's among them */
int sock_refcnt;

/* The cookie of the throw, how many times the exception callback ran and what it got */
#define COOKIE	7
int callbacks;
__u64 thrown_cookie;

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

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

static __noinline int spins(void)
{
	while (can_loop)
		;
	return 0;
}

/*
 * A load from the arena, where no page is. r2 becomes an address in arena by
 * addr_space_cast(r2, 0x0, 0x1), which the assembler of GCC does not know.
 */
#define FAULT()						\
	asm volatile (					\
		"r1 = %[arena] ll;"			\
		"r2 = 0x1000;"				\
		".8byte 0x1000122bf;"			\
		"r2 = *(u32 *)(r2 + 0);"		\
		:: __imm_addr(arena) : "r1", "r2")

/* Leave while holding what was taken */
static __always_inline void leave(void)
{
	if (site == SITE_STACK)
		dives();
	else if (site == SITE_GUARD)
		while (*(volatile unsigned long *)&one)
			;
	else if (site == SITE_MAY_GOTO)
		while (can_loop)
			;
	else if (site == SITE_CALLEE)
		spins();
	else if (site == SITE_FAULT)
		FAULT();
	else
		bpf_throw(COOKIE);
}

/*
 * The split lookup finds the connection of an in-order segment and takes
 * nothing, so the segment can be sent again once the program is gone.
 */
static __always_inline int unwinds(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_info info = {};
	struct xdp_frame *frame;
	struct bpf_dynptr ptr;
	struct sock *sk;
	char byte = 0;

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
	if (view) {
		bpf_dynptr_from_xdp_frame(frame, 0, &ptr);
		bpf_dynptr_read(&byte, sizeof(byte), &ptr, 0, 0);
		leave();
		bpf_dynptr_read(&byte, sizeof(byte), &ptr, 0, 0);
	} else {
		leave();
	}
	behind += 1 + !byte;
	bpf_xdp_frame_release(frame);
	bpf_xdp_tcp_release(sk);
	return XDP_CONSUME;
}

/* The pads of the main program return the kernel's value, or the cookie of the throw */
SEC("xdp")
int xdp_tcp_unwind(struct xdp_md *ctx)
{
	return unwinds(ctx);
}

/* It runs behind all pads of the main program, with the kernel's value or the cookie */
__noinline int thrown(u64 c)
{
	callbacks++;
	thrown_cookie = c;
	return XDP_DROP;
}

SEC("xdp")
__exception_cb(thrown)
int xdp_tcp_unwind_cb(struct xdp_md *ctx)
{
	return unwinds(ctx);
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

SEC("fentry/xdp_do_redirect_frame")
int BPF_PROG(on_redirect, struct net_device *dev, struct xdp_buff *xdp, struct xdp_frame *xdpf,
	     struct bpf_prog *prog)
{
	if (watched_prog && prog->aux->id == watched_prog)
		redirected++;
	return 0;
}

SEC("fentry/xdp_return_buff")
int BPF_PROG(on_buff_return, struct xdp_buff *xdp)
{
	if (held_frame && (__u64)xdp->data_hard_start == held_frame)
		buff_returned++;
	return 0;
}

SEC("fentry/bpf_xdp_frame_put")
int BPF_PROG(on_frame_put, struct xdp_frame *frame)
{
	/* the count shares its storage with a pointer, which BTF reads only as one */
	if (held_frame && (__u64)frame == held_frame) {
		frame_puts++;
		bpf_probe_read_kernel(&last_put_refs, sizeof(last_put_refs),
				      &frame->bpf_refs.refs.counter);
	}
	return 0;
}
