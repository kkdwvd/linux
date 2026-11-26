// SPDX-License-Identifier: GPL-2.0
/*
 * What the verifier allows around a coroutine frame in the headroom of a packet, see
 * bpf_coro_frame_alloc_xdp(): the frame is there for as long as the program has the packet,
 * and nothing else ends it.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_misc.h"

extern void *bpf_coro_frame_alloc_xdp(__u64 size, struct xdp_md *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct xdp_frame __kptr *stash;

struct slot {
	struct bpf_coro_xdp __kptr *xdp;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct slot);
} slots SEC(".maps");

__u64 sum;

/* what the first two return: XDP_PASS */

SEC("xdp")
__description("coro_frame in a packet: it is there until the program returns")
__success __retval(2)
int frame_to_the_end(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);

	if (!f)
		return XDP_DROP;
	f[0] = 1;
	f[7] = XDP_PASS - 1;
	return f[0] + f[7];
}

SEC("xdp")
__description("coro_frame in a packet: the largest one is 192 bytes")
__success __retval(2)
int frame_largest(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(192, ctx);

	if (!f)
		return XDP_DROP;
	f[23] = XDP_PASS;
	return f[23];
}

SEC("xdp")
__description("coro_frame in a packet: one byte more does not load")
__failure __msg("coro_frame of 193 bytes does not fit in the headroom of a packet, which lends 192")
int frame_too_large(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(193, ctx);

	return f ? XDP_PASS : XDP_DROP;
}

SEC("xdp")
__description("coro_frame in a packet: the size is a constant")
__failure __msg("R1 must be a known constant")
int frame_size_unknown(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(bpf_get_prandom_u32() & 63, ctx);

	return f ? XDP_PASS : XDP_DROP;
}

SEC("xdp")
__description("coro_frame in a packet: it is not read where there is none")
__failure __msg("invalid mem access 'coro_frame_or_null'")
int frame_null_unchecked(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);

	return f[0];
}

SEC("xdp")
__description("coro_frame in a packet: nothing frees it")
__failure __msg("is a coro_frame in memory of its host: it goes with the host")
int frame_freed(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);

	if (!f)
		return XDP_DROP;
	bpf_coro_frame_free(f);
	return XDP_PASS;
}

SEC("xdp")
__description("coro_frame in a packet: the program keeps it with the packet")
__success
int frame_kept(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p;

	if (!f)
		return XDP_DROP;
	f[2] = 1;
	p = bpf_xdp_frame_steal(ctx);
	if (!p)
		/* the buffer is the driver's as before, with the frame in it */
		return f[2] ? XDP_PASS : XDP_DROP;
	f[3] = f[2] + 1;
	sum += f[3];
	bpf_xdp_frame_release(p);
	return XDP_CONSUME;
}

SEC("xdp")
__description("coro_frame in a packet: it is gone with the packet that the program gave back")
__failure __msg("invalid mem access 'scalar'")
int frame_after_release(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p;

	if (!f)
		return XDP_DROP;
	f[2] = 1;
	p = bpf_xdp_frame_steal(ctx);
	if (!p)
		return XDP_PASS;
	bpf_xdp_frame_release(p);
	sum += f[2];
	return XDP_CONSUME;
}

SEC("xdp")
__description("coro_frame in a packet: it is gone with the packet that the program sent")
__failure __msg("invalid mem access 'scalar'")
int frame_after_xmit(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p;

	if (!f)
		return XDP_DROP;
	f[2] = 1;
	p = bpf_xdp_frame_steal(ctx);
	if (!p)
		return XDP_PASS;
	bpf_xdp_frame_xmit(p, 0);
	f[2] = 2;
	return XDP_CONSUME;
}

SEC("xdp")
__description("coro_frame in a packet: it is gone with the packet that went into a map")
__failure __msg("invalid mem access 'scalar'")
int frame_after_store(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p;

	if (!f)
		return XDP_DROP;
	f[2] = 1;
	p = bpf_xdp_frame_steal(ctx);
	if (!p)
		return XDP_PASS;
	p = bpf_kptr_xchg(&stash, p);
	if (p)
		bpf_xdp_frame_release(p);
	sum += f[2];
	return XDP_CONSUME;
}

/* A pointer into the frame is gone like one to its start */
SEC("xdp")
__description("coro_frame in a packet: a pointer into it is gone with the packet")
__failure __msg("invalid mem access 'scalar'")
int frame_alias_after_release(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx), *g;
	struct xdp_frame *p;

	if (!f)
		return XDP_DROP;
	g = f + 4;
	*g = 1;
	p = bpf_xdp_frame_steal(ctx);
	if (!p)
		return XDP_PASS;
	bpf_xdp_frame_release(p);
	sum += *g;
	return XDP_CONSUME;
}

/* What the frame held when the packet went is no longer reached through it */
SEC("xdp")
__description("coro_frame in a packet: what it holds has to be released before the packet goes")
__failure __msg("Unreleased reference")
int frame_holds_at_release(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p, *old;

	if (!f)
		return XDP_DROP;
	old = bpf_kptr_xchg(&stash, NULL);
	if (!old)
		return XDP_PASS;
	f[2] = (__u64)old;
	p = bpf_xdp_frame_steal(ctx);
	if (!p) {
		bpf_xdp_frame_release((struct xdp_frame *)f[2]);
		return XDP_PASS;
	}
	bpf_xdp_frame_release(p);
	return XDP_CONSUME;
}

static int alloc_cb(__u64 i, struct xdp_md **ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, *ctx);

	if (f)
		f[0] = i;
	return 0;
}

SEC("xdp")
__description("coro_frame in a packet: a callback, which runs any number of times, has none")
__failure __msg("Unreleased reference")
int frame_in_callback(struct xdp_md *ctx)
{
	bpf_loop(2, alloc_cb, &ctx, 0);
	return XDP_PASS;
}

SEC("xdp")
__description("coro_frame in a packet: a loop cannot have one in each trip")
__failure __msg("acquires more than it releases")
int frame_in_loop(struct xdp_md *ctx)
{
	__u64 *f;
	int i;

	bpf_for(i, 0, 4) {
		f = bpf_coro_frame_alloc_xdp(64, ctx);
		if (!f)
			continue;
		f[0] = i;
		sum += f[0];
	}
	return XDP_PASS;
}

/* The packet is the caller's, and the frame is good for as long as the function runs */
__noinline int frame_of_global(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);

	if (!f)
		return 0;
	f[0] = 1;
	return f[0];
}

SEC("xdp")
__description("coro_frame in a packet: a global function can have one")
__success
int frame_in_global(struct xdp_md *ctx)
{
	return frame_of_global(ctx) ? XDP_PASS : XDP_DROP;
}

/*
 * Suspension. The frame is parked with the packet in it, and the two functions give the packet
 * up: that is the end of the frame.
 */
static __noinline __used void resume_fn(void *frame)
{
	__u64 *f = frame;

	sum += f[2];
	bpf_xdp_frame_release((struct xdp_frame *)f[3]);
}

static __noinline __used void destroy_fn(void *frame)
{
	__u64 *f = frame;

	bpf_xdp_frame_release((struct xdp_frame *)f[3]);
}

static __always_inline int park(__u64 *f)
{
	struct bpf_coro_xdp *coro = bpf_coro_park_xdp(f);
	__u32 idx = 0;
	struct slot *s;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s) {
		bpf_coro_drop_xdp(coro);
		return XDP_ABORTED;
	}
	coro = bpf_kptr_xchg(&s->xdp, coro);
	if (coro)
		bpf_coro_drop_xdp(coro);
	return XDP_CONSUME;
}

SEC("xdp")
__description("coro_frame in a packet: it is parked with the packet in it")
__success
int frame_parked(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p;

	if (!f)
		return XDP_DROP;
	f[0] = (__u64)resume_fn;
	f[1] = (__u64)destroy_fn;
	f[2] = 1;
	p = bpf_xdp_frame_steal(ctx);
	if (!p)
		return XDP_PASS;
	f[3] = (__u64)p;
	return park(f);
}

SEC("xdp")
__description("coro_frame in a packet: it is not parked in a packet that the program does not keep")
__failure __msg("suspended coro_frame is in memory of the program context, which the program has to keep first")
int frame_parked_unkept(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);

	if (!f)
		return XDP_DROP;
	f[0] = (__u64)resume_fn;
	f[1] = (__u64)destroy_fn;
	f[2] = 1;
	f[3] = 0;
	return park(f);
}

SEC("xdp")
__description("coro_frame in a packet: it is not parked where the steal failed")
__failure __msg("suspended coro_frame is in memory of the program context, which the program has to keep first")
int frame_parked_steal_failed(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p;

	if (!f)
		return XDP_DROP;
	f[0] = (__u64)resume_fn;
	f[1] = (__u64)destroy_fn;
	f[2] = 1;
	f[3] = 0;
	p = bpf_xdp_frame_steal(ctx);
	if (p) {
		bpf_xdp_frame_release(p);
		return XDP_CONSUME;
	}
	return park(f);
}

static __noinline __used void nothing_fn(void *frame)
{
}

SEC("xdp")
__description("coro_frame in a packet: it is not parked without the packet in it")
__failure __msg("suspended coro_frame is in memory of reference id=")
__msg("which is in none of its slots")
int frame_parked_without_packet(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p;
	int ret;

	if (!f)
		return XDP_DROP;
	f[0] = (__u64)nothing_fn;
	f[1] = (__u64)nothing_fn;
	p = bpf_xdp_frame_steal(ctx);
	if (!p)
		return XDP_PASS;
	ret = park(f);
	bpf_xdp_frame_release(p);
	return ret;
}

static __noinline __used void resume_reads_fn(void *frame)
{
	__u64 *f = frame;

	bpf_xdp_frame_release((struct xdp_frame *)f[3]);
	sum += f[2];
}

SEC("xdp")
__description("coro_frame in a packet: its continuation has no frame behind the packet")
__failure __msg("invalid mem access 'scalar'")
int frame_cont_reads(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p;

	if (!f)
		return XDP_DROP;
	f[0] = (__u64)resume_reads_fn;
	f[1] = (__u64)destroy_fn;
	f[2] = 1;
	p = bpf_xdp_frame_steal(ctx);
	if (!p)
		return XDP_PASS;
	f[3] = (__u64)p;
	return park(f);
}

static __noinline __used void resume_frees_fn(void *frame)
{
	bpf_coro_frame_free(frame);
}

SEC("xdp")
__description("coro_frame in a packet: its continuation does not free it")
__failure __msg("is a coro_frame in memory of its host: it goes with the host")
int frame_cont_frees(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p;

	if (!f)
		return XDP_DROP;
	f[0] = (__u64)resume_frees_fn;
	f[1] = (__u64)destroy_fn;
	f[2] = 1;
	p = bpf_xdp_frame_steal(ctx);
	if (!p)
		return XDP_PASS;
	f[3] = (__u64)p;
	return park(f);
}

static __noinline __used void destroy_keeps_fn(void *frame)
{
	__u64 *f = frame;

	sum += f[2];
}

SEC("xdp")
__description("coro_frame in a packet: its destroy function gives the packet up")
__failure __msg("Unreleased reference")
int frame_destroy_keeps(struct xdp_md *ctx)
{
	__u64 *f = bpf_coro_frame_alloc_xdp(64, ctx);
	struct xdp_frame *p;

	if (!f)
		return XDP_DROP;
	f[0] = (__u64)resume_fn;
	f[1] = (__u64)destroy_keeps_fn;
	f[2] = 1;
	p = bpf_xdp_frame_steal(ctx);
	if (!p)
		return XDP_PASS;
	f[3] = (__u64)p;
	return park(f);
}

/*
 * Landing pads. No pad has a call for the frame. What the frame of the program holds through
 * it is released as through any coroutine frame, see progs/coro_unwind.c, and the packet in
 * whose memory the frame is goes last.
 */

/* The frames of a recursion that began */
unsigned long frames;

/* It calls itself until the stack has no room, which unwinds the program */
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

/* What the progs take: the task with this pid */
int pid;

/*
 * BTF FUNC records are not generated for kfuncs referenced from inline assembly. These
 * records are necessary for libbpf to link the program.
 */
void __kfunc_btf_root(void)
{
	bpf_task_release(bpf_task_from_pid(0));
	bpf_xdp_frame_release(bpf_xdp_frame_steal(NULL));
	bpf_coro_frame_alloc_xdp(0, NULL);
}

/* r6 = bpf_coro_frame_alloc_xdp(64, ctx), and the context in r7. XDP_DROP if there is none */
#define FRAME_IN_PACKET					\
	"r7 = r1;"					\
	"r1 = 64;"					\
	"r2 = r7;"					\
	"call %[bpf_coro_frame_alloc_xdp];"		\
	"if r0 != 0 goto 1f;"				\
	"r0 = 1;"					\
	"exit;"						\
"1:"							\
	"r6 = r0;"

SEC("xdp")
__description("coro_frame in a packet: a landing pad has no call for it")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 10: rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r0 = 0")
__xlated("exit")
__naked void pad_frame_of_context(void)
{
	asm volatile (
		FRAME_IN_PACKET
		"r1 = 1;"
		"*(u64 *)(r6 + 16) = r1;"
		"call dives;"
		"r0 = *(u64 *)(r6 + 16);"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc_xdp)
		: __clobber_all
	);
}

/*
 * The frame has a task that the program took before it kept the packet, and the packet. Left
 * to the order of the insns the pad would give the packet up first, and read the task from a
 * frame that is gone.
 */
SEC("xdp")
__description("coro_frame in a packet: a landing pad gives the packet up behind what the frame holds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 24: ref@11([r6+32]) ref@17([r6+24]) rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = *(u64 *)(r6 +32)")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r6 +24)")
__xlated("call kernel-function")
__xlated("r0 = 0")
__xlated("exit")
__naked void pad_packet_last(void)
{
	asm volatile (
		FRAME_IN_PACKET
		"r1 = %[pid] ll;"
		"r1 = *(u32 *)(r1 + 0);"
		"call %[bpf_task_from_pid];"
		"if r0 != 0 goto 2f;"
		"r0 = 1;"
		"exit;"
	"2:"
		"*(u64 *)(r6 + 32) = r0;"
		"r1 = r7;"
		"call %[bpf_xdp_frame_steal];"
		"if r0 != 0 goto 3f;"
		"r1 = *(u64 *)(r6 + 32);"
		"call %[bpf_task_release];"
		"r0 = 2;"
		"exit;"
	"3:"
		"*(u64 *)(r6 + 24) = r0;"
		"call dives;"
		"r1 = *(u64 *)(r6 + 32);"
		"call %[bpf_task_release];"
		"r1 = *(u64 *)(r6 + 24);"
		"call %[bpf_xdp_frame_release];"
		"r0 = 5;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc_xdp),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm(bpf_xdp_frame_steal),
		  __imm(bpf_xdp_frame_release),
		  __imm_addr(pid)
		: __clobber_all
	);
}

/* The packet in a register that the call saves, and the task in the frame */
SEC("xdp")
__description("coro_frame in a packet: a landing pad gives up a packet that a register has last too")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 24: ref@11([r6+32]) ref@17(r8) rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = *(u64 *)(r6 +32)")
__xlated("call kernel-function")
__xlated("r1 = r8")
__xlated("call kernel-function")
__xlated("r0 = 0")
__xlated("exit")
__naked void pad_packet_in_reg_last(void)
{
	asm volatile (
		FRAME_IN_PACKET
		"r1 = %[pid] ll;"
		"r1 = *(u32 *)(r1 + 0);"
		"call %[bpf_task_from_pid];"
		"if r0 != 0 goto 2f;"
		"r0 = 1;"
		"exit;"
	"2:"
		"*(u64 *)(r6 + 32) = r0;"
		"r1 = r7;"
		"call %[bpf_xdp_frame_steal];"
		"if r0 != 0 goto 3f;"
		"r1 = *(u64 *)(r6 + 32);"
		"call %[bpf_task_release];"
		"r0 = 2;"
		"exit;"
	"3:"
		"r8 = r0;"
		"call dives;"
		"r1 = *(u64 *)(r6 + 32);"
		"call %[bpf_task_release];"
		"r1 = r8;"
		"call %[bpf_xdp_frame_release];"
		"r0 = 5;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc_xdp),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm(bpf_xdp_frame_steal),
		  __imm(bpf_xdp_frame_release),
		  __imm_addr(pid)
		: __clobber_all
	);
}

char _license[] SEC("license") = "GPL";
