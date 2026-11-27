// SPDX-License-Identifier: GPL-2.0
/*
 * Continuations of a suspended coroutine, in the shape clang's lowering gives
 * them: the resume and destroy functions take the frame as their only
 * argument, and the frame's first two slots hold their addresses. What the
 * verifier says about them. bpf_testmod's bpf_kfunc_coro_suspend() resumes
 * the frame after the call, see coro_cont_run.c for what the continuations do.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

struct coro_obj {
	int data;
};

int coro_resumed;

static __noinline void coro_destroy(void *frame)
{
	__u64 *slots = frame;

	bpf_obj_drop((struct coro_obj *)slots[2]);
	bpf_coro_frame_free(frame);
}

/* Releases the object the frame holds, then the frame. */
static __noinline void coro_resume(void *frame)
{
	__u64 *slots = frame;
	struct coro_obj *obj = (struct coro_obj *)slots[2];

	coro_resumed = obj->data;
	bpf_obj_drop(obj);
	bpf_coro_frame_free(frame);
}

/* Frees the frame, and with it the only place that holds the object. */
static __noinline void coro_resume_leak(void *frame)
{
	bpf_coro_frame_free(frame);
}

/* Suspend a frame that holds an object with @data, to be resumed by @resume. */
static __always_inline int coro_start(void (*resume)(void *frame), int data)
{
	struct coro_obj *obj;
	__u64 *slots;

	slots = bpf_coro_frame_alloc(32, NULL);
	if (!slots)
		return 1;
	obj = bpf_obj_new(typeof(*obj));
	if (!obj) {
		bpf_coro_frame_free(slots);
		return 1;
	}
	obj->data = data;
	slots[0] = (__u64)resume;
	slots[1] = (__u64)coro_destroy;
	slots[2] = (__u64)obj;
	slots[3] = 0;
	bpf_kfunc_coro_suspend(0, slots);
	return 0;
}

SEC("tc")
__description("coro_cont: the continuation releases what the frame holds")
__success
int coro_cont_release(void *ctx)
{
	coro_resumed = 0;
	if (coro_start(coro_resume, 42))
		return 1;
	return coro_resumed;
}

SEC("tc")
__description("coro_cont: a continuation that frees the frame only leaks the object")
__failure __msg("Unreleased reference id=")
int coro_cont_leak(void *ctx)
{
	return coro_start(coro_resume_leak, 1);
}

SEC("tc")
__description("coro_cont: a frame without a resume function is rejected")
__failure __msg("suspended coro_frame has no resume function in its first slot")
int coro_cont_no_resume(void *ctx)
{
	__u64 *slots;

	slots = bpf_coro_frame_alloc(16, NULL);
	if (!slots)
		return 1;
	slots[0] = 0;
	slots[1] = (__u64)coro_resume_leak;
	bpf_kfunc_coro_suspend(0, slots);
	return 0;
}

SEC("tc")
__description("coro_cont: the context does not survive a suspension")
__failure __msg("coro_frame slot 2 holds ctx which cannot survive a suspension")
int coro_cont_ctx(void *ctx)
{
	__u64 *slots;

	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots)
		return 1;
	slots[0] = (__u64)coro_resume_leak;
	slots[1] = (__u64)coro_resume_leak;
	slots[2] = (__u64)ctx;
	bpf_kfunc_coro_suspend(0, slots);
	return 0;
}

/*
 * A socket that a helper looked up: a UDP socket or a TCP listener goes after a grace period of
 * RCU, whatever the program holds, and the continuation runs after that one.
 */
SEC("tc")
__description("coro_cont: a socket of a helper does not survive a suspension")
__failure __msg("coro_frame slot 2 holds sock which cannot survive a suspension")
int coro_cont_sock(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	__u64 *slots;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return 0;
	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots) {
		bpf_sk_release(sk);
		return 0;
	}
	slots[0] = (__u64)coro_resume_leak;
	slots[1] = (__u64)coro_resume_leak;
	slots[2] = (__u64)sk;
	bpf_kfunc_coro_suspend(0, slots);
	return 0;
}

/* An inner map of a map in map goes with its entry of the outer map, which the frame keeps not */
struct coro_inner {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, __u64);
} coro_inner SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, int);
	__array(values, struct coro_inner);
} coro_outer SEC(".maps") = {
	.values = { &coro_inner },
};

/* Suspend a frame with @p in slot 2 */
static __always_inline void coro_start_with(void *p)
{
	__u64 *slots;

	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots)
		return;
	slots[0] = (__u64)coro_resume_leak;
	slots[1] = (__u64)coro_resume_leak;
	slots[2] = (__u64)p;
	bpf_kfunc_coro_suspend(0, slots);
}

SEC("tc")
__description("coro_cont: an inner map does not survive a suspension")
__failure __msg("coro_frame slot 2 holds map_ptr which cannot survive a suspension")
int coro_cont_inner_map(void *ctx)
{
	void *inner;
	int key = 0;

	inner = bpf_map_lookup_elem(&coro_outer, &key);
	if (!inner)
		return 0;
	coro_start_with(inner);
	return 0;
}

SEC("tc")
__description("coro_cont: a value of an inner map does not survive a suspension")
__failure __msg("coro_frame slot 2 holds map_value which cannot survive a suspension")
int coro_cont_inner_value(void *ctx)
{
	void *inner, *v;
	int key = 0;

	inner = bpf_map_lookup_elem(&coro_outer, &key);
	if (!inner)
		return 0;
	v = bpf_map_lookup_elem(inner, &key);
	if (!v)
		return 0;
	coro_start_with(v);
	return 0;
}

/*
 * The copy of an object that the program released in the meantime: without CAP_PERFMON the slot
 * has a register that nothing can read, which the continuation cannot read either.
 */
SEC("tc")
__description("coro_cont: a slot with the copy of a released object")
__success __caps_unpriv(CAP_BPF | CAP_NET_ADMIN) __success_unpriv
int coro_cont_released_copy(void *ctx)
{
	struct coro_obj *obj;
	__u64 *slots;

	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots)
		return 1;
	obj = bpf_obj_new(typeof(*obj));
	if (!obj) {
		bpf_coro_frame_free(slots);
		return 1;
	}
	slots[2] = (__u64)obj;
	bpf_obj_drop(obj);
	slots[0] = (__u64)coro_resume_leak;
	slots[1] = (__u64)coro_resume_leak;
	bpf_kfunc_coro_suspend(0, slots);
	return 0;
}

SEC("tc")
__description("coro_cont: the object moves to the continuation")
__failure __msg("invalid mem access 'scalar'")
int coro_cont_moved(void *ctx)
{
	struct coro_obj *obj;
	__u64 *slots;

	slots = bpf_coro_frame_alloc(32, NULL);
	if (!slots)
		return 1;
	obj = bpf_obj_new(typeof(*obj));
	if (!obj) {
		bpf_coro_frame_free(slots);
		return 1;
	}
	slots[0] = (__u64)coro_resume;
	slots[1] = (__u64)coro_destroy;
	slots[2] = (__u64)obj;
	bpf_kfunc_coro_suspend(0, slots);
	return obj->data;
}

/* Allocates a frame of the size that the suspend point left in slot 2. */
static __noinline __used void coro_resume_alloc(void *frame)
{
	__u64 *slots = frame;
	void *p;

	p = bpf_coro_frame_alloc(slots[2], NULL);
	if (p)
		bpf_coro_frame_free(p);
	bpf_coro_frame_free(frame);
}

static __noinline __used void coro_destroy_frame(void *frame)
{
	bpf_coro_frame_free(frame);
}

/*
 * Two suspend points leave 8 and 16 in slot 2, which the continuation takes
 * as the constant size of a frame. A join of the two would make it a range.
 * In asm, so that the compiler does not make one call of the two.
 */
SEC("tc")
__description("coro_cont: the continuations of two suspend points keep their constants")
__success __retval(0)
__naked int coro_cont_two_sites(void)
{
	asm volatile (
	"r6 = r1;"
	"r1 = 24;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 != 0 goto 1f;"
	"exit;"
"1:"
	"r7 = r0;"
	"r1 = %[coro_resume_alloc] ll;"
	"*(u64 *)(r7 + 0) = r1;"
	"r1 = %[coro_destroy_frame] ll;"
	"*(u64 *)(r7 + 8) = r1;"
	"r2 = *(u32 *)(r6 + %[__sk_buff_len]);"
	"if r2 > 100 goto 2f;"
	"r1 = 8;"
	"*(u64 *)(r7 + 16) = r1;"
	"r1 = 0;"
	"r2 = r7;"
	"call %[bpf_kfunc_coro_suspend];"
	"r0 = 0;"
	"exit;"
"2:"
	"r1 = 16;"
	"*(u64 *)(r7 + 16) = r1;"
	"r1 = 0;"
	"r2 = r7;"
	"call %[bpf_kfunc_coro_suspend];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_coro_frame_alloc),
	  __imm(bpf_kfunc_coro_suspend),
	  __imm_addr(coro_resume_alloc),
	  __imm_addr(coro_destroy_frame),
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/* Suspends its frame again until slot 2 has counted to 3 */
static __noinline __used void coro_resume_again(void *frame)
{
	__u64 *slots = frame;

	if (slots[2] < 3) {
		slots[2]++;
		bpf_kfunc_coro_suspend(0, slots);
		return;
	}
	coro_resumed = slots[2];
	bpf_coro_frame_free(frame);
}

/*
 * The continuation suspends the frame again, with another count in slot 2
 * each time. The continuations of its suspend point meet at its first insn,
 * and their frames are joined: the count becomes a range, and the states
 * come to an end.
 */
SEC("tc")
__description("coro_cont: a continuation that suspends its frame again")
__success
int coro_cont_again(void *ctx)
{
	__u64 *slots;

	coro_resumed = 0;
	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots)
		return 1;
	slots[0] = (__u64)coro_resume_again;
	slots[1] = (__u64)coro_destroy_frame;
	slots[2] = 0;
	bpf_kfunc_coro_suspend(0, slots);
	return coro_resumed;
}

/* Suspend a frame that holds nothing, to be resumed by @resume */
static __always_inline int coro_start_empty(void *resume)
{
	__u64 *slots;

	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots)
		return -1;
	slots[0] = (__u64)resume;
	slots[1] = (__u64)coro_destroy_frame;
	slots[2] = 0;
	return bpf_kfunc_coro_suspend(0, slots);
}

/*
 * The kernel calls a continuation from bpf_coro_run() only, which tells the
 * kfunc when it was unwound: no function is a continuation and the callback
 * of a timer.
 */
struct coro_timer {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct coro_timer);
} coro_timers SEC(".maps");

static __noinline __used int coro_resume_timer(void *frame)
{
	bpf_coro_frame_free(frame);
	return 0;
}

static __noinline __used int coro_timer_resume(void *frame)
{
	bpf_coro_frame_free(frame);
	return 0;
}

static __always_inline void coro_arm(void *cb)
{
	struct coro_timer *e;
	int key = 0;

	e = bpf_map_lookup_elem(&coro_timers, &key);
	if (!e)
		return;
	bpf_timer_init(&e->t, &coro_timers, 1);
	bpf_timer_set_callback(&e->t, cb);
}

SEC("tc")
__description("coro_cont: a continuation cannot be the callback of a timer")
__failure __msg("is a coroutine continuation and cannot be an async callback")
int coro_cont_then_timer(void *ctx)
{
	coro_start_empty(coro_resume_timer);
	coro_arm(coro_resume_timer);
	return 0;
}

SEC("tc")
__description("coro_cont: the callback of a timer cannot be a continuation")
__failure __msg("is an async callback and cannot be a coroutine continuation")
int coro_timer_then_cont(void *ctx)
{
	coro_arm(coro_timer_resume);
	coro_start_empty(coro_timer_resume);
	return 0;
}

/* A continuation gets the frame in R1 and nothing else */
__naked __noinline __used static void coro_resume_reads_r2(void *frame)
{
	asm volatile (
	"r6 = r2;"
	"call %[bpf_coro_frame_free];"
	"r0 = r6;"
	"exit;"
	:
	: __imm(bpf_coro_frame_free)
	: __clobber_all);
}

SEC("tc")
__description("coro_cont: a continuation cannot read R2")
__failure __msg("R2 !read_ok")
int coro_cont_reads_r2(void *ctx)
{
	coro_start_empty(coro_resume_reads_r2);
	return 0;
}

/*
 * bpf_throw() unwinds a continuation like any callback, through landing pads:
 * its frame 0 leaves with kexit, into the pad of bpf_coro_run(), see
 * coro_cont_run.c for what bpf_coro_run() says.
 */
static __noinline __used void coro_resume_throws(void *frame)
{
	bpf_coro_frame_free(frame);
	bpf_throw(0);
}

SEC("tc")
__description("coro_cont: a continuation that throws")
__arch_x86_64
__arch_arm64
__success
int coro_cont_throws(void *ctx)
{
	coro_start_empty(coro_resume_throws);
	return 0;
}

/*
 * The check at the entry of a recursive function unwinds a frame that holds
 * nothing, and a continuation holds its frame from its first insn on. In asm:
 * the compiler makes a loop of the call.
 */
__naked __noinline __used static void coro_resume_rec(void *frame)
{
	asm volatile (
	"r6 = r1;"
	"r2 = *(u64 *)(r6 + 16);"
	"if r2 == 0 goto 1f;"
	"r2 += -1;"
	"*(u64 *)(r6 + 16) = r2;"
	"r1 = r6;"
	"call coro_resume_rec;"
	"exit;"
"1:"
	"r1 = r6;"
	"call %[bpf_coro_frame_free];"
	"exit;"
	:
	: __imm(bpf_coro_frame_free)
	: __clobber_all);
}

SEC("tc")
__description("coro_cont: a continuation cannot be recursive")
__failure __msg("coroutine continuation coro_resume_rec() is recursive")
int coro_cont_recursive(void *ctx)
{
	coro_start_empty(coro_resume_rec);
	return 0;
}

/*
 * A continuation that stores the address of a resume function in a frame and
 * suspends it does not call that function: the kernel resumes the frame later.
 * Neither the continuation that stores its own address, nor two that store each
 * other's, nor one that suspends a new frame to itself is on a cycle of calls.
 */
static __noinline __used void coro_resume_self(void *frame)
{
	__u64 *slots = frame;

	if (slots[2] < 3) {
		slots[2]++;
		slots[0] = (__u64)coro_resume_self;
		bpf_kfunc_coro_suspend(0, slots);
		return;
	}
	bpf_coro_frame_free(frame);
}

SEC("tc")
__description("coro_cont: a continuation that suspends its frame to itself")
__success
int coro_cont_self(void *ctx)
{
	coro_start_empty(coro_resume_self);
	return 0;
}

static __noinline __used void coro_resume_pong(void *frame);

static __noinline __used void coro_resume_ping(void *frame)
{
	__u64 *slots = frame;

	if (slots[2] < 3) {
		slots[2]++;
		slots[0] = (__u64)coro_resume_pong;
		bpf_kfunc_coro_suspend(0, slots);
		return;
	}
	bpf_coro_frame_free(frame);
}

static __noinline __used void coro_resume_pong(void *frame)
{
	__u64 *slots = frame;

	if (slots[2] < 3) {
		slots[2]++;
		slots[0] = (__u64)coro_resume_ping;
		bpf_kfunc_coro_suspend(0, slots);
		return;
	}
	bpf_coro_frame_free(frame);
}

SEC("tc")
__description("coro_cont: two continuations that suspend the frame to each other")
__success
int coro_cont_ping_pong(void *ctx)
{
	coro_start_empty(coro_resume_ping);
	return 0;
}

static __noinline __used void coro_resume_new_frame(void *frame)
{
	__u64 *slots = frame, n = slots[2], *next;

	bpf_coro_frame_free(frame);
	if (n >= 3)
		return;
	next = bpf_coro_frame_alloc(24, NULL);
	if (!next)
		return;
	next[0] = (__u64)coro_resume_new_frame;
	next[1] = (__u64)coro_destroy_frame;
	next[2] = n + 1;
	bpf_kfunc_coro_suspend(0, next);
}

SEC("tc")
__description("coro_cont: a continuation that suspends a new frame to itself")
__success
int coro_cont_new_frame(void *ctx)
{
	coro_start_empty(coro_resume_new_frame);
	return 0;
}

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} coro_arena SEC(".maps");

/* r12 += 16, compilers don't know r12 yet */
#define ADJ_16 (0x07 | 12 << 8 | 16ULL << 32)

static __naked __noinline __used void coro_uses_arena_stack(void)
{
	asm volatile (
	".8byte %[adj];"
	"exit;"
	:
	: __imm_const(adj, ADJ_16)
	: __clobber_all);
}

/*
 * A resume that gets no stack in arena would be skipped, and nobody would free the frame. It
 * doesn't matter which function that the continuation calls uses r12.
 */
static __noinline __used void coro_resume_arena(void *frame)
{
	bpf_coro_frame_free(frame);
	coro_uses_arena_stack();
}

SEC("tc")
__description("coro_cont: a continuation cannot use the stack in arena")
__failure __msg("coroutine continuation coro_resume_arena() cannot use R12")
int coro_cont_arena(void *ctx)
{
	coro_start_empty(coro_resume_arena);
	return 0;
}

SEC("tc")
__description("coro_cont: the program uses the stack in arena, its continuation does not")
__success
int coro_cont_arena_prog(void *ctx)
{
	coro_uses_arena_stack();
	coro_start_empty(coro_destroy_frame);
	return 0;
}

#endif

/*
 * A function that stores its own address and suspends a frame is not taken for one that
 * calls itself, see func_is_kept_for_later(). Where it loads the address back and calls
 * itself after all, the main pass sees the cycle: through bpf_loop() it is too deep.
 */
__naked __noinline __used static int coro_rec_cb(__u64 idx, void *ctx)
{
	asm volatile (
	"r1 = 16;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 == 0 goto 1f;"
	"r6 = r0;"
	"r1 = %[coro_rec_cb] ll;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = %[coro_destroy_frame] ll;"
	"*(u64 *)(r6 + 0) = r1;"
	"*(u64 *)(r6 + 8) = r1;"
	"r1 = 0;"
	"r2 = r6;"
	"call %[bpf_kfunc_coro_suspend];"
	"r1 = 2;"
	"r2 = *(u64 *)(r10 - 8);"
	"r3 = 0;"
	"r4 = 0;"
	"call %[bpf_loop];"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_coro_frame_alloc),
	  __imm(bpf_kfunc_coro_suspend),
	  __imm(bpf_loop),
	  __imm_addr(coro_rec_cb),
	  __imm_addr(coro_destroy_frame)
	: __clobber_all);
}

SEC("tc")
__description("coro_cont: a function that calls itself back through a stored address and a helper")
__failure __msg("the call stack of {{[0-9]+}} frames is too deep")
int coro_rec_loop(void *ctx)
{
	bpf_loop(1, coro_rec_cb, NULL, 0);
	return 0;
}

#ifdef CAN_USE_CALLX

/*
 * The first slot has one of two functions, loaded from a table in read-only
 * data. Only a function that is pushed is verified from the snapshot of the
 * frame, and the kernel calls what the slot has: the frame is not suspended.
 */
SEC("tc")
__description("coro_cont: a resume function that is one of a set is rejected")
__failure __msg("suspended coro_frame has no resume function in its first slot")
__naked int coro_cont_resume_set(void)
{
	asm volatile (
	".pushsection .rodata,\"a\",@progbits;"
	".balign 8;"
	"resume_tbl_%=:"
	".quad coro_resume_alloc; .quad coro_destroy_frame;"
	".type resume_tbl_%=, @object;"
	".size resume_tbl_%=, .-resume_tbl_%=;"
	".popsection;"
	"r6 = r1;"
	"r1 = 24;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 != 0 goto 1f;"
	"exit;"
"1:"
	"r7 = r0;"
	"r2 = *(u32 *)(r6 + %[__sk_buff_len]);"
	"r2 &= 1;"
	"r2 <<= 3;"
	"r1 = resume_tbl_%= ll;"
	"r1 += r2;"
	"r1 = *(u64 *)(r1 + 0);"
	"*(u64 *)(r7 + 0) = r1;"
	"r1 = %[coro_destroy_frame] ll;"
	"*(u64 *)(r7 + 8) = r1;"
	"r1 = 8;"
	"*(u64 *)(r7 + 16) = r1;"
	"r1 = 0;"
	"r2 = r7;"
	"call %[bpf_kfunc_coro_suspend];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_coro_frame_alloc),
	  __imm(bpf_kfunc_coro_suspend),
	  __imm_addr(coro_destroy_frame),
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/*
 * The same through callx: a function whose address is taken may be what callx calls, and is
 * on a cycle with it. Its stack is checked at run time.
 */
__naked __noinline __used static int coro_rec_callx(void)
{
	asm volatile (
	"r1 = 16;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 == 0 goto 1f;"
	"r6 = r0;"
	"r1 = %[coro_rec_callx] ll;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = %[coro_destroy_frame] ll;"
	"*(u64 *)(r6 + 0) = r1;"
	"*(u64 *)(r6 + 8) = r1;"
	"r1 = 0;"
	"r2 = r6;"
	"call %[bpf_kfunc_coro_suspend];"
	"r1 = *(u64 *)(r10 - 8);"
	"callx r1;"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_coro_frame_alloc),
	  __imm(bpf_kfunc_coro_suspend),
	  __imm_addr(coro_rec_callx),
	  __imm_addr(coro_destroy_frame)
	: __clobber_all);
}

SEC("tc")
__description("coro_cont: a function that calls itself back through a stored address and callx")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
__stderr("ERROR: No room in the stack for a call of a recursive function")
int coro_rec_callx_prog(void *ctx)
{
	asm volatile ("call coro_rec_callx;" ::: "r0", "r1", "r2", "r3", "r4", "r5", "memory");
	return 0;
}

/*
 * The rule of func_is_kept_for_later() for coroutines is about an address that goes to memory in
 * front of a kfunc that suspends a frame. The callback of a timer whose address the program
 * keeps in the stack as well and calls with callx is called by the program, as without the rule:
 * its loop, which nothing bounds, gets may_goto, which unwinds it in the call of the program.
 */
unsigned long coro_one = 1;

static __noinline __used int timer_cb_spins(void *map, int *key, void *value)
{
	while (*(volatile unsigned long *)&coro_one)
		;
	return 0;
}

SEC("tc")
__description("coro_cont: a timer callback that the program also calls from the stack")
__arch_x86_64
__arch_arm64
__success
__naked int timer_cb_called_too(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u32 *)(r10 - 8) = r1;"
	"r1 = %[coro_timers] ll;"
	"r2 = r10;"
	"r2 += -8;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto 1f;"
	"r6 = r0;"
	"r1 = r0;"
	"r2 = %[coro_timers] ll;"
	"r3 = 1;"
	"call %[bpf_timer_init];"
	"r1 = r6;"
	"r2 = %[timer_cb_spins] ll;"
	"*(u64 *)(r10 - 16) = r2;"
	"call %[bpf_timer_set_callback];"
	"r1 = *(u64 *)(r10 - 16);"
	"callx r1;"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_timer_init),
	  __imm(bpf_timer_set_callback),
	  __imm_addr(coro_timers),
	  __imm_addr(timer_cb_spins)
	: __clobber_all);
}

#endif /* CAN_USE_CALLX */

char _license[] SEC("license") = "GPL";
