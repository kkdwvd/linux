// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

#define MAX_RES 8
#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

/* See verifier_unwind_cb.c: the raw words of the insns a callee unwinds into its caller's pad with. */
#define unwind_goto(off) ".8byte ((" #off " & 0xffff) << 16) | 0x10e5;"	/* BPF_JMP | BPF_JCOND */
#define unwind_exit ".8byte 0x1095;"				/* BPF_JMP | BPF_EXIT */

struct foo {
	int data;
	struct bpf_list_node node;
};

struct locked_foo {
	int data;
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

/* Pages: the stack in arena of the cpu, the stack of a callback that runs under it, and spare. */
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 4);
} arena SEC(".maps");

private(A) struct bpf_spin_lock glock;

/* Resources the program under test acquired, in order. */
__u64 acquired[MAX_RES];
__u32 acquired_cnt;
/* The releases observed, in order: the handle of the resource, or none for a section. */
__u64 released[MAX_RES];
__u8 released_section[MAX_RES];
__u32 released_cnt;
/* The test process: the sections it leaves are the ones under test. */
__u32 test_pid;
/* A choice of the test, read by the program under test. */
__u32 param;

static __always_inline void mark_acquired(void *p)
{
	__u32 i = acquired_cnt;

	if (i < MAX_RES) {
		acquired[i] = (__u64)p;
		acquired_cnt = i + 1;
	}
}

/*
 * Record a release: of @p, one of the resources the program acquired, or of a
 * section of the test process, which has no handle. The hooks fire for every
 * unwind in the system, so releases of other programs are left out.
 */
static __always_inline void mark_released(void *p, bool section)
{
	__u32 i, n = released_cnt;

	if (n >= MAX_RES)
		return;
	if (section) {
		if (bpf_get_current_pid_tgid() >> 32 != test_pid)
			return;
	} else {
		if (!p)
			return;
		for (i = 0; i < MAX_RES; i++)
			if (i < acquired_cnt && acquired[i] == (__u64)p)
				break;
		if (i == MAX_RES)
			return;
	}
	released[n] = section ? 0 : (__u64)p;
	released_section[n] = section;
	released_cnt = n + 1;
}

/*
 * Observe every release the unwinder performs, identified like the program
 * sees it: the handle is the pointer to an object or a record, the address of
 * a stack object or of a lock; a section has none.
 */
SEC("fentry/bpf_unwind_release")
int BPF_PROG(release_hook, struct bpf_resource *res, void *handle, void *flags)
{
	/* The flags of an irqsave lock are restored with the lock: the flags came last, and go first. */
	if (flags)
		mark_released(flags, false);
	mark_released(handle, res->kind == BPF_RESOURCE_RCU || res->kind == BPF_RESOURCE_PREEMPT);
	return 0;
}

/* An object in a callee-saved register of the throwing frame. */
SEC("tc")
int throw_obj_reg(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_obj_drop(f);
	return 0;
}

/* Two objects, one spilled to the stack by the compiler. */
SEC("tc")
int throw_obj_two(struct __sk_buff *ctx)
{
	struct foo *f, *g;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	g = bpf_obj_new(typeof(*g));
	if (!g) {
		bpf_obj_drop(f);
		return 1;
	}
	mark_acquired(f);
	mark_acquired(g);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_obj_drop(f);
	bpf_obj_drop(g);
	return 0;
}

/* A ringbuf reservation. */
SEC("tc")
int throw_ringbuf(struct __sk_buff *ctx)
{
	void *p;

	p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
	if (!p)
		return 1;
	mark_acquired(p);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_ringbuf_discard(p, 0);
	return 0;
}

/* A task reference released through the destructor registry. */
SEC("tc")
int throw_task(struct __sk_buff *ctx)
{
	struct task_struct *t;

	t = bpf_task_acquire(bpf_get_current_task_btf());
	if (!t)
		return 1;
	mark_acquired(t);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_task_release(t);
	return 0;
}

/* Port, in network order, of the listener throw_sock_cast looks up. */
__u16 server_port;

/*
 * A socket acquired by a lookup and cast to its struct by a helper, which
 * carries the reference under the struct's type: released as the socket.
 */
SEC("tc")
int throw_sock_cast(struct __sk_buff *ctx)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *skc;
	struct tcp_sock *tp;

	tuple.ipv4.daddr = bpf_htonl(0x7f000001);
	tuple.ipv4.dport = server_port;
	skc = bpf_skc_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!skc)
		return 1;
	tp = bpf_skc_to_tcp_sock(skc);
	if (!tp) {
		bpf_sk_release(skc);
		return 1;
	}
	mark_acquired(tp);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_sk_release((struct bpf_sock *)tp);
	return 0;
}

/* An open-coded iterator on the stack. */
SEC("tc")
int throw_iter(struct __sk_buff *ctx)
{
	struct bpf_iter_num it;
	int *v;

	bpf_iter_num_new(&it, 0, 10);
	mark_acquired(&it);
	while ((v = bpf_iter_num_next(&it))) {
		if (*v == 3 && ctx->len)
			bpf_throw(0xeB9F);
	}
	bpf_iter_num_destroy(&it);
	return 0;
}

/* The object is NULL on one path and an object on the other at the throw. */
SEC("tc")
int throw_obj_maybe(struct __sk_buff *ctx)
{
	struct foo *f = NULL;

	if (ctx->len > 1) {
		f = bpf_obj_new(typeof(*f));
		if (!f)
			return 1;
		mark_acquired(f);
	}
	if (ctx->len)
		bpf_throw(0xeB9F);
	if (f)
		bpf_obj_drop(f);
	return 0;
}

static __noinline int throw_in_subprog(struct __sk_buff *ctx, int x)
{
	/* Use callee-saved registers so the caller's are saved in this frame. */
	__u64 a = x * 3, b = x * 5, c = x * 7;

	if (ctx->len)
		bpf_throw(0xeB9F);
	return a + b + c;
}

/* The object is held by the caller of the throwing static subprog. */
SEC("tc")
int throw_obj_caller(struct __sk_buff *ctx)
{
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	ret = throw_in_subprog(ctx, ctx->len);
	bpf_obj_drop(f);
	return ret;
}

/* The object is held by the caller across a call of the throwing subprog by its address. */
SEC("tc")
int throw_obj_callx_caller(struct __sk_buff *ctx)
{
	int (*callee)(struct __sk_buff *, int) = throw_in_subprog;
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	/* Hide the callee from the compiler, so that the call goes through the pointer: a callx. */
	asm volatile ("" : "+r"(callee));
	ret = callee(ctx, ctx->len);
	bpf_obj_drop(f);
	return ret;
}

/* Throws holding what it was passed, which it reads nowhere. */
static __noinline int throw_with(struct foo *f)
{
	bpf_throw(0xeB9F);
	return 0;
}

static __noinline int drop_and_throw(struct foo *f);

/*
 * A call through a pointer that may reach a callee that drops the object and
 * one that does not: the caller lists it for neither, since the one that
 * drops it does, and so the other one lists it too, from the register it
 * arrived in, although it reads it nowhere.
 */
SEC("tc")
int throw_obj_callx_targets_disagree(struct __sk_buff *ctx)
{
	int (*callee)(struct foo *) = param ? drop_and_throw : throw_with;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	asm volatile ("" : "+r"(callee));
	callee(f);
	return 0;
}

/* Allocates at its first insns: the origin of the object is at the start of the subprog. */
static __noinline int alloc_and_throw(void)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (f)
		mark_acquired(f);
	bpf_throw(0xeB9F);
	return 0;
}

/* A count the verifier does not know. */
volatile __u32 loops = 1;

/*
 * The loop gets a may_goto of the verifier's, in front of the subprog that
 * allocates at its first insns: what the main pass named by instruction has
 * to be told from the subprog starts as they are after that.
 */
SEC("tc")
int throw_obj_origin_after_guard(struct __sk_buff *ctx)
{
	__u32 i;

	for (i = 0; i < loops; i++)
		;
	return alloc_and_throw();
}

/* The throw is unconditional, so nothing after it keeps the object alive. */
SEC("tc")
int throw_obj_unconditional(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_throw(0xeB9F);
	return 0;
}

static __noinline int throw_unconditionally(void)
{
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The callee's throw is unconditional, so the caller never reads the object
 * again and no live location of its frame holds it at the call: the object
 * is released from its mirror, which the acquisition filled.
 */
SEC("tc")
int throw_obj_dead_caller(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	return throw_unconditionally();
}

static __noinline int subprog_acquire_throw(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_throw(0xeB9F);
	return 0;
}

/* The object is acquired and the throw raised in a static subprog. */
SEC("tc")
int throw_obj_subprog(struct __sk_buff *ctx)
{
	return subprog_acquire_throw(ctx) + 1;
}

__noinline int global_throw(struct __sk_buff *ctx)
{
	if (ctx->len)
		bpf_throw(0xeB9F);
	return 0;
}

/* The object is held by the caller of the throwing global subprog. */
SEC("tc")
int throw_obj_global_caller(struct __sk_buff *ctx)
{
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	ret = global_throw(ctx);
	bpf_obj_drop(f);
	return ret;
}

/*
 * R6 holds the ringbuf record on one path and a number on the other at the
 * site: no location describes both, so the record is released from its
 * mirror, a hidden slot of the frame, which the acquisition fills and the
 * release clears.
 */
#define MIRROR_PROG(name, site)						\
SEC("tc")								\
__naked int name(void)							\
{									\
	asm volatile (							\
	"r6 = *(u32 *)(r1 + %[len]);"					\
	"r7 = 0;"							\
	"if r6 == 0 goto 1f;"						\
	"r1 = %[ringbuf] ll;"						\
	"r2 = 8;"							\
	"r3 = 0;"							\
	"call %[bpf_ringbuf_reserve];"					\
	"if r0 == 0 goto 3f;"						\
	"r6 = r0;"							\
	"r7 = 1;"							\
	"r1 = %[acquired] ll;"						\
	"*(u64 *)(r1 + 0) = r0;"					\
	"r1 = %[acquired_cnt] ll;"					\
	"*(u32 *)(r1 + 0) = r7;"					\
	"goto 2f;"							\
	"1: r6 = 42;"							\
	"2: " site							\
	"if r7 == 0 goto 3f;"						\
	"r1 = r6;"							\
	"r2 = 0;"							\
	"call %[bpf_ringbuf_discard];"					\
	"3: r0 = 0;"							\
	"exit;"								\
	:								\
	: __imm_addr(ringbuf),						\
	  __imm_addr(acquired),						\
	  __imm_addr(acquired_cnt),					\
	  __imm(bpf_ringbuf_reserve),					\
	  __imm(bpf_ringbuf_discard),					\
	  __imm(bpf_throw),						\
	  [len]"i"(offsetof(struct __sk_buff, len))			\
	: __clobber_all);						\
}

/* An explicit throw. */
MIRROR_PROG(throw_mirror_conflict, "r1 = 0xeB9F; call %[bpf_throw];")

/* bpf_throw() leaves a spin lock and a section too. */
SEC("tc")
int throw_spin_lock(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	mark_acquired(&glock);
	bpf_spin_lock(&glock);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_spin_unlock(&glock);
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int throw_rcu(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_rcu_read_lock();
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_rcu_read_unlock();
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int throw_irq(struct __sk_buff *ctx)
{
	unsigned long flags;

	mark_acquired(&flags);
	bpf_local_irq_save(&flags);
	bpf_preempt_disable();
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_preempt_enable();
	bpf_local_irq_restore(&flags);
	return 0;
}

/*
 * The record is read by nothing after its acquisition, and the register that
 * held it is overwritten: no location of the frame holds it at the throw, so
 * it is released from its mirror, which the acquisition filled.
 */
SEC("tc")
__naked int throw_mirror_dead(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* Two elements, so that a lock of one is found through the pointer to it, not at a fixed address. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct locked_foo);
	__uint(max_entries, 2);
} lock_map SEC(".maps");

/*
 * The lock of a map element is taken through the pointer in R7, which the
 * path holding a record then moves to R9, leaving a number in R7. The paths
 * cannot join, as one holds the record, so both describe the throw: no
 * register holds the pointer on both, and the lock is released from its
 * mirror, which holds the address of the lock. The record is released after
 * the lock.
 */
SEC("tc")
__naked int throw_mirror_lock_two_locations(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[len]);"
	"r1 = 0;"
	"*(u32 *)(r10 - 4) = r1;"
	"r1 = %[lock_map] ll;"
	"r2 = r10;"
	"r2 += -4;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto 3f;"
	"r7 = r0;"
	"r2 = r7;"
	"r2 += %[lock_off];"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r2;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r8 = 0;"
	"if r6 == 0 goto 1f;"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 3f;"
	"r8 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 8) = r0;"
	"r2 = 2;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"1: r1 = r7;"
	"r1 += %[lock_off];"
	"call %[bpf_spin_lock];"
	"r9 = 42;"
	"if r8 == 0 goto 2f;"
	"r9 = r7;"
	"r7 = 42;"
	"2: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"3: r0 = 0;"
	"exit;"
	:
	: __imm_addr(lock_map),
	  __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_map_lookup_elem),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_spin_lock),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len)),
	  [lock_off]"i"(offsetof(struct locked_foo, lock))
	: __clobber_all);
}

/*
 * Two records, of which the one the test chooses is discarded at a single
 * instruction. The paths discarding either reach the throw with the other
 * record in its register and a dead pointer in the register of the discarded
 * one, so both records are mirrored, and the discard clears the mirror that
 * holds the pointer it releases, whichever it is.
 */
SEC("tc")
__naked int throw_mirror_shared_release(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r7 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r6;"
	"*(u64 *)(r1 + 8) = r7;"
	"r2 = 2;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r8 = %[param] ll;"
	"r8 = *(u32 *)(r8 + 0);"
	"r1 = r6;"
	"if r8 == 0 goto +1;"
	"r1 = r7;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm_addr(param),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* Returns the record in R1, or discards it and returns 0 when R2 is not 0. */
__naked __noinline __used
static long discard_maybe(void)
{
	asm volatile (
	"r0 = r1;"
	"if r2 == 0 goto 1f;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"r0 = 0;"
	"1: exit;"
	:
	: __imm(bpf_ringbuf_discard)
	: __clobber_all);
}

/*
 * The record is mirrored, as R6 holds it on one path to the throw and a
 * number on the other, and a callee discards it when the test says so,
 * returning what it leaves. A callee cannot clear the mirror of its caller:
 * the mirror is refreshed from R0 after the call, so that a discarded record
 * is not released again.
 */
SEC("tc")
__naked int throw_mirror_refresh(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[len]);"
	"if r6 == 0 goto 1f;"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 3f;"
	"r6 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r2 = %[param] ll;"
	"r2 = *(u32 *)(r2 + 0);"
	"r1 = r6;"
	"call discard_maybe;"
	"r6 = r0;"
	"goto 2f;"
	"1: r6 = 42;"
	"2: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"3: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm_addr(param),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/*
 * Reserves a record and returns it when R1 is 0; unwinds otherwise, with 0,
 * as the caller stores R0 in the mirror of the record on both ways out.
 */
__naked __noinline __used
static long reserve_or_unwind(void)
{
	asm volatile (
	"if r1 != 0 goto 1f;"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"exit;"
	"1: r0 = 0;"
	unwind_exit
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve)
	: __clobber_all);
}

/*
 * The record the callee returns is in no live location at the throw, so it
 * is mirrored from R0 after the call, where the unwind_goto of the call
 * follows: the refresh goes on both ways out, and the pad the callee unwinds
 * into lies in front of the call, where the way out has to jump back to.
 */
SEC("tc")
__naked int throw_mirror_pad_before_call(void)
{
	asm volatile (
	"r6 = %[param] ll;"
	"r6 = *(u32 *)(r6 + 0);"
	"goto 2f;"
	"1: r0 = 42;"
	"exit;"
	"2: r1 = r6;"
	"call reserve_or_unwind;"
	unwind_goto(-5)
	"if r0 == 0 goto 3f;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"3: r0 = 0;"
	"exit;"
	:
	: __imm_addr(param),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_throw)
	: __clobber_all);
}

struct refcounted_foo {
	int data;
	struct bpf_list_node node;
	struct bpf_refcount ref;
};

/*
 * Two references to one object, its allocation and a bpf_refcount_acquire()
 * of it, hold the same pointer. The one the test chooses is dropped, and the
 * other is in the register of the one dropped on the other path, so both are
 * mirrored: the drop clears one mirror holding the pointer, whichever it is,
 * and the unwinder drops the object exactly once more.
 */
SEC("tc")
int throw_refcount_shared_release(struct __sk_buff *ctx)
{
	struct refcounted_foo *a, *b;

	a = bpf_obj_new(typeof(*a));
	if (!a)
		return 1;
	b = bpf_refcount_acquire(a);
	mark_acquired(a);
	bpf_obj_drop(param ? a : b);
	bpf_throw(0xeB9F);
	return 0;
}

/* Drops the object its caller holds, then throws. */
static __noinline int drop_and_throw(struct foo *f)
{
	bpf_obj_drop(f);
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The caller holds both objects at the call, and the callee drops one of them
 * before it throws: the callee lists that one, the caller's descriptor at the
 * call omits it, and the unwinder releases the other alone.
 */
SEC("tc")
int throw_callee_drops_obj(struct __sk_buff *ctx)
{
	struct foo *f, *g;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	g = bpf_obj_new(typeof(*g));
	if (!g) {
		bpf_obj_drop(f);
		return 1;
	}
	mark_acquired(f);
	mark_acquired(g);
	drop_and_throw(f);
	bpf_obj_drop(g);
	return 0;
}

/* Unlocks the lock its caller holds, then throws. */
static __noinline int unlock_and_throw(struct locked_foo *f)
{
	bpf_spin_unlock(&f->lock);
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The caller holds the lock of its object at the call, and the callee unlocks
 * it before it throws: the callee lists the lock, the caller's descriptor at
 * the call omits it, and the unwinder releases the object alone.
 */
SEC("tc")
int throw_callee_unlocks(struct __sk_buff *ctx)
{
	struct locked_foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	mark_acquired(&f->lock);
	bpf_spin_lock(&f->lock);
	unlock_and_throw(f);
	bpf_obj_drop(f);
	return 0;
}

/* Destroys the iterator in its caller's stack, then throws. */
static __noinline int destroy_and_throw(struct bpf_iter_num *it)
{
	bpf_iter_num_destroy(it);
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The iterator lives in the caller's stack, and the callee destroys it through
 * the pointer before it throws: the callee lists it, the caller's descriptor
 * at the call omits it, and the unwinder releases the caller's object alone.
 */
SEC("tc")
int throw_callee_destroys_iter(struct __sk_buff *ctx)
{
	struct bpf_iter_num it;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(&it);
	mark_acquired(f);
	bpf_iter_num_new(&it, 0, 10);
	destroy_and_throw(&it);
	bpf_obj_drop(f);
	return 0;
}

/* Restores the IRQ flags its caller saved, then throws. */
static __noinline int restore_and_throw(unsigned long *flags)
{
	bpf_local_irq_restore(flags);
	bpf_throw(0xeB9F);
	return 0;
}

/* The same for the IRQ flags the caller saved in its stack. */
SEC("tc")
int throw_callee_restores_irq(struct __sk_buff *ctx)
{
	unsigned long flags;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(&flags);
	mark_acquired(f);
	bpf_local_irq_save(&flags);
	restore_and_throw(&flags);
	bpf_obj_drop(f);
	return 0;
}

/* Creates an iterator in its caller's stack, then throws with it live. */
static __noinline int new_and_throw(struct bpf_iter_num *it)
{
	bpf_iter_num_new(it, 0, 10);
	mark_acquired(it);
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The iterator is the callee's, which created it, but lives in the caller's
 * stack: the callee lists it through the pointer it holds and the caller does
 * not list it at the call, so it is destroyed once.
 */
SEC("tc")
int throw_iter_by_callee(struct __sk_buff *ctx)
{
	struct bpf_iter_num it;

	new_and_throw(&it);
	bpf_iter_num_destroy(&it);
	return 0;
}

/* The node first, so that the pointer to it is the pointer to the object. */
struct lfoo {
	struct bpf_list_node node;
	int data;
};

struct locked_list {
	struct bpf_spin_lock lock;
	struct bpf_list_head head __contains(lfoo, node);
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct locked_list);
	__uint(max_entries, 1);
} locked_list_map SEC(".maps");

/* Pops a node under its caller's lock, and throws holding it. */
static __noinline struct bpf_list_node *pop_and_throw(struct locked_list *l)
{
	struct bpf_list_node *n = bpf_list_pop_front(&l->head);

	if (n)
		mark_acquired(n);
	bpf_throw(0xeB9F);
	return n;
}

/*
 * The callee's node was popped under the lock its caller holds. Locks are
 * released before objects, whichever frame holds them: the unwinder unlocks
 * the caller's lock, then drops the node.
 */
SEC("tc")
int throw_obj_after_caller_lock(struct __sk_buff *ctx)
{
	struct bpf_list_node *n;
	struct locked_list *l;
	struct lfoo *f;
	int key = 0;

	l = bpf_map_lookup_elem(&locked_list_map, &key);
	if (!l)
		return 1;
	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(&l->lock);
	bpf_spin_lock(&l->lock);
	bpf_list_push_back(&l->head, &f->node);
	n = pop_and_throw(l);
	if (n)
		bpf_list_push_back(&l->head, n);
	bpf_spin_unlock(&l->lock);
	return 0;
}

/*
 * The stack in arena. A program that uses r12 takes one when it starts, the
 * stack of the cpu when that is free, and gives it back at its exit, which a
 * throw never reaches: the unwinder returns it. The programs record the
 * address of their frame, which is the same every time the stack of the cpu
 * is taken, and the test runs them twice on one cpu and compares. No compiler
 * emits r12 yet: these are the raw words of r12 += N, the first insn of a
 * function with a frame in arena, and of rX = r12, the address of the frame
 * as user space sees it.
 */
#define arena_sp_adj(n)		".8byte 0xc07 | ((" #n ") << 32);"
#define arena_sp_mov(dst)	".8byte 0xc0bf | ((" #dst ") << 8);"

/* The address of the frame of the main program and of a callback, in each of two runs. */
__u64 stack_addr[2], cb_stack_addr[2];

/* r6 = r12, stored to @arr[param] */
#define record_arena_sp(arr)			\
	arena_sp_mov(6)				\
	"r1 = %[" #arr "] ll;"			\
	"r2 = %[param] ll;"			\
	"r2 = *(u32 *)(r2 + 0);"		\
	"r2 &= 1;"				\
	"r2 <<= 3;"				\
	"r1 += r2;"				\
	"*(u64 *)(r1 + 0) = r6;"

/* Throws with a frame in the stack in arena. */
SEC("tc")
__naked int throw_arena_stack(void)
{
	asm volatile (
	arena_sp_adj(32)
	record_arena_sp(stack_addr)
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm(bpf_throw),
	  __imm_addr(stack_addr),
	  __imm_addr(param)
	: __clobber_all);
}

/* Has a frame in arena on top of its caller's, and records its address. */
static __naked __noinline __used long record_arena_frame(void)
{
	asm volatile (
	arena_sp_adj(32)
	record_arena_sp(cb_stack_addr)
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(cb_stack_addr),
	  __imm_addr(param)
	: __clobber_all);
}

/*
 * An exception callback that calls a function with a frame in arena takes a
 * stack of its own: the stack of the cpu, which the unwinder returned for the
 * main program before running the callback, so the frame is at the main
 * program's address. The callback has no frame of its own: the compiler
 * knows no r12, and a naked function's parameter has no name in BTF.
 */
__noinline int exception_cb_arena_stack(u64 cookie)
{
	record_arena_frame();
	return cookie;
}

SEC("tc")
__exception_cb(exception_cb_arena_stack)
__naked int throw_arena_stack_exception_cb(void)
{
	asm volatile (
	arena_sp_adj(32)
	record_arena_sp(stack_addr)
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm(bpf_throw),
	  __imm_addr(stack_addr),
	  __imm_addr(param)
	: __clobber_all);
}

/* Enters an RCU read section and throws in it. */
static __noinline int rcu_and_throw(void)
{
	bpf_rcu_read_lock();
	bpf_throw(0xeB9F);
	bpf_rcu_read_unlock();
	return 0;
}

/*
 * The destructor of a kmem_cache iterator sleeps, and the callee throws in an
 * RCU read section: sections are left before objects are released, whichever
 * frame holds them, so the iterator is destroyed outside the section. Only a
 * sleepable program may create it: a syscall program.
 */
SEC("syscall")
int throw_sleeping_dtor_after_section(void *ctx)
{
	struct bpf_iter_kmem_cache it;

	bpf_iter_kmem_cache_new(&it);
	mark_acquired(&it);
	rcu_and_throw();
	bpf_iter_kmem_cache_destroy(&it);
	return 0;
}

/*
 * Drops the object when told to, then throws. Called with a constant from two
 * call sites, it runs under two chains of calls: under one it has released
 * the object at the throw, under the other its caller still holds it.
 */
static __noinline int drop_if_and_throw(struct foo *f, int drop)
{
	if (drop)
		bpf_obj_drop(f);
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The caller lists the object at the call the callee keeps it through, and
 * not at the call the callee drops it through: one release on either chain,
 * by the program or by the unwinder.
 */
SEC("tc")
int throw_release_if(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (param)
		drop_if_and_throw(f, 0);
	else
		drop_if_and_throw(f, 1);
	bpf_obj_drop(f);
	return 0;
}

/*
 * Two paths save the same two sets of IRQ flags in opposite orders and meet at
 * the throw, kept apart by the RCU read section one of them holds: the
 * unwinder restores the flags saved with interrupts disabled first and the
 * ones saved with them enabled last, whichever path ran.
 */
SEC("tc")
int throw_irq_order(struct __sk_buff *ctx)
{
	int order = param;
	unsigned long a, b;

	mark_acquired(&a);
	mark_acquired(&b);
	if (order) {
		bpf_local_irq_save(&a);
		bpf_local_irq_save(&b);
		bpf_rcu_read_lock();
	} else {
		bpf_local_irq_save(&b);
		bpf_local_irq_save(&a);
	}
	if (ctx->len)
		bpf_throw(0xeB9F);
	if (order) {
		bpf_rcu_read_unlock();
		bpf_local_irq_restore(&b);
		bpf_local_irq_restore(&a);
	} else {
		bpf_local_irq_restore(&a);
		bpf_local_irq_restore(&b);
	}
	return 0;
}

/*
 * Discards the record when the flag its caller keeps in its stack and the
 * test say so, then throws. Called from two call sites with the flag each way
 * and a record of their own each, it runs under two chains of calls: under
 * the one it may discard the record it lists it, from the register it arrived
 * in, since it holds it nowhere at the throw; under the other it never
 * releases it, and its caller lists it at the call.
 */
__used static __noinline int discard_if_told_and_throw(void *rec, const long *discard)
{
	if (*discard && (param & 2))
		bpf_ringbuf_discard(rec, 0);
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The register the callee lists its record from under the one chain holds
 * the other caller's record under the other chain, which that caller lists
 * at its call: the descriptor listing the register is for the one chain
 * alone, and each record is released once, by the program or by the
 * unwinder.
 */
SEC("tc")
__naked int throw_arrival_listed_by_one_chain(void)
{
	asm volatile (
	"r6 = %[param] ll;"
	"r6 = *(u32 *)(r6 + 0);"
	"r6 &= 1;"
	"if r6 == 0 goto 1f;"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 3f;"
	"r6 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r1 = 1;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = r6;"
	"r2 = r10;"
	"r2 += -8;"
	"call discard_if_told_and_throw;"
	"goto 2f;"
	"1: r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 3f;"
	"r6 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r1 = 0;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = r6;"
	"r2 = r10;"
	"r2 += -8;"
	"call discard_if_told_and_throw;"
	"2: r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"3: r0 = 0;"
	"exit;"
	:
	: __imm_addr(param),
	  __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard)
	: __clobber_all);
}

/*
 * Holds the record its caller passes in R1 when R3 is 0, or loads it from the
 * slot of the caller's stack R2 points at otherwise, has a callee discard it
 * when the test says so, and throws with the record in R6 on the one path and
 * a dead pointer on the other: the record is mirrored, from the register it
 * arrives in under the one chain and from the load under the other, and the
 * call whose callee discarded it clears the mirror of either chain.
 */
__naked __noinline __used
static long hold_or_load_then_throw(void)
{
	asm volatile (
	"r6 = r1;"
	"if r3 == 0 goto 1f;"
	"r6 = *(u64 *)(r2 + 0);"
	"1: r7 = %[param] ll;"
	"r7 = *(u32 *)(r7 + 0);"
	"r7 &= 1;"
	"if r7 == 0 goto 2f;"
	"r1 = r6;"
	"r2 = 1;"
	"call discard_maybe;"
	"2: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm_addr(param),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The record is passed in R1, or through the slot of the caller's stack that
 * holds it, as the test says; the pointer to the slot keeps the callee in the
 * context of its caller either way.
 */
SEC("tc")
__naked int throw_mirror_arrives_two_ways(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"*(u64 *)(r10 - 8) = r6;"
	"r7 = %[param] ll;"
	"r7 = *(u32 *)(r7 + 0);"
	"r7 &= 2;"
	"if r7 == 0 goto 1f;"
	"r1 = 0;"
	"r2 = r10;"
	"r2 += -8;"
	"r3 = 1;"
	"call hold_or_load_then_throw;"
	"goto 2f;"
	"1: r1 = r6;"
	"r2 = r10;"
	"r2 += -8;"
	"r3 = 0;"
	"call hold_or_load_then_throw;"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(param),
	  __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve)
	: __clobber_all);
}

/*
 * Allocates, recurses while holding, and throws in the innermost frame: every
 * frame of the subprog owns an object obtained at the same instruction, and
 * its state holds the objects of the frames below, obtained there too.
 */
static __noinline int alloc_recurse_throw(int n)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	mark_acquired(f);
	if (n)
		alloc_recurse_throw(n - 1);
	else
		bpf_throw(0xeB9F);
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int throw_recursion_holding(struct __sk_buff *ctx)
{
	return alloc_recurse_throw(3);
}

char _license[] SEC("license") = "GPL";
