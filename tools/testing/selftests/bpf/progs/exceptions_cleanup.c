// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf_arena_common.h>

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

void *arena_ptr;

private(A) struct bpf_spin_lock glock;
private(B) struct bpf_res_spin_lock grlock;

/* Resources the program under test acquired, in order. */
__u64 acquired[MAX_RES];
__u32 acquired_cnt;
/* The releases observed, in order: the handle of the resource, or none for a section. */
__u64 released[MAX_RES];
__u8 released_section[MAX_RES];
__u32 released_cnt;
/* Objects allocated, dropped by the program and released by the unwinder, where the handles are not kept. */
__u32 alloc_cnt;
__u32 drop_cnt;
__u32 released_objs;
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
	if (res->kind == BPF_RESOURCE_OBJ && bpf_get_current_pid_tgid() >> 32 == test_pid)
		released_objs++;
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
/* Zero, which the verifier does not know: a bpf_loop() with these flags is not inlined. */
volatile __u32 loop_flags;

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

/* Spin until the timed may_goto gives up: cancels the program, or exits the loop. */
static __always_inline void spin(void)
{
	for (;;)
		cond_break;
}

/* A may_goto timeout cancels the program and releases what it holds. */
SEC("tc")
int cancel_may_goto_obj(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	spin();
	bpf_obj_drop(f);
	return 0;
}

static __noinline int spin_in_subprog(struct __sk_buff *ctx)
{
	__u64 a = ctx->len * 3, b = ctx->len * 5, c = ctx->len * 7;

	spin();
	return a + b + c;
}

/* The timeout hits in a static subprog while the caller holds the object. */
SEC("tc")
int cancel_may_goto_caller(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	spin_in_subprog(ctx);
	bpf_obj_drop(f);
	return 0;
}

static int spin_cb(u32 i, void *ctx)
{
	spin();
	return 0;
}

/*
 * The timeout hits in a bpf_loop() callback. With flags known to be zero
 * the loop is inlined and the callback is an ordinary callee: the frame is
 * unwound through at the inlined call.
 */
SEC("tc")
int cancel_may_goto_loop(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_loop(1, spin_cb, NULL, 0);
	bpf_obj_drop(f);
	return 0;
}

/*
 * The callback runs from the helper, which the flags the verifier cannot
 * see keep from being inlined: it is unwound and leaves into the pad of the
 * helper, which returns to the entry of the cancellation, and the
 * cancellation goes on from the call.
 */
SEC("tc")
int cancel_may_goto_loop_helper(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_loop(loops, spin_cb, NULL, loop_flags);
	bpf_obj_drop(f);
	return 0;
}

/* An RCU read section is left before the object is released. */
SEC("tc")
int cancel_may_goto_rcu(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_rcu_read_lock();
	spin();
	bpf_rcu_read_unlock();
	bpf_obj_drop(f);
	return 0;
}

/*
 * The frame the timeout hits in is reached both inside and outside an RCU
 * section: the section belongs to the caller that entered it, so the callee's
 * descriptor is the same on both paths. At run time the loop runs under RCU.
 */
SEC("tc")
int cancel_may_goto_rcu_shared(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (ctx->len == 0)
		spin_in_subprog(ctx);
	bpf_rcu_read_lock();
	spin_in_subprog(ctx);
	bpf_rcu_read_unlock();
	bpf_obj_drop(f);
	return 0;
}

/* Nested RCU sections and a preemption disabled section are all left. */
SEC("tc")
int cancel_may_goto_preempt(struct __sk_buff *ctx)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_lock();
	bpf_preempt_disable();
	spin();
	bpf_preempt_enable();
	bpf_rcu_read_unlock();
	bpf_rcu_read_unlock();
	return 0;
}

/* A global spin lock is released from its fixed address, before the object. */
SEC("tc")
int cancel_may_goto_spin_lock(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	mark_acquired(&glock);
	bpf_spin_lock(&glock);
	spin();
	bpf_spin_unlock(&glock);
	bpf_obj_drop(f);
	return 0;
}

/* The lock of an allocated object is found from the pointer to the object. */
SEC("tc")
int cancel_may_goto_obj_lock(struct __sk_buff *ctx)
{
	struct locked_foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	mark_acquired(&f->lock);
	bpf_spin_lock(&f->lock);
	spin();
	bpf_spin_unlock(&f->lock);
	bpf_obj_drop(f);
	return 0;
}

/* The lock is held by the caller of the frame the timeout hits in. */
SEC("tc")
int cancel_may_goto_lock_caller(struct __sk_buff *ctx)
{
	struct locked_foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	mark_acquired(&f->lock);
	bpf_spin_lock(&f->lock);
	spin_in_subprog(ctx);
	bpf_spin_unlock(&f->lock);
	bpf_obj_drop(f);
	return 0;
}

/* A resilient spin lock. */
SEC("tc")
int cancel_may_goto_res_lock(struct __sk_buff *ctx)
{
	mark_acquired(&grlock);
	if (bpf_res_spin_lock(&grlock))
		return 1;
	spin();
	bpf_res_spin_unlock(&grlock);
	return 0;
}

/* A resilient spin lock with IRQs disabled: the flags on the stack are restored with it. */
SEC("tc")
int cancel_may_goto_res_lock_irq(struct __sk_buff *ctx)
{
	unsigned long flags;

	/* The verifier tracks the lock first, then the flags it saved. */
	mark_acquired(&grlock);
	mark_acquired(&flags);
	if (bpf_res_spin_lock_irqsave(&grlock, &flags))
		return 1;
	spin();
	bpf_res_spin_unlock_irqrestore(&grlock, &flags);
	return 0;
}

/* Saved IRQ flags. */
SEC("tc")
int cancel_may_goto_irq(struct __sk_buff *ctx)
{
	unsigned long flags;

	mark_acquired(&flags);
	bpf_local_irq_save(&flags);
	spin();
	bpf_local_irq_restore(&flags);
	return 0;
}

static __noinline int spin_with_irqs_off(void)
{
	unsigned long flags;

	mark_acquired(&flags);
	bpf_local_irq_save(&flags);
	spin();
	bpf_local_irq_restore(&flags);
	return 0;
}

/*
 * The frame the timeout hits in saves IRQ flags of its own, and is reached
 * both under flags its caller saved and under none: each frame restores the
 * flags it saved, so the callee's descriptor is the same on both paths. At
 * run time the caller's flags are saved too, and restored after the callee's.
 */
SEC("tc")
int cancel_may_goto_irq_shared(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (ctx->len == 0)
		spin_with_irqs_off();
	mark_acquired(&flags);
	bpf_local_irq_save(&flags);
	spin_with_irqs_off();
	bpf_local_irq_restore(&flags);
	return 0;
}

/* Everything nested: released in the reverse order of acquisition. */
SEC("tc")
int cancel_may_goto_nested(struct __sk_buff *ctx)
{
	unsigned long flags, lflags;
	struct locked_foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_rcu_read_lock();
	mark_acquired(&flags);
	bpf_local_irq_save(&flags);
	mark_acquired(&grlock);
	mark_acquired(&lflags);
	if (bpf_res_spin_lock_irqsave(&grlock, &lflags)) {
		bpf_local_irq_restore(&flags);
		bpf_rcu_read_unlock();
		bpf_obj_drop(f);
		return 1;
	}
	spin();
	bpf_res_spin_unlock_irqrestore(&grlock, &lflags);
	bpf_local_irq_restore(&flags);
	bpf_rcu_read_unlock();
	bpf_obj_drop(f);
	return 0;
}

/* may_goto +2: BPF_JMP | BPF_JCOND, off 2 */
static const struct bpf_insn may_goto_insn = { .code = 0xe5, .off = 2 };

/*
 * R6 holds the ringbuf record on one path and a number on the other at the
 * site: no location describes both, so the record is released from its
 * mirror, a hidden slot of the frame, which the acquisition fills and the
 * release clears.
 */
/*
 * With guarded entries the record is not mirrored here after all: R7, which
 * the program keeps to know whether it holds the record, tells the paths
 * apart, and the entry for R6 is guarded by it. The same goes for
 * throw_mirror_shared_release and throw_mirror_arrives_two_ways; the mirror
 * tests that stay are the ones no scalar tells, the record read by nothing,
 * the lock at two locations, the IRQ flags saved in two orders, the
 * refcounted object, the refresh after a call and the pad before one.
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
	  [len]"i"(offsetof(struct __sk_buff, len)),			\
	  __imm_insn(may_goto, may_goto_insn)				\
	: __clobber_all);						\
}

/* A may_goto timeout: the loop spins until it is cancelled. */
MIRROR_PROG(cancel_may_goto_mirror_conflict, ".8byte %[may_goto]; r0 = 0; goto 2b;")
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

/* An address the arena has no page for: an access to it faults. */
static __always_inline int __arena *unmapped_arena_addr(void)
{
	arena_ptr = &arena;
	return (int __arena *)0xdeadbee0;
}

/* Keep the access to @addr behind everything before it, so that the fault is not hoisted. */
#define access_barrier(addr) asm volatile("" : "+r"(addr) : : "memory")

/* An arena page fault cancels the program and releases what it holds. */
SEC("tc")
int cancel_arena_read(struct __sk_buff *ctx)
{
	int __arena *addr = unmapped_arena_addr();
	struct foo *f;
	int v;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	access_barrier(addr);
	v = *addr;
	bpf_obj_drop(f);
	return v;
}

SEC("tc")
int cancel_arena_write(struct __sk_buff *ctx)
{
	int __arena *addr = unmapped_arena_addr();
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	access_barrier(addr);
	*addr = 1;
	bpf_obj_drop(f);
	return 0;
}

static __noinline int fault_in_subprog(struct __sk_buff *ctx)
{
	int __arena *addr = unmapped_arena_addr();
	__u64 a = ctx->len * 3, b = ctx->len * 5, c = ctx->len * 7;

	access_barrier(addr);
	*addr = 1;
	return a + b + c;
}

/* The fault hits in a static subprog while the caller holds the object. */
SEC("tc")
int cancel_arena_caller(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	fault_in_subprog(ctx);
	bpf_obj_drop(f);
	return 0;
}

/*
 * The object is only in R0 at a fetching atomic. The x86 lowering keeps R0
 * aside while RAX serves its CMPXCHG loop, so the fault handler has to put it
 * back before the register file is captured.
 */
SEC("tc")
int cancel_arena_fetch_r0(struct __sk_buff *ctx)
{
	static const struct bpf_insn fetch_or_insn = {
		.code	 = 0xc3,	/* BPF_STX | BPF_ATOMIC | BPF_W */
		.dst_reg = 1,		/* BPF_REG_1 */
		.src_reg = 2,		/* BPF_REG_2 */
		.off	 = 0,
		.imm	 = 0x41,	/* BPF_OR | BPF_FETCH */
	};
	int __arena *addr = unmapped_arena_addr();
	struct foo *f, *g;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	asm volatile (
		"r0 = %[f];"
		"r1 = %[addr];"
		"r1 = addr_space_cast(r1, 0x0, 0x1);"
		"r2 = 1;"
		".8byte %[fetch_or_insn];" /* r2 = atomic_fetch_or((u32 *)(r1 + 0), r2) */
		"%[g] = r0;"
		: [g] "=r" (g)
		: [f] "r" (f), [addr] "r" (addr),
		  __imm_insn(fetch_or_insn, fetch_or_insn)
		: "r0", "r1", "r2", "memory"
	);
	bpf_obj_drop(g);
	return 0;
}

static int fault_cb(u32 i, void *ctx)
{
	int __arena *addr = unmapped_arena_addr();

	access_barrier(addr);
	*addr = 1;
	return 0;
}

/* The fault hits in an inlined bpf_loop() callback, and in one the helper runs. */
SEC("tc")
int cancel_arena_loop(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_loop(1, fault_cb, NULL, 0);
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int cancel_arena_loop_helper(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_loop(loops, fault_cb, NULL, loop_flags);
	bpf_obj_drop(f);
	return 0;
}

__noinline int global_spin(void)
{
	spin();
	return 0;
}

/*
 * The timeout hits in a global subprog, which is verified on its own: the
 * call is a site of the caller, which holds the object.
 */
SEC("tc")
int cancel_may_goto_global(struct __sk_buff *ctx)
{
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	ret = global_spin();
	bpf_obj_drop(f);
	return ret;
}

__noinline int global_spin_in_subprog(struct __sk_buff *ctx)
{
	return spin_in_subprog(ctx);
}

/* The timeout hits in a static subprog of a global subprog. */
SEC("tc")
int cancel_may_goto_global_chain(struct __sk_buff *ctx)
{
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	ret = global_spin_in_subprog(ctx);
	bpf_obj_drop(f);
	return ret;
}

static int global_spin_cb(u32 i, void *ctx)
{
	return global_spin();
}

/* A global subprog called below a callback is cancelled like one called directly. */
SEC("tc")
int cancel_may_goto_global_callback(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_loop(1, global_spin_cb, NULL, 0);
	bpf_obj_drop(f);
	return 0;
}

static __noinline int spin_shared(void)
{
	spin();
	return 0;
}

static int spin_shared_cb(u32 i, void *ctx)
{
	return spin_shared();
}

/*
 * A static subprog reached below a callback as well as directly is cancelled
 * at either: the loop in the callback cancels the program.
 */
SEC("tc")
int cancel_may_goto_shared_subprog(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_loop(1, spin_shared_cb, NULL, 0);
	spin_shared();
	bpf_obj_drop(f);
	return 0;
}

/*
 * A tracing program with 64 bytes of stack runs on a private stack: the
 * record is released from its spill slot in that frame.
 */
SEC("fentry/bpf_fentry_test1")
__naked int cancel_may_goto_priv_stack(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"*(u64 *)(r10 - 8) = r0;"
	"*(u64 *)(r10 - 64) = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"2: .8byte %[may_goto];"
	"r0 = 0;"
	"goto 2b;"
	"r1 = *(u64 *)(r10 - 8);"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard),
	  __imm_insn(may_goto, may_goto_insn)
	: __clobber_all);
}

__noinline int global_fault(void)
{
	int __arena *addr = unmapped_arena_addr();

	access_barrier(addr);
	return *addr;
}

/* The fault hits in a global subprog while the caller holds the object. */
SEC("tc")
int cancel_arena_global(struct __sk_buff *ctx)
{
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	ret = global_fault();
	bpf_obj_drop(f);
	return ret;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, __u64);
	__uint(max_entries, 1);
} array_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, __u64);
	__uint(max_entries, 1);
} hash_map SEC(".maps");

static int spin_elem_cb(void *map, int *key, __u64 *val, void *ctx)
{
	spin();
	return 0;
}

/*
 * The timeout hits in the callback of bpf_for_each_map_elem(): the iterator of
 * the map leaves to its pad.
 */
SEC("tc")
int cancel_may_goto_for_each_array(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_for_each_map_elem(&array_map, spin_elem_cb, NULL, 0);
	bpf_obj_drop(f);
	return 0;
}

/* The hash map walk holds the RCU read lock around the callback, which the helper leaves on its way out. */
SEC("tc")
int cancel_may_goto_for_each_hash(struct __sk_buff *ctx)
{
	struct foo *f;
	__u64 val = 1;
	int key = 0;

	if (bpf_map_update_elem(&hash_map, &key, &val, BPF_ANY))
		return 1;
	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_for_each_map_elem(&hash_map, spin_elem_cb, NULL, 0);
	bpf_obj_drop(f);
	return 0;
}

/*
 * Two maps at one call keep the verifier from calling the iterator of the map
 * directly: the helper calls it, with a pad of its own, and the cancellation
 * goes through both pads.
 */
SEC("tc")
int cancel_may_goto_for_each_helper(struct __sk_buff *ctx)
{
	void *map = ctx->len > 1000 ? (void *)&hash_map : (void *)&array_map;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_for_each_map_elem(map, spin_elem_cb, NULL, 0);
	bpf_obj_drop(f);
	return 0;
}

struct rb_foo {
	int data;
	struct bpf_rb_node node;
};

private(C) struct bpf_spin_lock rblock;
private(C) struct bpf_rb_root rbtree __contains(rb_foo, node);

static bool rbless(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	return true;
}

static bool rbless_spin(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	spin();
	return true;
}

/*
 * Observe the drop of the node bpf_rbtree_add() was adding when its comparator
 * is cancelled: the kfunc drops it on its way to the pad after the call, not
 * the unwinder, and frees the fields of the node first. Attached by that test
 * alone, see run_prog().
 */
SEC("?fentry/bpf_obj_free_fields")
int BPF_PROG(drop_hook, const struct btf_record *rec, void *obj)
{
	mark_released(obj, false);
	return 0;
}

/*
 * The comparator of bpf_rbtree_add() is cancelled: the kfunc drops the node it
 * was adding and leaves, and the unwinder releases the lock of the tree, which
 * the caller holds, as the cancellation goes on from the call. The comparator
 * runs against the node added first.
 */
SEC("tc")
int cancel_may_goto_rbtree_less(struct __sk_buff *ctx)
{
	struct rb_foo *f, *g;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	g = bpf_obj_new(typeof(*g));
	if (!g) {
		bpf_obj_drop(f);
		return 1;
	}
	mark_acquired(g);
	mark_acquired(&rblock);
	bpf_spin_lock(&rblock);
	bpf_rbtree_add(&rbtree, &f->node, rbless);
	bpf_rbtree_add(&rbtree, &g->node, rbless_spin);
	bpf_spin_unlock(&rblock);
	return 0;
}

/* An address mapped in the test process, set by the test. */
__u64 vma_addr;

static int spin_vma_cb(struct task_struct *task, struct vm_area_struct *vma, void *ctx)
{
	spin();
	return 0;
}

/*
 * bpf_find_vma() holds the mmap lock around its callback and releases it on
 * its way out. It is a tracing helper, which a syscall program may call
 * without the test run triggering the other tracing programs, and a tracing
 * program may not drop an object with a list node, so the resource is a
 * ringbuf record here.
 */
SEC("syscall")
int cancel_may_goto_find_vma(void *ctx)
{
	void *p;

	p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
	if (!p)
		return 0;
	mark_acquired(p);
	bpf_find_vma(bpf_get_current_task_btf(), vma_addr, spin_vma_cb, NULL, 0);
	bpf_ringbuf_discard(p, 0);
	return 0;
}

struct timer_elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct timer_elem);
	__uint(max_entries, 1);
} timer_map SEC(".maps");

static int spin_timer_cb(void *map, int *key, struct timer_elem *e)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	mark_acquired(f);
	spin();
	bpf_obj_drop(f);
	return 0;
}

/*
 * The timeout hits in a timer callback, an invocation of its own: the
 * callback is unwound and the timer code ignores what it returns.
 */
SEC("tc")
int cancel_may_goto_timer(struct __sk_buff *ctx)
{
	struct timer_elem *e;
	int key = 0;

	e = bpf_map_lookup_elem(&timer_map, &key);
	if (!e)
		return 1;
	if (bpf_timer_init(&e->t, &timer_map, 1 /* CLOCK_MONOTONIC */))
		return 1;
	if (bpf_timer_set_callback(&e->t, spin_timer_cb))
		return 1;
	if (bpf_timer_start(&e->t, 0, 0))
		return 1;
	return 0;
}

/*
 * The timeout hits in the exception callback of the program, which took the
 * main frame over: the program completes with the default of its type, as
 * the callback cannot run a second time.
 */
__noinline int exception_cb_spin(u64 cookie)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	spin();
	bpf_obj_drop(f);
	return 1;
}

SEC("tc")
__exception_cb(exception_cb_spin)
int cancel_may_goto_exception_cb(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

/*
 * The stack in arena of a cancelled program goes back like that of a program
 * that throws, see throw_arena_stack(): a timed may_goto over the jump back
 * spins until the program is cancelled, as spin() does.
 */
#define arena_sp_spin				\
	"1:"					\
	".8byte 0x100e5;"			\
	"goto 1b;"

SEC("tc")
__naked int cancel_arena_stack(void)
{
	asm volatile (
	arena_sp_adj(32)
	record_arena_sp(stack_addr)
	arena_sp_spin
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(stack_addr),
	  __imm_addr(param)
	: __clobber_all);
}

/*
 * A callback the helper runs takes a stack of its own, one of the slots since
 * the main program holds the stack of the cpu, and is cancelled in it: the
 * unwinder returns the slot before the callback leaves into the pad of
 * bpf_loop(), and the stack of the main program when the cancellation goes
 * on from its call.
 */
static __naked __noinline __used long arena_stack_spin_cb(void)
{
	asm volatile (
	arena_sp_adj(32)
	record_arena_sp(cb_stack_addr)
	arena_sp_spin
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(cb_stack_addr),
	  __imm_addr(param)
	: __clobber_all);
}

SEC("tc")
__naked int cancel_arena_stack_callback(void)
{
	asm volatile (
	arena_sp_adj(32)
	record_arena_sp(stack_addr)
	"r1 = %[loops] ll;"
	"r1 = *(u32 *)(r1 + 0);"
	"r2 = arena_stack_spin_cb ll;"
	"r3 = 0;"
	"r4 = %[loop_flags] ll;"
	"r4 = *(u32 *)(r4 + 0);"
	"call %[bpf_loop];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_loop),
	  __imm_addr(loops),
	  __imm_addr(loop_flags),
	  __imm_addr(stack_addr),
	  __imm_addr(param)
	: __clobber_all);
}

/* Pops a node under its caller's lock, and spins holding it. */
static __noinline struct bpf_list_node *pop_and_spin(struct locked_list *l)
{
	struct bpf_list_node *n = bpf_list_pop_front(&l->head);

	if (n)
		mark_acquired(n);
	spin();
	return n;
}

/* The callee's node, popped under the caller's lock, is dropped after the lock is released. */
SEC("tc")
int cancel_may_goto_obj_after_caller_lock(struct __sk_buff *ctx)
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
	n = pop_and_spin(l);
	if (n)
		bpf_list_push_back(&l->head, n);
	bpf_spin_unlock(&l->lock);
	return 0;
}

/* Leaves the RCU read section its caller entered, then spins. */
static __noinline int rcu_unlock_and_spin(void)
{
	bpf_rcu_read_unlock();
	spin();
	return 0;
}

/*
 * The caller lists its RCU read section at the call, and the callee, which has
 * left it before the timeout, lists one section less: the unwinder leaves no
 * section.
 */
SEC("tc")
int cancel_may_goto_callee_leaves_rcu(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_rcu_read_lock();
	rcu_unlock_and_spin();
	bpf_obj_drop(f);
	return 0;
}

/* Unlocks the lock its caller holds, then spins. */
static __noinline int unlock_and_spin(struct locked_foo *f)
{
	bpf_spin_unlock(&f->lock);
	spin();
	return 0;
}

/*
 * The same for the lock of the caller's object, at a may_goto: the callee
 * lists the lock, which it has released, and the caller's descriptor at the
 * call omits it.
 */
SEC("tc")
int cancel_may_goto_callee_unlocks(struct __sk_buff *ctx)
{
	struct locked_foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	mark_acquired(&f->lock);
	bpf_spin_lock(&f->lock);
	unlock_and_spin(f);
	bpf_obj_drop(f);
	return 0;
}

/*
 * A loop the verifier cannot count gets a may_goto of its own, which cancels
 * the program when its time is up like a may_goto of the program does: the
 * object is released.
 */
SEC("tc")
int cancel_guard_obj(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	while (loops)
		;
	bpf_obj_drop(f);
	return 0;
}

/* R1 says how deep to go. It calls itself twice: 2^R1 calls, more than the time allows for 60. */
__naked __noinline __used
static unsigned long calls_itself_twice(void)
{
	asm volatile (
	"if r1 != 0 goto 1f;"
	"r0 = 1;"
	"exit;"
	"1: r6 = r1;"
	"r1 += -1;"
	"call calls_itself_twice;"
	"r7 = r0;"
	"r1 = r6;"
	"r1 += -1;"
	"call calls_itself_twice;"
	"r0 += r7;"
	"exit;"
	::: __clobber_all);
}

/*
 * A recursive subprog gets a check of its time and of the stack at its entry,
 * which cancels the program when its time is up like a may_goto does: the
 * record the caller holds is released.
 */
SEC("tc")
__naked int cancel_recursion_caller(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r6 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r1 = 60;"
	"call calls_itself_twice;"
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard)
	: __clobber_all);
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
 * Drops the object before the loop when told to, after it otherwise. Called
 * with a constant from two call sites, it runs under two chains of calls, and
 * holds the object at the may_goto under one of them only: the site gets a
 * descriptor per chain.
 */
static __noinline int drop_if_spin_drop(struct foo *f, int drop)
{
	if (drop)
		bpf_obj_drop(f);
	spin();
	if (!drop)
		bpf_obj_drop(f);
	return 0;
}

/* The callee releases the object under either chain: the caller lists it at neither call. */
SEC("tc")
int cancel_release_if_split(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (param)
		drop_if_spin_drop(f, 0);
	else
		drop_if_spin_drop(f, 1);
	return 0;
}

/* The same with the lock of the caller's object, which the callee unlocks before or after the loop. */
static __noinline int unlock_if_spin_unlock(struct locked_foo *f, int unlock)
{
	if (unlock)
		bpf_spin_unlock(&f->lock);
	spin();
	if (!unlock)
		bpf_spin_unlock(&f->lock);
	return 0;
}

SEC("tc")
int cancel_unlock_if_split(struct __sk_buff *ctx)
{
	struct locked_foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	mark_acquired(&f->lock);
	bpf_spin_lock(&f->lock);
	if (param)
		unlock_if_spin_unlock(f, 0);
	else
		unlock_if_spin_unlock(f, 1);
	bpf_obj_drop(f);
	return 0;
}

/*
 * Two paths save the same two sets of IRQ flags in opposite orders and meet at
 * the loop, kept apart by the RCU read section one of them holds.
 */
SEC("tc")
int cancel_irq_order(struct __sk_buff *ctx)
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
	spin();
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

/* Leaves the RCU read section its caller entered, and returns. */
static __noinline int rcu_unlock_and_return(void)
{
	bpf_rcu_read_unlock();
	return 0;
}

/* Enters an RCU read section, and returns holding it. */
static __noinline int rcu_lock_and_return(void)
{
	bpf_rcu_read_lock();
	return 0;
}

/* A loop that ends by itself: a site the program passes. */
static __always_inline void pass_a_site(void)
{
	int i;

	for (i = 0; i < 2 && can_loop; i++)
		;
}

/*
 * The section is entered at run time or not, so the frame counts its
 * sections in a hidden slot, and a callee leaves it: the count follows what
 * the callee did, and the unwinder leaves no section at the timeout.
 */
SEC("tc")
int cancel_section_left_by_callee(struct __sk_buff *ctx)
{
	int held = param;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (held)
		bpf_rcu_read_lock();
	pass_a_site();
	if (held)
		rcu_unlock_and_return();
	spin();
	bpf_obj_drop(f);
	return 0;
}

/* The same with a callee that enters the section and returns with it: the unwinder leaves it. */
SEC("tc")
int cancel_section_entered_by_callee(struct __sk_buff *ctx)
{
	int held = param;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (held)
		rcu_lock_and_return();
	pass_a_site();
	spin();
	if (held)
		bpf_rcu_read_unlock();
	bpf_obj_drop(f);
	return 0;
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

/* The same, with the innermost frame spinning until its time is up. */
static __noinline int alloc_recurse_spin(int n)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	mark_acquired(f);
	if (n)
		alloc_recurse_spin(n - 1);
	else
		spin();
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int cancel_recursion_holding(struct __sk_buff *ctx)
{
	return alloc_recurse_spin(3);
}

/*
 * Calls itself twice per level, holding an object per frame: 2^60 calls, more
 * than the time allows, so the check at the entry of the subprog cancels the
 * program at a depth the test does not know. Every object the frames hold is
 * released, see released_objs.
 */
static __noinline int alloc_and_call_twice(int n)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	alloc_cnt++;
	if (n) {
		alloc_and_call_twice(n - 1);
		alloc_and_call_twice(n - 1);
	}
	drop_cnt++;
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int cancel_recursion_check_holding(struct __sk_buff *ctx)
{
	return alloc_and_call_twice(60);
}

/* The object, in the stack of the frame that passes the struct to a callee. */
struct slot_ctx {
	struct foo *node;
};

/*
 * Stashes the caller's object, overwrites the slot it came from with a
 * number across the throw, and puts it back. The caller's descriptor at the
 * call cannot list the slot: the unwinder would release the number.
 */
static __noinline void clobber_slot_and_throw(struct slot_ctx *c)
{
	struct foo *f = c->node;

	c->node = (void *)(long)param;
	bpf_throw(0xeB9F);
	c->node = f;
}

/*
 * The caller keeps the object in the slot alone at the call, which the callee
 * writes: the object is released from its mirror, once, and nothing is
 * released from the slot.
 */
SEC("tc")
int throw_callee_clobbers_slot(struct __sk_buff *ctx)
{
	struct slot_ctx c;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	c.node = f;
	clobber_slot_and_throw(&c);
	bpf_obj_drop(c.node);
	return 0;
}

/* The same across the may_goto of a callback: the slot is a number while the callback spins. */
static int clobber_slot_cb(u32 i, struct slot_ctx *c)
{
	struct foo *f = c->node;

	c->node = (void *)(long)param;
	spin();
	c->node = f;
	return 0;
}

SEC("tc")
int cancel_callback_clobbers_slot(struct __sk_buff *ctx)
{
	struct slot_ctx c;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	c.node = f;
	bpf_loop(loops, clobber_slot_cb, &c, loop_flags);
	bpf_obj_drop(c.node);
	return 0;
}

/*
 * Guards: a callee, or the callback of a helper, releases the object on a
 * run-time condition, and the caller tests the condition afterwards to find
 * out. The paths that hold the object and the ones that do not differ in a
 * scalar of the frame, which the verifier found: the entry for the object is
 * guarded by it, and the unwinder releases the object only when the scalar
 * says it is there. Nothing is mirrored.
 */

/*
 * Drops the object when told to. The caller knows by the flag it keeps in its
 * stack, which the callee refines on each of its paths: the pointer makes
 * the verifier check the callee in the context of its caller, where the
 * refinement reaches the caller's slot.
 */
static __noinline void drop_if(struct foo *f, const __u64 *drop)
{
	if (*drop)
		bpf_obj_drop(f);
}

/*
 * The object is held at the throw when the flag is 0 and gone when it is 1,
 * in the register the caller keeps it in for the drop of its own, and the
 * flag is live at the throw: the entry for the object is guarded by the
 * flag.
 */
SEC("tc")
int throw_guard_drop_if(struct __sk_buff *ctx)
{
	__u64 flag = param;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	drop_if(f, &flag);
	if (flag > 1)
		return 2;
	if (!flag && ctx->len > 1000) {
		bpf_obj_drop(f);
		return 3;
	}
	bpf_throw(0xeB9F);
	return 0;
}

/* The same at the may_goto of a loop, after which the caller drops the object itself when it has it. */
SEC("tc")
int cancel_guard_drop_if(struct __sk_buff *ctx)
{
	__u64 flag = param;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	drop_if(f, &flag);
	spin();
	if (!flag)
		bpf_obj_drop(f);
	return 0;
}

/*
 * Holds the caller's object across the loop, dropped by the callee when told
 * to, with a copy of the flag in its own stack, linked to the caller's, and
 * drops it after the loop when the callee did not.
 */
static __noinline __u64 drop_if_and_spin(struct foo *f, const __u64 *drop)
{
	__u64 d = *drop;

	drop_if(f, &d);
	spin();
	if (!d)
		bpf_obj_drop(f);
	return d;
}

/*
 * The frame between the owner and the one that drops the object lists it at
 * the loop, guarded by its copy of the flag; the owner lists it at neither
 * call, since the callee chain releases it on every path.
 */
SEC("tc")
int cancel_guard_two_levels(struct __sk_buff *ctx)
{
	__u64 flag = param;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	drop_if_and_spin(f, &flag);
	return 0;
}

/* What a callback gets from its caller: the object and the flag that says whether it has gone. */
struct guard_ctx {
	struct foo *node;
	struct lfoo *lnode;
	__u64 done;
	__u64 drop;	/* the callback drops the object */
	__u64 spin_in_cb;	/* the callback spins; otherwise the caller spins after the loop */
};

static int guard_loop_cb(u32 i, struct guard_ctx *c)
{
	if (c->drop && !c->done) {
		bpf_obj_drop(c->node);
		c->done = 1;
	}
	if (c->spin_in_cb)
		spin();
	return 0;
}

/*
 * The callback drops the caller's object once and says so in a flag in the
 * caller's stack, the way a callback can release what its caller holds, and
 * the caller drops the object after the loop when the callback did not. The
 * caller lists the object at the call of the helper and at the loop after
 * it, guarded by the flag; the callback lists nothing of it. Cancelled in the
 * callback or after the loop, before or after the drop, the object is
 * released exactly once.
 */
SEC("tc")
int cancel_guard_loop_cb(struct __sk_buff *ctx)
{
	struct guard_ctx c = { .drop = param & 1, .spin_in_cb = param & 2 };
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	c.node = f;
	bpf_loop(loops, guard_loop_cb, &c, loop_flags);
	if (!c.spin_in_cb)
		spin();
	if (!c.done)
		bpf_obj_drop(c.node);
	return 0;
}

/* The same with the loop inlined: the callback is an ordinary callee then. */
SEC("tc")
int cancel_guard_loop_cb_inlined(struct __sk_buff *ctx)
{
	struct guard_ctx c = { .drop = param & 1, .spin_in_cb = param & 2 };
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	c.node = f;
	bpf_loop(1, guard_loop_cb, &c, 0);
	if (!c.spin_in_cb)
		spin();
	if (!c.done)
		bpf_obj_drop(c.node);
	return 0;
}

/* Pushes the caller's node into the list on the element the test names, once, under the list's lock. */
static int guard_push_cb(void *map, int *key, __u64 *val, struct guard_ctx *c)
{
	struct locked_list *l;
	int k = 0;

	if (c->drop && !c->done) {
		l = bpf_map_lookup_elem(&locked_list_map, &k);
		if (!l)
			return 1;
		bpf_spin_lock(&l->lock);
		bpf_list_push_back(&l->head, &c->lnode->node);
		bpf_spin_unlock(&l->lock);
		c->done = 1;
	}
	if (c->spin_in_cb)
		spin();
	return 0;
}

/*
 * The callback of bpf_for_each_map_elem() hands the caller's node to a list,
 * which releases it, and says so in the flag; the caller drops the node
 * after the walk when the callback did not.
 */
SEC("tc")
int cancel_guard_for_each_push(struct __sk_buff *ctx)
{
	struct guard_ctx c = { .drop = param & 1, .spin_in_cb = param & 2 };
	struct lfoo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	c.lnode = f;
	bpf_for_each_map_elem(&array_map, guard_push_cb, &c, 0);
	if (!c.spin_in_cb)
		spin();
	if (!c.done)
		bpf_obj_drop(c.lnode);
	return 0;
}

/* ---- what the frames hold at call depth two ---- */

/*
 * Throws holding the caller's record when told, and discards it otherwise.
 * The pointer argument keeps the callee in the context of its callers.
 */
static __noinline int discard_or_throw(void *rec, const long *flag)
{
	if (*flag)
		bpf_throw(0xeB9F);
	bpf_ringbuf_discard(rec, 0);
	return 0;
}

static __noinline int pass_down(void *rec, const long *flag)
{
	return discard_or_throw(rec, flag);
}

/*
 * main -> pass_down -> discard_or_throw, all in context: the record main owns
 * is listed by the frame that throws alone; the frame between passes it on.
 */
SEC("tc")
int throw_ringbuf_depth2(struct __sk_buff *ctx)
{
	long flag = param;
	void *rec;

	rec = bpf_ringbuf_reserve(&ringbuf, 8, 0);
	if (!rec)
		return 1;
	mark_acquired(rec);
	pass_down(rec, &flag);
	return 0;
}

/*
 * Reserves a record of its own and discards it before the throw when told,
 * after it otherwise: under a caller that says so by a constant, the throw
 * site holds the record under one chain and not under the other.
 */
__used static __noinline int reserve_and_throw(const long *flag, int drop)
{
	void *rec;

	rec = bpf_ringbuf_reserve(&ringbuf, 8, 0);
	if (!rec)
		return 1;
	mark_acquired(rec);
	if (drop)
		bpf_ringbuf_discard(rec, 0);
	if (*flag & 1)
		bpf_throw(0xeB9F);
	if (!drop)
		bpf_ringbuf_discard(rec, 0);
	return 0;
}

/* Two calls of reserve_and_throw() with a constant each, which clang would merge in C. */
__naked static __noinline int call_twice(const long *flag)
{
	asm volatile (
	"r6 = r1;"
	"r2 = *(u64 *)(r1 + 0);"
	"r2 &= 2;"
	"if r2 == 0 goto 1f;"
	"r1 = r6;"
	"r2 = 0;"
	"call reserve_and_throw;"
	"exit;"
	"1: r1 = r6;"
	"r2 = 1;"
	"call reserve_and_throw;"
	"exit;"
	:
	:
	: __clobber_all);
}

/*
 * The throw site at depth two keeps a descriptor per chain, which the
 * unwinder finds by the sites of the two frames below.
 */
SEC("tc")
int throw_ringbuf_depth2_split(struct __sk_buff *ctx)
{
	long flag = param;

	return call_twice(&flag);
}

/* Drops the object when the caller's stack says so, then throws. */
static __noinline int drop_told_and_throw(struct foo *f, const int *dp)
{
	if (*dp)
		bpf_obj_drop(f);
	bpf_throw(0xeB9F);
	return 0;
}

static __noinline long via_first(struct foo *f, const int *dp)
{
	return drop_told_and_throw(f, dp);
}

static __noinline long via_second(struct foo *f, const int *dp)
{
	return drop_told_and_throw(f, dp);
}

/*
 * Two frames between main and the throw, so that main has two call sites and
 * the throw site a chain for each, under which the object is held or not.
 */
SEC("tc")
int throw_obj_depth2_two_mids(struct __sk_buff *ctx)
{
	int d1 = 1, d0 = 0;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (param)
		return via_first(f, &d1) & 1;
	return via_second(f, &d0) & 1;
}

/* Throws holding the object, or drops it; verified on its own: no pointer into a caller's stack. */
static __noinline int drop_or_throw(struct foo *f, int drop)
{
	if (!drop)
		bpf_throw(0xeB9F);
	bpf_obj_drop(f);
	return 0;
}

/* Passes the object down and keeps it live across the call. */
static __noinline long middle_keeps(struct foo *f, int drop)
{
	long r = drop_or_throw(f, drop);

	return r ^ (long)f;
}

/*
 * main -> middle_keeps -> drop_or_throw, the callees verified on their own:
 * the release at the leaf is recorded at the root of the chains, and has to
 * reach the frame between and main through the calls.
 */
SEC("tc")
int throw_obj_depth2(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	return middle_keeps(f, param) & 1;
}

/* Drops the object when told, then throws: holding it or not, by the caller's constant. */
static __noinline int drop_told_then_throw(struct foo *f, int drop)
{
	if (drop)
		bpf_obj_drop(f);
	bpf_throw(0xeB9F);
	return 0;
}

static __noinline long middle_passes(struct foo *f, int drop)
{
	return drop_told_then_throw(f, drop);
}

/* The same with the leaf never returning: nothing is redone in context. */
SEC("tc")
int throw_obj_depth2_split(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (param)
		return middle_passes(f, 1) & 1;
	return middle_passes(f, 0) & 1;
}

/* ---- the lattice across paths of different stack depth ---- */

/*
 * A throw site visited first by a path that never allocated fp-16, then by
 * one that holds the record only there: the slot is not in the first path's
 * frame, and holds anything on it.
 */
SEC("tc")
__naked int throw_slot_unallocated(void)
{
	asm volatile (
	"r6 = %[param] ll;"
	"r6 = *(u32 *)(r6 + 0);"
	"if r6 == 0 goto 1f;"
	"2: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	"1: r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 3f;"
	"*(u64 *)(r10 - 16) = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"goto 2b;"
	"3: r0 = 0;"
	"exit;"
	:
	: __imm_addr(param),
	  __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* ---- what a call passes on some paths only ---- */

/* Discards what it is given, then throws when told. */
static __noinline int discard_then_throw(void *rec, const long *flag)
{
	bpf_ringbuf_discard(rec, 0);
	if (*flag & 1)
		bpf_throw(0xeB9F);
	return 0;
}

/*
 * One call site passes one of two records the caller holds, chosen at run
 * time: the caller has to list the record it did not pass.
 */
SEC("tc")
int throw_passed_some_paths(struct __sk_buff *ctx)
{
	long flag = param, sel = param & 2;
	void *a, *b;

	a = bpf_ringbuf_reserve(&ringbuf, 8, 0);
	if (!a)
		return 1;
	mark_acquired(a);
	b = bpf_ringbuf_reserve(&ringbuf, 8, 0);
	if (!b) {
		bpf_ringbuf_discard(a, 0);
		return 1;
	}
	mark_acquired(b);
	discard_then_throw(sel ? a : b, &flag);
	bpf_ringbuf_discard(sel ? b : a, 0);
	return 0;
}

/* ---- a reference that may be NULL at a site ---- */

static __noinline int throw_if_told(const long *flag)
{
	if (*flag & 1)
		bpf_throw(0xeB9F);
	return 0;
}

/*
 * A call between the acquisition and the NULL check: the task is listed at
 * the call, where it may be NULL, which the unwinder has to skip.
 */
SEC("tc")
int throw_task_maybe_null(struct __sk_buff *ctx)
{
	long flag = param;
	struct task_struct *t;

	t = bpf_task_from_pid(param & 2 ? test_pid : -1);
	mark_acquired(t);
	throw_if_told(&flag);
	if (!t)
		return 1;
	bpf_task_release(t);
	return 0;
}

/* ---- a mirror of a pointer into the object ---- */

private(D) struct bpf_spin_lock pop_lock;
private(D) struct bpf_list_head pop_head __contains(foo, node);

/* Pushes a fresh object into the list the pop below takes it from. */
__used static __noinline int push_one(void)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	mark_acquired(f);
	bpf_spin_lock(&pop_lock);
	bpf_list_push_front(&pop_head, &f->node);
	bpf_spin_unlock(&pop_lock);
	return 0;
}

/*
 * Pops a node, which points 8 bytes into its object, and keeps it in R6 on
 * one path and a number on the other, so that the throw releases it from the
 * mirror of the pop. With param the list is empty and the pop returns NULL,
 * which the mirror has to hold as NULL.
 */
SEC("tc")
__naked int throw_pop_null_mirror(void)
{
	asm volatile (
	"r1 = %[param] ll;"
	"r1 = *(u32 *)(r1 + 0);"
	"if r1 != 0 goto 1f;"
	"call push_one;"
	"1: r1 = %[pop_lock] ll;"
	"call %[bpf_spin_lock];"
	"r1 = %[pop_head] ll;"
	"call %[bpf_list_pop_front];"
	"r6 = r0;"
	"r1 = %[pop_lock] ll;"
	"call %[bpf_spin_unlock];"
	"if r6 != 0 goto 2f;"
	"r6 = 42;"
	"2: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm_addr(param),
	  __imm_addr(pop_lock),
	  __imm_addr(pop_head),
	  __imm(bpf_spin_lock),
	  __imm(bpf_spin_unlock),
	  __imm(bpf_list_pop_front),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* Drops the object the node belongs to when told, and hands the node back otherwise. */
__used static __noinline struct bpf_list_node *drop_told_or_return(struct bpf_list_node *n,
								   const long *flag)
{
	if (*flag) {
		bpf_obj_drop(container_of(n, struct foo, node));
		return NULL;
	}
	return n;
}

/*
 * The node arrives in R1, 8 bytes into the object. After the call that may
 * drop it, R6 holds the node or a number, so the throw releases it from the
 * mirror of the arrival, which R0 refreshes after the call.
 */
__naked static __noinline int node_mirror_and_throw(struct bpf_list_node *n, const long *flag)
{
	asm volatile (
	"call drop_told_or_return;"
	"if r0 != 0 goto 1f;"
	"r6 = 42;"
	"goto 2f;"
	"1: r6 = r0;"
	"2: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm(bpf_throw)
	: __clobber_all);
}

SEC("tc")
int throw_node_arrival_refresh(struct __sk_buff *ctx)
{
	long flag = param;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	node_mirror_and_throw(&f->node, &flag);
	return 0;
}

char _license[] SEC("license") = "GPL";
