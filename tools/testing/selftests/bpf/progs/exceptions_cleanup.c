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

private(A) struct bpf_spin_lock glock;
private(B) struct bpf_res_spin_lock grlock;

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
 * The timeout hits in a bpf_loop() callback. With a constant count the loop
 * is inlined and the callback is an ordinary callee: the frame is unwound
 * through at the inlined call.
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

/* A count the verifier does not know keeps bpf_loop() a helper call. */
volatile __u32 loops = 1;

/*
 * The callback runs from the helper: it is unwound and leaves into the pad of
 * the helper, which returns to the entry of the cancellation, and the
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
	bpf_loop(loops, spin_cb, NULL, 0);
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
 * The caller holds both objects at the call and lists them there, and the
 * callee drops one of them before it throws: it records the drop, and the
 * unwinder skips the caller's entry holding the dropped pointer.
 */
SEC("tc")
int throw_retract_obj(struct __sk_buff *ctx)
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
 * The caller holds the lock of its object at the call and lists it there,
 * and the callee unlocks it before it throws and records that: the unwinder
 * releases the object alone.
 */
SEC("tc")
int throw_retract_lock(struct __sk_buff *ctx)
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
 * The iterator lives in the caller's stack, which lists it at the call, and
 * the callee destroys it through the pointer before it throws and records
 * that: the unwinder releases the caller's object alone.
 */
SEC("tc")
int throw_retract_iter(struct __sk_buff *ctx)
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
int throw_retract_irq(struct __sk_buff *ctx)
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
 * The caller lists its RCU read section at the call, and the callee has left
 * it before the timeout and records that: the unwinder leaves no section.
 */
SEC("tc")
int cancel_may_goto_retract_rcu(struct __sk_buff *ctx)
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

/* The same for the lock of the caller's object, at a may_goto. */
SEC("tc")
int cancel_may_goto_retract_lock(struct __sk_buff *ctx)
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

char _license[] SEC("license") = "GPL";
