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

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1); /* number of pages */
} arena SEC(".maps");

void *arena_ptr;

private(A) struct bpf_spin_lock glock;
private(B) struct bpf_res_spin_lock grlock;

/* Resources the program under test acquired, and those the unwinder released. */
__u64 acquired[MAX_RES];
__u32 acquired_cnt;
__u64 released[MAX_RES];
__u32 released_cnt;
/* RCU and preemption sections the unwinder left. */
__u32 sections_cnt;

static __always_inline void mark_acquired(void *p)
{
	__u32 i = acquired_cnt;

	if (i < MAX_RES) {
		acquired[i] = (__u64)p;
		acquired_cnt = i + 1;
	}
}

static __always_inline void mark_released(void *p)
{
	__u32 i, n = released_cnt;

	if (n >= MAX_RES)
		return;
	for (i = 0; i < MAX_RES; i++) {
		if (acquired[i] == (__u64)p) {
			released[n] = (__u64)p;
			released_cnt = n + 1;
			return;
		}
	}
}

/* Observe every release the unwinder performs, identified like the program sees it. */
SEC("fentry/bpf_unwind_release")
int BPF_PROG(release_hook, struct bpf_resource *res, void *loc, void *flags)
{
	void *obj = loc;

	switch (res->kind) {
	case BPF_RESOURCE_RCU:
	case BPF_RESOURCE_PREEMPT:
		sections_cnt++;
		return 0;
	case BPF_RESOURCE_DYNPTR_RINGBUF:
	case BPF_RESOURCE_ITER:
	case BPF_RESOURCE_IRQ_FLAG:
	case BPF_RESOURCE_IRQ_FLAG_LOCK:
		break;
	case BPF_RESOURCE_SPIN_LOCK:
	case BPF_RESOURCE_RES_LOCK:
	case BPF_RESOURCE_RES_LOCK_IRQ:
		if (!loc) {
			obj = res->addr;
			break;
		}
		bpf_probe_read_kernel(&obj, sizeof(obj), loc);
		obj += res->delta;
		break;
	default:
		bpf_probe_read_kernel(&obj, sizeof(obj), loc);
	}
	mark_released(obj);
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
 * is released from the unique slot of its acquisition.
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
 * site: no location describes both, so the record is released from a unique
 * slot of the frame, which the acquisition fills and the release clears.
 */
#define SLOT_PROG(name, site)						\
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
SLOT_PROG(cancel_may_goto_slot, ".8byte %[may_goto]; r0 = 0; goto 2b;")
/* An explicit throw. */
SLOT_PROG(throw_slot, "r1 = 0xeB9F; call %[bpf_throw];")

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
	bpf_loop(loops, fault_cb, NULL, 0);
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
 * record is released from a slot of that frame.
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
	mark_released(obj);
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

char _license[] SEC("license") = "GPL";
