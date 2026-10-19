// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
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
SEC("fentry/bpf_fdesc_release")
int BPF_PROG(release_hook, struct bpf_fdesc_res *res, void *loc, void *flags)
{
	void *obj = loc;

	switch (res->kind) {
	case BPF_FDESC_RCU:
	case BPF_FDESC_PREEMPT:
		sections_cnt++;
		return 0;
	case BPF_FDESC_DYNPTR_RINGBUF:
	case BPF_FDESC_ITER:
	case BPF_FDESC_IRQ_FLAG:
	case BPF_FDESC_IRQ_FLAG_LOCK:
		break;
	case BPF_FDESC_SPIN_LOCK:
	case BPF_FDESC_RES_LOCK:
	case BPF_FDESC_RES_LOCK_IRQ:
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

/* In a callback the may_goto keeps exiting the loop: the program completes. */
SEC("tc")
int nocancel_may_goto_callback(struct __sk_buff *ctx)
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

/* A global subprog called below a callback keeps exiting its loop: the program completes. */
SEC("tc")
int nocancel_may_goto_global_callback(struct __sk_buff *ctx)
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
 * A static subprog reached below a callback as well as directly never
 * cancels: both of its loops exit and the program completes.
 */
SEC("tc")
int nocancel_may_goto_shared_subprog(struct __sk_buff *ctx)
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

static const struct bpf_insn may_goto_insn = { .code = 0xe5, .off = 2 };

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

struct locked_list {
	struct bpf_spin_lock lock;
	struct bpf_list_head head __contains(foo, node);
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct locked_list);
	__uint(max_entries, 1);
} locked_list_map SEC(".maps");

/* The node popped under the caller's lock is this frame's only resource: the lock is not. */
static __noinline struct bpf_list_node *pop_and_spin(struct locked_list *l)
{
	struct bpf_list_node *n = bpf_list_pop_front(&l->head);

	spin();
	return n;
}

/*
 * The callee holds an object while the caller holds the lock it was popped
 * under: a cancellation would drop the object under the lock, which no
 * program could do, so the site falls back and the loop exits.
 */
SEC("tc")
int nocancel_may_goto_obj_under_caller_lock(struct __sk_buff *ctx)
{
	struct bpf_list_node *n;
	struct locked_list *l;
	struct foo *f;
	int key = 0;

	l = bpf_map_lookup_elem(&locked_list_map, &key);
	if (!l)
		return 1;
	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_spin_lock(&l->lock);
	bpf_list_push_back(&l->head, &f->node);
	n = pop_and_spin(l);
	if (n)
		bpf_list_push_back(&l->head, n);
	bpf_spin_unlock(&l->lock);
	bpf_spin_lock(&l->lock);
	n = bpf_list_pop_front(&l->head);
	bpf_spin_unlock(&l->lock);
	if (n)
		bpf_obj_drop(container_of(n, struct foo, node));
	return 0;
}

char _license[] SEC("license") = "GPL";
