// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod.h"

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
 * Record a release: of @p, one of the resources the program acquired, or,
 * as a @section, of what the program has no handle of: a section of the test
 * process, or the reader of a file dynptr. The hooks fire for every unwind in
 * the system, so releases of other programs are left out.
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
int BPF_PROG(release_hook, struct bpf_resource *res, void *handle)
{
	mark_released(handle, res->kind == BPF_RESOURCE_RCU || res->kind == BPF_RESOURCE_PREEMPT ||
			      res->kind == BPF_RESOURCE_DYNPTR_FILE);
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

/*
 * The task the kernel passes a struct_ops program in a __ref argument is the
 * program's to release: the unwinder releases it when the program has not.
 */
SEC("struct_ops/test_refcounted")
int BPF_PROG(throw_ops_ref, int dummy, struct task_struct *task)
{
	mark_acquired(task);
	if (param)
		bpf_task_release(task);
	bpf_throw(0);
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops throwing_ops = {
	.test_refcounted = (void *)throw_ops_ref,
};

/* Set by the test before the open of a file that the program acts on. */
__u32 file_armed;

/*
 * The file is a referenced object, and the dynptr holds a reader of it that
 * the program has no handle of: the unwinder frees the reader, then puts the
 * file.
 */
SEC("lsm/file_open")
int BPF_PROG(throw_file_dynptr)
{
	struct bpf_dynptr dynptr;
	struct file *file;

	if (!file_armed || bpf_get_current_pid_tgid() >> 32 != test_pid)
		return 0;
	file_armed = 0;
	file = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!file)
		return 0;
	mark_acquired(file);
	bpf_dynptr_from_file(file, 0, &dynptr);
	if (param) {
		bpf_dynptr_file_discard(&dynptr);
		bpf_put_file(file);
	}
	bpf_throw(0);
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
 * one that does not: the object is in the slot of the caller's frame, which
 * the drop in the one callee clears, and the unwinder releases it from there
 * when the other one throws.
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

/* Allocates at its first insns: the call that acquires is at the start of the subprog. */
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
 * again after the call: the object is released from the slot of the caller's
 * frame, which the acquisition filled.
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
 * throw: the record is released from the hidden slot of the frame, which the
 * acquisition fills and the release clears, whatever R6 holds.
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
 * held it is overwritten: the program keeps the pointer nowhere at the throw,
 * and the record is released from the slot the acquisition filled.
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
 * path holding a record then moves to R9, leaving a number in R7: no
 * register holds the pointer on both paths to the throw. The lock is
 * released from the slot of the frame, which holds the address of the lock
 * since the call that took it, and the record after the lock.
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
 * one: the frame has a slot for each record, and the discard clears the slot
 * that holds the pointer it releases, whichever it is.
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
 * R6 holds the record on one path to the throw and a number on the other,
 * and a callee discards the record when the test says so, returning what it
 * leaves. The discard in the callee clears the slot of the caller's frame,
 * which holds the record, so that a discarded record is not released again.
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
 * Reserves a record and returns it when R1 is 0, handing the slot that holds
 * it over to its caller; unwinds otherwise, with 0, holding nothing.
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
 * The caller keeps the record the callee returns nowhere at the throw: the
 * callee handed the slot of the record over when it returned, and the
 * unwinder releases it from the caller's frame. The pad the callee unwinds
 * into lies in front of the call, where the unwind_goto after it jumps back.
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
 * of it, hold the same pointer, and the one the test chooses is dropped. Each
 * has a slot of the frame, and the two hold equal handles: the drop clears
 * one slot holding the pointer, whichever it is, and the unwinder drops the
 * object exactly once more.
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
 * before it throws: the drop clears the slot of the caller's frame that holds
 * it, and the unwinder releases the other alone.
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
 * it before it throws: the unlock clears the slot of the caller's frame that
 * holds the lock, and the unwinder releases the object alone.
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
 * the pointer before it throws: its address leaves the slot of the caller's
 * frame, and the unwinder releases the caller's object alone.
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
 * stack: its address is in a slot of the callee's frame, which ran the call
 * that created it, and in none of the caller's, so it is destroyed once.
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
 * Drops the object when told to, then throws. Its caller calls it twice, with
 * a constant each: through one call it has released the object at the throw,
 * through the other its caller still holds it.
 */
static __noinline int drop_if_and_throw(struct foo *f, int drop)
{
	if (drop)
		bpf_obj_drop(f);
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The object is in the slot of the caller's frame, which the drop in the
 * callee clears: one release through either call, by the program or by the
 * unwinder.
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
 * test say so, then throws. Two calls reach it, with the flag each way and a
 * record of their own each: through the one it may discard the record, which
 * it keeps nowhere at the throw; through the other it never releases it.
 */
__used static __noinline int discard_if_told_and_throw(void *rec, const long *discard)
{
	if (*discard && (param & 2))
		bpf_ringbuf_discard(rec, 0);
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * Either record arrives in the same register of the callee, and is in the
 * slot of the frame that reserved it through either call: the discard in the
 * callee clears that slot, and each record is released once, by the program
 * or by the unwinder.
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
 * a dead pointer on the other: the record is in the slot of the frame that
 * reserved it however it arrives, and the discard clears that slot.
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

/* A throw the verifier cannot rule out, which the tests always take. */
__u32 no_throw;

static __always_inline void throw_here(void)
{
	if (!no_throw)
		bpf_throw(0xeB9F);
}

/*
 * Drops its caller's object before the throw when told to, after it
 * otherwise: the object is in the caller's slot at the throw on the one path
 * only.
 */
static __noinline int drop_if_throw_drop(struct foo *f, int drop)
{
	if (drop)
		bpf_obj_drop(f);
	throw_here();
	if (!drop)
		bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int throw_release_if_split(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (param)
		drop_if_throw_drop(f, 0);
	else
		drop_if_throw_drop(f, 1);
	return 0;
}

/* The same with the lock of the caller's object, which the callee unlocks before or after the throw. */
static __noinline int unlock_if_throw_unlock(struct locked_foo *f, int unlock)
{
	if (unlock)
		bpf_spin_unlock(&f->lock);
	throw_here();
	if (!unlock)
		bpf_spin_unlock(&f->lock);
	return 0;
}

SEC("tc")
int throw_unlock_if_split(struct __sk_buff *ctx)
{
	struct locked_foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	mark_acquired(&f->lock);
	bpf_spin_lock(&f->lock);
	if (param)
		unlock_if_throw_unlock(f, 0);
	else
		unlock_if_throw_unlock(f, 1);
	bpf_obj_drop(f);
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

/*
 * The section is entered at run time or not, and a callee leaves it: the
 * callee hands its count of -1 to the caller when it returns, and the
 * unwinder leaves no section at the throw.
 */
SEC("tc")
int throw_section_left_by_callee(struct __sk_buff *ctx)
{
	int held = param;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (held)
		bpf_rcu_read_lock();
	if (held)
		rcu_unlock_and_return();
	throw_here();
	bpf_obj_drop(f);
	return 0;
}

/* The same with a callee that enters the section and returns with it: the unwinder leaves it. */
SEC("tc")
int throw_section_entered_by_callee(struct __sk_buff *ctx)
{
	int held = param;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (held)
		rcu_lock_and_return();
	throw_here();
	if (held)
		bpf_rcu_read_unlock();
	bpf_obj_drop(f);
	return 0;
}

/*
 * Allocates, recurses while holding, and throws in the innermost frame: every
 * frame of the subprog holds an object obtained at the same instruction, each
 * in the slot of its own frame.
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

/* The object, in the stack of the frame that passes the struct to a callee. */
struct slot_ctx {
	struct foo *node;
};

/*
 * Stashes the caller's object, overwrites the stack slot it came from with a
 * number across the throw, and puts it back: the caller's stack holds no
 * pointer to the object at the throw.
 */
static __noinline void clobber_slot_and_throw(struct slot_ctx *c)
{
	struct foo *f = c->node;

	c->node = (void *)(long)param;
	bpf_throw(0xeB9F);
	c->node = f;
}

/*
 * The caller keeps the object in the stack slot alone at the call, which the
 * callee writes: the object is released from the hidden slot of the caller's
 * frame, once, whatever the stack slot holds.
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
 * main -> pass_down -> discard_or_throw, all in context: the record is in the
 * slot of main, which the discard two frames above clears; the frame between
 * passes it on.
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
 * after it otherwise: its caller says so by a constant, and its frame holds
 * the record at the throw through one call and not through the other.
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
 * The throw is at depth two, reached through either call of the frame below:
 * the slot of the frame that throws holds the record or is empty.
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
 * Two subprogs between main and the throw, one for each call of main: through
 * one the object is dropped, which clears the slot of main, and through the
 * other main holds it at the throw.
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
 * the object the leaf drops is in no slot of its frame, and the drop clears
 * the slot of main, two frames below.
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

/* ---- a throw reached by paths of different stack depth ---- */

/*
 * A throw reached first by a path that never wrote fp-16, then by one that
 * keeps the record only there: the record is in the hidden slot of the frame
 * on the second path, and the slot is empty on the first.
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
 * One call passes one of two records the caller holds, chosen at run time:
 * the discard in the callee clears the slot of the record it was passed, and
 * the unwinder releases the other.
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

/* ---- a reference that may be NULL when a callee throws ---- */

static __noinline int throw_if_told(const long *flag)
{
	if (*flag & 1)
		bpf_throw(0xeB9F);
	return 0;
}

/*
 * A call that throws between the acquisition and the NULL check: a lookup
 * that returned NULL acquired nothing, and left the slot of the frame empty.
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

/* ---- a reference held as a pointer into the object ---- */

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
 * one path and a number on the other: the slot of the frame holds the object
 * the node is in, which the throw releases. With param the list is empty and
 * the pop returns NULL, which leaves the slot empty.
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
 * The node arrives in R1, 8 bytes into the object, which is in the slot of
 * the frame that allocated it. After the call that may drop the object,
 * which clears that slot, R6 holds the node or a number at the throw.
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

/* ---- what a frame releases of another frame's ---- */

/* With flags the verifier does not know, bpf_loop() stays a call of the helper. */
__u64 loop_flags;

/*
 * Drops the object when told to, and hands nothing back: only the flag in
 * the caller's stack tells the caller.
 */
static __noinline void drop_if(struct foo *f, const __u64 *drop)
{
	if (*drop)
		bpf_obj_drop(f);
}

/* The object is held at the throw when the flag is 0, and gone when it is 1. */
SEC("tc")
int throw_callee_drops_if(struct __sk_buff *ctx)
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

/* Unlocks the lock of a global, which no argument passes it, then throws. */
static __noinline void unlock_global_and_throw(void)
{
	bpf_spin_unlock(&glock);
	bpf_throw(0xeB9F);
}

/* The caller took the lock: nothing is left for the unwinder to unlock. */
SEC("tc")
int throw_callee_unlocks_global(struct __sk_buff *ctx)
{
	mark_acquired(&glock);
	bpf_spin_lock(&glock);
	if (ctx->len)
		unlock_global_and_throw();
	bpf_spin_unlock(&glock);
	return 0;
}

static int leave_rcu_and_throw(u32 i, void *ctx)
{
	bpf_rcu_read_unlock();
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The callback leaves the section its caller entered, then throws: the frame
 * that called the helper is in no section when the unwinding goes on from it.
 */
SEC("tc")
int throw_cb_leaves_rcu(struct __sk_buff *ctx)
{
	bpf_rcu_read_lock();
	bpf_loop(1, leave_rcu_and_throw, NULL, loop_flags);
	bpf_rcu_read_unlock();
	return 0;
}

struct held_ctx {
	struct foo *f;
};

static __noinline int drop_and_throw_cookie(struct foo *f)
{
	bpf_obj_drop(f);
	bpf_throw(0xeB9F);
	return 0;
}

static int drop_held_cb(u32 i, struct held_ctx *c)
{
	struct foo *f = c->f;

	drop_and_throw_cookie(f);
	return f->data;
}

/*
 * A subprog the callback calls drops the object of the frame that called
 * the helper, then throws: the object is not released again from that frame.
 */
SEC("tc")
int throw_cb_callee_drops(struct __sk_buff *ctx)
{
	struct held_ctx c;

	c.f = bpf_obj_new(typeof(*c.f));
	if (!c.f)
		return 1;
	mark_acquired(c.f);
	bpf_loop(1, drop_held_cb, &c, loop_flags);
	bpf_obj_drop(c.f);
	return 0;
}

/*
 * The record is spilled around a helper the JIT inlines, a spill the verifier
 * removes again, and sits in R6 at the throw: the unwinder takes it from the
 * slot its frame keeps it in, not from the program's stack.
 */
SEC("tc")
__naked int throw_fastcall_spill(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r1 = r0;"
	"*(u64 *)(r10 - 8) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 8);"
	"r6 = r1;"
	"r2 = %[acquired] ll;"
	"*(u64 *)(r2 + 0) = r6;"
	"r2 = %[acquired_cnt] ll;"
	"r3 = 1;"
	"*(u32 *)(r2 + 0) = r3;"
	"r2 = %[param] ll;"
	"r2 = *(u32 *)(r2 + 0);"
	"if r2 != 0 goto 1f;"
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
	  __imm(bpf_get_smp_processor_id),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* ---- throws inside callbacks ---- */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, __u64);
	__uint(max_entries, 2);
} elem_map SEC(".maps");

/* Returns from the first round and throws in the second, holding an object of its own. */
static int throw_in_round(u32 i, void *ctx)
{
	struct foo *g;

	g = bpf_obj_new(typeof(*g));
	if (!g)
		return 1;
	if (i == 1) {
		mark_acquired(g);
		bpf_throw(0xeB9F);
	}
	bpf_obj_drop(g);
	return 0;
}

/*
 * The callback of a helper throws: its frame is unwound, it leaves through
 * the pad of the helper, and the unwinding goes on from the call of the
 * helper with the cookie of the throw. The callback's object goes first.
 */
SEC("tc")
int throw_loop_cb(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_loop(3, throw_in_round, NULL, loop_flags);
	bpf_obj_drop(f);
	return 0;
}

/* The same with the loop inlined: the callback is an ordinary callee, and no helper is passed. */
SEC("tc")
int throw_loop_cb_inlined(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_loop(3, throw_in_round, NULL, 0);
	bpf_obj_drop(f);
	return 0;
}

static int throw_at_elem(void *map, int *key, __u64 *val, void *ctx)
{
	if (*key == 1)
		bpf_throw(0xeB9F);
	return 0;
}

/* The caller of the helper is in an RCU section and holds an object: the section goes first. */
SEC("tc")
int throw_for_each_cb(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_rcu_read_lock();
	bpf_for_each_map_elem(&elem_map, throw_at_elem, NULL, 0);
	bpf_rcu_read_unlock();
	bpf_obj_drop(f);
	return 0;
}

static int throw_holding(void *map, int *key, __u64 *val, void *ctx)
{
	struct foo *h;

	h = bpf_obj_new(typeof(*h));
	if (!h)
		return 1;
	mark_acquired(h);
	bpf_throw(0xeB9F);
	return 0;
}

static int for_each_holding(u32 i, void *ctx)
{
	struct foo *g;

	g = bpf_obj_new(typeof(*g));
	if (!g)
		return 1;
	mark_acquired(g);
	bpf_for_each_map_elem(&elem_map, throw_holding, NULL, 0);
	bpf_obj_drop(g);
	return 0;
}

/*
 * A callback of a helper runs a helper whose callback throws: the unwinding
 * passes two helpers, each through its pad, and every frame releases its own.
 */
SEC("tc")
int throw_nested_cb(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_loop(1, for_each_holding, NULL, loop_flags);
	bpf_obj_drop(f);
	return 0;
}

/* A subprog the callback calls throws, with a number in the cookie that the caller chose. */
static __noinline int throw_param(void)
{
	bpf_throw(0xeB00 + param);
	return 0;
}

static int call_thrower(u32 i, void *ctx)
{
	return throw_param();
}

SEC("tc")
int throw_cb_callee(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_loop(1, call_thrower, NULL, loop_flags);
	bpf_obj_drop(f);
	return 0;
}

/* Runs the callback it is handed: the address was taken a frame below. */
static __noinline int loop_with(void *cb)
{
	return bpf_loop(3, cb, NULL, loop_flags);
}

/*
 * The subprog that calls the helper did not take the address of the callback:
 * the throw is unwound through its frame all the same, into the frame that
 * did, which holds the object.
 */
SEC("tc")
int throw_cb_passed_down(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	loop_with(throw_in_round);
	bpf_obj_drop(f);
	return 0;
}

struct rb_foo {
	long key;
	struct bpf_rb_node node;
};

private(B) struct bpf_spin_lock rb_lock;
private(B) struct bpf_rb_root rb_root __contains(rb_foo, node);

static bool rb_first(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	return true;
}

static bool rb_throw(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	bpf_throw(0xeB9F);
	return true;
}

/*
 * The comparator of bpf_rbtree_add() throws under the lock of the tree: the
 * pad of the kfunc drops the node it was adding, and the caller's frame
 * releases the lock.
 */
SEC("tc")
int throw_rbtree_less(struct __sk_buff *ctx)
{
	struct rb_foo *a, *b;

	a = bpf_obj_new(typeof(*a));
	if (!a)
		return 1;
	b = bpf_obj_new(typeof(*b));
	if (!b) {
		bpf_obj_drop(a);
		return 1;
	}
	mark_acquired(&rb_lock);
	mark_acquired(b);
	bpf_spin_lock(&rb_lock);
	/* the first node meets no other: the comparator runs for the second */
	bpf_rbtree_add(&rb_root, &a->node, rb_first);
	bpf_rbtree_add(&rb_root, &b->node, rb_throw);
	bpf_spin_unlock(&rb_lock);
	return 0;
}

struct timer_elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct timer_elem);
	__uint(max_entries, 1);
} timer_map SEC(".maps");

/* Set by the callback of the timer before it throws, and after, which it never gets to. */
__u32 timer_ran;
__u32 timer_returned;

static int throw_in_timer(void *map, int *key, struct bpf_timer *timer)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	mark_acquired(f);
	timer_ran = 1;
	/* the cookie is what the callback returns to the timer code: 0, as from its exit */
	if (param)
		bpf_throw(0);
	timer_returned = 1;
	bpf_obj_drop(f);
	return 0;
}

/*
 * The callback of a timer throws: the kernel ran it on its own, so the
 * unwinding ends at the callback, which returns to the timer code.
 */
SEC("tc")
int arm_throwing_timer(struct __sk_buff *ctx)
{
	struct timer_elem *e;
	int key = 0;

	e = bpf_map_lookup_elem(&timer_map, &key);
	if (!e)
		return 1;
	bpf_timer_init(&e->timer, &timer_map, 1 /* CLOCK_MONOTONIC */);
	bpf_timer_set_callback(&e->timer, throw_in_timer);
	bpf_timer_start(&e->timer, 0, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
