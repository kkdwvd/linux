// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * A callback that a helper or a kfunc calls unwinds into a pad in the helper,
 * which leaves to the pad after the call of the helper. See verifier_unwind.c
 * for the insns. vmlinux.h, for the offsets the find_vma tests need, leaves no
 * BPF_RAW_INSN(), so here they are raw words: the code, src_reg = 1 in the
 * high nibble of the second byte, off in the next two bytes.
 */
#define unwind_goto(off) ".8byte ((" #off " & 0xffff) << 16) | 0x10e5;"	/* BPF_JMP | BPF_JCOND */
#define unwind_exit ".8byte 0x1095;"				/* BPF_JMP | BPF_EXIT */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} rhash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

struct node_data {
	long key;
	struct bpf_rb_node node;
};

struct node_ref {
	long key;
	struct bpf_rb_node node;
	struct bpf_refcount ref;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock glock;
private(A) struct bpf_rb_root groot __contains(node_data, node);
private(B) struct bpf_spin_lock rlock;
private(B) struct bpf_rb_root rroot __contains(node_ref, node);

/* A kptr whose destructor is not for NMI context */
struct node_task {
	long key;
	struct bpf_rb_node node;
	struct task_struct __kptr *task;
};

private(C) struct bpf_spin_lock tlock;
private(C) struct bpf_rb_root troot __contains(node_task, node);

/* A node with a list in it: its destructor takes the lock of the list */
struct elem {
	long key;
	struct bpf_list_node node;
};

struct node_list {
	long key;
	struct bpf_rb_node node;
	struct bpf_spin_lock lock;
	struct bpf_list_head head __contains(elem, node);
};

private(D) struct bpf_spin_lock llock;
private(D) struct bpf_rb_root lroot __contains(node_list, node);

/* No code has an elem: this puts it in BTF, for __contains() above */
void __elem_btf_root(struct elem *e)
{
}

/* How many times the callback ran */
__u64 runs;

/* What the verifier doesn't know: bpf_loop() is not inlined, a loop doesn't end */
volatile __u64 no_flags, forever = 1;

#define count_run()				\
	"r1 = %[runs] ll;"			\
	"r2 = *(u64 *)(r1 + 0);"		\
	"r2 += 1;"				\
	"*(u64 *)(r1 + 0) = r2;"

/* Unwinds with r0 = 5 on its first run */
__naked __noinline __used
static unsigned long cb_unwinds(void)
{
	asm volatile (
		count_run()
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(runs)
	);
}

/* Returns 0 twice, then unwinds */
__naked __noinline __used
static unsigned long cb_unwinds_third(void)
{
	asm volatile (
		count_run()
		"if r2 == 3 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(runs)
	);
}

/* Returns 0: the loop runs to its end */
__naked __noinline __used
static unsigned long cb_returns(void)
{
	asm volatile (
		count_run()
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(runs)
	);
}

__naked __noinline __used
static unsigned long always_unwinds(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
	);
}

/* What it calls unwinds. Its pad counts the run and unwinds on. */
__naked __noinline __used
static unsigned long cb_passes_on(void)
{
	asm volatile (
		"call always_unwinds;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		count_run()
		"r0 = 7;"
		unwind_exit
		:
		: __imm_addr(runs)
	);
}

/*
 * The pad after the call of the helper returns the number of runs plus what
 * the helper left in r0, which is what the callback unwound with, plus 41.
 */
#define PAD					\
	"r1 = %[runs] ll;"			\
	"r1 = *(u64 *)(r1 + 0);"		\
	"r0 += r1;"				\
	"r0 += 41;"				\
	"exit;"

/*
 * The loop is inlined, and so is its pad: unwind_goto after the call of the callback. The pad
 * brings back r6-r8: the loop counts in them.
 */
SEC("tc")
__description("unwind cb: the callback of bpf_loop unwinds on its first run")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(54)
__xlated("unwind_goto pc-15")
__naked int loop_cb_unwinds(void)
{
	asm volatile (
		"r6 = 1;"
		"r7 = 2;"
		"r8 = 4;"
		"r1 = 10;"
		"r2 = %[cb_unwinds] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r0 += r6;"
		"r0 += r7;"
		"r0 += r8;"
		PAD
		:
		: __imm_addr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_all
	);
}

/* Nothing is in the map. What follows the loop counts on its exit. */
static long cb_waits(u32 i, long *sum)
{
	int key = 0, *val;

	bpf_rcu_read_lock();
	do {
		val = bpf_map_lookup_elem(&hash, &key);
	} while (!val);
	*sum += *val;
	bpf_rcu_read_unlock();
	return 0;
}

/* The callback leaves its RCU section and unwinds, bpf_loop() leaves, the caller turns preemption on */
SEC("tc")
__description("unwind cb: a loop in the callback of bpf_loop is out of time")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(2)
int loop_in_cb(void *ctx)
{
	long sum = 7;

	bpf_preempt_disable();
	bpf_loop(2, cb_waits, &sum, no_flags);
	bpf_preempt_enable();
	return sum;
}

SEC("tc")
__description("unwind cb: the callback of bpf_loop unwinds on its third run")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(49)
__naked int loop_cb_unwinds_third(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_third];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_unwinds_third),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* unwind_goto after a helper whose callback returns: the pad is never taken */
SEC("tc")
__description("unwind cb: unwind_goto after bpf_loop whose callback returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3)
__naked int loop_cb_returns_pad(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_returns];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_returns),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: the exception goes through the pad of the callback")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(49)
__naked int loop_cb_passes_on(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_passes_on];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_passes_on),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* The verifier adds it, and the landing pad that ends the prog */
SEC("tc")
__description("unwind cb: no unwind_goto after bpf_loop whose callback unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
__naked int loop_cb_unwinds_no_pad(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Unwinds with a pointer in r0: the element of the array, with 6 in it */
__naked __noinline __used
static unsigned long cb_unwinds_with_ptr(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"r1 = %[array] ll;"
		"r2 = r10;"
		"r2 += -4;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 1f;"
		"r1 = 6;"
		"*(u32 *)(r0 + 0) = r1;"
		unwind_exit
	"1:"
		"exit;"
		:
		: __imm_addr(array),
		  __imm(bpf_map_lookup_elem)
		: __clobber_all
	);
}

/* The helper hands r0 on as it is: the pad reads through the pointer */
SEC("tc")
__description("unwind cb: the callback unwinds with a pointer in r0")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int loop_cb_unwinds_with_ptr(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_ptr];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r0 = *(u32 *)(r0 + 0);"
		"r0 += 41;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_ptr),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Unwinds with a pointer into its own stack */
__naked __noinline __used
static unsigned long cb_unwinds_with_fp(void)
{
	asm volatile (
		"r0 = r10;"
		"r0 += -8;"
		unwind_exit
	);
}

/* As after any return, the pointer is unreadable in the pad */
SEC("tc")
__description("unwind cb: the callback unwinds with a pointer into its stack")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("the caller cannot read the stack pointer in R0") __msg("R0 !read_ok")
__naked int loop_cb_unwinds_with_fp(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_fp];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_fp),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: the callback unwinds with a pointer into its stack, the pad doesn't read it")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int loop_cb_unwinds_with_fp_unread(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_fp];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_fp),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Unwinds with the key, which is in the frame of bpf_for_each_array_elem() */
__naked __noinline __used
static unsigned long cb_unwinds_with_key(void)
{
	asm volatile (
		"r0 = r2;"
		unwind_exit
	);
}

SEC("tc")
__description("unwind cb: the callback unwinds with a pointer into the frame of the helper")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("R0 invalid mem access 'scalar'")
__naked int for_each_cb_unwinds_with_key(void)
{
	asm volatile (
		"r1 = %[array] ll;"
		"r2 = %[cb_unwinds_with_key];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		unwind_goto(1)
		"exit;"
		"r0 = *(u32 *)(r0 + 0);"
		"exit;"
		:
		: __imm_addr(array),
		  __imm_ptr(cb_unwinds_with_key),
		  __imm(bpf_for_each_map_elem)
		: __clobber_common
	);
}

/* Its prototype returns two registers, but it unwinds with r0 alone */
struct pair {
	__u64 a;
	__u64 b;
};

__naked __noinline __used
static struct pair cb_unwinds_pair(void)
{
	asm volatile (
		count_run()
		"r0 = 5;"
		"r2 = 0;"
		unwind_exit
		:
		: __imm_addr(runs)
	);
}

/* r2 is the caller's at the revisit of the call: the callback, checked again */
SEC("tc")
__description("unwind cb: a callback that returns two registers unwinds with r0 alone")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int loop_cb_pair_unwinds(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_pair];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_unwinds_pair),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* The caller holds a constant in r0 at the call: the revisit brings another */
SEC("tc")
__description("unwind cb: the caller holds a constant in r0 at the call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int loop_cb_unwinds_r0_const(void)
{
	asm volatile (
		"r0 = 0;"
		"r1 = 10;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * The pad knows what the callback unwound with: 5, which cb_unwinds leaves in
 * r0, and reads the slot through it. An unknown r0 would be no offset for fp.
 */
SEC("tc")
__description("unwind cb: the pad knows what the callback unwound with")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(9)
__naked int loop_cb_r0_known(void)
{
	asm volatile (
		"r1 = 9;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = 10;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = r10;"
		"r1 += r0;"
		"r0 = *(u8 *)(r1 - 13);"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Allocates a node and unwinds with it: the reference comes back in r0 */
static __noinline long cb_unwinds_with_obj(u64 i, void *ctx)
{
	struct node_data *n = bpf_obj_new(typeof(*n));

	if (n)
		asm volatile ("r0 = %[n];" unwind_exit :: [n] "r"(n) : "r0");
	return 0;
}

/* The pad drops what came back */
SEC("tc")
__description("unwind cb: the callback unwinds with a reference, which the pad drops")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int loop_cb_obj_dropped(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_obj];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = r0;"
		"call %[bpf_obj_drop];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_obj),
		  __imm(bpf_loop),
		  __imm(bpf_obj_drop)
		: __clobber_common
	);
}

/* The pad may not leave without dropping it: the reference is the prog's now */
SEC("tc")
__description("unwind cb: the callback unwinds with a reference, which the pad leaks")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("Unreleased reference")
__naked int loop_cb_obj_leaked(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_obj];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_obj),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Unwinds with the index of the run, which the pad doesn't know */
__naked __noinline __used
static unsigned long cb_unwinds_with_index(void)
{
	asm volatile (
		"r0 = r1;"
		count_run()
		unwind_exit
		:
		: __imm_addr(runs)
	);
}

SEC("tc")
__description("unwind cb: the pad doesn't know the index the callback unwound with")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("math between fp pointer and register with unbounded min value is not allowed")
__naked int loop_cb_index_unknown(void)
{
	asm volatile (
		"r1 = 9;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_index];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = r10;"
		"r1 += r0;"
		"r0 = *(u8 *)(r1 - 13);"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_index),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Unwinds with r0 = 100, no offset for the slot */
__naked __noinline __used
static unsigned long cb_unwinds_100(void)
{
	asm volatile (
		"r0 = 100;"
		unwind_exit
	);
}

/*
 * Two callbacks on two paths into one call, unwinding with 5 and with 100. The
 * pad is checked with each: the second one puts the read out of the frame.
 */
SEC("tc")
__description("unwind cb: the pad is checked with what each callback unwound with")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("invalid read from stack")
__naked int loop_cbs_differ_pad_checked(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
		"r2 = %[cb_unwinds];"
		"if r6 == 64 goto 1f;"
		"r2 = %[cb_unwinds_100];"
	"1:"
		"r1 = 9;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = 10;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = r10;"
		"r1 += r0;"
		"r0 = *(u8 *)(r1 - 13);"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_ptr(cb_unwinds),
		  __imm_ptr(cb_unwinds_100),
		  __imm(bpf_loop)
		: __clobber_common, "r6"
	);
}

/* Unwinds with 8 on its first run, with 24 on the others, from one unwind_exit */
__naked __noinline __used
static unsigned long cb_unwinds_8_or_24(void)
{
	asm volatile (
		"r0 = 8;"
		"if r1 == 0 goto 1f;"
		"r0 = 24;"
	"1:"
		unwind_exit
	);
}

/*
 * The size of a record of the ring buffer has to be known, so the pad needs each
 * value that the callback unwinds with, also where the callback joins them: a
 * partition keeps them apart there.
 */
SEC("tc")
__description("unwind cb: the pad needs each value that the callback joins before it unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(8)
__naked int loop_cb_joins_pad_needs_each(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_8_or_24];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r6 = r0;"
		"r1 = %[ringbuf] ll;"
		"r2 = r0;"
		"r3 = 0;"
		"call %[bpf_ringbuf_reserve];"
		"if r0 == 0 goto 1f;"
		"r1 = r0;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard];"
	"1:"
		"r0 = r6;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_8_or_24),
		  __imm_addr(ringbuf),
		  __imm(bpf_loop),
		  __imm(bpf_ringbuf_reserve),
		  __imm(bpf_ringbuf_discard)
		: __clobber_common, "r6"
	);
}

/* A loop of one: the round that unwinds is the last the loop had */
SEC("tc")
__description("unwind cb: the callback of a loop of one unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int loop_once_cb_unwinds(void)
{
	asm volatile (
		"r1 = 1;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * The callback unwinds on the first of two rounds. The helper in the pad starts
 * its rounds afresh, so its callback is checked, and the verifier adds the
 * unwind_goto that its call has not.
 */
SEC("tc")
__description("unwind cb: a helper in the pad starts its rounds afresh")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
__naked int loop_cb_unwinds_then_loops(void)
{
	asm volatile (
		"r1 = 2;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = 1;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * The pad before the call: the inlined loop jumps back to it. Insn 13 is the
 * unwind_goto, insn 1 the pad: the callback is loaded in the asm, so that the
 * compiler puts nothing in front of it.
 */
SEC("tc")
__description("unwind cb: the pad before the call of the inlined bpf_loop")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__xlated("unwind_goto pc-15")
__naked int loop_cb_pad_before_call(void)
{
	asm volatile (
		"goto 1f;"
		PAD
	"1:"
		"r1 = 10;"
		"r2 = %[cb_unwinds] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(-13)
		"exit;"
		:
		: __imm_addr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * A loop of no rounds never runs its callback, so the call needs no unwind_goto,
 * and the inlined loop gets no pad: the insn after the call is what it was, not
 * the jump of a pad.
 */
SEC("tc")
__description("unwind cb: a loop of no rounds needs no pad")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int loop_none_cb_unwinds(void)
{
	asm volatile (
		"r1 = 0;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * A loop of no rounds with the unwind_goto in place: the pad after it is dead,
 * and so is the code in front of it, behind a branch the verifier decides. All
 * of it goes, and the inlined loop gets no pad, so nothing jumps into what went.
 */
SEC("tc")
__description("unwind cb: the pad after a loop of no rounds is dead")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(0)
__naked int loop_none_pad_dead(void)
{
	asm volatile (
		"r1 = 0;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(4)
		"r1 = 0;"
		"if r1 == 0 goto 1f;"
		"r0 = 1;"
		"r0 = 2;"
		"r0 = 7;"
		"exit;"
	"1:"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/*
 * One path passes a callback that unwinds, the other one that returns. The pad
 * is there for whoever takes it. 64 bytes come in: the first one.
 */
SEC("tc")
__description("unwind cb: the callbacks of one call may differ")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int loop_cbs_differ(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
		"r2 = %[cb_unwinds];"
		"if r6 == 64 goto 1f;"
		"r2 = %[cb_returns];"
	"1:"
		"r1 = 3;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_ptr(cb_unwinds),
		  __imm_ptr(cb_returns),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common, "r6"
	);
}

SEC("tc")
__description("unwind cb: the callback of bpf_for_each_map_elem over an array unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int for_each_array_cb_unwinds(void)
{
	asm volatile (
		"r1 = %[array] ll;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_addr(array),
		  __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_for_each_map_elem)
		: __clobber_common
	);
}

/*
 * The pad is the insn after the call. The JIT emits no code for unwind_goto, so
 * where the op of the array leaves to is its own return address.
 */
SEC("tc")
__description("unwind cb: the pad after bpf_for_each_map_elem is the insn after the call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int for_each_array_pad_after_call(void)
{
	asm volatile (
		"r1 = %[array] ll;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		unwind_goto(0)
		PAD
		:
		: __imm_addr(array),
		  __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_for_each_map_elem)
		: __clobber_common
	);
}

/* Two elements go in first. The hash iterators run the callback under RCU. */
#define FILL_MAP(map)				\
	"r1 = 1;"				\
	"*(u32 *)(r10 - 4) = r1;"		\
	"*(u32 *)(r10 - 8) = r1;"		\
	"r1 = %[" #map "] ll;"			\
	"r2 = r10;"				\
	"r2 += -4;"				\
	"r3 = r10;"				\
	"r3 += -8;"				\
	"r4 = 0;"				\
	"call %[bpf_map_update_elem];"		\
	"r1 = 2;"				\
	"*(u32 *)(r10 - 4) = r1;"		\
	"r1 = %[" #map "] ll;"			\
	"r2 = r10;"				\
	"r2 += -4;"				\
	"r3 = r10;"				\
	"r3 += -8;"				\
	"r4 = 0;"				\
	"call %[bpf_map_update_elem];"

SEC("tc")
__description("unwind cb: the callback of bpf_for_each_map_elem over a hash unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int for_each_hash_cb_unwinds(void)
{
	asm volatile (
		FILL_MAP(hash)
		"r1 = %[hash] ll;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_addr(hash),
		  __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_map_update_elem),
		  __imm(bpf_for_each_map_elem)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: the callback of bpf_for_each_map_elem over an rhash unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int for_each_rhash_cb_unwinds(void)
{
	asm volatile (
		FILL_MAP(rhash)
		"r1 = %[rhash] ll;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_addr(rhash),
		  __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_map_update_elem),
		  __imm(bpf_for_each_map_elem)
		: __clobber_common
	);
}

/*
 * The vma of the stack of the current task. The callback runs under the mmap
 * lock, which the helper drops on its way out whichever way the callback left.
 */
SEC("tc")
__description("unwind cb: the callback of bpf_find_vma unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(47)
__naked int find_vma_cb_unwinds(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r6 = r0;"
		"r1 = *(u64 *)(r6 + %[mm]);"
		"r2 = *(u64 *)(r1 + %[start_stack]);"
		"r1 = r6;"
		"r3 = %[cb_unwinds];"
		"r4 = 0;"
		"r5 = 0;"
		"call %[bpf_find_vma];"
		unwind_goto(1)
		"exit;"
		PAD
		:
		: __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_get_current_task_btf),
		  __imm(bpf_find_vma),
		  __imm_const(mm, offsetof(struct task_struct, mm)),
		  __imm_const(start_stack, offsetof(struct mm_struct, start_stack))
		: __clobber_common, "r6"
	);
}

static bool less_returns(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	return true;
}

/* Not naked: the branch keeps the return reachable. Unwinds with r0 = 5. */
static bool less_unwinds(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	runs++;
	if (a)
		asm volatile ("r0 = 5;" unwind_exit ::: "r0");
	return false;
}

/* The kfunc with a pad after it. The verifier fills r4 and r5. r0 + 42 from the pad. */
__naked __noinline __used
static int rbtree_add_with_pad(void *root, void *node, void *less)
{
	asm volatile (
		"call %[bpf_rbtree_add];"
		unwind_goto(1)
		"exit;"
		"r0 += 42;"
		"exit;"
		:
		: __imm(bpf_rbtree_add)
		: __clobber_all
	);
}

/*
 * The other spelling of it, with its own copy of the body and of the pad. It
 * takes meta and off from the prog, and the verifier fills them in.
 */
__naked __noinline __used
static int rbtree_add_impl_with_pad(void *root, void *node, void *less)
{
	asm volatile (
		"r4 = 0;"
		"r5 = 0;"
		"call %[bpf_rbtree_add_impl];"
		unwind_goto(1)
		"exit;"
		"r0 += 42;"
		"exit;"
		:
		: __imm(bpf_rbtree_add_impl)
		: __clobber_all
	);
}

/*
 * The first node goes in without a comparison. The second one meets it, the
 * comparator unwinds, and the kfunc drops the node on its way to the pad. The
 * lock is the caller's.
 */
static __always_inline int rbtree_cb_unwinds_via(bool impl)
{
	struct node_data *n, *m;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}

	bpf_spin_lock(&glock);
	if (impl) {
		bpf_rbtree_add_impl(&groot, &n->node, less_returns, NULL, 0);
		ret = rbtree_add_impl_with_pad(&groot, &m->node, (void *)less_unwinds);
	} else {
		bpf_rbtree_add(&groot, &n->node, less_returns);
		ret = rbtree_add_with_pad(&groot, &m->node, (void *)less_unwinds);
	}
	bpf_spin_unlock(&glock);
	return ret + runs;
}

SEC("tc")
__description("unwind cb: the comparator of bpf_rbtree_add unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(48)
int rbtree_cb_unwinds(void *ctx)
{
	return rbtree_cb_unwinds_via(false);
}

SEC("tc")
__description("unwind cb: the comparator of bpf_rbtree_add_impl unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(48)
int rbtree_impl_cb_unwinds(void *ctx)
{
	return rbtree_cb_unwinds_via(true);
}

/* Unwinds with the node it is handed first: the one being added */
__naked __noinline __used
static bool less_unwinds_with_node(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	asm volatile (
		"r0 = r1;"
		unwind_exit
	);
}

/* The pad reads the key of the node that came back in r0 */
__naked __noinline __used
static int rbtree_add_pad_reads_node(void *root, void *node, void *less)
{
	asm volatile (
		"call %[bpf_rbtree_add];"
		unwind_goto(1)
		"exit;"
		"r0 = *(u64 *)(r0 - 8);"
		"exit;"
		:
		: __imm(bpf_rbtree_add)
		: __clobber_all
	);
}

/*
 * The comparator unwinds with the node being added, which the kfunc drops on
 * its way to the pad: there is nothing left to read through it.
 */
SEC("tc")
__description("unwind cb: the comparator unwinds with the node the kfunc dropped")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("invalid mem access")
int rbtree_cb_unwinds_with_node(void *ctx)
{
	struct node_data *n, *m;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less_returns);
	ret = rbtree_add_pad_reads_node(&groot, &m->node, (void *)less_unwinds_with_node);
	bpf_spin_unlock(&glock);
	return ret;
}

/*
 * The node the comparator unwound on is not in the tree: the kfunc dropped it
 * on its way to the pad, and the caller has nothing left to read.
 */
SEC("tc")
__description("unwind cb: the node the comparator unwound on is gone")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("invalid mem access")
int rbtree_cb_unwinds_node_gone(void *ctx)
{
	struct node_data *n, *m;
	long key;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less_returns);
	ret = rbtree_add_with_pad(&groot, &m->node, (void *)less_unwinds);
	key = m->key;
	bpf_spin_unlock(&glock);
	return ret + key;
}

/*
 * The comparator was handed the node in the tree as well, and could have
 * unwound with it, so what the caller holds of the tree is gone too, as at an
 * unlock.
 */
SEC("tc")
__description("unwind cb: what the caller holds of the tree is gone when the comparator unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("invalid mem access")
int rbtree_cb_unwinds_first_gone(void *ctx)
{
	struct node_data *n, *m;
	struct bpf_rb_node *f;
	long key = 0;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less_returns);
	f = bpf_rbtree_first(&groot);
	ret = rbtree_add_with_pad(&groot, &m->node, (void *)less_unwinds);
	if (f)
		key = ((struct node_data *)((void *)f - offsetof(struct node_data, node)))->key;
	bpf_spin_unlock(&glock);
	return ret + key;
}

static bool less_waits(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	while (forever)
		;
	return false;
}

/* The kfunc drops the node. The pad that the verifier adds releases the lock and nothing else. */
SEC("tc")
__description("unwind cb: a loop in the comparator of bpf_rbtree_add is out of time")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(2)
int loop_in_comparator(void *ctx)
{
	struct node_data *n;
	int i;

	for (i = 0; i < 2; i++) {
		n = bpf_obj_new(typeof(*n));
		if (!n)
			return 1;
		bpf_spin_lock(&glock);
		bpf_rbtree_add(&groot, &n->node, less_waits);
		bpf_spin_unlock(&glock);
	}
	return 2;
}

struct node_tree {
	struct bpf_rb_node node;
	struct bpf_spin_lock lock;
	struct bpf_rb_root root __contains(node_data, node);
};

private(E) struct bpf_spin_lock nlock;
private(E) struct bpf_rb_root nroot __contains(node_tree, node);

/* The kfunc would drop the node under the lock of the tree, and to free it takes the lock in it */
SEC("tc")
__description("unwind cb: a loop in the comparator, the node has a lock and a tree of its own")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the JIT or the helper that calls the function cannot unwind it")
int loop_in_comparator_node_with_tree(void *ctx)
{
	struct node_tree *n = bpf_obj_new(typeof(*n));

	if (!n)
		return 0;
	bpf_spin_lock(&nlock);
	bpf_rbtree_add(&nroot, &n->node, less_waits);
	bpf_spin_unlock(&nlock);
	return 0;
}

/*
 * It is one function for both trees, and it has unwound out of the first one.
 * A path-sensitive run takes the edge of may_goto only in a loop that a run found to be infinite.
 * That is no guess, in the run that finds it and in those after it: the conflict of the comparator
 * that cannot unwind ends the failing path of each run.
 */
SEC("tc")
__description("unwind cb: one comparator with a loop for two trees, one of them has such nodes")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure
__log_level(2)
__msg("callback cannot unwind at insn {{[0-9]+}}: less_waits() does")
__msg("path-sensitive run after pass 1")
__msg("landing pad of may_goto at {{[0-9]+}}: conflict: the JIT or the helper that calls the function cannot unwind it")
int loop_in_comparator_of_two_trees(void *ctx)
{
	struct node_data *d = bpf_obj_new(typeof(*d));
	struct node_tree *n;

	if (!d)
		return 0;
	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &d->node, less_waits);
	bpf_spin_unlock(&glock);
	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 0;
	bpf_spin_lock(&nlock);
	bpf_rbtree_add(&nroot, &n->node, less_waits);
	bpf_spin_unlock(&nlock);
	return 0;
}

static __noinline int first_goes_in_again(void)
{
	struct bpf_rb_node *m = bpf_rbtree_first(&groot);

	m = m ? bpf_rbtree_remove(&groot, m) : NULL;
	return m ? rbtree_add_with_pad(&groot, m, (void *)less_unwinds) : 0;
}

/* The kfunc dropped f. The function is verified on its own: its caller is not in that state. */
SEC("tc")
__description("unwind cb: what the caller of a function holds of the tree is gone when the comparator unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("invalid mem access")
int rbtree_cb_unwinds_first_gone_in_func(void *ctx)
{
	struct bpf_rb_node *f;
	long key = 0;

	bpf_spin_lock(&glock);
	f = bpf_rbtree_first(&groot);
	first_goes_in_again();
	if (f)
		key = ((struct node_data *)((void *)f - offsetof(struct node_data, node)))->key;
	bpf_spin_unlock(&glock);
	return key;
}

/*
 * The node the comparator unwound on survives the drop by the kfunc when another
 * reference to it is held, and goes in again: the kfunc left it unlinked.
 */
SEC("tc")
__description("unwind cb: the node the comparator unwound on can be added again")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(48)
int rbtree_cb_unwinds_node_readded(void *ctx)
{
	struct node_ref *n, *m, *m2;
	int ret, again;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}
	m2 = bpf_refcount_acquire(m);
	if (!m2) {
		bpf_obj_drop(n);
		bpf_obj_drop(m);
		return 3;
	}

	bpf_spin_lock(&rlock);
	bpf_rbtree_add(&rroot, &n->node, less_returns);
	ret = rbtree_add_with_pad(&rroot, &m->node, (void *)less_unwinds);
	again = bpf_rbtree_add(&rroot, &m2->node, less_returns);
	bpf_spin_unlock(&rlock);
	return ret + again + runs;
}

/*
 * The pad of the kfunc drops the node when the comparator unwinds, with the
 * destructors of its fields, which a tracing program may not run on a type with
 * NMI unsafe fields, as it may not with bpf_obj_drop().
 */
SEC("tp_btf/task_newtask")
__description("unwind cb: the comparator unwinds in a tracing program on a type with NMI unsafe fields")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("bpf_rbtree_add with a comparator that unwinds cannot be used in tracing programs on types with NMI unsafe fields")
int BPF_PROG(rbtree_cb_unwinds_nmi_unsafe, struct task_struct *task, u64 clone_flags)
{
	struct node_task *n;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 0;
	bpf_spin_lock(&tlock);
	ret = rbtree_add_with_pad(&troot, &n->node, (void *)less_unwinds);
	bpf_spin_unlock(&tlock);
	return ret;
}

/*
 * The pad drops the node under the lock of the tree, and the destructor of the
 * list in the node takes the lock of the list. All bpf_spin_locks of a cpu keep
 * the irq flags in one word.
 */
SEC("tc")
__description("unwind cb: the comparator unwinds on a type that takes a lock when freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("bpf_rbtree_add with a comparator that unwinds cannot be used on types with a list head, an rb root or a referenced kptr")
int rbtree_cb_unwinds_lock_on_free(void *ctx)
{
	struct node_list *n;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 0;
	bpf_spin_lock(&llock);
	ret = rbtree_add_with_pad(&lroot, &n->node, (void *)less_unwinds);
	bpf_spin_unlock(&llock);
	return ret;
}

/*
 * The prog can call nothing under the lock of the tree that releases a task. The pad would: the
 * task of the node is released with it.
 */
SEC("tc")
__description("unwind cb: the comparator unwinds on a type with a kptr to a kernel object")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("bpf_rbtree_add with a comparator that unwinds cannot be used on types with a list head, an rb root or a referenced kptr")
int rbtree_cb_unwinds_kptr(void *ctx)
{
	struct node_task *n;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 0;
	bpf_spin_lock(&tlock);
	ret = rbtree_add_with_pad(&troot, &n->node, (void *)less_unwinds);
	bpf_spin_unlock(&tlock);
	return ret;
}

/* So the verifier doesn't let a comparator unwind there */
SEC("tp_btf/task_newtask")
__description("unwind cb: a loop in the comparator, tracing program, type with NMI unsafe fields")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the JIT or the helper that calls the function cannot unwind it")
int BPF_PROG(loop_in_comparator_nmi_unsafe, struct task_struct *task, u64 clone_flags)
{
	struct node_task *n;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 0;
	bpf_spin_lock(&tlock);
	bpf_rbtree_add(&troot, &n->node, less_waits);
	bpf_spin_unlock(&tlock);
	return 0;
}

static int inner_waits(u32 i, void *ctx)
{
	while (forever)
		;
	return 0;
}

static long elem_cb_loops(struct bpf_map *map, int *key, int *val, void *ctx)
{
	bpf_loop(1, inner_waits, NULL, no_flags);
	return 0;
}

/*
 * A callback of a callback is out of time: bpf_loop() leaves through its pad to the pad of the
 * outer callback, bpf_for_each_map_elem() leaves through its pad, and the prog leaves its section.
 */
SEC("tc")
__description("unwind cb: a loop in a callback of bpf_loop in a callback of bpf_for_each_map_elem")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(2)
int loop_in_nested_cb(void *ctx)
{
	bpf_rcu_read_lock();
	bpf_for_each_map_elem(&array, elem_cb_loops, NULL, 0);
	bpf_rcu_read_unlock();
	return 7;
}

static __noinline int waits_both_ways(u32 i, void *ctx)
{
	while (forever)
		;
	return 0;
}

/*
 * One subprog is called and is a callback: both calls of it are sites, and it has one pad. One
 * prog runs the call, the other one the helper: @called is 1 or 0, the verifier knows neither.
 */
#define CB_AND_CALLEE(name, desc, called)						\
SEC("tc")										\
__description("unwind cb: a subprog with a loop is called and is a callback of bpf_loop, " desc) \
__arch_x86_64 __arch_arm64 __load_if_JITed()						\
__success __retval(2)									\
int name(struct __sk_buff *skb)								\
{											\
	if (called)									\
		return waits_both_ways(0, NULL) + 5;					\
	bpf_loop(1, waits_both_ways, NULL, no_flags);					\
	return 7;									\
}

CB_AND_CALLEE(cb_and_callee, "the helper runs", no_flags)
CB_AND_CALLEE(cb_and_callee_called, "the call runs", forever)

static int throws_9(u32 i, void *ctx)
{
	bpf_throw(9);
	return 0;
}

static long elem_cb_throws_9(struct bpf_map *map, int *key, int *val, void *ctx)
{
	bpf_throw(9);
	return 0;
}

/*
 * The cookie goes through the pad of the helper, in C, to the pad of the prog, which returns it.
 * @tags: unwind_goto of the inlined bpf_loop() follows the call of the callback, 15 insns behind
 * its pad, and tells that the helper was inlined.
 */
#define COOKIE_THROUGH(name, desc, tags, call)						\
SEC("tc")										\
__description("unwind cb: the cookie of bpf_throw() gets through " desc)		\
__arch_x86_64 __arch_arm64 __load_if_JITed()						\
__success __retval(9) tags								\
int name(void *ctx)									\
{											\
	int key = 1, val = 1;								\
											\
	bpf_map_update_elem(&hash, &key, &val, 0);					\
	call;										\
	return 7;									\
}

COOKIE_THROUGH(cookie_through_loop, "bpf_loop", , bpf_loop(1, throws_9, NULL, no_flags))
COOKIE_THROUGH(cookie_through_inlined_loop, "the inlined bpf_loop",
	       __xlated("...") __xlated("call pc+{{[0-9]+}}") __xlated("kgoto pc-15"),
	       bpf_loop(1, throws_9, NULL, 0))
COOKIE_THROUGH(cookie_through_array, "bpf_for_each_map_elem of an array", ,
	       bpf_for_each_map_elem(&array, elem_cb_throws_9, NULL, 0))
COOKIE_THROUGH(cookie_through_hash, "bpf_for_each_map_elem of a hash", ,
	       bpf_for_each_map_elem(&hash, elem_cb_throws_9, NULL, 0))

/*
 * The prog holds a task on some paths, which takes hidden slots, and the node has one too.
 * bpf_rbtree_add() takes the node: its slot is cleared in front of the call. The second node is
 * compared with the first one. When the comparator is out of time the kfunc drops the node, and the
 * pad of the prog releases what its slots have: the task, and no node, since the slot of the node
 * is 0. A second drop would not show at run time. The insns show the slot that has the address
 * of the node being cleared in front of the call that has kgoto.
 */
SEC("tc")
__description("unwind cb: the comparator is out of time, the caller has hidden slots")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(2)
__log_level(2)
__msg("landing pad of call at {{[0-9]+}}: {{.*}}ref@{{[0-9]+}}(*fp-{{[0-9]+}}) if not 0")
__xlated("...")
__xlated("r0 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("r0 += 8")
__xlated("if r0 != r2 goto pc+2")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = 0")
__xlated("...")
__xlated("r5 = 8")
__xlated("call kernel-function")
__xlated("kgoto pc+{{[0-9]+}}")
int slots_around_rbtree_add(void *ctx)
{
	struct task_struct *t, *cur = bpf_get_current_task_btf();
	struct node_data *n;
	bool own;
	int i;

	t = bpf_task_from_pid(forever & 2 ? 2 : 1);
	own = !!t;
	barrier_var(own);
	if (!t)
		t = cur;
	barrier_var(t);
	for (i = 0; i < 2; i++) {
		n = bpf_obj_new(typeof(*n));
		if (!n)
			break;
		bpf_spin_lock(&glock);
		bpf_rbtree_add(&groot, &n->node, less_waits);
		bpf_spin_unlock(&glock);
	}
	if (own)
		bpf_task_release(t);
	return 7;
}

char _license[] SEC("license") = "GPL";
