// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * A callback that can unwind says so in r3 like any other subprog. bpf_loop(),
 * bpf_for_each_map_elem() and bpf_find_vma() pass the bit on: they stop, return
 * through their own epilogue and hand it to the caller, where
 * 'call helper; if r3 != 0 goto pad' catches it. A helper that doesn't look at
 * r3 still holds the callback to r3 == 0. An async callback and an exception
 * callback have no BPF caller, so they may unwind.
 */
#define __unwind __attribute__((btf_decl_tag("unwind")))

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
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} user_ringbuf SEC(".maps");

struct elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} timers SEC(".maps");

__naked __noinline __used __unwind
static unsigned long cb_returns(void)
{
	asm volatile (
		"r0 = 0;"
		"r3 = 0;"
		"exit;"
	);
}

__naked __noinline __used __unwind
static unsigned long cb_unwinds(void)
{
	asm volatile (
		"r0 = 0;"
		"r3 = 1;"
		"exit;"
	);
}

__naked __noinline __used __unwind
static unsigned long cb_r3_not_set(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
	);
}

__naked __noinline __used
static unsigned long cb_no_tag(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
	);
}

/* bpf_loop callback: r1 is the iteration, unwinds on the second one */
__naked __noinline __used __unwind
static unsigned long loop_cb_unwinds_at_1(void)
{
	asm volatile (
		"if r1 == 1 goto 1f;"
		"r0 = 0;"
		"r3 = 0;"
		"exit;"
	"1:"
		"r0 = 0;"
		"r3 = 1;"
		"exit;"
	);
}

/* bpf_for_each_map_elem callback: r2 is the key, unwinds on key 1 */
__naked __noinline __used __unwind
static unsigned long map_cb_unwinds_at_1(void)
{
	asm volatile (
		"r1 = *(u32 *)(r2 + 0);"
		"if r1 == 1 goto 1f;"
		"r0 = 0;"
		"r3 = 0;"
		"exit;"
	"1:"
		"r0 = 0;"
		"r3 = 1;"
		"exit;"
	);
}

/*
 * skb->mark is 0, but the verifier doesn't know, so bpf_loop() with it as flags
 * is not inlined and the helper runs.
 */
SEC("tc")
__description("unwind cb: bpf_loop passes the bit on")
__arch_x86_64
__load_if_JITed()
__success __retval(42)
__naked int loop_helper_unwinds(void)
{
	asm volatile (
		"r4 = *(u32 *)(r1 + %[mark]);"
		"r1 = 3;"
		"r2 = %[loop_cb_unwinds_at_1];"
		"r3 = 0;"
		"call %[bpf_loop];"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(loop_cb_unwinds_at_1),
		  __imm(bpf_loop),
		  __imm_const(mark, offsetof(struct __sk_buff, mark))
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: bpf_loop returns the count when the callback returns")
__arch_x86_64
__load_if_JITed()
__success __retval(3)
__naked int loop_helper_returns(void)
{
	asm volatile (
		"r4 = *(u32 *)(r1 + %[mark]);"
		"r1 = 3;"
		"r2 = %[cb_returns];"
		"r3 = 0;"
		"call %[bpf_loop];"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(cb_returns),
		  __imm(bpf_loop),
		  __imm_const(mark, offsetof(struct __sk_buff, mark))
		: __clobber_common
	);
}

/*
 * With flags known to be 0 bpf_loop() is inlined. The callback returns to the
 * inlined loop, which leaves it with r3 as the callback left it. The branch
 * after the call of the callback is an extable entry, so 'r7 += 1' follows
 * the call.
 */
SEC("tc")
__description("unwind cb: inlined bpf_loop passes the bit on")
__arch_x86_64
__load_if_JITed()
__success __retval(42)
__jited("	callq	0x{{.*}}")
__jited("	incq	%r13")
__naked int loop_inlined_unwinds(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[loop_cb_unwinds_at_1];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(loop_cb_unwinds_at_1),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: inlined bpf_loop returns the count when the callback returns")
__arch_x86_64
__load_if_JITed()
__success __retval(3)
__naked int loop_inlined_returns(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_returns];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(cb_returns),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* r3 is the context on entry, it has to be 0 when the callback never ran */
SEC("tc")
__description("unwind cb: inlined bpf_loop with no iterations leaves r3 == 0")
__arch_x86_64
__load_if_JITed()
__success __retval(0)
__naked int loop_inlined_no_iterations(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[mark]);"
		"r2 = %[cb_unwinds];"
		"r3 = r10;"
		"r3 += -8;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop),
		  __imm_const(mark, offsetof(struct __sk_buff, mark))
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: inlined bpf_loop with too many iterations leaves r3 == 0")
__arch_x86_64
__load_if_JITed()
__success __retval(5)
__naked int loop_inlined_e2big(void)
{
	asm volatile (
		"r1 = 0x1000000;"
		"r2 = %[cb_unwinds];"
		"r3 = r10;"
		"r3 += -8;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"if r3 != 0 goto 1f;"
		"if w0 != -7 goto 1f;"
		"r0 = 5;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: r3 is not readable after bpf_loop with a callback without the tag")
__arch_x86_64
__load_if_JITed()
__failure __msg("R3 !read_ok")
__naked int loop_cb_without_tag(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_no_tag];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(cb_no_tag),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: the callback of bpf_loop doesn't set r3")
__arch_x86_64
__load_if_JITed()
__failure __msg("R3 !read_ok")
__naked int loop_cb_r3_not_set(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_r3_not_set];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_r3_not_set),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* The fixup pass picks the helper per insn. */
SEC("tc")
__description("unwind cb: callbacks at one call disagree on unwinding")
__arch_x86_64
__load_if_JITed()
__failure __msg("disagree on unwinding")
__naked int loop_cbs_disagree(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
		"r2 = %[cb_no_tag];"
		"if r6 != 64 goto 1f;"
		"r2 = %[cb_returns];"
	"1:"
		"r1 = 3;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_no_tag),
		  __imm_ptr(cb_returns),
		  __imm(bpf_loop),
		  __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_common, "r6"
	);
}

/* bpf_user_ringbuf_drain() doesn't look at r3 */
SEC("tc")
__description("unwind cb: a helper that doesn't pass the bit on")
__arch_x86_64
__load_if_JITed()
__failure __msg("callback cannot unwind")
__naked int drain_cb_unwinds(void)
{
	asm volatile (
		"r1 = %[user_ringbuf] ll;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_user_ringbuf_drain];"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_user_ringbuf_drain),
		  __imm_addr(user_ringbuf)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: bpf_for_each_map_elem passes the bit on")
__arch_x86_64
__load_if_JITed()
__success __retval(42)
__naked int for_each_array_unwinds(void)
{
	asm volatile (
		"r1 = %[array] ll;"
		"r2 = %[map_cb_unwinds_at_1];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(map_cb_unwinds_at_1),
		  __imm(bpf_for_each_map_elem),
		  __imm_addr(array)
		: __clobber_common
	);
}

SEC("tc")
__description("unwind cb: bpf_for_each_map_elem returns the count when the callback returns")
__arch_x86_64
__load_if_JITed()
__success __retval(3)
__naked int for_each_array_returns(void)
{
	asm volatile (
		"r1 = %[array] ll;"
		"r2 = %[cb_returns];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(cb_returns),
		  __imm(bpf_for_each_map_elem),
		  __imm_addr(array)
		: __clobber_common
	);
}

/* The hash is empty: the callback never runs and r3 is 0. */
SEC("tc")
__description("unwind cb: bpf_for_each_map_elem over an empty map leaves r3 == 0")
__arch_x86_64
__load_if_JITed()
__success __retval(0)
__naked int for_each_hash_empty(void)
{
	asm volatile (
		"r1 = %[hash] ll;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_for_each_map_elem),
		  __imm_addr(hash)
		: __clobber_common
	);
}

/*
 * The vma of the stack of the current task. The callback runs under mmap_lock,
 * which the helper drops on the way out whether the callback unwound or not.
 */
SEC("tc")
__description("unwind cb: bpf_find_vma passes the bit on")
__arch_x86_64
__load_if_JITed()
__success __retval(42)
__naked int find_vma_unwinds(void)
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
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_get_current_task_btf),
		  __imm(bpf_find_vma),
		  __imm_const(mm, offsetof(struct task_struct, mm)),
		  __imm_const(start_stack, offsetof(struct mm_struct, start_stack))
		: __clobber_common, "r6"
	);
}

SEC("tc")
__description("unwind cb: bpf_find_vma returns 0 when the callback returns")
__arch_x86_64
__load_if_JITed()
__success __retval(0)
__naked int find_vma_returns(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r6 = r0;"
		"r1 = *(u64 *)(r6 + %[mm]);"
		"r2 = *(u64 *)(r1 + %[start_stack]);"
		"r1 = r6;"
		"r3 = %[cb_returns];"
		"r4 = 0;"
		"r5 = 0;"
		"call %[bpf_find_vma];"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		: __imm_ptr(cb_returns),
		  __imm(bpf_get_current_task_btf),
		  __imm(bpf_find_vma),
		  __imm_const(mm, offsetof(struct task_struct, mm)),
		  __imm_const(start_stack, offsetof(struct mm_struct, start_stack))
		: __clobber_common, "r6"
	);
}

/* Runs bpf_loop() with a callback that unwinds and passes the bit on. */
__naked __noinline __used __unwind
static unsigned long loop_passes_on(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[loop_cb_unwinds_at_1];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"if r3 != 0 goto 1f;"
		"r3 = 0;"
		"exit;"
	"1:"
		"r0 = 0;"
		"r3 = 1;"
		"exit;"
		:
		: __imm_ptr(loop_cb_unwinds_at_1),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* callback -> inlined loop -> subprog -> main, each step the same */
SEC("tc")
__description("unwind cb: the bit goes up through a subprog")
__arch_x86_64
__load_if_JITed()
__success __retval(42)
__naked int through_subprog(void)
{
	asm volatile (
		"call loop_passes_on;"
		"if r3 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 42;"
		"exit;"
		:
		:
		: __clobber_all
	);
}

/* The kernel calls it and looks at r0 only. */
SEC("tc")
__description("unwind cb: an async callback may unwind")
__arch_x86_64
__load_if_JITed()
__success __retval(0)
int async_cb_unwinds(void *ctx)
{
	struct elem *e;
	int key = 0;

	e = bpf_map_lookup_elem(&timers, &key);
	if (!e)
		return 1;
	bpf_timer_init(&e->t, &timers, 0);
	bpf_timer_set_callback(&e->t, (void *)cb_unwinds);
	return 0;
}

/*
 * bpf_throw() lands in it and the prog returns what it returns. Not naked: clang
 * leaves the parameter of a naked function unnamed in BTF, which the kernel
 * rejects for a global function. The compiler's own 'w0 = 0; exit' follows the
 * asm and leaves r3 alone.
 */
__noinline __used __unwind
int exception_cb_unwinds(u64 cookie)
{
	asm volatile ("r3 = 1;" ::: "r3");
	return 0;
}

SEC("tc")
__description("unwind cb: an exception callback may unwind")
__arch_x86_64
__load_if_JITed()
__success __retval(0)
__exception_cb(exception_cb_unwinds)
__naked int throws_to_unwinding_cb(void)
{
	asm volatile (
		"r1 = 0;"
		"call %[bpf_throw];"
		"exit;"
		:
		: __imm(bpf_throw)
		: __clobber_all
	);
}

/* BTF FUNC records are not generated for kfuncs referenced from inline asm only. */
void __kfunc_btf_root(void)
{
	bpf_throw(0);
}

char _license[] SEC("license") = "GPL";
