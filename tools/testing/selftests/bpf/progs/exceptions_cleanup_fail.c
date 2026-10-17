// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_misc.h"
#include "exceptions_cleanup.h"

__u64 input = 0;

static __used __noinline void __kfunc_btf_anchor(void)
{
	bpf_throw(0);
	bpf_unwind();
	bpf_preempt_disable();
	bpf_preempt_enable();
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_unwind_resume(NULL);
}

/* An unwind raised in a callee, which is how a cleanup region gets one. */
static __used __naked __noinline __u64 inner_unwind(void)
{
	asm volatile (
	"call bpf_unwind;"
	::: __clobber_all);
}

static int unwinding_cb(__u32 idx, void *ctx)
{
	bpf_unwind();
	return 0;
}

SEC("?syscall")
__failure __msg("may unwind and is used as a callback")
int callback_may_unwind(void *ctx)
{
	bpf_loop(1, unwinding_cb, NULL, 0);
	return 0;
}

/* An exception callback returns to the kernel, which has no branch for it. */
__noinline int unwinding_exc_cb(u64 cookie)
{
	bpf_unwind();
	return 0;
}

SEC("?syscall")
__exception_cb(unwinding_exc_cb)
__failure __msg("exception callback subprog {{[0-9]+}} cannot unwind")
int exception_cb_unwinds(void *ctx)
{
	if (input)
		bpf_throw(0);
	return 0;
}

static __used __naked __noinline __u64 nested_pad_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
"1:"	"call inner_unwind;"		/* first cleanup region */
"2:"
	"call bpf_preempt_enable;"
	"r0 = 0;"
	"exit;"
"3:"					/* first pad, second region's call */
	"call bpf_preempt_enable;"
"4:"
	"call bpf_unwind_resume;"
"5:"					/* second pad */
	"call bpf_preempt_enable;"
	"call bpf_unwind_resume;"
	CLEANUP_REC("1b", "2b", "3b")
	CLEANUP_REC("3b", "4b", "5b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("is inside the call-site range of")
int nested_landing_pad(void *ctx)
{
	return nested_pad_frame();
}

/*
 * A tail call in a subprog that can unwind: the tail-called program returns
 * to the subprog's caller without saying in r3 how the frame left.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} tc_map SEC(".maps");

static __used __naked __noinline __u64 tail_call_pad_frame(void)
{
	asm volatile (
	"r6 = r1;"
"1:"	"call inner_unwind;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r1 = r6;"
	"r2 = %[tc_map] ll;"
	"r3 = 0;"
	"call %[bpf_tail_call];"
	"call bpf_unwind_resume;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: __imm(bpf_tail_call), __imm_addr(tc_map)
	: __clobber_all);
}

SEC("?syscall")
__failure __msg("can unwind and has a tail call")
int tail_call_in_unwinding_subprog(void *ctx)
{
	return tail_call_pad_frame();
}

#if defined(__BPF_FEATURE_STACK_ARGUMENT)

/*
 * A pad reading an incoming stack argument after the call it covers: the
 * call clobbered the register the JIT keeps it in. Every parameter is used,
 * so the caller passes them all, and summed before the call, so the pad's is
 * the only stack argument load after it.
 */
static __used __noinline __u64 stack_arg_pad_frame(__u64 a, __u64 b, __u64 c,
						   __u64 d, __u64 e, __u64 f)
{
	__u64 sum = a + b + c + d + e + f;

	asm volatile (
"1:"	"call inner_unwind;"		/* cleanup region */
"2:"
	"goto 4f;"
"3:"					/* landing pad */
	"r0 = *(u64 *)(r11 + 8);"
	"call bpf_unwind_resume;"
"4:"
	CLEANUP_REC("1b", "2b", "3b")
	: "+r"(sum) :: __clobber_common);
	return sum;
}

SEC("?syscall")
__failure __msg("r11 load must be before any r11 store or call insn")
int stack_arg_load_in_pad(void *ctx)
{
	return stack_arg_pad_frame(1, 2, 3, 4, 5, 6);
}

#endif /* __BPF_FEATURE_STACK_ARGUMENT */

/*
 * A BPF_LD_[ABS|IND] in a subprog that can unwind: a failed load leaves
 * through the epilogue without saying in r3 how the frame left.
 */
static __used __naked __noinline __u64 ld_abs_pad_frame(void)
{
	asm volatile (
	"r6 = r1;"			/* the skb BPF_LD_ABS reads */
"1:"	"call inner_unwind;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* landing pad */
	"r0 = *(u32 *)skb[0];"
	"call bpf_unwind_resume;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?tc")
__failure __msg("can unwind and has a BPF_LD_[ABS|IND]")
__naked void ld_abs_in_unwinding_subprog(void)
{
	asm volatile (
	"call ld_abs_pad_frame;"
	"exit;"
	::: __clobber_all);
}

/*
 * An unwind with no landing pad anywhere leaves the main program through
 * its unwind stub, an exit, so what it still holds is refused there.
 */
SEC("?syscall")
__failure __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_rcu_read_lock-ed region")
int unwind_no_pad_rcu(void *ctx)
{
	bpf_rcu_read_lock();
	bpf_unwind();
	bpf_rcu_read_unlock();
	return 0;
}

/*
 * Lock and reference state is the program's, not a frame's: an unwind carries
 * it through every pad it runs, and what is still held when the main program
 * returns is refused there. A pad that drops what its caller holds is fine;
 * the caller's own pad dropping it again is not.
 */
static __used __naked __noinline __u64 pad_drops_caller_lock_frame(void)
{
	asm volatile (
"1:"	"call bpf_unwind;"		/* cleanup region */
"2:"	"goto 2b;"
"3:"					/* pad: drops a lock it never took */
	"call bpf_rcu_read_unlock;"
	"call bpf_unwind_resume;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

static __used __naked __noinline __u64 caller_holds_lock_frame(void)
{
	asm volatile (
	"call bpf_rcu_read_lock;"
"1:"	"call pad_drops_caller_lock_frame;"
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* pad */
	"call bpf_rcu_read_unlock;"
	"call bpf_unwind_resume;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("unmatched rcu read unlock")
int pad_drops_caller_lock(void *ctx)
{
	return caller_holds_lock_frame();
}

/* The other way round: a pad that does not drop what its own frame took. */
static __used __naked __noinline __u64 pad_keeps_own_lock_frame(void)
{
	asm volatile (
	"call bpf_rcu_read_lock;"
"1:"	"call inner_unwind;"		/* cleanup region */
"2:"
	"call bpf_rcu_read_unlock;"
	"r0 = 0;"
	"exit;"
"3:"					/* pad: forgets the unlock */
	"call bpf_unwind_resume;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_rcu_read_lock-ed region")
int pad_keeps_own_lock(void *ctx)
{
	return pad_keeps_own_lock_frame();
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} unwind_ringbuf SEC(".maps");

/*
 * Always unwinds, so its caller is never returned to on the modelled path,
 * and the caller's post-call code, which never releases the record, is not
 * walked. Its pad discards the record the caller reserved.
 */
static __used __naked __noinline __u64 pad_drops_caller_ref_frame(void)
{
	asm volatile (
	"r6 = r1;"			/* the caller's reserved record */
"1:"	"call bpf_unwind;"		/* cleanup region */
"2:"	"goto 2b;"
"3:"					/* pad: drops what it never acquired */
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"call bpf_unwind_resume;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: __imm(bpf_ringbuf_discard)
	: __clobber_all);
}

/* And this frame's own pad drops it a second time. */
static __used __naked __noinline __u64 caller_holds_ref_frame(void)
{
	asm volatile (
	"r1 = %[unwind_ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 9f;"
	"r6 = r0;"
	"r1 = r6;"
"1:"	"call pad_drops_caller_ref_frame;"	/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* pad */
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"call bpf_unwind_resume;"
"9:"
	"r0 = 0;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: __imm(bpf_ringbuf_reserve), __imm(bpf_ringbuf_discard),
	  __imm_addr(unwind_ringbuf)
	: __clobber_all);
}

SEC("?syscall")
__failure __msg("R1 type=scalar expected=ringbuf_mem")
int pad_drops_caller_ref(void *ctx)
{
	return caller_holds_ref_frame();
}

/*
 * A frame an unwind passes through without a pad leaves through its unwind
 * stub right after the call: nothing of it runs again, and whatever it
 * acquired is never released -- which the main program's exit then finds
 * still held.
 */
static __used __naked __noinline __u64 pad_resumes_frame(void)
{
	asm volatile (
"1:"	"call bpf_unwind;"		/* cleanup region */
"2:"	"goto 2b;"
"3:"					/* pad */
	"call bpf_unwind_resume;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

static __used __naked __noinline __u64 uncovered_holds_lock_frame(void)
{
	asm volatile (
	"call bpf_rcu_read_lock;"
	"call pad_resumes_frame;"	/* no record covers this call */
	"call bpf_rcu_read_unlock;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_rcu_read_lock-ed region")
int unwind_through_call_keeps_lock(void *ctx)
{
	return uncovered_holds_lock_frame();
}

static __used __naked __noinline __u64 uncovered_holds_ref_frame(void)
{
	asm volatile (
	"r1 = %[unwind_ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 9f;"
	"r6 = r0;"
	"call pad_resumes_frame;"	/* no record covers this call */
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
"9:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ringbuf_reserve), __imm(bpf_ringbuf_discard),
	  __imm_addr(unwind_ringbuf)
	: __clobber_all);
}

SEC("?syscall")
__failure __msg("Unreleased reference id=")
int unwind_through_call_keeps_ref(void *ctx)
{
	return uncovered_holds_ref_frame();
}

/*
 * A callee writes its caller's stack through a pointer argument, then
 * unwinds. The caller's pad runs after that write, so it cannot keep trusting
 * the slot to hold the zero it held at the call.
 */
static __used __naked __noinline __u64 stack_writer(void)
{
	asm volatile (
	"r2 = 0x10000000;"
	"*(u64 *)(r1 + 0) = r2;"	/* r1 is the caller's fp-8 */
	"call bpf_unwind;"
	::: __clobber_all);
}

static __used __naked __noinline __u64 stale_stack_frame(void)
{
	asm volatile (
	"r6 = 0;"
	"*(u64 *)(r10 - 8) = r6;"
	"*(u64 *)(r10 - 64) = r6;"
	"r1 = r10;"
	"r1 += -8;"
"1:"	"call stack_writer;"		/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* pad: fp-8 as an offset into fp-64 */
	"r1 = *(u64 *)(r10 - 8);"
	"r2 = r10;"
	"r2 += -64;"
	"r2 += r1;"
	"r0 = *(u8 *)(r2 + 0);"
	"call bpf_unwind_resume;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("invalid read from stack R2 off=268435392 size=1")
int stale_stack_pad(void *ctx)
{
	return stale_stack_frame();
}

/* The same through a global subprog, which is not walked from its caller. */
__noinline int global_stack_writer(__u64 *p)
{
	if (!p)
		return 0;
	*p = 0x10000000;
	bpf_unwind();
	return 0;
}

static __used __naked __noinline __u64 global_stale_stack_frame(void)
{
	asm volatile (
	"r6 = 0;"
	"*(u64 *)(r10 - 8) = r6;"
	"*(u64 *)(r10 - 64) = r6;"
	"r1 = r10;"
	"r1 += -8;"
"1:"	"call global_stack_writer;"	/* cleanup region */
"2:"
	"r0 = 0;"
	"exit;"
"3:"					/* pad: fp-8 as an offset into fp-64 */
	"r1 = *(u64 *)(r10 - 8);"
	"r2 = r10;"
	"r2 += -64;"
	"r2 += r1;"
	"r0 = *(u8 *)(r2 + 0);"
	"call bpf_unwind_resume;"
	CLEANUP_REC("1b", "2b", "3b")
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("math between fp pointer and register with unbounded min value")
int global_stale_stack_pad(void *ctx)
{
	return global_stale_stack_frame();
}

/* gcc has no indirect calls, and only these JITs emit them */
#if defined(__clang__) && \
	(defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64))

/*
 * A callback calling an unwinding subprog through a pointer it read from its
 * caller's stack: it neither calls nor takes the address of inner_unwind, so
 * only the marking of every subprog with a callx makes it might_unwind.
 */
static __used __naked __noinline int callx_cb(void)
{
	asm volatile (
	"r1 = *(u64 *)(r2 + 0);"
	"callx r1;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("?syscall")
__failure __msg("may unwind and is used as a callback")
__naked int callback_callx_may_unwind(void)
{
	asm volatile (
	"r1 = %[inner_unwind] ll;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = 1;"
	"r2 = %[callx_cb] ll;"
	"r3 = r10;"
	"r3 += -8;"
	"r4 = 0;"
	"call %[bpf_loop];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(inner_unwind), __imm_addr(callx_cb), __imm(bpf_loop)
	: __clobber_all);
}

#endif /* __clang__ && (x86 || arm64) */

char _license[] SEC("license") = "GPL";
