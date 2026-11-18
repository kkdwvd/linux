// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * Programs that the kernel unwinds while a frame on their stack holds a coroutine frame: the
 * landing pad of that frame frees the coroutine frame with bpf_coro_frame_free(). The progs
 * call dives(), which calls itself until the stack has no room. They are in assembly, and the
 * plan of the landing pad and its insns are matched: the pad of a main program is behind its
 * last insn.
 *
 * It takes the JIT of x86-64 or arm64, CAP_BPF and CAP_PERFMON.
 */

#define TC_ACT_OK	0

char _license[] SEC("license") = "GPL";

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

/* The frames of a recursion that began, and how many times the code behind a call ran */
unsigned long frames;
unsigned long behind;

/* @var++ in assembly, with r1 and r2 */
#define COUNT(var)				\
	"r1 = %[" #var "] ll;"			\
	"r2 = *(u64 *)(r1 + 0);"		\
	"r2 += 1;"				\
	"*(u64 *)(r1 + 0) = r2;"

/* It calls itself until the stack has no room, which unwinds the program */
__naked __noinline __used
static unsigned long dives(void)
{
	asm volatile (
		COUNT(frames)
		"*(u64 *)(r10 - 128) = r2;"
		"call dives;"
		COUNT(behind)
		"exit;"
		:
		: __imm_addr(frames),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* r0 = bpf_coro_frame_alloc(@size), r0 = 0 and exit if there is none */
#define FRAME_ALLOC(size)			\
	"r1 = " #size ";"			\
	"r2 = 0;"				\
	"call %[bpf_coro_frame_alloc];"		\
	"if r0 != 0 goto 1f;"			\
	"exit;"					\
"1:"

#define FRAME_FREE(reg)				\
	"r1 = " #reg ";"			\
	"call %[bpf_coro_frame_free];"

/*
 * BTF FUNC records are not generated for kfuncs referenced from inline assembly. These
 * records are necessary for libbpf to link the program.
 */
void __kfunc_btf_root(void)
{
	bpf_coro_frame_free(bpf_coro_frame_alloc(0, 0));
	bpf_throw(0);
}

/* The frame is in r6, and the pad frees it from there */
SEC("tc")
__description("coro unwind: the coroutine frame of a frame that waits in a call is freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 6: ref@2(r6) rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void frame_at_call(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		"call dives;"
		COUNT(behind)
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* The only copy of the frame that outlives the call is in the stack */
SEC("tc")
__description("coro unwind: a coroutine frame in a stack slot is freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 6: ref@2(*fp-8) rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void frame_spilled_at_call(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"*(u64 *)(r10 - 8) = r0;"
		"call dives;"
		COUNT(behind)
		"r1 = *(u64 *)(r10 - 8);"
		"call %[bpf_coro_frame_free];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * bpf_throw() takes the frames through the same pads. The prog has no exception callback, and
 * its pad keeps the cookie in a hidden word while it frees the frame, and returns it. The call
 * of bpf_throw() is a jump to the pad, and what was behind it is gone.
 */
SEC("tc")
__description("coro unwind: a coroutine frame is freed when the prog throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3) __log_level(2)
__msg("landing pad of bpf_throw at 7: ref@2(r6) rcu=0 preempt=0")
__xlated("r6 = r0")
__xlated("r1 = 3")
__xlated("gotol pc+0")
__xlated("*(u64 *)(r10 -8) = r1")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -8)")
__xlated("exit")
__naked void frame_at_throw(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		"r1 = 3;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_throw)
		: __clobber_all
	);
}

/*
 * The prog did not test the frame since bpf_coro_frame_alloc() returned it: there may be
 * none. The pad makes the test and leaves the call out for NULL.
 */
SEC("tc")
__description("coro unwind: a coroutine frame that may be NULL is tested and freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 4: ref@2(r6) if not 0 rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void frame_maybe_null_at_call(void)
{
	asm volatile (
		"r1 = 16;"
		"r2 = 0;"
		"call %[bpf_coro_frame_alloc];"
		"r6 = r0;"
		"call dives;"
		COUNT(behind)
		"if r6 == 0 goto 1f;"
		FRAME_FREE(r6)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm_addr(behind)
		: __clobber_all
	);
}
