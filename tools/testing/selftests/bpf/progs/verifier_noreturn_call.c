// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

/*
 * A subprog may end with a call that doesn't return: of bpf_throw, of
 * __bpf_trap, or of a subprog that doesn't return on any path. llvm emits
 * nothing after a call of a noreturn function, so in C++ a landing pad ends
 * with a call of std::terminate(), and std::terminate() with a call of abort().
 *
 * libbpf lays the subprogs out after the main prog in the order in which it
 * finds the calls of them, depth first.
 */

#define unwind_goto(off) ".8byte %[insn_unwind_goto_" #off "];"
#define __imm_unwind_goto(off) \
	__imm_insn(insn_unwind_goto_##off, \
		   BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, off, 0))
#define unwind_exit ".8byte %[insn_unwind_exit];"
#define __imm_unwind_exit \
	__imm_insn(insn_unwind_exit, \
		   BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))

/* as in bpf_experimental.h, which can't be used together with linux/bpf.h */
#define __exception_cb(name) __attribute__((btf_decl_tag("exception_callback:" #name)))

extern void bpf_throw(__u64 cookie) __ksym;
extern void __bpf_trap(void) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} prog_array SEC(".maps");

__naked __noinline __used
static void throws_7(void)
{
	asm volatile (
		"r1 = 7;"
		"call %[bpf_throw];"
		:
		: __imm(bpf_throw)
	);
}

__naked __noinline __used
static void calls_throws_7(void)
{
	asm volatile (
		"call throws_7;"
	);
}

__naked __noinline __used
static void calls_calls_throws_7(void)
{
	asm volatile (
		"r6 = 1;"
		"call calls_throws_7;"
	);
}

/* What abort() compiles to. The trap and the exit are dead code. */
__naked __noinline __used
static void abort_like(void)
{
	asm volatile (
		"r1 = 9;"
		"call %[bpf_throw];"
		"call %[__bpf_trap];"
		"exit;"
		:
		: __imm(bpf_throw),
		  __imm(__bpf_trap)
	);
}

/* What std::terminate() compiles to */
__naked __noinline __used
int global_terminate(void)
{
	asm volatile (
		"call abort_like;"
	);
}

__naked __noinline __used
int global_throws_13(void)
{
	asm volatile (
		"r1 = 13;"
		"call %[bpf_throw];"
		:
		: __imm(bpf_throw)
	);
}

__naked __noinline __used
static void calls_global_throws_13(void)
{
	asm volatile (
		"call global_throws_13;"
	);
}

__naked __noinline __used
static int returns_0(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
	);
}

__naked __noinline __used
static void calls_returns_0(void)
{
	asm volatile (
		"call returns_0;"
	);
}

__naked __noinline __used
int global_returns_0(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
	);
}

__naked __noinline __used
static void calls_global_returns_0(void)
{
	asm volatile (
		"call global_returns_0;"
	);
}

/* A taken tail call leaves the subprog like an exit does */
__naked __noinline __used
static int tail_calls_then_throws(void)
{
	asm volatile (
		"r2 = %[prog_array] ll;"
		"r3 = 0;"
		"call %[bpf_tail_call];"
		"r1 = 1;"
		"call %[bpf_throw];"
		:
		: __imm_addr(prog_array),
		  __imm(bpf_tail_call),
		  __imm(bpf_throw)
	);
}

__naked __noinline __used
static void calls_tail_calls_then_throws(void)
{
	asm volatile (
		"call tail_calls_then_throws;"
	);
}

__naked __noinline __used
static void throws_11_then_traps(void)
{
	asm volatile (
		"r1 = 11;"
		"call %[bpf_throw];"
		"call %[__bpf_trap];"
		:
		: __imm(bpf_throw),
		  __imm(__bpf_trap)
	);
}

__naked __noinline __used
static void traps(void)
{
	asm volatile (
		"call %[__bpf_trap];"
		:
		: __imm(__bpf_trap)
	);
}

__naked __noinline __used
static void calls_helper(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		:
		: __imm(bpf_get_prandom_u32)
	);
}

SEC("tc")
__description("noreturn: a subprog ends with a call of bpf_throw")
__arch_x86_64
__arch_arm64
__arch_s390x
__success __retval(7)
__naked int ends_with_throw(void)
{
	asm volatile (
		"call throws_7;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("noreturn: a chain of subprogs that end with calls")
__arch_x86_64
__arch_arm64
__arch_s390x
__success __retval(7)
__naked int ends_with_call_chain(void)
{
	asm volatile (
		"call calls_calls_throws_7;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

/* main, throws_7, then calls_throws_7, whose call is the last insn */
SEC("tc")
__description("noreturn: the last insn of the prog is a call")
__arch_x86_64
__arch_arm64
__arch_s390x
__log_level(2)
__msg("func#1 @4")
__msg("func#2 @6")
__success __retval(7)
__naked int last_insn_is_call(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
		"if r6 < 100 goto 1f;"
		"call throws_7;"
	"1:"
		"call calls_throws_7;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

SEC("tc")
__description("noreturn: the exit after bpf_throw doesn't make a subprog return")
__arch_x86_64
__arch_arm64
__arch_s390x
__success __retval(9)
__naked int exit_after_throw(void)
{
	asm volatile (
		"call global_terminate;"
		::: __clobber_all
	);
}

SEC("tc")
__description("noreturn: a subprog ends with a call of a global subprog that throws")
__arch_x86_64
__arch_arm64
__arch_s390x
__success __retval(13)
__naked int ends_with_global_throw(void)
{
	asm volatile (
		"call calls_global_throws_13;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

/* The verifier doesn't follow the global subprog */
SEC("tc")
__description("noreturn: nothing after a call of a global subprog that throws is checked")
__arch_x86_64
__arch_arm64
__arch_s390x
__success __retval(13)
__naked int dead_code_after_global_throw(void)
{
	asm volatile (
		"call global_throws_13;"
		"r0 = r1;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * The call is described for the unwinder like a bpf_throw: when the callee
 * throws, the unwinder releases the reference the caller holds, and the
 * exception callback returns the cookie.
 */
SEC("tc")
__description("noreturn: a reference held across a final call of a global subprog")
__arch_x86_64
__arch_arm64
__success __retval(13)
__naked int global_throw_with_reference(void)
{
	asm volatile (
		"r2 = 0;"
		"*(u32 *)(r10 - 8) = r2;"
		"*(u64 *)(r10 - 16) = r2;"
		"*(u64 *)(r10 - 24) = r2;"
		"*(u64 *)(r10 - 32) = r2;"
		"*(u64 *)(r10 - 40) = r2;"
		"*(u64 *)(r10 - 48) = r2;"
		"r2 = r10;"
		"r2 += -48;"
		"r3 = %[sizeof_bpf_sock_tuple];"
		"r4 = 0;"
		"r5 = 0;"
		"call %[bpf_sk_lookup_tcp];"
		"r6 = r0;"
		"call global_throws_13;"
		:
		: __imm(bpf_sk_lookup_tcp),
		  __imm_const(sizeof_bpf_sock_tuple, sizeof(struct bpf_sock_tuple))
		: __clobber_all
	);
}

/* The unwinder leaves the RCU section the caller is in at the call. */
SEC("tc")
__description("noreturn: RCU read lock held across a final call of a global subprog")
__arch_x86_64
__arch_arm64
__success __retval(13)
__naked int global_throw_under_rcu(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call global_throws_13;"
		:
		: __imm(bpf_rcu_read_lock)
		: __clobber_all
	);
}

SEC("tc")
__description("noreturn: a subprog ends with a call of a subprog that returns")
__failure __msg("calls func#{{[0-9]+}} ('returns_0'), which might return")
__naked int ends_with_call_that_returns(void)
{
	asm volatile (
		"call calls_returns_0;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("noreturn: a subprog ends with a call of a global subprog that returns")
__failure __msg("calls func#{{[0-9]+}} ('global_returns_0'), which might return")
__naked int ends_with_global_call_that_returns(void)
{
	asm volatile (
		"call calls_global_returns_0;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

/* An unwind_exit returns to the unwind_goto after the call, like an exit */
__naked __noinline __used
static void only_unwinds(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

__naked __noinline __used
static void calls_only_unwinds(void)
{
	asm volatile (
		"call only_unwinds;"
	);
}

SEC("tc")
__description("noreturn: a subprog ends with a call of a subprog that only unwinds")
__arch_x86_64
__arch_arm64
__failure __msg("calls func#{{[0-9]+}} ('only_unwinds'), which might unwind")
__naked int ends_with_call_that_unwinds(void)
{
	asm volatile (
		"call calls_only_unwinds;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("noreturn: a subprog that tail calls might return")
__arch_x86_64
__arch_arm64
__arch_s390x
__failure __msg("calls func#{{[0-9]+}} ('tail_calls_then_throws'), which might return")
__naked int ends_with_call_of_tail_caller(void)
{
	asm volatile (
		"call calls_tail_calls_then_throws;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("noreturn: a subprog ends with a dead call of __bpf_trap")
__arch_x86_64
__arch_arm64
__arch_s390x
__success __retval(11)
__naked int ends_with_dead_trap(void)
{
	asm volatile (
		"call throws_11_then_traps;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("noreturn: a subprog ends with a call of __bpf_trap that is reached")
__failure __msg("unexpected __bpf_trap() due to uninitialized variable?")
__naked int ends_with_live_trap(void)
{
	asm volatile (
		"call traps;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("noreturn: a subprog cannot end with a call of a helper")
__failure __msg("last insn is not an exit or jmp")
__naked int ends_with_helper_call(void)
{
	asm volatile (
		"call calls_helper;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * The callback isn't a jump target, as nothing calls it. It isn't __naked,
 * as BTF of a global function has to name its argument.
 */
__noinline int exception_cb_starts_with_unwind_goto(__u64 cookie)
{
	asm volatile (
		unwind_goto(1)
		"r0 = 1;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
	return 0;
}

/* main, throws_7, calls_throws_7, then the exception callback */
SEC("tc")
__description("noreturn: unwind_goto after a call that ends the previous subprog")
__arch_x86_64
__arch_arm64
__exception_cb(exception_cb_starts_with_unwind_goto)
__failure __msg("unwind_goto at insn 7 doesn't follow a call of a subprog")
__naked int unwind_goto_after_final_call(void)
{
	asm volatile (
		"call throws_7;"
		"call calls_throws_7;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * The path ends at the exception exit inside the loop, before the verifier
 * has made a checkpoint in it.
 */
SEC("tc")
__description("noreturn: bpf_throw ends a path inside a loop")
__arch_x86_64
__arch_arm64
__arch_s390x
__success __retval(3)
__naked int throw_in_loop(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
	"1:"
		"r1 = 3;"
		"call %[bpf_throw];"
		"if r6 != 0 goto 1b;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm(bpf_throw)
		: __clobber_all
	);
}

SEC("tc")
__description("noreturn: a call of a global subprog that throws ends a path inside a loop")
__arch_x86_64
__arch_arm64
__arch_s390x
__success __retval(13)
__naked int global_throw_in_loop(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
	"1:"
		"call global_throws_13;"
		"if r6 != 0 goto 1b;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

/*
 * llvm lays out a block that ends with a call of a function that doesn't
 * return like any other, here the one at 1, and jumps to it from several
 * places. The edge after the call is then a loop in the CFG that never runs.
 */
SEC("tc")
__description("noreturn: an edge after a call that doesn't return makes a loop")
__arch_x86_64
__arch_arm64
__arch_s390x
__success __retval(13)
__naked int loop_through_noreturn_call(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
		"if r6 < 100 goto 2f;"
	"1:"
		"call throws_7;"
	"2:"
		"call global_throws_13;"
		"if r6 > 200 goto 1b;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

/*
 * BTF FUNC records are not generated for kfuncs referenced
 * from inline assembly. These records are necessary for
 * libbpf to link the program. The function below is a hack
 * to ensure that BTF FUNC records are generated.
 */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_throw(0);
}

char _license[] SEC("license") = "GPL";
