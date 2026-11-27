// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

/*
 * A frame that the kernel unwinds leaves with kexit, which goes to kgoto after the call: insns
 * that only the verifier emits. unwind_goto of the program is for unwind_exit, which the program
 * has. So a landing pad of the program is not entered when the kernel unwinds, and cannot end
 * that. See prog_tests/kunwind.c for what runs and what is released.
 */
#define unwind_goto(off) ".8byte %[insn_unwind_goto_" #off "];"
#define unwind_exit ".8byte %[insn_unwind_exit];"

#define __imm_unwind_goto(off) \
	__imm_insn(insn_unwind_goto_##off, \
		   BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, off, 0))
#define __imm_unwind_exit \
	__imm_insn(insn_unwind_exit, \
		   BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))
#define __exception_cb(name) __attribute__((btf_decl_tag("exception_callback:" #name)))

/* src_reg of the two insns: one more than the uapi has, see include/linux/filter.h */
#define BPF_KGOTO	2
#define BPF_KEXIT	2

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern void bpf_throw(__u64 cookie) __ksym;

/* kfuncs that only asm calls need BTF */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_throw(0);
}

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long one = 1;
unsigned long two = 2;

/*
 * r1 == 0: returns 7. r1 == 1: a loop that nothing ends, the kernel unwinds it when its time is
 * up. Otherwise it leaves with unwind_exit, r0 = 5.
 */
__naked __noinline __used
static unsigned long leaves(void)
{
	asm volatile (
		"if r1 == 0 goto 2f;"
		"if r1 != 1 goto 3f;"
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	"2:	r0 = 7;"
		"exit;"
	"3:	r0 = 5;"
		unwind_exit
		:: __imm_addr(one), __imm_unwind_exit : __clobber_all);
}

/*
 * The call has unwind_goto of the prog, and gets kgoto behind it. Neither is code: what follows the
 * native call is 'r0 = 7'. The pad of the verifier returns TC_ACT_SHOT.
 */
#define LEAVES(name, how)						\
__naked void name(void)							\
{									\
	asm volatile (							\
		"r1 = %[" #how "] ll;"					\
		"r1 = *(u64 *)(r1 + 0);"				\
		"r2 = 0x1234;"						\
		"call leaves;"						\
		unwind_goto(2)						\
		"r0 = 7;"						\
		"exit;"							\
		"r0 += 37;"						\
		"exit;"							\
		:: __imm_addr(how), __imm_unwind_goto(2) : __clobber_all); \
}

SEC("tc")
__description("kunwind: kexit goes to kgoto, past unwind_goto of the prog")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__xlated("...")
__xlated("r2 = 4660")
__xlated("call pc+")
__xlated("unwind_goto pc+3")
__xlated("kgoto pc+4")
__xlated("r0 = 7")
__xlated("exit")
__xlated("r0 += 37")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
/* leaves() */
__xlated("...")
__xlated("r0 = 5")
__xlated("unwind_exit")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__arch_x86_64
__jited("	movl	$0x1234, %esi")
__jited("...") /* call depth accounting */
__jited("	callq	0x{{.*}}")
__jited("	movl	$0x7, %eax")
__arch_arm64
__jited("	mov	x1, #0x1234")
__jited("	bl	{{.*}}")
__jited("	mov	x8, x0")
__jited("	mov	x8, #0x7")
LEAVES(kexit_past_unwind_goto, one)

SEC("tc")
__description("kunwind: unwind_exit goes to unwind_goto of the same call")
__success __retval(42)
__load_if_JITed()
__arch_x86_64 __arch_arm64
LEAVES(unwind_exit_to_unwind_goto, two)

SEC("tc")
__description("kunwind: the call returns")
__success __retval(7)
__load_if_JITed()
__arch_x86_64 __arch_arm64
LEAVES(call_returns, zero)

/* The same, and a frame of 200 bytes: a tracing prog gets a private stack */
__naked __noinline __used
static unsigned long leaves_big_stack(void)
{
	asm volatile (
		"*(u64 *)(r10 - 200) = r1;"
		"if r1 == 0 goto 2f;"
		"if r1 != 1 goto 3f;"
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	"2:	r0 = 7;"
		"exit;"
	"3:	r0 = 5;"
		unwind_exit
		:: __imm_addr(one), __imm_unwind_exit : __clobber_all);
}

/*
 * x86-64 keeps the pointer to the private stack in r9 and saves it around a call: 'pop r9' follows
 * the native call, and each pad needs it done. The landings that do it stand behind the last insn
 * of the prog: what returns goes on with the next insn of the prog, with no jump over them.
 */
#define LEAVES_PRIVATE_STACK(name, how)					\
__naked void name(void)							\
{									\
	asm volatile (							\
		"*(u64 *)(r10 - 200) = 42;"				\
		"r1 = %[" #how "] ll;"					\
		"r1 = *(u64 *)(r1 + 0);"				\
		"r2 = 0x1234;"						\
		"call leaves_big_stack;"				\
		unwind_goto(3)						\
		"r1 = *(u64 *)(r10 - 200);"				\
		"r0 += r1;"						\
		"exit;"							\
		"r1 = *(u64 *)(r10 - 200);"				\
		"r0 += r1;"						\
		"r0 += 100;"						\
		"exit;"							\
		:: __imm_addr(how), __imm_unwind_goto(3) : __clobber_all); \
}

SEC("raw_tp")
__description("kunwind: private stack, kexit goes to kgoto")
__success __retval(0)
__load_if_JITed()
__arch_x86_64
__jited("	movl	$0x1234, %esi")
__jited("	pushq	%r9")
__jited("...") /* call depth accounting */
__jited("	callq	0x{{.*}}")
__jited("	popq	%r9")
__jited("	movq	-0xc8(%r9), %rdi")
__jited("...")
__jited("	popq	%r9")
__jited("	jmp	L{{.*}}")
__jited("	popq	%r9")
__jited("	jmp	L{{.*}}")
__arch_arm64
LEAVES_PRIVATE_STACK(private_stack_kexit, one)

SEC("raw_tp")
__description("kunwind: private stack, unwind_exit goes to unwind_goto")
__success __retval(147)
__load_if_JITed()
__arch_x86_64 __arch_arm64
LEAVES_PRIVATE_STACK(private_stack_unwind_exit, two)

SEC("raw_tp")
__description("kunwind: private stack, the call returns")
__success __retval(49)
__load_if_JITed()
__arch_x86_64 __arch_arm64
LEAVES_PRIVATE_STACK(private_stack_returns, zero)

/* kgoto alone: the prog has no unwind_goto, and nothing leaves with unwind_exit */
__naked __noinline __used
static unsigned long spins(void)
{
	asm volatile (
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind: kgoto alone is no code behind the call")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__xlated("...")
__xlated("r2 = 4660")
__xlated("call pc+")
__xlated("kgoto pc+2")
__xlated("r0 = 9")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
__arch_x86_64
__jited("	movl	$0x1234, %esi")
__jited("...") /* call depth accounting */
__jited("	callq	0x{{.*}}")
__jited("	movl	$0x9, %eax")
__arch_arm64
__jited("	mov	x1, #0x1234")
__jited("	bl	{{.*}}")
__jited("	mov	x8, x0")
__jited("	mov	x8, #0x9")
__naked void kgoto_alone(void)
{
	asm volatile (
		"r2 = 0x1234;"
		"call spins;"
		"r0 = 9;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long spins_big_stack(void)
{
	asm volatile (
		"*(u64 *)(r10 - 200) = r1;"
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:: __imm_addr(one) : __clobber_all);
}

SEC("raw_tp")
__description("kunwind: private stack, kgoto alone")
__success __retval(0)
__load_if_JITed()
__arch_x86_64
__jited("	movl	$0x1234, %esi")
__jited("	pushq	%r9")
__jited("...") /* call depth accounting */
__jited("	callq	0x{{.*}}")
__jited("	popq	%r9")
__jited("	movq	-0xc8(%r9), %rdi")
__jited("...")
__jited("	popq	%r9")
__jited("	jmp	L{{.*}}")
__arch_arm64
__naked void private_stack_kgoto_alone(void)
{
	asm volatile (
		"*(u64 *)(r10 - 200) = 42;"
		"r2 = 0x1234;"
		"call spins_big_stack;"
		"r1 = *(u64 *)(r10 - 200);"
		"r0 += r1;"
		"exit;"
		::: __clobber_all);
}

/*
 * Nothing leaves the callee with unwind_exit: the pad of the prog is dead code, and unwind_goto of
 * the prog, which is never taken, goes with it. kgoto stays behind the call.
 */
SEC("socket")
__description("kunwind: unwind_goto of the prog is never taken, kgoto stays behind the call")
__success __retval(0)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__xlated("...")
__xlated("call pc+4")
__xlated("kgoto pc+1")
__xlated("exit")
__xlated("r0 = 0")
__xlated("exit")
__naked void unwind_goto_never_taken(void)
{
	asm volatile (
		"call spins;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:: __imm_unwind_goto(1) : __clobber_all);
}

__naked __noinline __used
static unsigned long always_throws(void)
{
	asm volatile ("r1 = 9; call %[bpf_throw]; exit;" :: __imm(bpf_throw) : __clobber_all);
}

/*
 * Nothing gets to unwind_goto of the prog: the callee neither returns nor leaves with unwind_exit.
 * It is dead code and so is the pad of the prog. kgoto stands behind the call, and a trap behind
 * that, where the unwind_goto was.
 */
SEC("tc")
__description("kunwind: unwind_goto of the prog is dead code, kgoto stays behind the call")
__success __retval(9)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__xlated("0: call pc+")
__xlated("1: kgoto pc+1")
__xlated("2: goto pc-1")
__xlated("3: exit")
__naked void dead_unwind_goto(void)
{
	asm volatile (
		"call always_throws;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:: __imm_unwind_goto(1) : __clobber_all);
}

/* What the frames hold is released by the pads of the verifier, in each frame once */
__naked __noinline __used
static unsigned long spins_in_section(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call spins;"
		"r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

/* The pad of the prog would leave one section and return in the other. It is not entered. */
SEC("tc")
__description("kunwind: the pad of the prog does not leave its sections, the pad of kgoto does")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of call at 2: rcu=2 preempt=0")
__msg("landing pad of call at {{[0-9]+}}: rcu=1 preempt=0")
__naked void pad_of_prog_leaks(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call %[bpf_rcu_read_lock];"
		"call spins_in_section;"
		unwind_goto(4)
		"call %[bpf_rcu_read_unlock];"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 7;"
		"exit;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 42;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock), __imm_unwind_goto(4)
		: __clobber_all);
}

/* The same pad is checked for unwind_exit, which gets to it */
__naked __noinline __used
static unsigned long unwinds_at_once(void)
{
	asm volatile ("r0 = 5;" unwind_exit :: __imm_unwind_exit : __clobber_all);
}

SEC("tc")
__description("kunwind: the pad of the prog does not leave its sections, unwind_exit gets to it")
__failure __msg("cannot be used inside bpf_rcu_read_lock-ed region")
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void pad_of_prog_leaks_unwind_exit(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call %[bpf_rcu_read_lock];"
		"call unwinds_at_once;"
		unwind_goto(4)
		"call %[bpf_rcu_read_unlock];"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 7;"
		"exit;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 42;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock), __imm_unwind_goto(4)
		: __clobber_all);
}

/*
 * A frame in between has no landing pad of its own: the verifier emits one for unwind_exit of the
 * callee as well, which leaves the section and passes on what unwind_exit left, to the pad of the
 * prog. In a prog without bpf_throw() too, and what it left need not be a number.
 */
__naked __noinline __used
static unsigned long unwinds_with_pointer(void)
{
	asm volatile ("r0 = %[two] ll;" unwind_exit
		      :: __imm_addr(two), __imm_unwind_exit : __clobber_all);
}

__naked __noinline __used
static unsigned long in_between(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call unwinds_with_pointer;"
		"r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

SEC("tc")
__description("kunwind: what unwind_exit left gets through a pad of the verifier")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of call at {{[0-9]+}} for unwind_exit: rcu=1 preempt=0")
/* in_between(): nothing comes back from its call but by unwind_exit */
__xlated("...")
__xlated("call kernel-function")
__xlated("call pc+")
__xlated("unwind_goto pc+1")
__xlated("goto pc-1")
__xlated("*(u64 *)(r10 -8) = r0")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -8)")
__xlated("unwind_exit")
__naked void value_through_pad(void)
{
	asm volatile (
		"call in_between;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 = *(u64 *)(r0 + 0);"
		"exit;"
		:: __imm_unwind_goto(2) : __clobber_all);
}

/* A subprog that returns two registers leaves with both, and the pad in between keeps both */
struct pair {
	__u64 a;
	__u64 b;
};

__naked __noinline __used
static struct pair unwinds_with_pair(void)
{
	asm volatile ("r0 = 5; r2 = 6;" unwind_exit :: __imm_unwind_exit : __clobber_all);
}

__naked __noinline __used
static struct pair pair_in_between(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call unwinds_with_pair;"
		"r6 = r0;"
		"r7 = r2;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"r2 = r7;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

SEC("tc")
__description("kunwind: both registers of unwind_exit get through a pad of the verifier")
__success __retval(11)
__load_if_JITed()
__arch_x86_64 __arch_arm64
/* pair_in_between() */
__xlated("...")
__xlated("call kernel-function")
__xlated("call pc+")
__xlated("unwind_goto pc+1")
__xlated("goto pc-1")
__xlated("*(u64 *)(r10 -16) = r0")
__xlated("*(u64 *)(r10 -8) = r2")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -16)")
__xlated("r2 = *(u64 *)(r10 -8)")
__xlated("unwind_exit")
__naked void pair_through_pad(void)
{
	asm volatile (
		"call pair_in_between;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += r2;"
		"exit;"
		:: __imm_unwind_goto(2) : __clobber_all);
}

/*
 * The callers of a global subprog are verified without it, and what comes out of it is a number to
 * them. What unwind_exit of a callee left in r0 need not be one, and r2 of a callee that returns
 * one register is what it happened to be. So a pad of the verifier in a global subprog passes
 * nothing on: r0 comes with the value of the kernel, TC_ACT_SHOT here, and r2 as 0.
 */
__noinline struct pair global_pair_in_between(void)
{
	return unwinds_with_pair();
}

SEC("tc")
__description("kunwind: out of a pad of the verifier in a global subprog r0 is the value of the kernel, r2 is 0")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
/*
 * global_pair_in_between() follows the prog: nothing comes back from its call but by unwind_exit.
 * So it never returns, and what follows its call in the prog is dead code in turn: a trap stands
 * behind unwind_goto there too.
 */
__xlated("0: call pc+4")
__xlated("1: unwind_goto pc+1")
__xlated("2: goto pc-1")
__xlated("3: r0 += r2")
__xlated("4: exit")
__xlated("5: call pc+5")
__xlated("6: unwind_goto pc+1")
__xlated("7: goto pc-1")
__xlated("8: r0 = 2")
__xlated("9: r2 = 0")
__xlated("10: unwind_exit")
__naked void pair_through_global(void)
{
	asm volatile (
		"call global_pair_in_between;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += r2;"
		"exit;"
		:: __imm_unwind_goto(2) : __clobber_all);
}

/*
 * The pointer that unwind_exit left does not get out of the global subprog: the pad of the prog
 * above reads a number. A prog with such a frame loads, as it does when the frame returns nothing.
 */
__noinline unsigned long global_in_between(void)
{
	return unwinds_with_pointer();
}

SEC("tc")
__description("kunwind: a pointer of unwind_exit does not get out of a global subprog")
__success __retval(42)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void pointer_through_global(void)
{
	asm volatile (
		"call global_in_between;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += 40;"
		"exit;"
		:: __imm_unwind_goto(2) : __clobber_all);
}

/* Nor does a register that the callee has not written */
__naked __noinline __used
static unsigned long unwinds_with_nothing(void)
{
	asm volatile (unwind_exit :: __imm_unwind_exit : __clobber_all);
}

__noinline unsigned long global_in_between_nothing(void)
{
	return unwinds_with_nothing();
}

SEC("tc")
__description("kunwind: r0 that unwind_exit left unwritten does not get out of a global subprog")
__success __retval(42)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void nothing_through_global(void)
{
	asm volatile (
		"call global_in_between_nothing;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += 40;"
		"exit;"
		:: __imm_unwind_goto(2) : __clobber_all);
}

/*
 * In a prog with bpf_throw() the pads of the sites of the kernel pass the value on, the cookie.
 * A pad of the verifier in a global subprog that unwind_exit comes back to does not, there as in
 * any other prog: the callers get the value of the kernel, also out of a subprog that returns
 * nothing, and a pointer that unwind_exit left is no error.
 */
__noinline void global_void_in_between(void)
{
	unwinds_with_pointer();
}

__noinline int returns_cookie(__u64 cookie)
{
	return cookie;
}

SEC("tc")
__description("kunwind: a pointer of unwind_exit does not get out of a global subprog in a prog that throws")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__exception_cb(returns_cookie)
__naked void pointer_through_global_throws(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 1f;"
		"r1 = 0;"
		"call %[bpf_throw];"
	"1:	call global_void_in_between;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		"r0 &= 0xfff;"
		"exit;"
		:: __imm_addr(zero), __imm(bpf_throw), __imm_unwind_goto(2) : __clobber_all);
}

/*
 * Nor does a number: what a pad of the verifier in a global subprog leaves does not depend on
 * bpf_throw() being somewhere in the prog. The pad of the prog reads TC_ACT_SHOT, not 5.
 */
__naked __noinline __used
static unsigned long unwinds_with_5(void)
{
	asm volatile ("r0 = 5;" unwind_exit :: __imm_unwind_exit : __clobber_all);
}

__noinline unsigned long global_in_between_5(void)
{
	return unwinds_with_5();
}

SEC("tc")
__description("kunwind: a number of unwind_exit does not get out of a global subprog in a prog that throws")
__success __retval(42)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void number_through_global_throws(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 1f;"
		"r1 = 0;"
		"call %[bpf_throw];"
	"1:	call global_in_between_5;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += 40;"
		"exit;"
		:: __imm_addr(zero), __imm(bpf_throw), __imm_unwind_goto(2) : __clobber_all);
}

/* may_goto of the prog: when its time is up the kernel unwinds the function */
__naked __noinline __used
static unsigned long may_goto_spins(void)
{
	asm volatile (
	"1:	may_goto 2f;"
		"goto 1b;"
	"2:	r0 = 0;"
		"exit;"
		::: __clobber_all);
}

/*
 * A known consequence: the pad of the prog behind the call leaves all nine sections, and it is not
 * entered when the kernel unwinds the callee. The pad of kgoto has to do that, and a pad of the
 * verifier leaves eight at most. The prog loaded as long as what the kernel unwound went to
 * unwind_goto of the prog, and it loads without landing pads, where may_goto jumps. The same holds
 * for every other limit of a pad of the verifier: a call that has a pad of the prog needs one that
 * the verifier can make as well.
 */
SEC("tc")
__description("kunwind: the pad of the prog would do for the call, the pad of kgoto holds too much")
__failure
__msg("what the call at {{[0-9]+}} calls is left at: may_goto of the program")
__msg("landing pad of call at {{[0-9]+}}: conflict: too much is held")
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void pad_of_prog_is_not_enough(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"call may_goto_spins;"
		unwind_goto(11)
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = 7;"
		"exit;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = 42;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock), __imm_unwind_goto(11)
		: __clobber_all);
}

/*
 * A pad of the verifier that passes on what unwind_exit left keeps it in a hidden word of the stack
 * over its calls. A pad without a call needs none: r0 stays where it is, also in a frame that has
 * used up its stack.
 */
__naked __noinline __used
static unsigned long full_stack_in_between(void)
{
	asm volatile (
		"*(u64 *)(r10 - 2048) = 1;"
		"call unwinds_at_once;"
		"exit;"
		::: __clobber_all);
}

SEC("tc")
__description("kunwind: a pad of the verifier without a call takes no word of the stack")
__success __retval(47)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(4) __msg("stack depth max 2048")
/* full_stack_in_between(): its pad is unwind_exit alone */
__xlated("...")
__xlated("*(u64 *)(r10 -2048) = 1")
__xlated("call pc+")
__xlated("unwind_goto pc+1")
__xlated("goto pc-1")
__xlated("unwind_exit")
__naked void value_through_full_stack(void)
{
	asm volatile (
		"call full_stack_in_between;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += 42;"
		"exit;"
		:: __imm_unwind_goto(2) : __clobber_all);
}

/* With a call the pad needs the word, and such a frame has no room for it */
__naked __noinline __used
static unsigned long full_stack_in_section(void)
{
	asm volatile (
		"*(u64 *)(r10 - 2048) = 1;"
		"call %[bpf_rcu_read_lock];"
		"call unwinds_at_once;"
		"r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

SEC("tc")
__description("kunwind: no room in the stack for what a pad of the verifier passes on")
__failure
__msg("landing pad of call at {{[0-9]+}} for unwind_exit: conflict: no room in the stack for the value")
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void no_room_for_value(void)
{
	asm volatile (
		"call full_stack_in_section;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += 42;"
		"exit;"
		:: __imm_unwind_goto(2) : __clobber_all);
}

/* It returns 7 or leaves with unwind_exit, by what is in memory */
__naked __noinline __used
static unsigned long unwinds_or_returns(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto +2;"
		"r0 = 5;"
		unwind_exit
		"r0 = 7;"
		"exit;"
		:: __imm_addr(zero), __imm_unwind_exit : __clobber_all);
}

__naked __noinline __used
static unsigned long uses_up_stack(void)
{
	asm volatile (
		"*(u64 *)(r10 - 2048) = 1;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

/*
 * As many calls as it takes to see the time, each with a pad of the verifier that needs the word.
 * The frame that uses up the stack is one of a callee, which keeps the states of the verifier
 * small. Whether the stack has room for the word is asked of the whole program, and it is asked
 * once for the function, not once per call.
 */
__naked __noinline __used
static unsigned long many_calls_in_section(void)
{
	asm volatile (
		"call uses_up_stack;"
		"call %[bpf_rcu_read_lock];"
		".rept 8000;"
		"call unwinds_or_returns;"
		".endr;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

/*
 * The test asserts no time: it fails in the same way on a kernel that asks once per call, after
 * 8000 walks over the program per pass.
 */
SEC("tc")
__description("kunwind: no room in the stack for the value at many calls of one function")
__failure
__msg("landing pad of call at {{[0-9]+}} for unwind_exit: conflict: no room in the stack for the value")
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void no_room_for_value_at_many_calls(void)
{
	asm volatile (
		"call many_calls_in_section;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += 42;"
		"exit;"
		:: __imm_unwind_goto(2) : __clobber_all);
}

/* A global subprog passes nothing on, see above: its pad loads the value and needs no word */
__noinline unsigned long global_full_stack_in_section(void)
{
	unsigned long ret;

	asm volatile ("*(u64 *)(r10 - 2048) = 1;");
	bpf_rcu_read_lock();
	ret = unwinds_at_once();
	bpf_rcu_read_unlock();
	return ret;
}

SEC("tc")
__description("kunwind: a pad of the verifier in a global subprog takes no word of the stack")
__success __retval(42)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void global_full_stack(void)
{
	asm volatile (
		"call global_full_stack_in_section;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += 40;"
		"exit;"
		:: __imm_unwind_goto(2) : __clobber_all);
}

/* Returns 1 to end the loop, spins, or leaves with unwind_exit. r1 is the index. */
__naked __noinline __used
static unsigned long cb_leaves(void)
{
	asm volatile (
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 == 0 goto 2f;"
		"if r1 != 1 goto 3f;"
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	"2:	r0 = 1;"
		"exit;"
	"3:	r0 = 5;"
		unwind_exit
		:: __imm_addr(one), __imm_unwind_exit : __clobber_all);
}

/*
 * The loop is inlined: the call of the callback has unwind_goto and kgoto, each with a pad that
 * brings r6-r8 back and goes where the insn after the call of bpf_loop() went.
 */
#define LOOP_LEAVES(name, how)						\
__naked void name(void)							\
{									\
	asm volatile (							\
		"r6 = 30;"						\
		"r1 = %[" #how "] ll;"					\
		"r1 = *(u64 *)(r1 + 0);"				\
		"*(u64 *)(r10 - 8) = r1;"				\
		"r1 = 3;"						\
		"r2 = %[cb_leaves] ll;"					\
		"r3 = r10;"						\
		"r3 += -8;"						\
		"r4 = 0;"						\
		"call %[bpf_loop];"					\
		unwind_goto(2)						\
		"r0 += r6;"						\
		"exit;"							\
		"r0 += r6;"						\
		"r0 += 7;"						\
		"exit;"							\
		:: __imm_addr(how), __imm_addr(cb_leaves), __imm(bpf_loop), \
		   __imm_unwind_goto(2) : __clobber_all);		\
}

SEC("tc")
__description("kunwind: the inlined bpf_loop() has a pad for kexit of its callback")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__xlated("...")
__xlated("r6 = *(u64 *)(r10 -32)")
__xlated("r7 = *(u64 *)(r10 -24)")
__xlated("r8 = *(u64 *)(r10 -16)")
__xlated("gotol pc+")
__xlated("r6 = *(u64 *)(r10 -32)")
__xlated("r7 = *(u64 *)(r10 -24)")
__xlated("r8 = *(u64 *)(r10 -16)")
__xlated("gotol pc+")
__xlated("...")
__xlated("call pc+")
__xlated("unwind_goto pc-19")
__xlated("kgoto pc-16")
__xlated("r7 += 1")
LOOP_LEAVES(loop_cb_kexit, one)

SEC("tc")
__description("kunwind: the inlined bpf_loop() still has a pad for unwind_exit of its callback")
__success __retval(42)
__load_if_JITed()
__arch_x86_64 __arch_arm64
LOOP_LEAVES(loop_cb_unwind_exit, two)

SEC("tc")
__description("kunwind: the inlined bpf_loop() returns")
__success __retval(31)
__load_if_JITed()
__arch_x86_64 __arch_arm64
LOOP_LEAVES(loop_cb_returns, zero)

/* callx: the insn has two bytes on x86-64, and gets a third one for the entry of kgoto */
SEC("tc")
__description("kunwind: callx, kexit goes to kgoto")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__xlated("...")
__xlated("callx r6")
__xlated("unwind_goto pc+3")
__xlated("kgoto pc+")
__naked void callx_kexit(void)
{
	asm volatile (
		"r6 = %[leaves] ll;"
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"callx r6;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += 37;"
		"exit;"
		:: __imm_addr(leaves), __imm_addr(one), __imm_unwind_goto(2) : __clobber_all);
}

SEC("tc")
__description("kunwind: callx, unwind_exit goes to unwind_goto")
__success __retval(42)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void callx_unwind_exit(void)
{
	asm volatile (
		"r6 = %[leaves] ll;"
		"r1 = %[two] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"callx r6;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 += 37;"
		"exit;"
		:: __imm_addr(leaves), __imm_addr(two), __imm_unwind_goto(2) : __clobber_all);
}

/*
 * The exception callback is called by the pad of the main prog. It has unwind_exit, so it can
 * leave unwound, and its loop makes the kernel unwind it: the pad has kgoto for that, to its own
 * exit. The prog returns what the kernel says.
 */
__noinline int cb_spins_or_unwinds(__u64 cookie)
{
	if (cookie == 77)
		asm volatile ("r0 = 5;" unwind_exit :: __imm_unwind_exit : "r0");
	while (*(volatile unsigned long *)&one)
		;
	return 7;
}

SEC("tc")
__description("kunwind: the kernel unwinds the exception callback")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__exception_cb(cb_spins_or_unwinds)
__xlated("...")
__xlated("r1 = 2")
__xlated("call pc+")
__xlated("unwind_goto pc+1")
__xlated("kgoto pc+0")
__xlated("exit")
__naked void exception_cb_kexit(void)
{
	asm volatile (
		"call spins;"
		"exit;"
		::: __clobber_all);
}

/*
 * The same with a private stack: 'pop r9' follows the native call of the callback. Both gotos go
 * to the exit of the pad, and each way there pops r9 once, in a landing behind the last insn of
 * the prog: the exit follows the call. See prog_tests/kunwind.c for what the caller of such a prog
 * gets back.
 */
SEC("raw_tp")
__description("kunwind: private stack, each way out of the exception callback pops r9 once")
__success
__load_if_JITed()
__arch_x86_64 __arch_arm64
__exception_cb(cb_spins_or_unwinds)
__xlated("...")
__xlated("call pc+")
__xlated("unwind_goto pc+1")
__xlated("kgoto pc+0")
__xlated("exit")
__arch_x86_64
__jited("	movl	$0x4d, %edi")
__jited("...")
__jited("	pushq	%r9")
__jited("...") /* call depth accounting */
__jited("	callq	0x{{.*}}")
__jited("	popq	%r9")
__jited("L{{.*}}:	leave")
__jited("...")
__jited("	popq	%r9")
__jited("	jmp	L{{.*}}")
__jited("	popq	%r9")
__jited("	jmp	L{{.*}}")
__naked void private_stack_exception_cb(void)
{
	asm volatile (
		"*(u64 *)(r10 - 200) = 42;"
		"r1 = 77;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_throw) : __clobber_all);
}

/* Only the verifier emits the two insns */
SEC("tc")
__description("kunwind: a prog cannot have kgoto")
__failure __msg("unknown opcode e6")
__naked void kgoto_in_prog(void)
{
	asm volatile (
		"call spins;"
		".8byte %[bad];"
		"exit;"
		:: __imm_insn(bad, BPF_RAW_INSN(BPF_JMP32 | BPF_JCOND, 0, BPF_KGOTO, 0, 0))
		: __clobber_all);
}

SEC("tc")
__description("kunwind: a prog cannot have kgoto with 16 bits for the offset either")
__failure __msg("invalid may_goto imm 0")
__naked void kgoto16_in_prog(void)
{
	asm volatile (
		"call spins;"
		".8byte %[bad];"
		"exit;"
		:: __imm_insn(bad, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_KGOTO, 0, 0))
		: __clobber_all);
}

SEC("tc")
__description("kunwind: a prog cannot have kexit")
__failure __msg("BPF_EXIT uses reserved fields")
__naked void kexit_in_prog(void)
{
	asm volatile (
		"r0 = 0;"
		".8byte %[bad];"
		:: __imm_insn(bad, BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_KEXIT, 0, 0))
		: __clobber_all);
}

__naked __noinline __used
static unsigned long has_kexit(void)
{
	asm volatile (
		"r0 = 0;"
		".8byte %[bad];"
		:: __imm_insn(bad, BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_KEXIT, 0, 0))
		: __clobber_all);
}

SEC("tc")
__description("kunwind: a subprog cannot have kexit")
__failure __msg("BPF_EXIT uses reserved fields")
__naked void kexit_in_subprog(void)
{
	asm volatile (
		"call has_kexit;"
		"exit;"
		::: __clobber_all);
}

char _license[] SEC("license") = "GPL";
