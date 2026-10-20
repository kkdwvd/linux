// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for callx through a number: the address of a function that was stored
 * to memory and loaded back. The verifier doesn't check what such callx calls.
 * It verifies each function whose address is taken on its own instead. It's a
 * stopgap until there are verified pointers to functions.
 *
 * This object has no arena: libbpf binds the arena of an object to every
 * program in it, and a program with an arena may load through a number under
 * BPF_F_ARENA_SCALAR, which the tests of a callee's arguments must see refused.
 * The tests with an arena are in verifier_callx_scalar_arena.c.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../../../include/linux/filter.h"

/* callx and BPF_F_ARENA_SCALAR need a JIT that supports both */
#if defined(__clang__) && (defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64))

#define __callx_scalar __flag(BPF_F_ARENA_SCALAR) __arch_x86_64 __arch_arm64

#define unwind_goto(off) ".8byte %[insn_unwind_goto_" #off "];"
#define unwind_exit ".8byte %[insn_unwind_exit];"

#define __imm_unwind_goto(off) \
	__imm_insn(insn_unwind_goto_##off, \
		   BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, off, 0))
#define __imm_unwind_exit \
	__imm_insn(insn_unwind_exit, \
		   BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))

void bpf_preempt_disable(void) __ksym;
void bpf_preempt_enable(void) __ksym;

struct val_with_lock {
	struct bpf_spin_lock lock;
	int cnt;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct val_with_lock);
} map_lock SEC(".maps");

/* the verifier doesn't know what is in there */
unsigned long fn_slot;

/* add3(x) { return x + 3; } */
__naked __noinline __used
static unsigned long add3(void)
{
	asm volatile (
		"r0 = r1;"
		"r0 += 3;"
		"exit;"
	);
}

/* the address of add3() is stored to a global and loaded back */
SEC("socket")
__description("callx scalar: address of a function in a global")
__callx_scalar
__success __retval(8)
__naked void callx_scalar_global(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[add3] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r2 = *(u64 *)(r6 + 0);"
		"r1 = 5;"
		"callx r2;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(add3)
		: __clobber_all);
}

/* without BPF_F_ARENA_SCALAR a number is not called */
SEC("socket")
__description("callx scalar: needs BPF_F_ARENA_SCALAR")
__failure __msg("R2 has type scalar, expected func")
__naked void callx_scalar_no_flag(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[add3] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r2 = *(u64 *)(r6 + 0);"
		"r1 = 5;"
		"callx r2;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(add3)
		: __clobber_all);
}

/* r6-r9 and the stack of the caller are what they were */
SEC("socket")
__description("callx scalar: the caller keeps its stack and r6-r9")
__callx_scalar
__success __retval(57)
__naked void callx_scalar_caller_state(void)
{
	asm volatile (
		"r1 = 42;"
		"*(u64 *)(r10 - 8) = r1;"
		"r6 = 7;"
		"r7 = %[fn_slot] ll;"
		"r1 = %[add3] ll;"
		"*(u64 *)(r7 + 0) = r1;"
		"r2 = *(u64 *)(r7 + 0);"
		"r1 = 5;"
		"callx r2;"
		"r0 += r6;"
		"r1 = *(u64 *)(r10 - 8);"
		"r0 += r1;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(add3)
		: __clobber_all);
}

/* r1-r5 are clobbered */
SEC("socket")
__description("callx scalar: r1-r5 are clobbered")
__callx_scalar
__failure __msg("R1 !read_ok")
__naked void callx_scalar_clobbers_args(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[add3] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r2 = *(u64 *)(r6 + 0);"
		"r1 = 5;"
		"callx r2;"
		"r0 = r1;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(add3)
		: __clobber_all);
}

SEC("socket")
__description("callx scalar: a constant is not an address of a function")
__callx_scalar
__failure __msg("R1 is 0, not the address of a function")
__naked void callx_scalar_const(void)
{
	asm volatile (
		"r1 = 0;"
		"callx r1;"
		"exit;"
		::: __clobber_all);
}

SEC("socket")
__description("callx scalar: no function has its address taken")
__callx_scalar
__failure __msg("R2 is a number, and no function has its address taken")
__naked void callx_scalar_no_callee(void)
{
	asm volatile (
		"r2 = %[fn_slot] ll;"
		"r2 = *(u64 *)(r2 + 0);"
		"r1 = 5;"
		"callx r2;"
		"exit;"
		:
		: __imm_addr(fn_slot)
		: __clobber_all);
}

/* nothing calls it but callx of a number, and it's verified */
__naked __noinline __used
static unsigned long reads_r6(void)
{
	asm volatile (
		"r0 = r6;"
		"exit;"
	);
}

SEC("socket")
__description("callx scalar: a function only callx of a number calls is verified")
__callx_scalar
__failure __msg("R6 !read_ok")
__naked void callx_scalar_callee_verified(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[reads_r6] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r2 = *(u64 *)(r6 + 0);"
		"callx r2;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(reads_r6)
		: __clobber_all);
}

/* the arguments are numbers. There is no arena, so the load is invalid. */
__naked __noinline __used
static unsigned long deref_r1(void)
{
	asm volatile (
		"r0 = *(u64 *)(r1 + 0);"
		"exit;"
	);
}

SEC("socket")
__description("callx scalar: the arguments of the callee are numbers")
__callx_scalar
__failure __msg("R1 invalid mem access 'scalar'")
__naked void callx_scalar_callee_args(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[deref_r1] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r2 = *(u64 *)(r6 + 0);"
		"r1 = r10;"
		"r1 += -8;"
		"callx r2;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(deref_r1)
		: __clobber_all);
}

/*
 * deref_r1() is called directly with a pointer, which is valid, but its
 * address is taken too, so it's verified with a number as well.
 */
SEC("socket")
__description("callx scalar: a function called directly as well is verified on its own")
__callx_scalar
__failure __msg("R1 invalid mem access 'scalar'")
__naked void callx_scalar_callee_called_directly(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = r10;"
		"r1 += -8;"
		"call deref_r1;"
		"r6 = %[fn_slot] ll;"
		"r1 = %[deref_r1] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r2 = *(u64 *)(r6 + 0);"
		"callx r2;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(deref_r1)
		: __clobber_all);
}

/*
 * [WIP] No callx here, but another program may call deref_r1() through the
 * address that is stored to the slot, so it's verified on its own all the
 * same, with a number for r1.
 */
SEC("socket")
__description("callx scalar: a function whose address is taken is verified without callx")
__callx_scalar
__failure __msg("R1 invalid mem access 'scalar'")
__naked void callx_scalar_addr_taken_no_callx(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[deref_r1] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(deref_r1)
		: __clobber_all);
}

/* and it's kept: what was stored is a function, not a trap */
SEC("socket")
__description("callx scalar: a function whose address is taken is verified without callx, safe")
__callx_scalar
__success __retval(7) __log_level(1)
__msg("Func#1 ('add3') is safe for any scalar args")
__naked void callx_scalar_addr_taken_no_callx_safe(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[add3] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(add3)
		: __clobber_all);
}

/*
 * [WIP] The address is taken in dead code: the verifier doesn't reach the
 * ld_imm64, and would remove the function with it, but libbpf fills a slot
 * in arena data with its address. It's verified and kept all the same.
 */
SEC("socket")
__description("callx scalar: a function whose address dead code takes is verified and kept")
__callx_scalar
__success __retval(7) __log_level(1)
__msg("Func#1 ('add3') is safe for any scalar args")
__naked void callx_scalar_addr_taken_dead(void)
{
	asm volatile (
		"r0 = 7;"
		"if r0 == 7 goto 1f;"
		"r6 = %[fn_slot] ll;"
		"r1 = %[add3] ll;"
		"*(u64 *)(r6 + 0) = r1;"
	"1:"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(add3)
		: __clobber_all);
}

/* without BPF_F_ARENA_SCALAR nothing calls a number, and the function stays unverified */
SEC("socket")
__description("callx scalar: a function whose address is taken is not verified without the flag")
__success __retval(7)
__naked void callx_scalar_addr_taken_no_flag(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[deref_r1] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(deref_r1)
		: __clobber_all);
}

/* the callee can't take the lock that the caller holds */
SEC("tc")
__description("callx scalar: not under a lock")
__callx_scalar
__failure __msg("callx of a number is not allowed while holding a lock")
__naked void callx_scalar_under_lock(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[map_lock] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 != 0 goto 1f;"
		"exit;"
	"1:"
		"r6 = r0;"
		"r7 = %[fn_slot] ll;"
		"r1 = %[add3] ll;"
		"*(u64 *)(r7 + 0) = r1;"
		"r1 = r6;"
		"call %[bpf_spin_lock];"
		"r2 = *(u64 *)(r7 + 0);"
		"r1 = 1;"
		"callx r2;"
		"r1 = r6;"
		"call %[bpf_spin_unlock];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm_addr(map_lock),
		  __imm_addr(fn_slot),
		  __imm_addr(add3)
		: __clobber_all);
}

/* calls the number in fn_slot, which may be itself */
__naked __noinline __used
static unsigned long call_slot(void)
{
	asm volatile (
		"r2 = %[fn_slot] ll;"
		"r2 = *(u64 *)(r2 + 0);"
		"callx r2;"
		"exit;"
		:
		: __imm_addr(fn_slot)
		: __clobber_all);
}

SEC("socket")
__description("callx scalar: callee that has callx of a number may recurse")
__callx_scalar
__failure __msg("recursive call from call_slot() to call_slot()")
__naked void callx_scalar_recursion(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[call_slot] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r2 = *(u64 *)(r6 + 0);"
		"callx r2;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(call_slot)
		: __clobber_all);
}

/*
 * The stack of a function that callx of a number may call is accounted on
 * top of the caller, even though the address is taken elsewhere. Four
 * 480-byte frames are within the budget, five are not.
 */
__naked __noinline __used
static unsigned long use_stack_480_0(void)
{
	asm volatile (
		"r0 = 0;"
		"*(u64 *)(r10 - 480) = r0;"
		"exit;"
	);
}

__naked __noinline __used
static unsigned long use_stack_480_1(void)
{
	asm volatile (
		"r0 = 0;"
		"*(u64 *)(r10 - 480) = r0;"
		"call use_stack_480_0;"
		"exit;"
	);
}

__naked __noinline __used
static unsigned long use_stack_480_2(void)
{
	asm volatile (
		"r0 = 0;"
		"*(u64 *)(r10 - 480) = r0;"
		"call use_stack_480_1;"
		"exit;"
	);
}

__naked __noinline __used
static unsigned long use_stack_480_3(void)
{
	asm volatile (
		"r0 = 0;"
		"*(u64 *)(r10 - 480) = r0;"
		"call use_stack_480_2;"
		"exit;"
	);
}

__naked __noinline __used
static unsigned long store_use_stack_480_3(void)
{
	asm volatile (
		"r1 = %[fn_slot] ll;"
		"r2 = %[use_stack_480_3] ll;"
		"*(u64 *)(r1 + 0) = r2;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(use_stack_480_3)
		: __clobber_all);
}

__naked __noinline __used
static unsigned long call_slot_stack_480(void)
{
	asm volatile (
		"r0 = 0;"
		"*(u64 *)(r10 - 480) = r0;"
		"r2 = %[fn_slot] ll;"
		"r2 = *(u64 *)(r2 + 0);"
		"callx r2;"
		"exit;"
		:
		: __imm_addr(fn_slot)
		: __clobber_all);
}

SEC("socket")
__description("callx scalar: stack depth of the callee")
__callx_scalar
__failure __msg("combined stack size of 6 calls is 2400. Too large")
__naked void callx_scalar_stack_depth(void)
{
	asm volatile (
		"call store_use_stack_480_3;"
		"call call_slot_stack_480;"
		"exit;"
		::: __clobber_all);
}

/* r1 == 0: returns 7, otherwise unwinds with r0 = 5 */
__naked __noinline __used
static unsigned long may_unwind(void)
{
	asm volatile (
		"if r1 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

SEC("socket")
__description("callx scalar: unwind_goto has to follow if a callee may unwind")
__callx_scalar
__failure __msg("no unwind_goto after callx of a number that may unwind")
__naked void callx_scalar_unwind_no_goto(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[may_unwind] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r2 = *(u64 *)(r6 + 0);"
		"r1 = 0;"
		"callx r2;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(may_unwind)
		: __clobber_all);
}

SEC("socket")
__description("callx scalar: the callee returns")
__callx_scalar
__success __retval(7)
__naked void callx_scalar_returns(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[may_unwind] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r2 = *(u64 *)(r6 + 0);"
		"r1 = 0;"
		"callx r2;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(may_unwind),
		  __imm_unwind_goto(1)
		: __clobber_all);
}

SEC("socket")
__description("callx scalar: the callee unwinds")
__callx_scalar
__success __retval(42)
__naked void callx_scalar_unwinds(void)
{
	asm volatile (
		"r6 = %[fn_slot] ll;"
		"r1 = %[may_unwind] ll;"
		"*(u64 *)(r6 + 0) = r1;"
		"r2 = *(u64 *)(r6 + 0);"
		"r1 = 1;"
		"callx r2;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_addr(fn_slot),
		  __imm_addr(may_unwind),
		  __imm_unwind_goto(1)
		: __clobber_all);
}

/* The same in C */

static __noinline int mul7(int x)
{
	return x * 7;
}

int (* volatile fnptr)(int);

SEC("syscall")
__description("callx scalar: C, address of a function in a global")
__callx_scalar
__success __retval(42)
int callx_scalar_c_global(void *ctx)
{
	fnptr = mul7;
	return fnptr(6);
}

static __noinline int copy_user(int x)
{
	if (x)
		bpf_copy_from_user(&x, sizeof(x), NULL);
	return x;
}

int (* volatile sleepy_fnptr)(int);

/* a function that may sleep might be called */
SEC("syscall")
__description("callx scalar: C, sleepable callee with preemption disabled")
__callx_scalar
__failure __msg("callx of a number may call a sleepable function")
int callx_scalar_c_sleepable(void *ctx)
{
	int ret;

	sleepy_fnptr = copy_user;
	bpf_preempt_disable();
	ret = sleepy_fnptr(0);
	bpf_preempt_enable();
	return ret;
}

SEC("syscall")
__description("callx scalar: C, sleepable callee")
__callx_scalar
__success __retval(0)
int callx_scalar_c_sleepable_ok(void *ctx)
{
	sleepy_fnptr = copy_user;
	return sleepy_fnptr(0);
}

/* referenced from C, so BTF has their FUNC records */
void bpf_throw(__u64 cookie) __ksym;
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

static __noinline int throws_21(int x)
{
	bpf_throw(21);
	return x;
}

int (* volatile throwing_fnptr)(int);

/*
 * A callee might throw, so the frame of the caller is described at the callx
 * like at a call of a global function: the unwinder leaves the RCU section the
 * caller is in on the way to the exception callback, which returns the cookie.
 */
SEC("syscall")
__description("callx scalar: C, the callee throws under the RCU read lock")
__callx_scalar
__success __retval(21)
int callx_scalar_c_throws(void *ctx)
{
	int ret;

	throwing_fnptr = throws_21;
	bpf_rcu_read_lock();
	ret = throwing_fnptr(0);
	bpf_rcu_read_unlock();
	return ret;
}

#else

SEC("socket")
__success
int dummy(void *ctx)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
