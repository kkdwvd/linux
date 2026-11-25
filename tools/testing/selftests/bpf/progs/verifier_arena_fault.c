// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf_arena_common.h>

/*
 * An access to the arena that no page backs ends the prog: it unwinds like one whose time slice is
 * over. Where no landing pad will do the prog is rejected. In a subprog that cannot unwind the
 * access is skipped. Each prog returns 7 if the access is skipped.
 */
#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

/* rN = addr_space_cast(rN, 0x0, 0x1), which the assembler of GCC doesn't know */
#define to_arena(n) ".8byte 0x1000100bf | (0x11 * " #n ") << 8;"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 8);
} arena SEC(".maps");

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long one = 1;

/* r8 = an address of the arena, no page is there */
#define NO_PAGE						\
		"r1 = %[arena] ll;"			\
		"r8 = 0x1000;"				\
		to_arena(8)

/* @reg = a task, which has to be released */
#define ACQUIRE_TASK(reg)				\
		"r1 = 1;"				\
		"call %[bpf_task_from_pid];"		\
		"if r0 != 0 goto +1;"			\
		"exit;"					\
		#reg " = r0;"
#define RELEASE_TASK(reg) "r1 = " #reg ";" "call %[bpf_task_release];"
#define TASK_IMM __imm_addr(arena), __imm(bpf_task_from_pid), __imm(bpf_task_release)

#define ENTER_9 ".rept 9;" "call %[bpf_rcu_read_lock];" ".endr;"
#define LEAVE_9 ".rept 9;" "call %[bpf_rcu_read_unlock];" ".endr;"
#define RCU_IMM __imm_addr(arena), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)

/* kfuncs that only asm calls need BTF */
void __kfunc_btf_root(void)
{
	struct bpf_iter_num it;
	unsigned long flags;

	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_task_release(bpf_task_from_pid(0));
	bpf_preempt_disable();
	bpf_preempt_enable();
	bpf_local_irq_save(&flags);
	bpf_local_irq_restore(&flags);
	bpf_iter_num_new(&it, 0, 1);
	bpf_iter_num_destroy(&it);
	bpf_res_spin_lock(NULL);
	bpf_res_spin_unlock(NULL);
}

/* Nothing is held: no insn is added at the access. All such accesses of a function share a pad. */
SEC("socket")
__description("fault: a load in the main prog ends it")
__success __retval(0)
__xlated("4: r2 = *(u32 *)(r8 +0)")
__xlated("5: r0 = 7")
__xlated("6: exit")
__xlated("7: r0 = 0")
__xlated("8: exit")
__naked void load_in_main(void)
{
	asm volatile (
	NO_PAGE
		"r2 = *(u32 *)(r8 + 0);"
		"r0 = 7;"
		"exit;"
		:: __imm_addr(arena) : __clobber_all);
}

#define FAULT(sec, val, name, insns)						\
SEC(sec)									\
__description("fault: " #name)							\
__success __retval(val)								\
__naked void name(void)								\
{										\
	asm volatile (NO_PAGE insns "r0 = 7; exit;" :: TASK_IMM : __clobber_all); \
}

FAULT("socket", 0, store, "*(u32 *)(r8 + 0) = 1;")
/* On x86-64 two native insns of it can fault */
FAULT("socket", 0, fetch_or, "r3 = 1; r3 = atomic_fetch_or((u64 *)(r8 + 0), r3);")
/* 'w0 = w0' is added after the insn. The mark of the shared pad stays on the insn. */
FAULT("socket", 0, cmpxchg32, "r0 = 1; r1 = 2; w0 = cmpxchg32_32(r8 + 0, w0, w1); r9 = r0;")
/* .. and it comes after unwind_goto, not in front of it */
FAULT("tc", 2, cmpxchg32_task, ACQUIRE_TASK(r6)
      "w0 = 0; w2 = 1; w0 = cmpxchg32_32(r8 + 0, w0, w2); r9 = r0;" RELEASE_TASK(r6))
/* R0-R5 are as before the access: they are places */
FAULT("tc", 2, task_in_r0, ACQUIRE_TASK(r0) "r2 = *(u32 *)(r8 + 0);" RELEASE_TASK(r0))
/*
 * On x86-64 the insn is a loop around CMPXCHG, which takes RAX: R0 waits in another register, and
 * the handler of the fault puts it back for the pad.
 * The page was never there, so the insn faults at its first native insn, the load in front of the
 * loop, where RAX still has R0. These two have a task in R0, and R0 as the operand, at such an
 * insn: they do not see what the handler puts back. That takes a fault at CMPXCHG after the load
 * went through, a page that goes away in between, which a test cannot bring about.
 */
FAULT("tc", 2, task_in_r0_fetch_or, ACQUIRE_TASK(r0)
      "r3 = 1; r3 = atomic_fetch_or((u64 *)(r8 + 0), r3);" RELEASE_TASK(r0))
FAULT("tc", 2, task_in_r0_fetch_and_r0, ACQUIRE_TASK(r6)
      "r0 = 1; r0 = atomic_fetch_and((u64 *)(r8 + 0), r0);" RELEASE_TASK(r6))
/* The register that the insn would load is the place of the task: the pad gets it as it was */
FAULT("tc", 2, xchg_of_the_task, ACQUIRE_TASK(r6)
      "r7 = r6; r6 = xchg_64(r8 + 0, r6);" RELEASE_TASK(r7))
/* The frame is in the private stack, r9 on x86-64: the landing pad finds the task there */
FAULT("raw_tp", 0, private_stack, "r1 = 42; *(u64 *)(r10 - 512) = r1;" ACQUIRE_TASK(r6)
      "*(u64 *)(r10 - 8) = r6; r6 = 0; r2 = *(u32 *)(r8 + 0); r6 = *(u64 *)(r10 - 8);"
      RELEASE_TASK(r6))

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, long);
} one_elem SEC(".maps");

#define HELD_IMM									\
	__imm_addr(arena), __imm_addr(ringbuf),						\
	__imm(bpf_preempt_disable), __imm(bpf_preempt_enable),				\
	__imm(bpf_local_irq_save), __imm(bpf_local_irq_restore),			\
	__imm(bpf_iter_num_new), __imm(bpf_iter_num_destroy),				\
	__imm(bpf_ringbuf_reserve_dynptr), __imm(bpf_ringbuf_discard_dynptr)

/*
 * The load faults while the frame holds what @acquire takes. The pad gives it back: tc returns 2,
 * which a pad that releases nothing returns as well. So @plan is what the pad of the access has,
 * and @call the release in the pad, behind the exit of the prog: a helper, a kfunc, or what the
 * verifier makes of bpf_iter_num_destroy().
 */
#define FAULT_HOLDING(name, plan, call, acquire, release)			\
SEC("tc")									\
__description("fault: " #name)							\
__success __retval(2)								\
__log_level(2)									\
__msg("landing pad of arena access at {{[0-9]+}}: " plan "rcu=0 preempt=")	\
__xlated("...")									\
__xlated("r0 = 7")								\
__xlated("exit")								\
__xlated("...")									\
__xlated(call)									\
__xlated("r0 = 2")								\
__xlated("exit")								\
__naked void name(void)								\
{										\
	asm volatile (NO_PAGE acquire "r2 = *(u32 *)(r8 + 0);" release		\
		      "r0 = 7; exit;" :: HELD_IMM : __clobber_all);		\
}

FAULT_HOLDING(a_preempt_section_is_held, "", "call kernel-function",
	      "call %[bpf_preempt_disable];", "call %[bpf_preempt_enable];")
FAULT_HOLDING(irq_flags_are_held, "irq@{{[0-9]+}}(fp-8) ", "call kernel-function",
	      "r1 = r10; r1 += -8; call %[bpf_local_irq_save];",
	      "r1 = r10; r1 += -8; call %[bpf_local_irq_restore];")
FAULT_HOLDING(an_iterator_is_held, "iter@{{[0-9]+}}(fp-8) ", "goto pc+0",
	      "r1 = r10; r1 += -8; r2 = 0; r3 = 10; call %[bpf_iter_num_new];",
	      "r1 = r10; r1 += -8; call %[bpf_iter_num_destroy];")
FAULT_HOLDING(a_dynptr_is_held, "dynptr@{{[0-9]+}}(fp-16, 0) ", "call unknown",
	      "r1 = %[ringbuf] ll; r2 = 8; r3 = 0; r4 = r10; r4 += -16;"
	      "call %[bpf_ringbuf_reserve_dynptr];",
	      "r1 = r10; r1 += -16; r2 = 0; call %[bpf_ringbuf_discard_dynptr];")

/* The callback of a helper faults: it is unwound, the helper leaves through its pad, the prog ends */
static __naked __used int loads_in_cb(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r2 = 0x1000;"
		to_arena(2)
		"r0 = *(u32 *)(r2 + 0);"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(arena) : __clobber_all);
}

/* kgoto of the inlined loop follows the call of the callback, 15 insns behind its pad */
SEC("tc")
__description("fault: a load in the callback of the inlined bpf_loop()")
__success __retval(2)
__xlated("...")
__xlated("call pc+{{[0-9]+}}")
__xlated("kgoto pc-15")
__naked void load_in_inlined_loop_cb(void)
{
	asm volatile (
		"r1 = 1;"
		"r2 = loads_in_cb ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"r0 = 7;"
		"exit;"
		:: __imm(bpf_loop) : __clobber_all);
}

/* The flags are 0 and not known to be: the helper is called */
SEC("tc")
__description("fault: a load in the callback of bpf_loop()")
__success __retval(2)
__naked void load_in_loop_cb(void)
{
	asm volatile (
		"r4 = %[zero] ll;"
		"r4 = *(u64 *)(r4 + 0);"
		"r1 = 1;"
		"r2 = loads_in_cb ll;"
		"r3 = 0;"
		"call %[bpf_loop];"
		"r0 = 7;"
		"exit;"
		:: __imm_addr(zero), __imm(bpf_loop) : __clobber_all);
}

SEC("tc")
__description("fault: a load in the callback of bpf_for_each_map_elem()")
__success __retval(2)
__naked void load_in_for_each_cb(void)
{
	asm volatile (
		"r1 = %[one_elem] ll;"
		"r2 = loads_in_cb ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		"r0 = 7;"
		"exit;"
		:: __imm_addr(one_elem), __imm(bpf_for_each_map_elem) : __clobber_all);
}

/* The callback holds something at its load: the access has a pad of its own in the callback */
static __naked __used int loads_in_section_in_cb(void)
{
	asm volatile (
		"call %[bpf_preempt_disable];"
		"r1 = %[arena] ll;"
		"r2 = 0x1000;"
		to_arena(2)
		"r0 = *(u32 *)(r2 + 0);"
		"call %[bpf_preempt_enable];"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(arena), __imm(bpf_preempt_disable), __imm(bpf_preempt_enable)
		: __clobber_all);
}

SEC("tc")
__description("fault: a load in the callback of bpf_loop(), which is in a preempt section")
__success __retval(2)
__log_level(2)
__msg("landing pad of arena access at {{[0-9]+}}: rcu=0 preempt=1")
__xlated("...")
__xlated("r0 = *(u32 *)(r2 +0)")
__xlated("unwind_goto pc+{{[0-9]+}}")
__naked void load_in_section_in_loop_cb(void)
{
	asm volatile (
		"r4 = %[zero] ll;"
		"r4 = *(u64 *)(r4 + 0);"
		"r1 = 1;"
		"r2 = loads_in_section_in_cb ll;"
		"r3 = 0;"
		"call %[bpf_loop];"
		"r0 = 7;"
		"exit;"
		:: __imm_addr(zero), __imm(bpf_loop) : __clobber_all);
}

/* unwind_goto is an entry in the exception table: the native code has nothing after the load */
SEC("tc")
__description("fault: a task is held")
__success __retval(2)
__xlated("...")
__xlated("r2 = *(u32 *)(r8 +0)")
__xlated("unwind_goto pc+4")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 7")
__xlated("exit")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__arch_x86_64
__jited("	movl	(%r14,%r12), %esi")
__jited("	movq	%rbx, %rdi")
__arch_arm64
__naked void task_in_main(void)
{
	asm volatile (
	NO_PAGE
	ACQUIRE_TASK(r6)
		"r2 = *(u32 *)(r8 + 0);"
	RELEASE_TASK(r6)
		"r0 = 7;"
		"exit;"
		:: TASK_IMM : __clobber_all);
}

struct bpf_spin_lock lock_a SEC(".data.lock_a") __hidden;
struct bpf_spin_lock lock_b SEC(".data.lock_b") __hidden;

/* One insn takes one of two locks. What the prog keeps for its own unlock tells which. */
SEC("tc")
__description("fault: one of two locks in global variables is held")
__success __retval(2)
__xlated("...")
__xlated("exit")
__xlated("r1 = r6")
__xlated("call {{.*}}")
__xlated("r0 = 2")
__naked void one_of_two_locks(void)
{
	asm volatile (
	NO_PAGE
		"r9 = %[zero] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"r6 = %[lock_a] ll;"
		"if r9 == 0 goto +2;"
		"r6 = %[lock_b] ll;"
		"r1 = r6;"
		"call %[bpf_spin_lock];"
		"r2 = *(u32 *)(r8 + 0);"
		"r1 = r6;"
		"call %[bpf_spin_unlock];"
		"r0 = 7;"
		"exit;"
		:: __imm_addr(arena), __imm_addr(zero), __imm_addr(lock_a), __imm_addr(lock_b),
		   __imm(bpf_spin_lock), __imm(bpf_spin_unlock)
		: __clobber_all);
}

struct bpf_res_spin_lock res_a SEC(".data.res_a") __hidden;
struct bpf_res_spin_lock res_b SEC(".data.res_b") __hidden;

/* @reg = the address of @lock if the lock is taken, else 0 */
#define TAKE(reg, lock)					\
		#reg " = %[" #lock "] ll;"		\
		"r1 = " #reg ";"			\
		"call %[bpf_res_spin_lock];"		\
		"if r0 == 0 goto +1;"			\
		#reg " = 0;"
#define RELEASE_IF(reg)					\
		"if " #reg " == 0 goto +2;"		\
		"r1 = " #reg ";"			\
		"call %[bpf_res_spin_unlock];"

/*
 * Two locks: one path takes the first, one the second, one both. The states that hold one lock say
 * nothing about the order of the two, in whichever order they get to the access: the state that
 * holds both does. The paths get to the access in the order of their jumps.
 */
#define TWO_LOCKS(name, first, second, third)						\
SEC("tc")										\
__description("fault: two locks on three paths, " #name)				\
__success __retval(2)									\
__log_level(2)										\
__msg("landing pad of arena access at {{[0-9]+}}: res_lock@{{[0-9]+}}(r7) if not 0 res_lock@{{[0-9]+}}(r6) if not 0 rcu=0 preempt=0") \
__naked void two_locks_##name(void)							\
{											\
	asm volatile (									\
	NO_PAGE										\
		"r9 = %[one] ll;"							\
		"r9 = *(u64 *)(r9 + 0);"						\
		"r6 = 0;"								\
		"r7 = 0;"								\
		"if r9 == 3 goto " #first ";"						\
		"if r9 == 2 goto " #second ";"						\
		"if r9 == 1 goto " #third ";"						\
	"4:"										\
		"r2 = *(u32 *)(r8 + 0);"						\
	RELEASE_IF(r7)									\
	RELEASE_IF(r6)									\
		"r0 = 7;"								\
		"exit;"									\
	"1:"										\
	TAKE(r6, res_a)									\
		"goto 4b;"								\
	"2:"										\
	TAKE(r7, res_b)									\
		"goto 4b;"								\
	"3:"										\
	TAKE(r6, res_a)									\
		"if r6 == 0 goto 4b;"							\
	TAKE(r7, res_b)									\
		"goto 4b;"								\
		:: __imm_addr(arena), __imm_addr(one), __imm_addr(res_a), __imm_addr(res_b), \
		   __imm(bpf_res_spin_lock), __imm(bpf_res_spin_unlock)			\
		: __clobber_all);							\
}

TWO_LOCKS(the_first_the_second_then_both, 1f, 2f, 3f)
TWO_LOCKS(the_second_the_first_then_both, 2f, 1f, 3f)
TWO_LOCKS(both_then_each, 3f, 1f, 2f)

/*
 * The path that takes both takes them against the order of the insns that take one: the second
 * lock first, at another insn. Each lock is one entry of the plan whichever insn took it, and the
 * only state that says anything about their order is the one that holds both. The pad releases the
 * first lock first, as that state has to, in whichever order the three get to the access.
 */
#define TWO_LOCKS_OTHER_WAY(name, first, second, third)					\
SEC("tc")										\
__description("fault: two locks on three paths, taken the other way round, " #name)	\
__success __retval(2)									\
__log_level(2)										\
__msg("landing pad of arena access at {{[0-9]+}}: res_lock@{{[0-9]+}}(r6) if not 0 res_lock@{{[0-9]+}}(r7) if not 0 rcu=0 preempt=0") \
__naked void two_locks_other_way_##name(void)						\
{											\
	asm volatile (									\
	NO_PAGE										\
		"r9 = %[one] ll;"							\
		"r9 = *(u64 *)(r9 + 0);"						\
		"r6 = 0;"								\
		"r7 = 0;"								\
		"if r9 == 3 goto " #first ";"						\
		"if r9 == 2 goto " #second ";"						\
		"if r9 == 1 goto " #third ";"						\
	"4:"										\
		"r2 = *(u32 *)(r8 + 0);"						\
	RELEASE_IF(r6)									\
	RELEASE_IF(r7)									\
		"r0 = 7;"								\
		"exit;"									\
	"1:"										\
	TAKE(r6, res_a)									\
		"goto 4b;"								\
	"2:"										\
	TAKE(r7, res_b)									\
		"goto 4b;"								\
	"3:"										\
	TAKE(r7, res_b)									\
		"if r7 == 0 goto 4b;"							\
	TAKE(r6, res_a)									\
		"goto 4b;"								\
		:: __imm_addr(arena), __imm_addr(one), __imm_addr(res_a), __imm_addr(res_b), \
		   __imm(bpf_res_spin_lock), __imm(bpf_res_spin_unlock)			\
		: __clobber_all);							\
}

TWO_LOCKS_OTHER_WAY(the_first_the_second_then_both, 1f, 2f, 3f)
TWO_LOCKS_OTHER_WAY(the_second_the_first_then_both, 2f, 1f, 3f)
TWO_LOCKS_OTHER_WAY(both_then_each, 3f, 1f, 2f)

struct bpf_res_spin_lock res_c SEC(".data.res_c") __hidden;

/*
 * Three locks, and each path takes two of them: the first then the second, the second then the
 * third, the third then the first. No two paths disagree about two locks, and no order of the
 * three suits all paths.
 */
SEC("tc")
__description("fault: three locks, two on each of three paths, in orders that no pad has")
__failure
__msg("landing pad of arena access at {{[0-9]+}}: conflict: the order of the releases differs")
__naked void three_locks_in_a_circle(void)
{
	asm volatile (
	NO_PAGE
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"*(u64 *)(r10 - 8) = r1;"
		"r6 = 0;"
		"r7 = 0;"
		"r9 = 0;"
		"if r1 == 1 goto 1f;"
		"if r1 == 2 goto 2f;"
		"if r1 == 3 goto 3f;"
	"4:"
		"r2 = *(u32 *)(r8 + 0);"
		"r1 = *(u64 *)(r10 - 8);"
		"if r1 == 2 goto 5f;"
		"if r1 == 3 goto 6f;"
	RELEASE_IF(r7)
	RELEASE_IF(r6)
		"goto 7f;"
	"5:"
	RELEASE_IF(r9)
	RELEASE_IF(r7)
		"goto 7f;"
	"6:"
	RELEASE_IF(r6)
	RELEASE_IF(r9)
	"7:"
		"r0 = 7;"
		"exit;"
	"1:"
	TAKE(r6, res_a)
		"if r6 == 0 goto 4b;"
	TAKE(r7, res_b)
		"goto 4b;"
	"2:"
	TAKE(r7, res_b)
		"if r7 == 0 goto 4b;"
	TAKE(r9, res_c)
		"goto 4b;"
	"3:"
	TAKE(r9, res_c)
		"if r9 == 0 goto 4b;"
	TAKE(r6, res_a)
		"goto 4b;"
		:: __imm_addr(arena), __imm_addr(one), __imm_addr(res_a), __imm_addr(res_b),
		   __imm_addr(res_c), __imm(bpf_res_spin_lock), __imm(bpf_res_spin_unlock)
		: __clobber_all);
}

/*
 * States that hold nothing go by without a look at the plan. When one comes that holds the task all
 * is done again, so that the plan sees r6 == 0 too.
 */
SEC("tc")
__description("fault: a task is held on some paths, the pointer is NULL on the others")
__success __retval(2)
__xlated("...")
__xlated("r2 = *(u32 *)(r8 +0)")
__xlated("unwind_goto pc+")
__xlated("...")
__xlated("exit")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__naked void task_or_null(void)
{
	asm volatile (
	NO_PAGE
		"r9 = %[one] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"r6 = 0;"
		"if r9 == 0 goto 1f;"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"r6 = r0;"
	"1:"
		"r2 = *(u32 *)(r8 + 0);"
		"if r6 == 0 goto 2f;"
	RELEASE_TASK(r6)
	"2:"
		"r0 = 7;"
		"exit;"
		:: TASK_IMM, __imm_addr(one) : __clobber_all);
}

/*
 * The state that holds the task is first at the load, and it has compared r6 with NULL. Only the
 * visit of the state that holds nothing brings the test.
 */
SEC("tc")
__description("fault: a task is held on some paths, the state that holds it comes first")
__success __retval(2)
__xlated("...")
__xlated("exit")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__naked void task_first_or_null(void)
{
	asm volatile (
	NO_PAGE
		"r9 = %[zero] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"r6 = 0;"
		"if r9 != 0 goto 3f;"
		"r7 = 1;"
		"goto 1f;"
	"3:"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"r6 = r0;"
		"if r6 == 0 goto 2f;"
	"1:"
		"r2 = *(u32 *)(r8 + 0);"
		"if r6 == 0 goto 2f;"
	RELEASE_TASK(r6)
	"2:"
		"r0 = 7;"
		"exit;"
		:: TASK_IMM, __imm_addr(zero) : __clobber_all);
}

/*
 * How deep the task is in sections: the preempt count, and the depth of its RCU sections where RCU
 * is preemptible and has a count of its own
 */
static __always_inline long sections_now(void)
{
	struct task_struct *t = bpf_get_current_task_btf();
	long n = get_preempt_count();

	if (bpf_core_field_exists(t->rcu_read_lock_nesting))
		n += t->rcu_read_lock_nesting;
	return n;
}

long sections_at_entry;

__noinline __used
static unsigned long notes_sections(void)
{
	sections_at_entry = sections_now();
	return 0;
}

/* How many more than at the start of the prog */
__noinline __used
static unsigned long sections_since_entry(void)
{
	return sections_now() - sections_at_entry;
}

/*
 * The exception callback runs when the landing pad of the prog has done its releases, also where
 * the kernel unwinds, and the prog returns what it returns: the number of sections that the pad
 * did not leave, or with a minus the number that it left and the prog had not entered.
 */
__noinline int sections_left_over(u64 cookie)
{
	return sections_since_entry();
}

/* The count tells: a prog that asks in a section of either kind sees one more */
#define SECTION_IS_SEEN(name, desc, enter, leave)					\
SEC("socket")										\
__description("fault: " desc)								\
__success __retval(1)									\
__naked void name(void)									\
{											\
	asm volatile (									\
		"call notes_sections;"							\
		"call %[" #enter "];"							\
		"call sections_since_entry;"						\
		"r6 = r0;"								\
		"call %[" #leave "];"							\
		"r0 = r6;"								\
		"exit;"									\
		:: __imm(enter), __imm(leave) : __clobber_all);				\
}

SECTION_IS_SEEN(rcu_section_is_seen, "a prog that is in an RCU section counts one section more",
		bpf_rcu_read_lock, bpf_rcu_read_unlock)
SECTION_IS_SEEN(preempt_section_is_seen,
		"a prog that is in a preempt section counts one section more",
		bpf_preempt_disable, bpf_preempt_enable)

/*
 * No test of a pointer tells whether the prog is in the section. A hidden slot does: it is set
 * where the section is entered, and the pad leaves the section if it is set.
 * The prog runs with the section entered, @var is one, and without, zero. A pad that leaves a
 * section which was not entered, or keeps one that was, makes the kernel complain, and the prog
 * returns what its exception callback finds behind the pad: 0 sections more or less than at the
 * start.
 */
#define SECTION_ON_SOME_PATHS(name, desc, group, var, enter, leave)			\
SEC("socket")										\
__description("fault: " desc)								\
__success __retval(0)									\
__exception_cb(sections_left_over)							\
__log_level(2) __msg("func#0 has hidden slots for: " group)				\
__xlated("0: *(u64 *)(r10 -8) = 0")							\
__xlated("...")										\
__xlated("*(u64 *)(r10 -8) = 1")							\
__xlated("call kernel-function")							\
__xlated("r2 = *(u32 *)(r8 +0)")							\
__xlated("unwind_goto pc+")								\
__xlated("...")										\
__xlated("r0 = 7")									\
__xlated("exit")									\
/* the pad */										\
__xlated("r1 = *(u64 *)(r10 -8)")							\
__xlated("if r1 == 0x0 goto pc+1")							\
__xlated("call kernel-function")							\
__xlated("r1 = 0")									\
__xlated("call pc+")									\
__xlated("exit")									\
__naked void name(void)									\
{											\
	asm volatile (									\
		"call notes_sections;"							\
	NO_PAGE										\
		"r9 = %[" #var "] ll;"							\
		"r9 = *(u64 *)(r9 + 0);"						\
		"if r9 == 0 goto +1;"							\
		"call %[" #enter "];"							\
		"r2 = *(u32 *)(r8 + 0);"						\
		"if r9 == 0 goto +1;"							\
		"call %[" #leave "];"							\
		"r0 = 7;"								\
		"exit;"									\
		:: RCU_IMM, __imm_addr(one), __imm_addr(zero),				\
		   __imm(bpf_preempt_disable), __imm(bpf_preempt_enable)		\
		: __clobber_all);							\
}

SECTION_ON_SOME_PATHS(section_on_some_paths,
		      "an RCU section on some paths, a hidden slot tells",
		      "rcu", one, bpf_rcu_read_lock, bpf_rcu_read_unlock)
SECTION_ON_SOME_PATHS(section_on_some_paths_not_entered,
		      "an RCU section on some paths, the prog is not in it",
		      "rcu", zero, bpf_rcu_read_lock, bpf_rcu_read_unlock)
SECTION_ON_SOME_PATHS(preempt_on_some_paths,
		      "a preempt section on some paths, a hidden slot tells",
		      "preempt", one, bpf_preempt_disable, bpf_preempt_enable)
SECTION_ON_SOME_PATHS(preempt_on_some_paths_not_entered,
		      "a preempt section on some paths, the prog is not in it",
		      "preempt", zero, bpf_preempt_disable, bpf_preempt_enable)

__naked __noinline __used
static unsigned long loads(void)
{
	asm volatile (
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u32 *)(r8 + 0);"
		"r0 += 5;"
		"exit;"
		::: __clobber_all);
}

SEC("tc")
__description("fault: a load in a subprog, the caller holds a task")
__success __retval(2)
__xlated("...")
__xlated("call pc+")
__xlated("kgoto pc+4")
__xlated("...")
__xlated("exit")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__xlated("...")
__xlated("exit")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__naked void load_in_subprog(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
	ACQUIRE_TASK(r6)
		"call loads;"
	RELEASE_TASK(r6)
		"r0 = 7;"
		"exit;"
		:: TASK_IMM : __clobber_all);
}

/*
 * No landing pad does for the call: a pad leaves eight sections. The call has only a fault below
 * it, and that has no other way out: the prog is rejected, with the insn and the reason.
 */
SEC("socket")
__description("fault: a load in a subprog, the caller holds too much")
__failure
__msg("what the call at {{[0-9]+}} calls is left at: arena access")
__msg("landing pad of call at {{[0-9]+}}: conflict: too much is held")
__naked void load_in_subprog_too_much(void)
{
	asm volatile (
	NO_PAGE
	ENTER_9
		"call loads;"
		"r6 = r0;"
	LEAVE_9
		"r0 = 7;"
		"if r6 != 5 goto +1;"
		"r2 = *(u32 *)(r8 + 0);"
		"exit;"
		:: RCU_IMM : __clobber_all);
}

/* The same at the access itself */
SEC("socket")
__description("fault: a load, the prog holds too much")
__failure
__msg("landing pad of arena access at {{[0-9]+}}: conflict: too much is held")
__naked void load_too_much(void)
{
	asm volatile (
	NO_PAGE
	ENTER_9
		"r2 = *(u32 *)(r8 + 0);"
	LEAVE_9
		"r0 = 7;"
		"exit;"
		:: RCU_IMM : __clobber_all);
}

/* BPF_JMP | BPF_JCOND with BPF_UNWIND_GOTO in src_reg, and BPF_JMP | BPF_EXIT with BPF_UNWIND_EXIT */
#define unwind_goto(label) ".8byte ((((" #label " - .) / 8 - 1) & 0xffff) << 16) | 0x10e5;"
#define unwind_exit ".8byte 0x1095;"

/* A loop that nothing ends: the kernel unwinds it when its time is up */
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

/* The same load in too many sections, in a function that only the landing pad below calls */
__naked __noinline __used
static unsigned long loads_holding_too_much(void)
{
	asm volatile (
	ENTER_9
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u32 *)(r8 + 0);"
	LEAVE_9
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

__naked __noinline __used
static unsigned long pad_calls_the_load(void)
{
	asm volatile (
		"call spins;"
		unwind_goto(1f)
		"r0 = 7;"
		"exit;"
	"1:	r6 = r0;"
		"call loads_holding_too_much;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}

/*
 * The landing pad only resumes, so the kernel enters it when it unwinds the loop, and only then
 * the program gets to the load. No pad does for the load, and that rejects as at any other load:
 * the function is code of the program. The log says how the program got there.
 */
SEC("tc")
__description("fault: a load that has no pad, in what only a landing pad calls")
__failure
__msg("from 4 to the landing pad at 8 of func#1: the kernel unwinds")
__msg("func#3 is called from a landing pad of the program that the kernel would enter")
__msg("landing pad of arena access at 29: conflict: too much is held")
__naked void load_below_pad_code(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"call pad_calls_the_load;"
		"exit;"
		:: __imm_addr(arena) : __clobber_all);
}

/* r0 = 0; do r0 += r1; while (r0 != r2). Only a loop that is out of time leaves it unwound. */
__naked __noinline __used
static unsigned long counts(void)
{
	asm volatile (
		"r0 = 0;"
	"1:	r0 += r1;"
		"if r0 != r2 goto 1b;"
		"exit;"
		::: __clobber_all);
}

/* pad_calls_the_load() with counts() in front of its landing pad */
__naked __noinline __used
static unsigned long pad_calls_the_load_around_count(void)
{
	asm volatile (
		"call counts;"
		unwind_goto(1f)
		"r0 = 7;"
		"exit;"
	"1:	r6 = r0;"
		"call loads_holding_too_much;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}

/*
 * The same load, in what a landing pad calls that no run of the program gets into: counts() ends
 * for each of the two calls, and for both together its loop has no trip count. Then the kernel
 * unwinds it, the pad is entered, and the load that has no pad is an error of that pass, at the
 * visit: no plan is settled in such a pass. The calls behind which the kernel entered a landing
 * pad are causes of any error of the pass. Kept apart, nothing enters the pad, and the program
 * loads.
 */
SEC("tc")
__description("fault: a load that has no pad, in what a landing pad calls that only joined calls enter")
__success __retval(3)
__log_level(2)
__msg("from 10 to the landing pad at 14 of func#1: the kernel unwinds")
__msg("func#3 is called from a landing pad of the program that the kernel would enter")
__msg("landing pad of arena access at 33: conflict: too much is held")
__not_msg("the kernel enters it")
__msg("processed {{[0-9]+}} insns")
__naked void load_below_pad_of_joined_calls(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r1 = 1;"
		"r2 = 1000000;"
		"call pad_calls_the_load_around_count;"
		"r1 = -1;"
		"r2 = -999993;"
		"call pad_calls_the_load_around_count;"
		"r0 = 3;"
		"exit;"
		:: __imm_addr(arena) : __clobber_all);
}

/* Returns 5. If r1 * r1 is not r2 it loads from the arena first, where no page is. One exit. */
__naked __noinline __used
static unsigned long loads_unless_square(void)
{
	asm volatile (
		"r3 = r1;"
		"r3 *= r1;"
		"if r3 == r2 goto 1f;"
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u32 *)(r8 + 0);"
	"1:"
		"r0 = 5;"
		"exit;"
		::: __clobber_all);
}

/*
 * No call gets to the load: 2 * 2 is 4 and 3 * 3 is 9. The two calls joined do, with 2 or 3 and 4
 * or 9 and nothing that says which goes with which: the function is left at the load, and its
 * caller is in more sections than a landing pad leaves. The calls have to be kept apart for that,
 * and nothing at the call tells: its arguments are constants, and the function has one exit.
 */
SEC("socket")
__description("fault: two calls that skip a load, only their join gets to it")
__success __retval(10)
__naked void load_only_in_join(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
	ENTER_9
		"r1 = 2;"
		"r2 = 4;"
		"call loads_unless_square;"
		"r6 = r0;"
		"r1 = 3;"
		"r2 = 9;"
		"call loads_unless_square;"
		"r6 += r0;"
	LEAVE_9
		"r0 = r6;"
		"exit;"
		:: RCU_IMM : __clobber_all);
}

/*
 * r6 is the task that is held, or current: never NULL. Only a hidden slot can tell. The call has
 * nothing but a fault below it, and gets one: the task is released if the prog holds it.
 */
SEC("tc")
__description("fault: a load in a subprog, the caller has a hidden slot")
__success __retval(2)
__log_level(2) __msg("func#0 has hidden slots for: refs")
__naked void load_in_subprog_slot(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r9 = %[one] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"r7 = 0;"
		"if r9 == 0 goto 1f;"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"r7 = 1;"
		"if r0 != 0 goto 2f;"
		"r7 = 0;"
	"1:"
		"call %[bpf_get_current_task_btf];"
	"2:"
		"r6 = r0;"
		"call loads;"
		"if r7 == 0 goto 3f;"
	RELEASE_TASK(r6)
	"3:"
		"r0 = 7;"
		"exit;"
		:: TASK_IMM, __imm_addr(one), __imm(bpf_get_current_task_btf) : __clobber_all);
}

/*
 * One unwound state per stretch of accesses goes to the caller. A store to the stack of the caller,
 * a call and a join end the stretch. The caller has its task in fp-8 alone, and the callee, which
 * has the address, puts something else there for a while. When an access faults at that time no
 * place of the caller has the task: only a hidden slot does. So the state of that time has to get
 * to the call. If it did not, the pad of the call would take what is in fp-8 for the task.
 */
#define TASK_IN_STACK(name, callee, slots)					\
SEC("tc")									\
__description("fault: " #callee)						\
__success __retval(2)								\
__log_level(2) slots								\
__naked void name(void)								\
{										\
	asm volatile (								\
		"r1 = %[arena] ll;"						\
	ACQUIRE_TASK(r0)							\
		"*(u64 *)(r10 - 8) = r0;"					\
		"r1 = r10;"							\
		"r1 += -16;"							\
		"call " #callee ";"						\
		"r1 = *(u64 *)(r10 - 8);"					\
		"call %[bpf_task_release];"					\
		"r0 = 7;"							\
		"exit;"								\
		:: TASK_IMM : __clobber_all);					\
}
#define HAS_SLOTS __msg("func#0 has hidden slots for: refs")
#define NO_SLOTS __not_msg("has hidden slots")

/* fp-8 of the caller has the task at both loads: it is the place, and nothing is added */
__naked __noinline __used
static unsigned long loads_only(void)
{
	asm volatile (
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u64 *)(r8 + 0);"
		"r0 = *(u64 *)(r8 + 8);"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}
TASK_IN_STACK(task_stays_in_stack, loads_only, NO_SLOTS)

__naked __noinline __used
static unsigned long stores_between_loads(void)
{
	asm volatile (
		"r6 = r1;"
		"r7 = *(u64 *)(r6 + 8);"
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u64 *)(r8 + 0);"
		"*(u64 *)(r6 + 8) = 2;"
		"r0 = *(u64 *)(r8 + 8);"
		"*(u64 *)(r6 + 8) = r7;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}
TASK_IN_STACK(task_gone_after_store, stores_between_loads, HAS_SLOTS)

/* The helper writes to fp-8 of the caller */
__naked __noinline __used
static unsigned long calls_between_loads(void)
{
	asm volatile (
		"r6 = r1;"
		"r6 += 8;"
		"r7 = *(u64 *)(r6 + 0);"
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u64 *)(r8 + 0);"
		"r1 = r6;"
		"r2 = 8;"
		"r3 = 0;"
		"call %[bpf_probe_read_kernel];"
		"r0 = *(u64 *)(r8 + 8);"
		"*(u64 *)(r6 + 0) = r7;"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_probe_read_kernel) : __clobber_all);
}
TASK_IN_STACK(task_gone_after_call, calls_between_loads, HAS_SLOTS)

/*
 * One path has a load, and fp-8 as it was. The other one has the store and no load. They are
 * joined: the load that follows is the first one of the path with the store.
 */
__naked __noinline __used
static unsigned long joins_between_loads(void)
{
	asm volatile (
		"r6 = r1;"
		"r7 = *(u64 *)(r6 + 8);"
		"r8 = 0x1000;"
		to_arena(8)
		"r4 = %[zero] ll;"
		"r3 = *(u64 *)(r4 + 0);"
		"if r3 == 1 goto 1f;"
		"*(u64 *)(r6 + 8) = 2;"
		"goto 2f;"
	"1:"
		"r0 = *(u64 *)(r8 + 0);"
	"2:"
		"r0 = *(u64 *)(r8 + 16);"
		"*(u64 *)(r6 + 8) = r7;"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(zero) : __clobber_all);
}
TASK_IN_STACK(task_gone_after_join, joins_between_loads, HAS_SLOTS)

/* In C a pointer to arena takes a compiler that has address spaces */
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST

struct foo {
	int data;
};

void *arena_ptr;

/* An address the arena has no page for: an access to it faults. */
static __always_inline int __arena *unmapped_arena_addr(void)
{
	arena_ptr = &arena;
	return (int __arena *)0xdeadbee0;
}

/* Keep the access to @addr behind everything before it, so that the fault is not hoisted. */
#define access_barrier(addr) asm volatile("" : "+r"(addr) : : "memory")

__noinline int global_fault(void)
{
	int __arena *addr = unmapped_arena_addr();

	access_barrier(addr);
	return *addr;
}

SEC("tc")
__description("fault: a load in a global subprog, the caller holds an object")
__success __retval(2)
int cancel_arena_global(struct __sk_buff *ctx)
{
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	ret = global_fault();
	bpf_obj_drop(f);
	return ret + 7;
}

int __arena consumed;

static __noinline long try_consume(struct task_struct *t)
{
	while (*(volatile unsigned long *)&zero == 2)
		;
	if (zero)
		return 0;
	bpf_task_release(t);
	consumed = 1;
	return 1;
}

/*
 * The loop unwinds while the caller holds the task, the store when it is gone. A call with a loop
 * below it has to have a pad.
 */
SEC("syscall")
__description("fault: a subprog with a loop releases the task of its caller, then a store")
__failure __msg("landing pad of call at {{[0-9]+}}: conflict: a resource is held on some paths only")
int store_after_release_for_caller(void *ctx)
{
	struct task_struct *t = bpf_task_from_pid(1);

	if (!t)
		return 3;
	if (!try_consume(t))
		bpf_task_release(t);
	return 7;
}

struct leaf {
	struct bpf_rb_node node;
	long key;
};

/* To free it takes the lock in it: bpf_rbtree_add() must not drop it under the lock of its tree */
struct node_with_tree {
	struct bpf_rb_node node;
	struct bpf_spin_lock lock;
	struct bpf_rb_root root __contains(leaf, node);
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(T) struct bpf_spin_lock tree_lock;
private(T) struct bpf_rb_root tree_root __contains(node_with_tree, node);

/* No code has a leaf: this puts it in BTF, for __contains() above */
struct leaf *__leaf_btf_root SEC(".data.leaf");

long loaded = -1, less_went_on;

/* The load faults. The comparator of this tree cannot unwind: the load is skipped and reads 0. */
__naked __noinline __used
static bool less_load_is_skipped(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r2 = 0x1000;"
		to_arena(2)
		"r3 = 5;"
		"r3 = *(u32 *)(r2 + 0);"
		"r1 = %[loaded] ll;"
		"*(u64 *)(r1 + 0) = r3;"
		"r1 = %[less_went_on] ll;"
		"r3 = *(u64 *)(r1 + 0);"
		"r3 += 1;"
		"*(u64 *)(r1 + 0) = r3;"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(arena), __imm_addr(loaded), __imm_addr(less_went_on)
		: __clobber_all);
}

/*
 * Two nodes, so that the comparator runs, one time: it goes on behind its load, and so does the
 * prog. Returns 31 then.
 */
static __always_inline int load_is_skipped_in_comparator(bool (less)(struct bpf_rb_node *a,
								     const struct bpf_rb_node *b))
{
	struct bpf_rb_node *node;
	struct node_with_tree *n;
	int i;

	loaded = -1;
	less_went_on = 0;
	for (i = 0; i < 2; i++) {
		n = bpf_obj_new(typeof(*n));
		if (!n)
			return 1;
		bpf_spin_lock(&tree_lock);
		bpf_rbtree_add(&tree_root, &n->node, less);
		bpf_spin_unlock(&tree_lock);
	}
	for (i = 0; i < 2; i++) {
		bpf_spin_lock(&tree_lock);
		node = bpf_rbtree_first(&tree_root);
		node = node ? bpf_rbtree_remove(&tree_root, node) : NULL;
		bpf_spin_unlock(&tree_lock);
		if (!node)
			return 2;
		bpf_obj_drop(container_of(node, struct node_with_tree, node));
	}
	return 7 + (loaded == 0) * 8 + (less_went_on == 1) * 16;
}

SEC("syscall")
__description("fault: a load in a subprog that cannot unwind is skipped")
__success __retval(31)
__log_level(2)
__msg("func#1 cannot unwind, the call at {{[0-9]+}} has no landing pad for it: its may_goto jumps, its arena accesses are skipped")
int load_in_stuck_comparator(void *ctx)
{
	return load_is_skipped_in_comparator(less_load_is_skipped);
}

#define NINE_TIMES(what) what; what; what; what; what; what; what; what; what

/*
 * The call of the function is in nine RCU sections, and no pad leaves them: that is an error when
 * the verifier gets there, see load_in_subprog_too_much(). Then the function turns out to be a
 * comparator that cannot unwind: its load is skipped, nothing comes back unwound to the call, and
 * the pass is done again without the error.
 */
SEC("syscall")
__description("fault: a conflict at the call of a function that cannot unwind after all")
__success __retval(31)
int conflict_then_stuck(void *ctx)
{
	struct bpf_rb_node *node = NULL;

	if (zero) {
		NINE_TIMES(bpf_rcu_read_lock());
		less_load_is_skipped(node, node);
		NINE_TIMES(bpf_rcu_read_unlock());
	}
	return load_is_skipped_in_comparator(less_load_is_skipped);
}

#define NINE(what) what(1) what(2) what(3) what(4) what(5) what(6) what(7) what(8) what(9)
#define ITER_NEW(i) bpf_iter_num_new(&it##i, 0, 1);
#define ITER_DESTROY(i) bpf_iter_num_destroy(&it##i);

/* Nine iterators are more than a landing pad destroys, see load_too_much() */
static __noinline long loads_with_nine_iters(void)
{
	struct bpf_iter_num it1, it2, it3, it4, it5, it6, it7, it8, it9;
	int __arena *addr = unmapped_arena_addr();
	long v;

	NINE(ITER_NEW)
	access_barrier(addr);
	v = *addr;
	NINE(ITER_DESTROY)
	return v;
}

static bool less_calls_loads(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	loaded = loads_with_nine_iters();
	less_went_on++;
	return false;
}

/*
 * What a subprog that cannot unwind calls cannot unwind either: the load of the function is skipped,
 * and it needs no landing pad there. It is no error that none would do.
 */
SEC("syscall")
__description("fault: a function that a subprog that cannot unwind calls holds too much")
__success __retval(31)
int load_below_stuck_comparator(void *ctx)
{
	return load_is_skipped_in_comparator(less_calls_loads);
}

/* The same function in a prog that calls it: it can unwind, and the load ends the prog */
SEC("syscall")
__description("fault: the same load in a subprog that can unwind ends the prog")
__success __retval(-ECANCELED)
int load_in_called_comparator(void *ctx)
{
	struct bpf_rb_node *node = NULL;

	return 7 + less_load_is_skipped(node, node);
}

static __noinline bool less_faults(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r2 = 0x1000;"
		to_arena(2)
		"r2 = *(u32 *)(r2 + 0);"
		:: __imm_addr(arena) : "r1", "r2");
	if (a == (void *)1)
		while (*(volatile unsigned long *)&one)
			;
	return false;
}

/*
 * The first pass joins the three pairs and gets to bpf_rbtree_add(), which no run of the prog
 * calls. The comparator of such a tree cannot unwind. That is found late: its access to arena is
 * skipped and the pass is done again, and then its loop has no way out. A pass that keeps the pairs
 * apart has no such call. That the function cannot leave with unwind_exit is gone with the pass
 * which found it: where the function is called with 1 its loop unwinds. Its access to arena stays
 * skipped, which is what it was before programs were unwound: that is safe to keep.
 */
SEC("syscall")
__description("fault: a call that only one pass gets to says nothing about what can unwind")
__success __retval(-ECANCELED)
int cleared_in_another_pass(void *ctx)
{
	u32 r = bpf_get_prandom_u32() % 3;
	struct node_with_tree *n;
	void *p = NULL;
	long x, y;

	if (r == 0) {
		x = 1;
		y = 1;
	} else if (r == 1) {
		x = 2;
		y = 4;
	} else {
		x = 3;
		y = 9;
	}
	barrier_var(x);
	barrier_var(y);
	barrier_var(p);
	less_faults(p, NULL);
	if (x * x != y) {
		n = bpf_obj_new(typeof(*n));
		if (n) {
			bpf_spin_lock(&tree_lock);
			bpf_rbtree_add(&tree_root, &n->node, less_faults);
			bpf_spin_unlock(&tree_lock);
		}
	}
	p = (void *)1;
	barrier_var(p);
	less_faults(p, NULL);
	return 7;
}

/* It leaves the section of its caller, loads from the arena, and would enter the section again */
__naked __noinline __used
static unsigned long leaves_section_and_faults(void)
{
	asm volatile (
		"call %[bpf_preempt_enable];"
	NO_PAGE
		"r2 = *(u32 *)(r8 + 0);"
		"call %[bpf_preempt_disable];"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(arena), __imm(bpf_preempt_enable), __imm(bpf_preempt_disable)
		: __clobber_all
	);
}

/*
 * The function that gets a new chunk for an allocator: called under a lock, which it drops to
 * take pages. The frame holds nothing where the load faults, and is in one section less than it
 * was called in: the pad of the load enters the section, and the pad of the call leaves it.
 */
SEC("tc")
__description("fault: a load in a subprog that has left the section of its caller")
__success __retval(2)
__log_level(2)
__msg("landing pad of call at 1: rcu=0 preempt=1")
__msg("landing pad of arena access at {{[0-9]+}}: rcu=0 preempt=-1")
__naked void load_where_section_of_caller_is_left(void)
{
	asm volatile (
		"call %[bpf_preempt_disable];"
		"call leaves_section_and_faults;"
		"call %[bpf_preempt_enable];"
		"r0 = 7;"
		"exit;"
		:
		: __imm(bpf_preempt_disable), __imm(bpf_preempt_enable)
		: __clobber_all
	);
}

/* r1: the irq flags of the caller. It restores them and then loads from the arena. */
__naked __noinline __used
static unsigned long restores_irq_and_faults(void)
{
	asm volatile (
		"call %[bpf_local_irq_restore];"
	NO_PAGE
		"r2 = *(u32 *)(r8 + 0);"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(arena), __imm(bpf_local_irq_restore)
		: __clobber_all
	);
}

/*
 * The prog saves the flags on some paths, so the loop needs a hidden slot for them. The subprog
 * restores them and can fault behind that: its frame holds nothing there, but it is left with the
 * slot of the prog not cleared. The load is a site for that, the function of the prog gets no
 * hidden slots for its locks, and the loop has no plan.
 */
SEC("tc")
__description("fault: a load in a subprog that has restored the irq flags of its caller")
__failure
__msg("landing pad of may_goto at {{[0-9]+}}: conflict: a resource is held on some paths only")
__naked void load_where_irq_of_caller_is_restored(void)
{
	asm volatile (
		"r9 = %[one] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"if r9 == 0 goto 4f;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
	"4:"
		"r2 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"if r9 == 0 goto 5f;"
		"r1 = r10;"
		"r1 += -8;"
		"call restores_irq_and_faults;"
	"5:"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one), __imm_addr(zero), __imm(bpf_local_irq_save)
		: __clobber_all
	);
}

#endif /* __BPF_FEATURE_ADDR_SPACE_CAST */

#else

SEC("socket")
__description("fault: unwinding is not supported, use a dummy test")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
