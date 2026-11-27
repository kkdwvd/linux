// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf_arena_common.h>

char _license[] SEC("license") = "GPL";

/*
 * A landing pad of the prog that only cleans up and resumes runs when the kernel unwinds its
 * frame: a destructor of C++, drop glue of Rust. A pad that can go on with the function, a catch,
 * does not: an unwind that the kernel starts cannot be caught. Behind a pad that ran the verifier
 * releases what the frame still holds.
 *
 * The pads are written by hand, in the shapes that LLVM gives them. Each prog is a chain of three
 * frames: the prog, which holds a task and has a pad that catches behind its call; a function in
 * between, which has the pad that the test is about; and what that function calls, a leaf or a
 * helper with a callback, which leaves in the way that 'mode' says:
 *
 *	0	it returns: every frame goes on behind its call and says so in 'went_on'
 *	1	the kernel unwinds it: the prog ends with the value of the kernel
 *	2	it leaves with unwind_exit, r0 = 5: the prog unwinds as it would without the kernel
 *
 * What ran says so in a word of its own. The task that runs the prog has as many references after
 * a run as before.
 */
#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

/* BPF_JMP | BPF_JCOND with BPF_UNWIND_GOTO in src_reg, and BPF_JMP | BPF_EXIT with BPF_UNWIND_EXIT */
#define unwind_goto(label) ".8byte ((((" #label " - .) / 8 - 1) & 0xffff) << 16) | 0x10e5;"
#define unwind_exit ".8byte 0x1095;"
/* rN = addr_space_cast(rN, 0x0, 0x1) */
#define to_arena(n) ".8byte 0x1000100bf | (0x11 * " #n ") << 8;"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 8);
} arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} array2 SEC(".maps");

int mode, mode_b;
__u64 went_on, caught, dtor_ran, handler_ran, personality_ran, terminated;
/* what unwind_exit of a call in a pad left in r0, see calls_twice_in_pad() */
__u64 second_left;

/* What the verifier doesn't know: a loop doesn't end, bpf_loop() is not inlined, what a clause takes */
__u64 forever = 1, no_flags, selector;

/* kfuncs that only asm calls need BTF */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_task_release(bpf_task_acquire(bpf_get_current_task_btf()));
	bpf_task_release(bpf_task_from_pid(1));
	bpf_res_spin_lock_irqsave(NULL, NULL);
	bpf_res_spin_unlock_irqrestore(NULL, NULL);
	bpf_throw(0);
}

/* The count of the task that runs the progs, which bpf_task_acquire() raises */
SEC("syscall")
int task_usage(void *ctx)
{
	return bpf_get_current_task_btf()->rcu_users.refs.counter;
}

/* The same of the task with pid 1: what a prog releases once too often is missing there */
SEC("syscall")
int init_usage(void *ctx)
{
	struct task_struct *init = bpf_task_from_pid(1);
	int usage;

	if (!init)
		return -1;
	usage = init->rcu_users.refs.counter;
	bpf_task_release(init);
	return usage;
}

/*
 * The RCU sections that the task is in: one that a prog did not leave is still counted here. A
 * kernel that cannot preempt in such a section has no count.
 */
SEC("syscall")
int rcu_nesting(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	if (!bpf_core_field_exists(task->rcu_read_lock_nesting))
		return 0;
	return task->rcu_read_lock_nesting;
}

/* @reg = a reference to the task that runs the prog */
#define ACQUIRE(reg)					\
		"call %[bpf_get_current_task_btf];"	\
		"r1 = r0;"				\
		"call %[bpf_task_acquire];"		\
		"if r0 != 0 goto +2;"			\
		"r0 = 3;"				\
		"exit;"					\
		#reg " = r0;"
#define RELEASE(reg) "r1 = " #reg ";" "call %[bpf_task_release];"
#define TASK_IMM __imm(bpf_get_current_task_btf), __imm(bpf_task_acquire), __imm(bpf_task_release)

/* *@var += 1 */
#define COUNT(var)					\
		"r1 = %[" #var "] ll;"			\
		"r2 = *(u64 *)(r1 + 0);"		\
		"r2 += 1;"				\
		"*(u64 *)(r1 + 0) = r2;"

/* What is called looks at @var first. Mode 1 goes on behind this. */
#define MODE_OF(var)					\
		"r1 = %[" #var "] ll;"			\
		"r1 = *(u32 *)(r1 + 0);"		\
		"if r1 == 0 goto 8f;"			\
		"if r1 == 2 goto 9f;"
#define MODE MODE_OF(mode)
/* @ret: what it returns in mode 0 */
#define RETURNS(ret)					\
	"8:	r0 = " #ret ";"				\
		"exit;"					\
	"9:	r0 = 5;"				\
		unwind_exit

/* The ways in which the kernel starts to unwind. bpf_throw(): the prog returns the cookie. */
__naked __noinline __used
static unsigned long throws(void)
{
	asm volatile (
	MODE
		"r1 = 9;"
		"call %[bpf_throw];"
	RETURNS(7)
		:: __imm_addr(mode), __imm(bpf_throw) : __clobber_all);
}

/* may_goto that the verifier adds to a loop which nothing ends, when its time is up */
__naked __noinline __used
static unsigned long spins(void)
{
	asm volatile (
	MODE
		"r2 = %[forever] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	RETURNS(7)
		:: __imm_addr(mode), __imm_addr(forever) : __clobber_all);
}

/* the same, told by 'mode_b' */
__naked __noinline __used
static unsigned long spins_b(void)
{
	asm volatile (
	MODE_OF(mode_b)
		"r2 = %[forever] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	RETURNS(7)
		:: __imm_addr(mode_b), __imm_addr(forever) : __clobber_all);
}

/* may_goto that the prog has, when its time is up */
__naked __noinline __used
static unsigned long may_goto_spins(void)
{
	asm volatile (
	MODE
	"1:	may_goto 8f;"
		"goto 1b;"
	RETURNS(7)
		:: __imm_addr(mode) : __clobber_all);
}

/* an access to a page of the arena that is not there */
__naked __noinline __used
static unsigned long faults(void)
{
	asm volatile (
		"r2 = %[arena] ll;"
	MODE
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u64 *)(r8 + 0);"
	RETURNS(7)
		:: __imm_addr(mode), __imm_addr(arena) : __clobber_all);
}

/* the check of a recursion, when the stack has no room for one more frame */
__naked __noinline __used
static unsigned long recurses(void)
{
	asm volatile (
	MODE
		"call recurses;"
		"exit;"
	RETURNS(7)
		:: __imm_addr(mode) : __clobber_all);
}

/* What a destructor does: it says that it ran */
__naked __noinline __used
static void dtor(void)
{
	asm volatile (
	COUNT(dtor_ran)
		"exit;"
		:: __imm_addr(dtor_ran) : __clobber_all);
}

/*
 * What follows the call in the prog, and its landing pad, which catches: it ends the unwinding
 * and returns 42. Both release the task, as they have to: they are code of the prog. 'went_on' is
 * 100 more than what the call returned, 'caught' is what unwind_exit left in r0.
 * The kernel does not enter this pad. So in mode 1 neither word is set.
 */
#define AFTER_CALL							\
		unwind_goto(7f)						\
		"r7 = r0;"						\
		"r7 += 100;"						\
	RELEASE(r6)							\
		"r1 = %[went_on] ll;"					\
		"*(u64 *)(r1 + 0) = r7;"				\
		"r0 = 1;"						\
		"exit;"							\
	"7:	r7 = r0;"						\
	RELEASE(r6)							\
		"r1 = %[caught] ll;"					\
		"*(u64 *)(r1 + 0) = r7;"				\
		"r0 = 42;"						\
		"exit;"
#define AFTER_IMM TASK_IMM, __imm_addr(went_on), __imm_addr(caught)

#define TOP(name, mid)							\
SEC("tc")								\
__naked void name(void)							\
{									\
	asm volatile (							\
	ACQUIRE(r6)							\
		"call " #mid ";"					\
	AFTER_CALL							\
		:: AFTER_IMM : __clobber_all);				\
}

/* The exception callback gets the cookie when the prog has released what it holds */
__noinline int adds_100(u64 cookie)
{
	return cookie + 100;
}

#define TOP_EXCEPTION_CB(name, mid)					\
SEC("tc")								\
__exception_cb(adds_100)						\
__naked void name(void)							\
{									\
	asm volatile (							\
	ACQUIRE(r6)							\
		"call " #mid ";"					\
	AFTER_CALL							\
		:: AFTER_IMM : __clobber_all);				\
}

/*
 * The function in between has a guard: 'r7 = r0; call dtor; r0 = r7; unwind_exit' is what clang
 * makes of its destructor. It holds a task, which its pad releases like its normal path does, and
 * it is in an RCU section. When the prog unwinds, the pad leaves the section, as it has to. When
 * the kernel unwinds, r0 is 0 in the pad, and this pad leaves the section to the verifier: the
 * code that stands in for unwind_exit leaves it.
 */
#define DTOR_PAD							\
	"3:	r7 = r0;"						\
		"call dtor;"						\
	RELEASE(r6)							\
		"if r7 == 0 goto +1;"					\
		"call %[bpf_rcu_read_unlock];"				\
		"r0 = r7;"						\
		unwind_exit

#define MID_DTOR(name, leaf)						\
__naked __noinline __used						\
static unsigned long name(void)						\
{									\
	asm volatile (							\
	ACQUIRE(r6)							\
		"call %[bpf_rcu_read_lock];"				\
		"call " #leaf ";"					\
		unwind_goto(3f)						\
		"r7 = r0;"						\
		"call %[bpf_rcu_read_unlock];"				\
	RELEASE(r6)							\
		"r0 = r7;"						\
		"exit;"							\
	DTOR_PAD							\
		:: TASK_IMM, __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) \
		: __clobber_all);					\
}

MID_DTOR(dtor_throws, throws)
TOP(dtor_below_throw, dtor_throws)
TOP_EXCEPTION_CB(dtor_below_throw_exception_cb, dtor_throws)
MID_DTOR(dtor_spins, spins)
TOP(dtor_below_guard, dtor_spins)
MID_DTOR(dtor_may_goto_spins, may_goto_spins)
TOP(dtor_below_may_goto, dtor_may_goto_spins)
MID_DTOR(dtor_faults, faults)
TOP(dtor_below_fault, dtor_faults)
MID_DTOR(dtor_recurses, recurses)
TOP(dtor_below_recursion, dtor_recurses)

/* The same starts in a callback: the helper is a frame of the kernel between it and the pad */
#define CB(name, how, imm...)						\
__naked __noinline __used						\
static unsigned long name(void)						\
{									\
	asm volatile (							\
		"r2 = %[arena] ll;"					\
	MODE								\
		how							\
	RETURNS(1)							\
		:: __imm_addr(mode), __imm_addr(arena), ##imm : __clobber_all); \
}

CB(cb_throws, "r1 = 9;" "call %[bpf_throw];", __imm(bpf_throw))
CB(cb_spins, "r2 = %[forever] ll;" "1: r1 = *(u64 *)(r2 + 0);" "if r1 != 0 goto 1b;",
   __imm_addr(forever))
CB(cb_may_goto_spins, "1: may_goto 8f;" "goto 1b;")
CB(cb_faults, "r8 = 0x1000;" to_arena(8) "r0 = *(u64 *)(r8 + 0);")
CB(cb_recurses, "call recurses;" "r0 = 1;" "exit;")

/* @flags: 0, and the verifier inlines the loop, or what it does not know */
#define MID_DTOR_LOOP(name, cb, flags)					\
__naked __noinline __used						\
static unsigned long name(void)						\
{									\
	asm volatile (							\
	ACQUIRE(r6)							\
		"call %[bpf_rcu_read_lock];"				\
		"r1 = 3;"						\
		"r2 = %[" #cb "] ll;"					\
		"r3 = 0;"						\
		flags							\
		"call %[bpf_loop];"					\
		unwind_goto(3f)						\
		"r7 = r0;"						\
		"call %[bpf_rcu_read_unlock];"				\
	RELEASE(r6)							\
		"r0 = r7;"						\
		"exit;"							\
	DTOR_PAD							\
		:: TASK_IMM, __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock), \
		   __imm(bpf_loop), __imm_addr(cb), __imm_addr(no_flags) \
		: __clobber_all);					\
}
#define NOT_INLINED "r4 = %[no_flags] ll;" "r4 = *(u64 *)(r4 + 0);"
#define INLINED "r4 = 0;"

MID_DTOR_LOOP(dtor_loop_throws, cb_throws, NOT_INLINED)
TOP(dtor_below_loop_throw, dtor_loop_throws)
MID_DTOR_LOOP(dtor_loop_spins, cb_spins, NOT_INLINED)
TOP(dtor_below_loop_guard, dtor_loop_spins)
MID_DTOR_LOOP(dtor_loop_may_goto_spins, cb_may_goto_spins, NOT_INLINED)
TOP(dtor_below_loop_may_goto, dtor_loop_may_goto_spins)
MID_DTOR_LOOP(dtor_loop_faults, cb_faults, NOT_INLINED)
TOP(dtor_below_loop_fault, dtor_loop_faults)
MID_DTOR_LOOP(dtor_loop_recurses, cb_recurses, NOT_INLINED)
TOP(dtor_below_loop_recursion, dtor_loop_recurses)
MID_DTOR_LOOP(dtor_loop_inlined_throws, cb_throws, INLINED)
TOP(dtor_below_loop_inlined_throw, dtor_loop_inlined_throws)
MID_DTOR_LOOP(dtor_loop_inlined_spins, cb_spins, INLINED)
TOP(dtor_below_loop_inlined_guard, dtor_loop_inlined_spins)

/* The call under the guard is one through a pointer */
__naked __noinline __used
static unsigned long dtor_callx_spins(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call %[bpf_rcu_read_lock];"
		"r8 = %[spins] ll;"
		"callx r8;"
		unwind_goto(3f)
		"r7 = r0;"
		"call %[bpf_rcu_read_unlock];"
	RELEASE(r6)
		"r0 = r7;"
		"exit;"
	DTOR_PAD
		:: TASK_IMM, __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock), __imm_addr(spins)
		: __clobber_all);
}
TOP(dtor_callx_below_guard, dtor_callx_spins)

/*
 * A global function with the guard: it is verified without its callers, which expect the kernel
 * to unwind it once that is found. Its frame is forced like any other, and what it leaves with
 * when the prog unwinds is a number to its callers.
 */
__naked __noinline __used
unsigned long global_dtor_spins(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call %[bpf_rcu_read_lock];"
		"call spins;"
		unwind_goto(3f)
		"r7 = r0;"
		"call %[bpf_rcu_read_unlock];"
	RELEASE(r6)
		"r0 = r7;"
		"exit;"
	DTOR_PAD
		:: TASK_IMM, __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}
TOP(dtor_global_below_guard, global_dtor_spins)

/*
 * The personality routine of C++ says in memory whether a clause takes the exception. 'selector'
 * is 1 for a clause that does.
 */
__naked __noinline __used
static unsigned long personality(void)
{
	asm volatile (
	COUNT(personality_ran)
		"r1 = %[selector] ll;"
		"r0 = *(u64 *)(r1 + 0);"
		"exit;"
		:: __imm_addr(personality_ran), __imm_addr(selector) : __clobber_all);
}

/* What every function in between that follows does when its call returns */
#define MID_RETURNS							\
		"r7 = r0;"						\
	RELEASE(r6)							\
		"r0 = r7;"						\
		"exit;"

/* The handler of a catch clause: it says that it ran, and the function returns 77 */
#define HANDLER								\
	COUNT(handler_ran)						\
	RELEASE(r6)							\
		"r0 = 77;"						\
		"exit;"

/*
 * try { } catch (T &): the pad asks the personality routine, and goes to the handler or resumes.
 * It can return, so the kernel does not enter it, and the personality routine is not asked.
 */
__naked __noinline __used
static unsigned long typed_catch(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call spins;"
		unwind_goto(3f)
	MID_RETURNS
	"3:	r7 = r0;"
		"call personality;"
		"if r0 != 1 goto 4f;"
	HANDLER
	"4:"
	RELEASE(r6)
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM, __imm_addr(handler_ran) : __clobber_all);
}
TOP(typed_catch_below_guard, typed_catch)

/* try { } catch (...), and catch_unwind() of Rust: the pad is the handler */
__naked __noinline __used
static unsigned long catch_all(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call spins;"
		unwind_goto(3f)
	MID_RETURNS
	"3:"
	HANDLER
		:: TASK_IMM, __imm_addr(handler_ran) : __clobber_all);
}
TOP(catch_all_below_guard, catch_all)

/*
 * A noexcept function: the pad calls std::terminate(), which is bpf_throw(0). It has no
 * unwind_exit, and the kernel does not enter it either.
 */
__naked __noinline __used
static unsigned long terminates(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call spins;"
		unwind_goto(3f)
	MID_RETURNS
	"3:"
	COUNT(terminated)
		"r1 = 0;"
		"call %[bpf_throw];"
		"exit;"
		:: TASK_IMM, __imm_addr(terminated), __imm(bpf_throw) : __clobber_all);
}
TOP(terminate_below_guard, terminates)

/* What __cxa_rethrow() does: the object in r1 is thrown again */
__naked __noinline __used
static unsigned long rethrow(void)
{
	asm volatile (
		"r0 = r1;"
		unwind_exit
		::: __clobber_all);
}

/*
 * try { } catch (T &) { throw; }: the handler throws the object again, and the pad of that call
 * is where the first pad resumes too. No path returns: the kernel enters the pad. Its r0 is 0, the
 * handler runs and rethrows that 0, with unwind_exit of the prog. The frame stays one that the
 * kernel unwinds: it leaves with the value of the kernel, and the catch of the prog above does
 * not run.
 */
__naked __noinline __used
static unsigned long catch_rethrow(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call spins;"
		unwind_goto(3f)
	MID_RETURNS
	"3:	r7 = r0;"
		"call personality;"
		"if r0 != 1 goto 5f;"
	COUNT(handler_ran)
		"r1 = r7;"
		"call rethrow;"
		unwind_goto(4f)
	"4:	r7 = r0;"
	"5:"
	RELEASE(r6)
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM, __imm_addr(handler_ran) : __clobber_all);
}
TOP(catch_rethrow_below_guard, catch_rethrow)

/*
 * A function with a guard and a try block: clang makes one resume block, and the pad of the try
 * goes there when no clause takes the exception. The pad of the first call only resumes, the pad
 * of the second one can return. 'mode' is for the first call, 'mode_b' for the second one.
 * The kernel unwinds the first callee in one run: the hidden word of the frame says so when its
 * pad gets to the resume block. In the next run the second callee leaves with unwind_exit, at the
 * same depth of the stack, no clause takes it, and its pad gets to the same block: the prog
 * unwinds, and the prog above catches. Nothing of the first run is left in that word.
 */
__naked __noinline __used
static unsigned long shares_resume(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call spins;"
		unwind_goto(3f)
		"call spins_b;"
		unwind_goto(4f)
	MID_RETURNS
	"3:	r7 = r0;"
		"call dtor;"
		"goto 5f;"
	"4:	r7 = r0;"
		"call personality;"
		"if r0 != 1 goto 5f;"
	HANDLER
	"5:"
	RELEASE(r6)
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM, __imm_addr(handler_ran) : __clobber_all);
}
TOP(shared_resume_below_guard, shares_resume)

/*
 * _Unwind_RaiseException() inlined into a function with a guard: 'r0 = exn; goto pad'. The pad is
 * entered by a jump, by unwind_goto and by the kernel. Mode 3 raises, with 6.
 */
__naked __noinline __used
static unsigned long raises_inline(void)
{
	asm volatile (
	ACQUIRE(r6)
		"r1 = %[mode] ll;"
		"r1 = *(u32 *)(r1 + 0);"
		"if r1 != 3 goto +2;"
		"r0 = 6;"
		"goto 3f;"
		"call spins;"
		unwind_goto(3f)
	MID_RETURNS
	"3:	r7 = r0;"
		"call dtor;"
	RELEASE(r6)
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM, __imm_addr(mode) : __clobber_all);
}
TOP(raise_inlined_below_guard, raises_inline)

/* It throws 1, with unwind_exit of the prog, and never returns */
__naked __noinline __used
static unsigned long raises_1(void)
{
	asm volatile (
		"r0 = 1;"
		unwind_exit
		::: __clobber_all);
}

/*
 * A destructor that throws, and the pad has no landing pad for that call: the verifier adds one.
 * When the prog unwinds it passes on what the destructor threw, the 1, and the prog above catches
 * that. When the kernel unwinds the frame the same call leaves the frame with the value of the
 * kernel: unwind_exit of the prog in a pad does not make the unwinding one of the prog.
 */
__naked __noinline __used
static unsigned long dtor_raises(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call spins;"
		unwind_goto(3f)
	MID_RETURNS
	"3:	r7 = r0;"
		"call dtor;"
	RELEASE(r6)
		"call raises_1;"
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM : __clobber_all);
}
TOP(dtor_raises_below_guard, dtor_raises)

/*
 * The kernel starts to unwind a second time, in the pad that it entered: the destructor faults in
 * arena, in the pad itself. The frame leaves there, with what it holds released, and the value is
 * the one that the unwinding began with: the prog returns what the exception callback makes of the
 * cookie of bpf_throw(), not of the value of a fault.
 * When the prog unwinds to this pad, the fault is where the kernel starts: the value of a fault.
 */
__naked __noinline __used
static unsigned long dtor_faults_in_pad(void)
{
	asm volatile (
		"r2 = %[arena] ll;"
	ACQUIRE(r6)
		"call throws;"
		unwind_goto(3f)
	MID_RETURNS
	"3:	r7 = r0;"
		"call dtor;"
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u64 *)(r8 + 0);"
	RELEASE(r6)
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM, __imm_addr(arena) : __clobber_all);
}
TOP_EXCEPTION_CB(dtor_faults_below_throw, dtor_faults_in_pad)

/* A destructor that loops until its time is up, whatever 'mode' is */
__naked __noinline __used
static unsigned long dtor_that_spins(void)
{
	asm volatile (
	COUNT(dtor_ran)
		"r2 = %[forever] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"exit;"
		:: __imm_addr(dtor_ran), __imm_addr(forever) : __clobber_all);
}

/* The same, and the second start is in a function that the pad calls */
__naked __noinline __used
static unsigned long dtor_spins_in_pad(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call throws;"
		unwind_goto(3f)
	MID_RETURNS
	"3:	r7 = r0;"
		"call dtor_that_spins;"
	RELEASE(r6)
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM : __clobber_all);
}
TOP_EXCEPTION_CB(dtor_spins_below_throw, dtor_spins_in_pad)

/*
 * bpf_throw() in the pad that the kernel entered: its cookie is dropped. The verifier does not
 * know that the pad always throws: a pad that never gets to unwind_exit is not entered.
 */
__naked __noinline __used
static unsigned long dtor_throws_in_pad(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call throws;"
		unwind_goto(3f)
	MID_RETURNS
	"3:	r7 = r0;"
		"call dtor;"
	RELEASE(r6)
		"r1 = %[forever] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto +2;"
		"r1 = 21;"
		"call %[bpf_throw];"
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM, __imm(bpf_throw), __imm_addr(forever) : __clobber_all);
}
TOP_EXCEPTION_CB(dtor_throws_below_throw, dtor_throws_in_pad)

/*
 * The function holds a task that its pad releases only when the prog unwinds: with 0 in r0 the pad
 * leaves it. r6 is not read behind that, so nothing has the pointer where the pad ends. The entry
 * of the pad has put it into a word of the frame, and the code in place of unwind_exit releases
 * it from there, once.
 */
#define MID_LEAVES_TASK(name, leaf)					\
__naked __noinline __used						\
static unsigned long name(void)						\
{									\
	asm volatile (							\
	ACQUIRE(r6)							\
		"call " #leaf ";"					\
		unwind_goto(3f)						\
	MID_RETURNS							\
	"3:	r7 = r0;"						\
		"call dtor;"						\
		"if r7 == 0 goto +2;"					\
	RELEASE(r6)							\
		"r0 = r7;"						\
		unwind_exit						\
		:: TASK_IMM : __clobber_all);				\
}

MID_LEAVES_TASK(leaves_task_spins, spins)
TOP(leaves_task_below_guard, leaves_task_spins)
MID_LEAVES_TASK(leaves_task_throws, throws)
TOP_EXCEPTION_CB(leaves_task_below_throw, leaves_task_throws)
MID_LEAVES_TASK(leaves_task_faults, faults)
TOP(leaves_task_below_fault, leaves_task_faults)

/*
 * Two calls with pads that only resume and share their end, as the pads of one function of C++ do.
 * The function holds one task at the first call and two at the second one, and when the kernel
 * unwinds the pads leave all of them. The entry of the first call fills one word of the frame and
 * clears the other, the entry of the second call fills both, and the code in place of unwind_exit
 * releases what a word has. 'mode' is for the first call, 'mode_b' for the second one.
 */
__naked __noinline __used
static unsigned long holds_one_then_two(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call spins;"
		unwind_goto(3f)
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +4;"
	RELEASE(r6)
		"r0 = 3;"
		"exit;"
		"r8 = r0;"
		"call spins_b;"
		unwind_goto(4f)
		"r7 = r0;"
	RELEASE(r8)
	RELEASE(r6)
		"r0 = r7;"
		"exit;"
	"4:	r7 = r0;"
		"call dtor;"
		"if r7 == 0 goto 6f;"
	RELEASE(r8)
		"goto 5f;"
	"3:	r7 = r0;"
		"call dtor;"
		"if r7 == 0 goto 6f;"
	"5:"
	RELEASE(r6)
	"6:	r0 = r7;"
		unwind_exit
		:: TASK_IMM : __clobber_all);
}
TOP(one_then_two_below_guard, holds_one_then_two)

/*
 * The same two calls where the first one holds one task or two, by what is in memory: the states
 * that get to it do not agree on what the frame holds, so its entry saves nothing, and its pad
 * releases all that is held, whoever unwinds. The entry of the second call saves the task, and
 * the code in place of unwind_exit releases it from the save word when the kernel unwinds there.
 * A frame that came through the first entry gets to that code as well, with nothing left to
 * release: that entry has put 0 into the word.
 */
__naked __noinline __used
static unsigned long holds_one_or_two_then_one(void)
{
	asm volatile (
		"r8 = 0;"
	ACQUIRE(r6)
		"r1 = %[forever] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 1f;"
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +4;"
	RELEASE(r6)
		"r0 = 3;"
		"exit;"
		"r8 = r0;"
	"1:	call spins;"
		unwind_goto(3f)
		"if r8 == 0 goto 2f;"
	RELEASE(r8)
	"2:	call spins_b;"
		unwind_goto(4f)
		"r7 = r0;"
	RELEASE(r6)
		"r0 = r7;"
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
	RELEASE(r6)
		"if r8 == 0 goto 5f;"
	RELEASE(r8)
		"goto 5f;"
	"4:	r7 = r0;"
		"call dtor;"
		"if r7 == 0 goto 5f;"
	RELEASE(r6)
	"5:	r0 = r7;"
		unwind_exit
		:: TASK_IMM, __imm_addr(forever) : __clobber_all);
}
TOP(one_or_two_then_one_below_guard, holds_one_or_two_then_one)

struct bpf_res_spin_lock lock_a SEC(".data.lock_a") __hidden;

/*
 * The function holds a task, and a lock that it took with the interrupts off: three of refs[], the
 * task, the lock and the irq flags that the lock saved. Its pad unlocks, as the destructor of a
 * guard does, and leaves the task when the kernel unwinds. The save word of the task is the one
 * that the code in place of unwind_exit reads, whatever else the frame held at the call.
 */
#define LOCK_A(call)							\
		"r1 = %[lock_a] ll;"					\
		"r2 = r10;"						\
		"r2 += -8;"						\
		"call %[" #call "];"

__naked __noinline __used
static unsigned long leaves_task_under_lock(void)
{
	asm volatile (
	ACQUIRE(r6)
	LOCK_A(bpf_res_spin_lock_irqsave)
		"if r0 == 0 goto +4;"
	RELEASE(r6)
		"r0 = 3;"
		"exit;"
		"call faults;"
		unwind_goto(3f)
		"r7 = r0;"
	LOCK_A(bpf_res_spin_unlock_irqrestore)
	RELEASE(r6)
		"r0 = r7;"
		"exit;"
	"3:	r7 = r0;"
	LOCK_A(bpf_res_spin_unlock_irqrestore)
		"call dtor;"
		"if r7 == 0 goto +2;"
	RELEASE(r6)
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM, __imm_addr(lock_a), __imm(bpf_res_spin_lock_irqsave),
		   __imm(bpf_res_spin_unlock_irqrestore) : __clobber_all);
}
TOP(leaves_task_below_lock, leaves_task_under_lock)

/* It returns in mode 0. In any other mode the kernel unwinds it: the program never does. */
__naked __noinline __used
static unsigned long spins_or_returns(void)
{
	asm volatile (
		"r1 = %[mode] ll;"
		"r1 = *(u32 *)(r1 + 0);"
		"if r1 == 0 goto 2f;"
		"r2 = %[forever] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	"2:	r0 = 7;"
		"exit;"
		:: __imm_addr(mode), __imm_addr(forever) : __clobber_all);
}

/*
 * The pad takes the task to r1 and then waits in a loop, in an RCU section, before it releases.
 * The time of the prog is up when the kernel enters the pad, so the loop is left at its guard at
 * once. The pad of that guard leaves the section first, and r1 is gone by then: it releases the
 * task from the word that the entry of the landing pad put it into.
 */
__naked __noinline __used
static unsigned long waits_with_task_in_r1(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call spins_or_returns;"
		unwind_goto(3f)
	MID_RETURNS
	"3:	r7 = r0;"
	COUNT(dtor_ran)
		"call %[bpf_rcu_read_lock];"
		"r1 = r6;"
		"r2 = %[forever] ll;"
	"4:	r3 = *(u64 *)(r2 + 0);"
		"if r3 != 0 goto 4b;"
		"call %[bpf_task_release];"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM, __imm_addr(dtor_ran), __imm_addr(forever), __imm(bpf_rcu_read_lock),
		   __imm(bpf_rcu_read_unlock) : __clobber_all);
}
TOP(task_in_r1_below_guard, waits_with_task_in_r1)

/*
 * An object of the program that has a field of its own to release: a task. The function makes it
 * and puts it into a map, takes it out again and holds it over the call. Its pad frees the object
 * when the prog unwinds, and leaves it when the kernel does: no register has the pointer where the
 * pad ends then, r6 is 0. The word that the entry of the pad filled has it, and what the word is
 * for says what frees it and of which type it is: the task of the object is released with it. An
 * object that is freed as memory alone leaves the count of the task one too high.
 */
struct with_task {
	struct task_struct __kptr *task;
};

struct has_obj {
	struct with_task __kptr *obj;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct has_obj);
} obj_map SEC(".maps");

__noinline __used
static int stashes_obj(void)
{
	struct with_task *o, *old;
	struct task_struct *task;
	struct has_obj *v;
	int key = 0;

	v = bpf_map_lookup_elem(&obj_map, &key);
	if (!v)
		return 1;
	o = bpf_obj_new(typeof(*o));
	if (!o)
		return 1;
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task) {
		bpf_obj_drop(o);
		return 1;
	}
	task = bpf_kptr_xchg(&o->task, task);
	if (task)
		bpf_task_release(task);
	old = bpf_kptr_xchg(&v->obj, o);
	if (old)
		bpf_obj_drop(old);
	return 0;
}

__naked __noinline __used
static unsigned long leaves_obj(void)
{
	asm volatile (
		"call stashes_obj;"
		"if r0 != 0 goto 1f;"
		"*(u32 *)(r10 - 4) = r0;"
		"r1 = %[obj_map] ll;"
		"r2 = r10;"
		"r2 += -4;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 1f;"
		"r1 = r0;"
		"r2 = 0;"
		"call %[bpf_kptr_xchg];"
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
		"call spins;"
		unwind_goto(3f)
		"r7 = r0;"
		"r1 = r6;"
		"call %[bpf_obj_drop];"
		"r0 = r7;"
		"exit;"
	"1:	r0 = 3;"
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
		"if r7 == 0 goto +2;"
		"r1 = r6;"
		"call %[bpf_obj_drop];"
		"r6 = 0;"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(obj_map), __imm(bpf_map_lookup_elem), __imm(bpf_kptr_xchg),
		   __imm(bpf_obj_drop) : __clobber_all);
}
TOP(leaves_obj_below_guard, leaves_obj)

/*
 * Two tasks, and the one that the function acquires first stands behind the other one in its
 * text: the task that runs the prog in r6, then the task with pid 1 in r8. The pad releases the
 * second one on every way and leaves the first one when the kernel unwinds. The code in place of
 * unwind_exit releases the first one, from the word that the entry of the pad put it into: not the
 * second one once more.
 */
__naked __noinline __used
static unsigned long holds_two_out_of_order(void)
{
	asm volatile (
		"goto 2f;"
	"1:	r1 = 1;"
		"call %[bpf_task_from_pid];"
		"if r0 != 0 goto +4;"
	RELEASE(r6)
		"r0 = 3;"
		"exit;"
		"r8 = r0;"
		"call spins;"
		unwind_goto(3f)
		"r7 = r0;"
	RELEASE(r8)
	RELEASE(r6)
		"r0 = r7;"
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
	RELEASE(r8)
		"if r7 == 0 goto +2;"
	RELEASE(r6)
		"r0 = r7;"
		unwind_exit
	"2:"
	ACQUIRE(r6)
		"goto 1b;"
		:: TASK_IMM, __imm(bpf_task_from_pid) : __clobber_all);
}
TOP(two_out_of_order_below_guard, holds_two_out_of_order)

/*
 * The register that keeps the task has a pointer into it, 8 bytes behind its start, as a pointer
 * to a member has. The word gets the pointer that the release takes: the entry takes the 8 off,
 * unless the register is 0.
 */
__naked __noinline __used
static unsigned long leaves_task_at_offset(void)
{
	asm volatile (
	ACQUIRE(r6)
		"r6 += 8;"
		"call spins;"
		unwind_goto(3f)
		"r7 = r0;"
		"r1 = r6;"
		"r1 += -8;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
		"if r7 == 0 goto +3;"
		"r1 = r6;"
		"r1 += -8;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM : __clobber_all);
}
TOP(leaves_task_at_offset_below_guard, leaves_task_at_offset)

/*
 * The call in the pad has a landing pad of its own that only resumes, and what it calls loops until
 * its time is up: the kernel unwinds it. Where the kernel has entered the first pad already that is
 * a second entry of the same frame. It stores nothing: the frame keeps the value of the first one,
 * the cookie of bpf_throw(), and the task that the first one put into its word.
 * When the prog unwinds into the first pad the same entry is the first one of the frame.
 */
__naked __noinline __used
static unsigned long pad_in_pad(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call throws;"
		unwind_goto(3f)
	MID_RETURNS
	"3:	r7 = r0;"
		"call dtor_that_spins;"
		unwind_goto(4f)
		"if r7 == 0 goto 5f;"
	RELEASE(r6)
	"5:	r0 = r7;"
		unwind_exit
	"4:"
	COUNT(handler_ran)
		"goto 5b;"
		:: TASK_IMM, __imm_addr(handler_ran) : __clobber_all);
}
TOP_EXCEPTION_CB(pad_in_pad_below_throw, pad_in_pad)

/*
 * A function without an exit: it throws what its callee returns, plus 10. Its pad goes back to
 * the first insn of the function, once, in mode 1, and sets the mode to 0 before: the callee
 * returns then, and the function throws. A frame that the kernel unwinds stays one on that way.
 * The store that clears the hidden word is where calls of the function get to, not where a jump to
 * its first insn does: the frame leaves with the value of the kernel, and the prog above does not
 * catch the 17.
 * The callee faults: after a loop whose time is up the guard of the loop that the pad closes
 * would end the frame before it gets back.
 */
__naked __noinline __used
static unsigned long starts_again(void)
{
	asm volatile (
	"1:	call faults;"
		unwind_goto(3f)
		"r0 += 10;"
		unwind_exit
	"3:	r7 = r0;"
		"call dtor;"
		"r1 = %[mode] ll;"
		"r2 = *(u32 *)(r1 + 0);"
		"if r2 != 1 goto 4f;"
		"r2 = 0;"
		"*(u32 *)(r1 + 0) = r2;"
		"goto 1b;"
	"4:	r0 = r7;"
		unwind_exit
		:: __imm_addr(mode) : __clobber_all);
}
TOP(starts_again_below_fault, starts_again)

/*
 * A function that calls itself, r1 deep, with a task and a pad in every frame. The pad leaves the
 * task when the kernel unwinds. Each frame has a hidden word and a save word of its own: each
 * destructor runs once and each task is released once.
 */
__naked __noinline __used
static unsigned long recurses_with_pad(void)
{
	asm volatile (
		"r9 = r1;"
	ACQUIRE(r6)
		"if r9 == 0 goto 1f;"
		"r1 = r9;"
		"r1 += -1;"
		"call recurses_with_pad;"
		unwind_goto(3f)
		"goto 2f;"
	"1:	call spins;"
		unwind_goto(3f)
	"2:"
	MID_RETURNS
	"3:	r7 = r0;"
		"call dtor;"
		"if r7 == 0 goto +2;"
	RELEASE(r6)
		"r0 = r7;"
		unwind_exit
		:: TASK_IMM : __clobber_all);
}

SEC("tc")
__naked void recursion_with_pad_below_guard(void)
{
	asm volatile (
	ACQUIRE(r6)
		"r1 = 3;"
		"call recurses_with_pad;"
	AFTER_CALL
		:: AFTER_IMM : __clobber_all);
}

/*
 * The exception callback has the guard. bpf_throw() of the prog calls it, and what it calls
 * leaves in the way that 'mode_b' says. The callback is a frame that the kernel called: when the
 * kernel unwinds its callee, its pad runs, and the prog ends with the value of the kernel.
 */
/* Not naked: a global function has BTF for its argument, and its return stays reachable */
__noinline int cb_with_dtor(u64 cookie)
{
	asm volatile (
		"call spins_b;"
		unwind_goto(1f)
		"goto 2f;"
	"1:	r7 = r0;"
		"call dtor;"
		"r0 = r7;"
		unwind_exit
	"2:"
		::: __clobber_all);
	return cookie + 100;
}

SEC("tc")
__exception_cb(cb_with_dtor)
__naked void dtor_in_exception_cb(void)
{
	asm volatile (
		"r1 = 9;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_throw) : __clobber_all);
}

/*
 * The callback of bpf_for_each_map_elem() has the guard. The verifier does not know which of two
 * maps it is: the helper calls the function of the map, and that calls the callback, two frames of
 * the kernel between the pad and the function that called the helper.
 */
__naked __noinline __used
static unsigned long elem_cb_with_dtor(void)
{
	asm volatile (
		"call spins;"
		unwind_goto(3f)
		"r0 = 1;"
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
		"r0 = r7;"
		unwind_exit
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long for_each_elem(void)
{
	asm volatile (
	ACQUIRE(r6)
		"r1 = %[array] ll;"
		"r2 = %[no_flags] ll;"
		"r2 = *(u64 *)(r2 + 0);"
		"if r2 == 0 goto +2;"
		"r1 = %[array2] ll;"
		"r2 = %[elem_cb_with_dtor] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
	MID_RETURNS
		:: TASK_IMM, __imm(bpf_for_each_map_elem), __imm_addr(array), __imm_addr(array2),
		   __imm_addr(no_flags), __imm_addr(elem_cb_with_dtor) : __clobber_all);
}
TOP(dtor_in_for_each_cb, for_each_elem)

/*
 * The prog itself has the pad that only resumes: in the frame that the kernel called unwind_exit
 * is exit. The kernel enters the pad, the destructor runs, and the prog ends with the value of the
 * kernel, not with what the pad leaves in r0.
 */
SEC("tc")
__naked void dtor_in_main(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call spins;"
		unwind_goto(3f)
		"r7 = r0;"
		"r7 += 100;"
	RELEASE(r6)
		"r1 = %[went_on] ll;"
		"*(u64 *)(r1 + 0) = r7;"
		"r0 = 1;"
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
	RELEASE(r6)
		"r0 = r7;"
		"r0 += 60;"
		unwind_exit
		:: TASK_IMM, __imm_addr(went_on) : __clobber_all);
}

/*
 * STALE WORDS. Nothing clears the hidden word K where a function begins: a stub clears it where
 * unwind_exit of a callee comes back, and the entry of a pad sets it where the kernel unwinds a
 * callee. So a frame finds in that word what an earlier frame at the same depth of the stack left
 * there, and nothing may read it before one of the two has stored.
 * paints() is that earlier frame: it fills 320 bytes of its stack with ones and is called right in
 * front of the function that the test is about, from the same frame. The hidden words of that
 * function and of what it calls are among them. A function that takes a 1 there for its own K
 * leaves as if the kernel unwound it: the prog above does not catch, and the prog ends with the
 * value of the kernel, or with what it finds where the value of bpf_throw() waits.
 * None of these functions keeps a handle in a save word: a word that is wrong shows in what the
 * prog returns. An interrupt between the two calls writes over the ones, so a kernel that is
 * right never fails here, and one that is wrong nearly always does.
 */
#define PAINT1(off) "*(u64 *)(r10 - " #off ") = 1;"
#define PAINT8(a, b, c, d, e, f, g, h)					\
	PAINT1(a) PAINT1(b) PAINT1(c) PAINT1(d) PAINT1(e) PAINT1(f) PAINT1(g) PAINT1(h)

__naked __noinline __used
static void paints(void)
{
	asm volatile (
	PAINT8(8, 16, 24, 32, 40, 48, 56, 64)
	PAINT8(72, 80, 88, 96, 104, 112, 120, 128)
	PAINT8(136, 144, 152, 160, 168, 176, 184, 192)
	PAINT8(200, 208, 216, 224, 232, 240, 248, 256)
	PAINT8(264, 272, 280, 288, 296, 304, 312, 320)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

/* TOP() and TOP_EXCEPTION_CB() with the stack below the prog painted in front of the call */
#define TOP_PAINTED(name, mid)						\
SEC("tc")								\
__naked void name(void)							\
{									\
	asm volatile (							\
	ACQUIRE(r6)							\
		"call paints;"						\
		"call " #mid ";"					\
	AFTER_CALL							\
		:: AFTER_IMM : __clobber_all);				\
}

#define TOP_PAINTED_EXCEPTION_CB(name, mid)				\
SEC("tc")								\
__exception_cb(adds_100)						\
__naked void name(void)							\
{									\
	asm volatile (							\
	ACQUIRE(r6)							\
		"call paints;"						\
		"call " #mid ";"					\
	AFTER_CALL							\
		:: AFTER_IMM : __clobber_all);				\
}

/* A guard, in a function that holds nothing: its frame has K, and no save word */
#define MID_GUARD(name, leaf)						\
__naked __noinline __used						\
static unsigned long name(void)						\
{									\
	asm volatile (							\
		"call " #leaf ";"					\
		unwind_goto(3f)						\
		"exit;"							\
	"3:	r7 = r0;"						\
		"call dtor;"						\
		"r0 = r7;"						\
		unwind_exit						\
		::: __clobber_all);					\
}

/*
 * The prog unwinds into the pad of a frame whose K is 1 from before: the stub of unwind_goto clears
 * it, the pad resumes with unwind_exit, and the prog above catches. The kernel unwinds into it: the
 * entry sets K whatever was there.
 */
MID_GUARD(guard_spins, spins)
TOP_PAINTED(stale_below_guard, guard_spins)
/*
 * The same below bpf_throw(): the word where the value waits is 1 from before too. The entry does
 * not test K before it stores the cookie there.
 */
MID_GUARD(guard_throws, throws)
TOP_PAINTED_EXCEPTION_CB(stale_below_throw, guard_throws)

/* It returns 7 or leaves with unwind_exit, as 'mode_b' says. The kernel unwinds it nowhere. */
__naked __noinline __used
static unsigned long raises_b(void)
{
	asm volatile (
	MODE_OF(mode_b)
	RETURNS(7)
		:: __imm_addr(mode_b) : __clobber_all);
}

/*
 * A guard, and a try block around a call of something that the kernel never unwinds: that call
 * is no site of any kind, the verifier has no plan for it. Its pad is a typed catch, which the
 * kernel does not enter, and when no clause takes the exception it goes on in the resume block of
 * the function, where K is read. unwind_goto of that call has a stub like the one of the guard.
 */
__naked __noinline __used
static unsigned long catch_without_plan(void)
{
	asm volatile (
		"call spins;"
		unwind_goto(3f)
		"call raises_b;"
		unwind_goto(4f)
		"exit;"
	"4:	r7 = r0;"
		"call personality;"
		"if r0 != 1 goto 5f;"
	COUNT(handler_ran)
		"r0 = 77;"
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
	"5:	r0 = r7;"
		unwind_exit
		:: __imm_addr(handler_ran) : __clobber_all);
}
TOP_PAINTED(stale_below_catch, catch_without_plan)

/*
 * What a throw statement calls, in another object: a global function with no path to an exit. It
 * leaves with unwind_exit, r0 = 5, or the kernel unwinds it in a loop that nothing ends, if
 * 'mode_b' is 1.
 */
__naked __noinline __used
unsigned long global_throws(void)
{
	asm volatile (
		"r1 = %[mode_b] ll;"
		"r1 = *(u32 *)(r1 + 0);"
		"if r1 != 1 goto 9f;"
		"r2 = %[forever] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	"9:	r0 = 5;"
		unwind_exit
		:: __imm_addr(mode_b), __imm_addr(forever) : __clobber_all);
}

/*
 * A guard, and the throw statement in front of its landing pad, as a compiler lays it out. The
 * verifier knows that global_throws() never returns: nothing falls into the pad, the function is
 * not mixed, and nothing clears K where it begins. The frame gets into the pad from the second
 * call as from the first one: through the stub, which clears the K that is 1 from before, or
 * through the entry.
 */
__naked __noinline __used
static unsigned long guard_and_global_throw(void)
{
	asm volatile (
		"call spins;"
		unwind_goto(3f)
		"call global_throws;"
		unwind_goto(3f)
	"3:	r7 = r0;"
		"call dtor;"
		"r0 = r7;"
		unwind_exit
		::: __clobber_all);
}
TOP_PAINTED(stale_below_global_throw, guard_and_global_throw)

/* Four frames of one function with a guard, each with a K that is 1 from before */
__naked __noinline __used
static unsigned long recurses_with_guard(void)
{
	asm volatile (
		"if r1 == 0 goto 1f;"
		"r1 += -1;"
		"call recurses_with_guard;"
		unwind_goto(3f)
		"exit;"
	"1:	call spins;"
		unwind_goto(3f)
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
		"r0 = r7;"
		unwind_exit
		::: __clobber_all);
}

SEC("tc")
__naked void stale_below_recursion(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call paints;"
		"r1 = 3;"
		"call recurses_with_guard;"
	AFTER_CALL
		:: AFTER_IMM : __clobber_all);
}

MID_GUARD(guard_spins_b, spins_b)

/*
 * A frame that the kernel unwinds calls a function with a guard twice, in its pad, at the same
 * depth of the stack. The kernel unwinds the callee of the first call: the entry of the guard sets
 * K of that frame. The second call stands in the landing pad of the first one, and its callee
 * leaves with unwind_exit. The frame of the guard has the 1 of the first call in its K: the stub
 * clears it, the guard resumes with unwind_exit, and the pad of the second call gets the 5 that
 * the callee threw, 'second_left'.
 * This frame itself is one that the kernel unwinds all along. The entry behind its first call in
 * the pad tests K and keeps the cookie of bpf_throw(), not the value of the kernel that unwound
 * that call. unwind_goto behind its second call has no stub: K stays set, and the prog above does
 * not catch.
 */
__naked __noinline __used
static unsigned long calls_twice_in_pad(void)
{
	asm volatile (
		"call throws;"
		unwind_goto(3f)
		"exit;"
	"3:	r7 = r0;"
		"call guard_spins_b;"
		unwind_goto(4f)
		"goto 6f;"
	"4:	r1 = %[mode_b] ll;"
		"r2 = 2;"
		"*(u32 *)(r1 + 0) = r2;"
		"call guard_spins_b;"
		unwind_goto(5f)
		"goto 6f;"
	"5:	r1 = %[second_left] ll;"
		"*(u64 *)(r1 + 0) = r0;"
	"6:	r0 = r7;"
		unwind_exit
		:: __imm_addr(mode_b), __imm_addr(second_left) : __clobber_all);
}
TOP_EXCEPTION_CB(twice_in_pad_below_throw, calls_twice_in_pad)

/*
 * bpf_loop() that the verifier inlines, under a guard. The call of the callback in the inlined
 * loop has gotos that are copies of those behind the call of the helper: its unwind_goto goes
 * where that one goes, to the stub. No other insn gets to a stub by a copy. K is 1 from before.
 */
__naked __noinline __used
static unsigned long guard_loop_inlined(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_spins] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(3f)
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(cb_spins), __imm(bpf_loop) : __clobber_all);
}
TOP_PAINTED(stale_below_loop_inlined, guard_loop_inlined)

/* cb_spins(), told by 'mode_b' */
__naked __noinline __used
static unsigned long cb_spins_b(void)
{
	asm volatile (
	MODE_OF(mode_b)
		"r2 = %[forever] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	RETURNS(1)
		:: __imm_addr(mode_b), __imm_addr(forever) : __clobber_all);
}

/*
 * The same loop in pad code: a frame that the kernel unwinds calls it, and the call has a landing
 * pad of its own. There the copy of kgoto goes to an entry that tests K, which keeps the cookie of
 * the first entry, and the copy of unwind_goto goes to the landing pad itself: no stub clears K.
 */
__naked __noinline __used
static unsigned long loops_in_pad(void)
{
	asm volatile (
		"call throws;"
		unwind_goto(3f)
		"exit;"
	"3:	r7 = r0;"
		"r1 = 1;"
		"r2 = %[cb_spins_b] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(4f)
		"goto 5f;"
	"4:	r1 = %[second_left] ll;"
		"*(u64 *)(r1 + 0) = r0;"
	"5:	r0 = r7;"
		unwind_exit
		:: __imm_addr(cb_spins_b), __imm_addr(second_left), __imm(bpf_loop)
		: __clobber_all);
}
TOP_EXCEPTION_CB(loop_in_pad_below_throw, loops_in_pad)

/*
 * One landing pad for a call on the normal path and for a call in pad code: the pad at 4 is where
 * unwind_goto of the first call goes, through a stub, and where unwind_goto of the call in the pad
 * at 3 goes, with no stub. That call leaves with unwind_exit: the pad makes 'mode_b' say so.
 */
__naked __noinline __used
static unsigned long shares_pad_in_and_out(void)
{
	asm volatile (
		"call spins;"
		unwind_goto(4f)
		"call spins_b;"
		unwind_goto(3f)
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
		"r1 = %[mode_b] ll;"
		"r2 = 2;"
		"*(u32 *)(r1 + 0) = r2;"
		"call spins_b;"
		unwind_goto(4f)
		"goto 5f;"
	"4:	r7 = r0;"
		"r1 = %[second_left] ll;"
		"*(u64 *)(r1 + 0) = r0;"
	"5:	r0 = r7;"
		unwind_exit
		:: __imm_addr(mode_b), __imm_addr(second_left) : __clobber_all);
}
TOP_PAINTED(shared_pad_in_and_out, shares_pad_in_and_out)

/*
 * A frame of 200 bytes in a tracing prog is in a private stack, and so is its K: the word is the
 * same in every run on a cpu. The kernel unwinds the callee in one run, and the entry sets K. In
 * the next run on that cpu the callee leaves with unwind_exit: the stub clears the 1 of the run
 * before, and the prog catches.
 * The callee has such a frame too, and so a private stack of its own: it comes back with its own
 * frame pointer in the register that the JIT keeps for it, on every way. The pad reads what its
 * function stored in the frame before the call, 'seen_in_frame': the 0x77 is there only if the
 * register is the one of the function again behind the landing that kexit or unwind_exit took.
 */
__u64 seen_in_frame;

__naked __noinline __used
static unsigned long spins_in_private_stack(void)
{
	asm volatile (
		"r2 = 0x99;"
		"*(u64 *)(r10 - 200) = r2;"
	MODE
		"r2 = %[forever] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	RETURNS(7)
		:: __imm_addr(mode), __imm_addr(forever) : __clobber_all);
}

__naked __noinline __used
static unsigned long guard_in_private_stack(void)
{
	asm volatile (
		"r1 = 0x77;"
		"*(u64 *)(r10 - 200) = r1;"
		"call spins_in_private_stack;"
		unwind_goto(3f)
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
		"r1 = *(u64 *)(r10 - 200);"
		"r2 = %[seen_in_frame] ll;"
		"*(u64 *)(r2 + 0) = r1;"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(seen_in_frame) : __clobber_all);
}

SEC("raw_tp")
__naked void stale_in_private_stack(void)
{
	asm volatile (
		"call guard_in_private_stack;"
		unwind_goto(7f)
		"r0 += 100;"
		"r1 = %[went_on] ll;"
		"*(u64 *)(r1 + 0) = r0;"
		"r0 = 1;"
		"exit;"
	"7:	r1 = %[caught] ll;"
		"*(u64 *)(r1 + 0) = r0;"
		"r0 = 42;"
		"exit;"
		:: __imm_addr(went_on), __imm_addr(caught) : __clobber_all);
}

/*
 * MIXED functions: an insn is in a landing pad that only resumes and on the normal path as well.
 * What reads K there can be reached from the first insn of the function with no landing on the
 * way, so the entry of such a function clears K, as every function did before. Each of them runs
 * with the stack painted: without that store the normal path would take the 1 for its own.
 */
/* 'unwind_goto +0': the landing pad is what follows the call. The function throws what it got. */
__naked __noinline __used
static unsigned long falls_into_pad(void)
{
	asm volatile (
		"call spins;"
		unwind_goto(3f)
	"3:	r7 = r0;"
		"call dtor;"
		"r0 = r7;"
		"r0 += 10;"
		unwind_exit
		::: __clobber_all);
}
TOP_PAINTED(mixed_falls_into_pad, falls_into_pad)

/* The function throws by itself, and its unwind_exit is the one that its landing pad ends in */
__naked __noinline __used
static unsigned long shares_unwind_exit(void)
{
	asm volatile (
		"call spins;"
		unwind_goto(3f)
		"r7 = r0;"
		"r7 += 10;"
		"goto 4f;"
	"3:	r7 = r0;"
		"call dtor;"
	"4:	r0 = r7;"
		unwind_exit
		::: __clobber_all);
}
TOP_PAINTED(mixed_shares_unwind_exit, shares_unwind_exit)

/* A throw that is a jump into the landing pad, in mode 3, with 6: raises_inline() without a task */
__naked __noinline __used
static unsigned long jumps_into_pad(void)
{
	asm volatile (
		"r1 = %[mode] ll;"
		"r1 = *(u32 *)(r1 + 0);"
		"if r1 != 3 goto +2;"
		"r0 = 6;"
		"goto 3f;"
		"call spins;"
		unwind_goto(3f)
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(mode) : __clobber_all);
}
TOP_PAINTED(mixed_jumps_into_pad, jumps_into_pad)

/* starts_again(), whose pad goes back to its first insn */
TOP_PAINTED(mixed_starts_again, starts_again)

/* @nr RCU sections around a call of @callee with @a and @b */
#define CALLS_IN_SECTIONS(name, callee, nr, a, b)			\
__naked __noinline __used						\
static unsigned long name(void)						\
{									\
	asm volatile (							\
		".rept " #nr ";"					\
		"call %[bpf_rcu_read_lock];"				\
		".endr;"						\
		"r1 = " #a ";"						\
		"r2 = " #b ";"						\
		"call " #callee ";"					\
		".rept " #nr ";"					\
		"call %[bpf_rcu_read_unlock];"				\
		".endr;"						\
		"r0 = 0;"						\
		"exit;"							\
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)	\
		: __clobber_all);					\
}

/*
 * Two callers of one function, in nine RCU sections both: the first one entered four of them and
 * the prog the other five, the second one entered all nine, which is more than a pad of the
 * verifier leaves. So the second one must not get what the kernel unwinds, and it does not: it
 * passes what keeps the function from the call. The verifier has to keep the two calls apart to
 * see that, and then the kernel enters the landing pad for the first caller.
 */
#define TWO_CALLERS(name, first, second)				\
SEC("tc")								\
__naked void name(void)							\
{									\
	asm volatile (							\
		".rept 5;"						\
		"call %[bpf_rcu_read_lock];"				\
		".endr;"						\
		"call " #first ";"					\
		".rept 5;"						\
		"call %[bpf_rcu_read_unlock];"				\
		".endr;"						\
		"call " #second ";"					\
		"r0 = 1;"						\
		"exit;"							\
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)	\
		: __clobber_all);					\
}

/* A guard around a call that r1 == 0 skips */
__naked __noinline __used
static unsigned long guard_unless_0(void)
{
	asm volatile (
		"if r1 == 0 goto 2f;"
		"call spins_or_returns;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
	"2:	r0 = 0;"
		"exit;"
		::: __clobber_all);
}
CALLS_IN_SECTIONS(guard_in_4_of_9, guard_unless_0, 4, 1, 1)
CALLS_IN_SECTIONS(no_guard_in_9_of_9, guard_unless_0, 9, 0, 0)
TWO_CALLERS(two_callers_of_guard, guard_in_4_of_9, no_guard_in_9_of_9)

/*
 * r0 = 0; do r0 += r1; while (r0 != r2); and then, unless r2 is negative, a call that the kernel
 * unwinds in mode 1. Each of the two callers has a trip count for the loop, their join has none.
 */
__naked __noinline __used
static unsigned long counts_then_spins(void)
{
	asm volatile (
		"r6 = r2;"
		"r0 = 0;"
	"1:	r0 += r1;"
		"if r0 != r2 goto 1b;"
		"if r6 s< 0 goto 2f;"
		"call spins_or_returns;"
	"2:	r0 = 0;"
		"exit;"
		::: __clobber_all);
}

/* A guard around that call: what decides whether the kernel unwinds is in the callee */
__naked __noinline __used
static unsigned long guard_around_count(void)
{
	asm volatile (
		"call counts_then_spins;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}
CALLS_IN_SECTIONS(count_in_4_of_9, guard_around_count, 4, 1, 1000000)
CALLS_IN_SECTIONS(count_in_9_of_9, guard_around_count, 9, -1, -999993)
TWO_CALLERS(two_callers_of_count, count_in_4_of_9, count_in_9_of_9)

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

/* It holds more than a pad of the verifier releases, around a loop that nothing ends */
__naked __noinline __used
static unsigned long holds_too_much_and_spins(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r2 = %[forever] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(forever), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

/* A guard around counts() whose destructor calls that function: nothing else calls it */
__naked __noinline __used
static unsigned long guard_calls_too_much(void)
{
	asm volatile (
		"call counts;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"call holds_too_much_and_spins;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}

/*
 * counts() ends for each of the two calls, and for the two together the verifier has no trip
 * count: then the kernel unwinds the loop, gets into the landing pad, and what the pad calls
 * has no plan. The verifier has to keep the two calls apart to see that no run gets there, and
 * then the object loads. The prog returns, and the destructor does not run.
 */
SEC("tc")
__naked void pad_of_joined_calls(void)
{
	asm volatile (
		"r1 = 1;"
		"r2 = 1000000;"
		"call guard_calls_too_much;"
		"r1 = -1;"
		"r2 = -999993;"
		"call guard_calls_too_much;"
		"r0 = 1;"
		"exit;"
		::: __clobber_all);
}

#else

SEC("tc")
int dummy(void *ctx)
{
	return 0;
}

#endif
