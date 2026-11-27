// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf_arena_common.h>

char _license[] SEC("license") = "GPL";

/*
 * An unwind that the kernel starts cannot be caught. Each prog has a landing pad of its own after
 * a call, which returns 42 and says so in 'caught'. What it calls, a subprog or a helper with a
 * callback, leaves in the way that 'mode' says:
 *
 *	0	it returns: the prog goes on, says so in 'went_on' and returns 1
 *	1	the kernel unwinds it: the prog ends with the value of the kernel, TC_ACT_SHOT for
 *		tc or what bpf_throw() was passed, and neither the pad nor what follows the call
 *		runs
 *	2	it leaves with unwind_exit, r0 = 5: the pad of the prog gets it, with that 5
 *
 * Each frame on the way holds a reference to the task that runs the prog. Whichever way the prog
 * ends, the task has as many references after it as before.
 */
#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

/* See verifier_unwind_cb.c */
#define unwind_goto(off) ".8byte ((" #off " & 0xffff) << 16) | 0x10e5;"	/* BPF_JMP | BPF_JCOND */
#define unwind_exit ".8byte 0x1095;"				/* BPF_JMP | BPF_EXIT */
/* rN = addr_space_cast(rN, 0x0, 0x1), which the assembler of GCC doesn't know */
#define to_arena(n) ".8byte 0x1000100bf | (0x11 * " #n ") << 8;"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 8);
} arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} array2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} user_ringbuf SEC(".maps");

struct node_data {
	long key;
	struct bpf_rb_node node;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock glock;
private(A) struct bpf_rb_root groot __contains(node_data, node);

int mode;
__u64 caught, went_on, mid_caught;

/* What the verifier doesn't know: bpf_loop() is not inlined, a loop doesn't end, which map it is */
__u64 no_flags, forever = 1;

/* kfuncs that only asm calls need BTF */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_task_release(bpf_task_acquire(bpf_get_current_task_btf()));
	bpf_res_spin_lock(NULL);
	bpf_res_spin_unlock(NULL);
}

/* The count of the task that runs the progs, which bpf_task_acquire() raises */
SEC("syscall")
int task_usage(void *ctx)
{
	return bpf_get_current_task_btf()->rcu_users.refs.counter;
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

/* What is called looks at 'mode' first. Mode 1 goes on behind this. */
#define MODE						\
		"r1 = %[mode] ll;"			\
		"r1 = *(u32 *)(r1 + 0);"		\
		"if r1 == 0 goto 8f;"			\
		"if r1 == 2 goto 9f;"
/* @ret: what it returns in mode 0 */
#define RETURNS(ret)					\
	"8:	r0 = " #ret ";"				\
		"exit;"					\
	"9:	r0 = 5;"				\
		unwind_exit

/* The kernel unwinds it at bpf_throw(): the prog returns the cookie */
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

/* at may_goto that the verifier adds to a loop which nothing ends, when its time is up */
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

/* at may_goto that the program has */
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

/* at an access to a page of the arena that is not there */
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

/* at the check of a recursion, when the stack has no room for one more frame */
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

/*
 * A frame in between that has no landing pad of its own: the verifier emits one for each way in
 * which what it calls comes back unwound. Both release the task and leave the RCU section. The one
 * for unwind_exit passes on what the leaf left in r0.
 */
#define MID(name, leaf)							\
__naked __noinline __used						\
static unsigned long name(void)						\
{									\
	asm volatile (							\
	ACQUIRE(r6)							\
		"call %[bpf_rcu_read_lock];"				\
		"call " #leaf ";"					\
		"r7 = r0;"						\
		"call %[bpf_rcu_read_unlock];"				\
	RELEASE(r6)							\
		"r0 = r7;"						\
		"exit;"							\
		:: TASK_IMM, __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) \
		: __clobber_all);					\
}

/*
 * What follows the call, and the landing pad of the prog. Both release the task, as they have to:
 * they are code of the prog. 9 insns are between unwind_goto and the pad. 'went_on' is 100 more
 * than what the call returned, 'caught' is what unwind_exit left in r0.
 */
#define AFTER_CALL							\
		unwind_goto(9)						\
		"r7 = r0;"						\
		"r7 += 100;"						\
	RELEASE(r6)							\
		"r1 = %[went_on] ll;"					\
		"*(u64 *)(r1 + 0) = r7;"				\
		"r0 = 1;"						\
		"exit;"							\
		"r7 = r0;"						\
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

/*
 * A frame in between with a landing pad of its own that cleans up and unwinds on: it runs for
 * unwind_exit of the leaf, says so in 'mid_caught', and hands the value to the pad of the prog. It
 * only resumes, so it runs when the kernel unwinds the leaf too: it releases the task and leaves
 * the section itself, nothing is left for the verifier to release behind it, and the frame leaves
 * with the value of the kernel, not with what the pad has in r0. See kunwind_pads.c for more of
 * that. 6 insns are between unwind_goto and the pad.
 */
#define MID_PAD(name, leaf)						\
__naked __noinline __used						\
static unsigned long name(void)						\
{									\
	asm volatile (							\
	ACQUIRE(r6)							\
		"call %[bpf_rcu_read_lock];"				\
		"call " #leaf ";"					\
		unwind_goto(6)						\
		"r7 = r0;"						\
		"call %[bpf_rcu_read_unlock];"				\
	RELEASE(r6)							\
		"r0 = r7;"						\
		"exit;"							\
		"r7 = r0;"						\
		"call %[bpf_rcu_read_unlock];"				\
	RELEASE(r6)							\
		"r1 = %[mid_caught] ll;"				\
		"r2 = 1;"						\
		"*(u64 *)(r1 + 0) = r2;"				\
		"r0 = r7;"						\
		unwind_exit						\
		:: TASK_IMM, __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock), \
		   __imm_addr(mid_caught) : __clobber_all);		\
}

/*
 * A global subprog in between: its callers are verified without it. They expect the kernel to
 * unwind it where it has may_goto of the prog below it, and find out late where the verifier adds
 * may_goto to a loop below it. It has no landing pad: the one that the verifier emits for
 * unwind_exit of the leaf leaves with the value of the kernel, 2 for tc, see verifier_kunwind.c.
 */
#define GLOBAL_MID(name, leaf)						\
__noinline unsigned long name(void)					\
{									\
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf()); \
	unsigned long ret;						\
									\
	if (!t)								\
		return 3;						\
	bpf_rcu_read_lock();						\
	ret = leaf();							\
	bpf_rcu_read_unlock();						\
	bpf_task_release(t);						\
	return ret;							\
}

MID(mid_throws, throws)
TOP(below_throw, mid_throws)
MID_PAD(mid_pad_throws, throws)
TOP(below_mid_pad_throw, mid_pad_throws)
MID_PAD(mid_pad_spins, spins)
TOP(below_mid_pad_guard, mid_pad_spins)
GLOBAL_MID(global_mid_spins, spins)
TOP(below_global_guard, global_mid_spins)
GLOBAL_MID(global_mid_may_goto_spins, may_goto_spins)
TOP(below_global_may_goto, global_mid_may_goto_spins)
MID(mid_spins, spins)
TOP(below_guard, mid_spins)
MID(mid_may_goto_spins, may_goto_spins)
TOP(below_may_goto, mid_may_goto_spins)
MID(mid_faults, faults)
TOP(below_fault, mid_faults)
MID(mid_recurses, recurses)
TOP(below_recursion, mid_recurses)

/* The exception callback gets the cookie when the prog has released what it holds */
__noinline int adds_100(u64 cookie)
{
	return cookie + 100;
}

SEC("tc")
__exception_cb(adds_100)
__naked void below_throw_exception_cb(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call mid_throws;"
	AFTER_CALL
		:: AFTER_IMM : __clobber_all);
}

/* A callback: it ends the helper when it returns, with 1 */
__naked __noinline __used
static unsigned long cb_throws(void)
{
	asm volatile (
	MODE
		"r1 = 9;"
		"call %[bpf_throw];"
	RETURNS(1)
		:: __imm_addr(mode), __imm(bpf_throw) : __clobber_all);
}

__naked __noinline __used
static unsigned long cb_spins(void)
{
	asm volatile (
	MODE
		"r2 = %[forever] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	RETURNS(1)
		:: __imm_addr(mode), __imm_addr(forever) : __clobber_all);
}

/*
 * A callback that holds a task where the kernel unwinds it: at an access to arena that faults, and
 * at may_goto of the prog when the time is up. The landing pad of the callback releases the task.
 * It returns 1, which ends the loop, also when there is no task.
 */
#define CB_HOLDS(name, how)						\
__naked __noinline __used						\
static unsigned long name(void)						\
{									\
	asm volatile (							\
		"r2 = %[arena] ll;"					\
		"call %[bpf_get_current_task_btf];"			\
		"r1 = r0;"						\
		"call %[bpf_task_acquire];"				\
		"if r0 != 0 goto +2;"					\
		"r0 = 1;"						\
		"exit;"							\
		"r6 = r0;"						\
	MODE								\
		how							\
	"8:"								\
	RELEASE(r6)							\
		"r0 = 1;"						\
		"exit;"							\
	"9:"								\
	RELEASE(r6)							\
		"r0 = 5;"						\
		unwind_exit						\
		:: TASK_IMM, __imm_addr(mode), __imm_addr(arena) : __clobber_all); \
}

CB_HOLDS(cb_holds_faults,
	 "r8 = 0x1000;"
	 to_arena(8)
	 "r0 = *(u64 *)(r8 + 0);")
CB_HOLDS(cb_holds_may_goto_spins,
	 "1: may_goto 8f;"
	 "goto 1b;")

/* The helper is a frame of the kernel between the callback and the prog */
#define TOP_CB(name, args, helper, imm...)				\
SEC("tc")								\
__naked void name(void)							\
{									\
	asm volatile (							\
	ACQUIRE(r6)							\
		args							\
		"call %[" #helper "];"					\
	AFTER_CALL							\
		:: AFTER_IMM, __imm(helper), ##imm : __clobber_all);	\
}

/* The loop is inlined: the callback is called by the prog, and the call has a pad for each way */
TOP_CB(below_loop_inlined,
       "r1 = 3;"
       "r2 = %[cb_throws] ll;"
       "r3 = 0;"
       "r4 = 0;",
       bpf_loop, __imm_addr(cb_throws))

TOP_CB(below_loop,
       "r1 = 3;"
       "r2 = %[cb_throws] ll;"
       "r3 = 0;"
       "r4 = %[no_flags] ll;"
       "r4 = *(u64 *)(r4 + 0);",
       bpf_loop, __imm_addr(cb_throws), __imm_addr(no_flags))

TOP_CB(below_loop_guard,
       "r1 = 3;"
       "r2 = %[cb_spins] ll;"
       "r3 = 0;"
       "r4 = %[no_flags] ll;"
       "r4 = *(u64 *)(r4 + 0);",
       bpf_loop, __imm_addr(cb_spins), __imm_addr(no_flags))

TOP_CB(below_loop_inlined_holds_fault,
       "r1 = 3;"
       "r2 = %[cb_holds_faults] ll;"
       "r3 = 0;"
       "r4 = 0;",
       bpf_loop, __imm_addr(cb_holds_faults))

TOP_CB(below_loop_holds_fault,
       "r1 = 3;"
       "r2 = %[cb_holds_faults] ll;"
       "r3 = 0;"
       "r4 = %[no_flags] ll;"
       "r4 = *(u64 *)(r4 + 0);",
       bpf_loop, __imm_addr(cb_holds_faults), __imm_addr(no_flags))

TOP_CB(below_loop_holds_may_goto,
       "r1 = 3;"
       "r2 = %[cb_holds_may_goto_spins] ll;"
       "r3 = 0;"
       "r4 = %[no_flags] ll;"
       "r4 = *(u64 *)(r4 + 0);",
       bpf_loop, __imm_addr(cb_holds_may_goto_spins), __imm_addr(no_flags))

/* The verifier knows the map and calls its op */
TOP_CB(below_for_each,
       "r1 = %[array] ll;"
       "r2 = %[cb_throws] ll;"
       "r3 = 0;"
       "r4 = 0;",
       bpf_for_each_map_elem, __imm_addr(array), __imm_addr(cb_throws))

/* It does not: the helper calls the op, which calls the callback. Two frames of the kernel. */
TOP_CB(below_for_each_two_maps,
       "r1 = %[array] ll;"
       "r2 = %[no_flags] ll;"
       "r2 = *(u64 *)(r2 + 0);"
       "if r2 == 0 goto +2;"
       "r1 = %[array2] ll;"
       "r2 = %[cb_throws] ll;"
       "r3 = 0;"
       "r4 = 0;",
       bpf_for_each_map_elem, __imm_addr(array), __imm_addr(array2), __imm_addr(cb_throws),
       __imm_addr(no_flags))

/* User space has put a sample in */
TOP_CB(below_drain,
       "r1 = %[user_ringbuf] ll;"
       "r2 = %[cb_throws] ll;"
       "r3 = 0;"
       "r4 = 0;",
       bpf_user_ringbuf_drain, __imm_addr(user_ringbuf), __imm_addr(cb_throws))

/* The vma of the stack of the task. The helper returns 0 when its callback returns. */
TOP_CB(below_find_vma,
       "r1 = *(u64 *)(r6 + %[mm]);"
       "r2 = *(u64 *)(r1 + %[start_stack]);"
       "r1 = r6;"
       "r3 = %[cb_throws] ll;"
       "r4 = 0;"
       "r5 = 0;",
       bpf_find_vma, __imm_addr(cb_throws),
       __imm_const(mm, offsetof(struct task_struct, mm)),
       __imm_const(start_stack, offsetof(struct mm_struct, start_stack)))

static bool less_returns(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	return true;
}

/* Not naked: the branches keep the return reachable */
static bool less_throws(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	if (mode == 1)
		bpf_throw(9);
	if (mode == 2)
		asm volatile ("r0 = 5;" unwind_exit ::: "r0");
	return false;
}

/* The kfunc with the landing pad of the prog after it. The verifier fills r4 and r5. */
__naked __noinline __used
static int rbtree_add_with_pad(void *root, void *node, void *less)
{
	asm volatile (
		"call %[bpf_rbtree_add];"
		unwind_goto(2)
		"r0 = 1;"
		"exit;"
		"r1 = %[caught] ll;"
		"*(u64 *)(r1 + 0) = r0;"
		"r0 = 42;"
		"exit;"
		:: __imm(bpf_rbtree_add), __imm_addr(caught) : __clobber_all);
}

/*
 * The first node goes in without a comparison, the second one meets it. The lock is the prog's:
 * when the kernel unwinds the comparator, the landing pad that the verifier emits in the prog
 * releases it, and the task.
 */
SEC("tc")
int below_rbtree_add(void *ctx)
{
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf());
	struct node_data *n, *m;
	int ret;

	if (!t)
		return 3;
	n = bpf_obj_new(typeof(*n));
	m = bpf_obj_new(typeof(*m));
	if (!n || !m) {
		if (n)
			bpf_obj_drop(n);
		if (m)
			bpf_obj_drop(m);
		bpf_task_release(t);
		return 3;
	}
	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less_returns);
	ret = rbtree_add_with_pad(&groot, &m->node, (void *)less_throws);
	bpf_spin_unlock(&glock);
	bpf_task_release(t);
	if (ret == 1)
		went_on = 100;
	return ret;
}

/*
 * The exception callback may be unwound itself. It has no exception callback of its own: the
 * landing pad of the main prog calls it once, and what unwinds it ends at the exit of that pad, so
 * nothing calls it a second time. Each prog below throws 9 while it holds a task, and its callback
 * takes a task and is unwound while it holds it, in one of four ways. The callback counts its
 * runs, both tasks are released, and the prog returns the value of the unwind of the callback:
 * what the callback threw, or what the kernel returns for a tc prog that it unwinds, TC_ACT_SHOT.
 * Not the 9 of the throw that the callback was called for, which ended when the callback was
 * called, and not the 109 that the callback returns when nothing unwinds it.
 */
__u64 cb_runs;

/* What unwinds the callback, while it holds @t */
#define CB_UNWOUND(name, how)						\
__noinline int name(u64 cookie)						\
{									\
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf()); \
									\
	cb_runs++;							\
	if (!t)								\
		return 3;						\
	how;								\
	bpf_task_release(t);						\
	return cookie + 100;						\
}									\
									\
SEC("tc")								\
__exception_cb(name)							\
int throws_and_##name(void *ctx)					\
{									\
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf()); \
									\
	if (!t)								\
		return 3;						\
	if (mode)							\
		bpf_throw(9);						\
	bpf_task_release(t);						\
	return 1;							\
}

/* bpf_throw() in the callback: the prog returns what the callback threw */
CB_UNWOUND(cb_throws_21, if (*(volatile __u64 *)&forever) bpf_throw(21))
/* an access to a page of the arena that is not there */
CB_UNWOUND(cb_faults_holding,
	   asm volatile ("r1 = %[arena] ll;"
			 "r1 = 0x1000;"
			 to_arena(1)
			 "r1 = *(u64 *)(r1 + 0);"
			 :: __imm_addr(arena) : "r1"))
/* a loop that nothing ends: the verifier adds may_goto, and the time is up */
CB_UNWOUND(cb_spins_holding, while (*(volatile __u64 *)&forever))
/* a recursion without an end in a function that it calls: the stack has no room for one more */
CB_UNWOUND(cb_recurses_holding, recurses())

/*
 * A lock next to a landing pad of the prog: the prog takes it, calls what the kernel unwinds, and
 * both its code behind the call and its pad unlock. When the kernel unwinds, neither runs, and the
 * pad of the verifier unlocks. The next run takes the lock again: it returns 4 if it cannot.
 * 12 insns are between unwind_goto and the pad.
 */
private(B) struct bpf_res_spin_lock rlock;

SEC("tc")
__naked void below_guard_lock(void)
{
	asm volatile (
	ACQUIRE(r6)
		"r1 = %[rlock] ll;"
		"call %[bpf_res_spin_lock];"
		"if r0 == 0 goto +4;"
	RELEASE(r6)
		"r0 = 4;"
		"exit;"
		"call spins;"
		unwind_goto(12)
		"r7 = r0;"
		"r7 += 100;"
		"r1 = %[rlock] ll;"
		"call %[bpf_res_spin_unlock];"
	RELEASE(r6)
		"r1 = %[went_on] ll;"
		"*(u64 *)(r1 + 0) = r7;"
		"r0 = 1;"
		"exit;"
		"r7 = r0;"
		"r1 = %[rlock] ll;"
		"call %[bpf_res_spin_unlock];"
	RELEASE(r6)
		"r1 = %[caught] ll;"
		"*(u64 *)(r1 + 0) = r7;"
		"r0 = 42;"
		"exit;"
		:: AFTER_IMM, __imm_addr(rlock), __imm(bpf_res_spin_lock),
		   __imm(bpf_res_spin_unlock) : __clobber_all);
}

/*
 * A tail call: the callee is a prog of its own. What the kernel unwinds in it ends at its main
 * frame, with the value of the kernel, and so does unwind_exit that nothing in the callee catches.
 * That is what the subprog of the caller that made the tail call returns: the caller goes on, and
 * its landing pad is not entered.
 */
SEC("tc")
__naked void tail_callee(void)
{
	asm volatile (
	ACQUIRE(r6)
		"call mid_spins;"
	RELEASE(r6)
		"r0 = 7;"
		"exit;"
		:: TASK_IMM : __clobber_all);
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__array(values, void (void));
} tc_jmp_table SEC(".maps") = {
	.values = {
		[0] = (void *)&tail_callee,
	},
};

__naked __noinline __used
static unsigned long tail_calls_tc(void *ctx)
{
	asm volatile (
		"r2 = %[tc_jmp_table] ll;"
		"r3 = 0;"
		"call %[bpf_tail_call];"
		"r0 = 1000;"
		"exit;"
		:: __imm_addr(tc_jmp_table), __imm(bpf_tail_call) : __clobber_all);
}

SEC("tc")
__naked void above_tail_call(void)
{
	asm volatile (
		"call tail_calls_tc;"
		unwind_goto(6)
		"r0 += 100;"
		"r1 = %[went_on] ll;"
		"*(u64 *)(r1 + 0) = r0;"
		"r0 = 1;"
		"exit;"
		"r1 = %[caught] ll;"
		"*(u64 *)(r1 + 0) = r0;"
		"r0 = 42;"
		"exit;"
		:: __imm_addr(went_on), __imm_addr(caught) : __clobber_all);
}

/*
 * The landing pad of the main prog calls the exception callback, and that call has unwind_goto and
 * kgoto when the callback can leave both ways. This prog has a private stack: on x86-64 its
 * address is in r9, which is pushed in front of every call and popped behind it, also on the way to
 * a pad. Whichever way the callback leaves, the prog leaves the stack pointer and the registers of
 * its caller as they were.
 */
/* Not naked: a global function has BTF for its argument, and the branches keep the return reachable */
__noinline int cb_leaves(u64 cookie)
{
	if (mode == 1)
		while (*(volatile __u64 *)&forever)
			;
	if (mode == 2)
		asm volatile ("r0 = 5;" unwind_exit ::: "r0");
	return cookie + 100;
}

SEC("raw_tp")
__exception_cb(cb_leaves)
__naked void priv_stack_throws(void)
{
	asm volatile (
		"*(u64 *)(r10 - 200) = r1;"
		"r6 = 6;"
		"r7 = 7;"
		"r8 = 8;"
		"r9 = 9;"
		"r1 = 9;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_throw) : __clobber_all);
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__array(values, void (void));
} jmp_table SEC(".maps") = {
	.values = {
		[0] = (void *)&priv_stack_throws,
	},
};

__naked __noinline __used
static unsigned long tail_calls(void *ctx)
{
	asm volatile (
		"r2 = %[jmp_table] ll;"
		"r3 = 0;"
		"call %[bpf_tail_call];"
		"r0 = 1000;"
		"exit;"
		:: __imm_addr(jmp_table), __imm(bpf_tail_call) : __clobber_all);
}

/*
 * A caller that tells: the prog above takes the place of tail_calls() and returns to this one,
 * which has put what user space chose into r6-r9 and writes down what it finds there afterwards.
 * Its own exit restores the registers of the kernel from its own frame.
 */
__u64 regs_in[4], regs_out[4];

SEC("raw_tp")
__naked void regs_around_priv_stack_throws(void)
{
	asm volatile (
		"r2 = %[regs_in] ll;"
		"r6 = *(u64 *)(r2 + 0);"
		"r7 = *(u64 *)(r2 + 8);"
		"r8 = *(u64 *)(r2 + 16);"
		"r9 = *(u64 *)(r2 + 24);"
		"call tail_calls;"
		"r2 = %[regs_out] ll;"
		"*(u64 *)(r2 + 0) = r6;"
		"*(u64 *)(r2 + 8) = r7;"
		"*(u64 *)(r2 + 16) = r8;"
		"*(u64 *)(r2 + 24) = r9;"
		"exit;"
		:: __imm_addr(regs_in), __imm_addr(regs_out) : __clobber_all);
}

#else

SEC("tc")
int dummy(void *ctx)
{
	return 0;
}

#endif
