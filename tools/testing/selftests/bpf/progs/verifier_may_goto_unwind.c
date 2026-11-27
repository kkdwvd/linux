// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * may_goto that the program has: can_loop and cond_break are made of it. When its time is up it
 * ends the program, like may_goto that the verifier adds to a loop: the frame is left by way of a
 * landing pad that releases what it holds, and so are its callers. The jump of the insn is not
 * taken, and what it leads to is not verified.
 *
 * Not where the subprog cannot unwind, and not with the form that counts trips: there the insn
 * jumps where the program says, as it did before the verifier unwound programs.
 *
 * A tc prog that is unwound returns TC_ACT_SHOT, 2. A socket filter returns 0.
 */
char _license[] SEC("license") = "GPL";

int zero;

#if (defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)) && __clang_major__ >= 18

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, long);
} empty SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb SEC(".maps");

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock lock;
private(A) long locked_cnt;

/* What the verifier doesn't know */
volatile long never;
long one_div = 1;

/*
 * The loop ends when the lookup has an element, or when the time is up. On that edge p is NULL: a
 * prog that goes on there cannot be loaded. It is not verified, the prog ends at the may_goto.
 */
SEC("tc")
__description("may_goto unwinds: a lookup is tried until it has an element")
__load_if_JITed()
__success __retval(2)
int lookup_until_found(void *ctx)
{
	int key = 0;
	long *p;

	do {
		p = bpf_map_lookup_elem(&empty, &key);
	} while (!p && can_loop);
	return *p;
}

/* The same in insns: the may_goto goes to the pad, and the load that follows the loop stays */
SEC("tc")
__description("may_goto unwinds: the insn goes to the landing pad of the prog")
__load_if_JITed()
__success __retval(2)
__xlated("...")
__xlated("goto pc-{{[0-9]+}}")
__xlated("r0 = *(u64 *)(r0 +0)")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
__naked void lookup_until_found_asm(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u32 *)(r10 - 4) = r1;"
"1:	r2 = r10;"
	"r2 += -4;"
	"r1 = %[empty] ll;"
	"call %[bpf_map_lookup_elem];"
	"if r0 != 0 goto 2f;"
	"may_goto 2f;"
	"goto 1b;"
"2:	r0 = *(u64 *)(r0 + 0);"
	"exit;"
	:: __imm(bpf_map_lookup_elem), __imm_addr(empty) : __clobber_all);
}

/*
 * No state takes the jump of may_goto, so its target is dead code. If the insn kept that target it
 * would be a jump that is never taken, 'goto +0', and the loop would have nothing that stops it.
 * It goes to the pad before dead code is looked for: the loop stays bounded.
 */
SEC("socket")
__description("may_goto unwinds: may_goto with a dead target still bounds the loop")
__load_if_JITed()
__success __retval(0)
/* the main prog sets count, timestamp, owner */
__xlated("0: r0 = ")
__xlated("2: r0 = &(void __percpu *)(r0)")
__xlated("3: *(u64 *)(r0 +0) = 65535")
__xlated("4: *(u64 *)(r0 +8) = 0")
__xlated("5: *(u64 *)(r0 +16) = 0")
/* may_goto: its jump goes to the pad */
__xlated("6: r0 = ")
__xlated("8: r0 = &(void __percpu *)(r0)")
__xlated("9: r13 = *(u64 *)(r0 +0)")
__xlated("10: if r13 == 0x0 goto pc+6")
__xlated("11: r13 -= 1")
__xlated("12: if r13 != 0x0 goto pc+2")
__xlated("13: r13 = r0")
__xlated("14: call unknown")
__xlated("15: *(u64 *)(r0 +0) = r13")
__xlated("16: goto pc-11")
/* 'r0 = 7; exit' is gone, the pad follows */
__xlated("17: r0 = 0")
__xlated("18: exit")
__naked void dead_target_bounds_loop(void)
{
	asm volatile (
"1:	may_goto 2f;"
	"goto 1b;"
"2:	r0 = 7;"
	"exit;"
	::: __clobber_all);
}

/*
 * A prog that is loaded without CAP_PERFMON gets no landing pad: its may_goto jumps where the
 * program says, as it did before the verifier unwound programs, and the target is no dead code.
 */
SEC("socket")
__description("may_goto jumps: without CAP_PERFMON the insn keeps its target")
__load_if_JITed()
__success __success_unpriv __retval(1) __retval_unpriv(1)
__xlated("...")
__xlated("r0 = 1")
__xlated("exit")
__xlated("r0 = 0")
__xlated("exit")
__xlated_unpriv("...")
__xlated_unpriv("10: if r13 == 0x0 goto pc+7")
__xlated_unpriv("...")
__xlated_unpriv("16: r0 = 1")
__xlated_unpriv("17: exit")
__xlated_unpriv("18: r0 = 7")
__xlated_unpriv("19: exit")
__naked void no_perfmon_keeps_target(void)
{
	asm volatile (
	"may_goto 1f;"
	"r0 = 1;"
	"exit;"
"1:	r0 = 7;"
	"exit;"
	::: __clobber_all);
}

/* The prog is in an RCU section when the time is up: the pad leaves it */
SEC("tc")
__description("may_goto unwinds: the prog is in an RCU section")
__load_if_JITed()
__success __retval(2)
/* what follows the loop is dead code: the pad has the only bpf_rcu_read_unlock() */
__xlated("...")
__xlated("goto pc-{{[0-9]+}}")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
int rcu_section_in_prog(void *ctx)
{
	long n = zero;

	bpf_rcu_read_lock();
	while (can_loop)
		n++;
	bpf_rcu_read_unlock();
	return 7 + (n & 1);
}

/* It holds a record of a ring buffer: the pad discards it */
SEC("tc")
__description("may_goto unwinds: the prog holds a reference")
__load_if_JITed()
__success __retval(2)
__log_level(2) __msg("landing pad of may_goto of the program at {{[0-9]+}}: ref@")
int reference_in_prog(void *ctx)
{
	long *p = bpf_ringbuf_reserve(&rb, sizeof(*p), 0);
	long n = zero;

	if (!p)
		return 1;
	while (can_loop)
		n++;
	*p = n;
	bpf_ringbuf_discard(p, 0);
	return 7;
}

/*
 * It holds a bpf_spin_lock: the pad unlocks it. The second prog takes the lock again: it could
 * not if the first one had kept it.
 */
#define LOCK_IN_PROG(name)						\
SEC("tc")								\
__description("may_goto unwinds: the prog holds a lock, " #name)	\
__load_if_JITed()							\
__success __retval(2)							\
__log_level(2)								\
__msg("landing pad of may_goto of the program at {{[0-9]+}}: spin_lock@")\
int lock_in_prog_##name(void *ctx)					\
{									\
	bpf_spin_lock(&lock);						\
	while (can_loop)						\
		locked_cnt++;						\
	bpf_spin_unlock(&lock);						\
	return 7;							\
}

LOCK_IN_PROG(first)
LOCK_IN_PROG(again)

/*
 * All of R0-R9 are live at may_goto, so the insn has no register to count in: it keeps R0 in the
 * stack meanwhile, and puts it back before it goes to the landing pad. The pad finds the task
 * there.
 */
SEC("tc")
__description("may_goto unwinds: R0-R9 are live, the task that the pad releases is in R0")
__load_if_JITed()
__success __retval(2)
__log_level(2)
__msg("landing pad of may_goto of the program at {{[0-9]+}}: ref@{{[0-9]+}}(r0) rcu=0 preempt=0")
__xlated("...")
__xlated("if r13 != 0x0 goto pc+2")
__xlated("r0 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("gotol pc+{{[0-9]+}}")
__naked void all_regs_live_task_in_r0(void)
{
	asm volatile (
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"if r0 != 0 goto +2;"
		"r0 = 1;"
		"exit;"
		"r1 = 1;"
		"r2 = 2;"
		"r3 = 3;"
		"r4 = 4;"
		"r5 = 5;"
		"r6 = 6;"
		"r7 = 7;"
		"r8 = 8;"
		"r9 = 9;"
	"1:	may_goto 2f;"
		"goto 1b;"
	"2:	r1 += r2;"
		"r1 += r3;"
		"r1 += r4;"
		"r1 += r5;"
		"r1 += r6;"
		"r1 += r7;"
		"r1 += r8;"
		"r1 += r9;"
		"r6 = r1;"
		"r1 = r0;"
		"call %[bpf_task_release];"
		"r0 = r6;"
		"exit;"
		:: __imm(bpf_task_from_pid), __imm(bpf_task_release)
		: __clobber_all);
}

/*
 * One insn acquires in each trip, and the task of the trip before is released behind may_goto. At
 * the insn the frame holds the new task in r1 alone and, from the second trip on, the old one in
 * r6. No state says which of the two the pad releases first. The places do: r1 does not outlive a
 * call, so its task goes first, and no hidden slot is needed.
 */
#define NEW_IN_R1_OLD_IN_R6(release)				\
		"r6 = 0;"					\
	"1:	r1 = 1;"					\
		"call %[bpf_task_from_pid];"			\
		"if r0 == 0 goto 2f;"				\
		"r1 = r0;"					\
		"may_goto 2f;"					\
		"r7 = r6;"					\
		"r6 = r1;"					\
		"if r7 == 0 goto 1b;"				\
		"r1 = r7;"					\
		release						\
		"goto 1b;"					\
	"2:	if r6 == 0 goto +2;"				\
		"r1 = r6;"					\
		"call %[bpf_task_release];"			\
		"r0 = 0;"					\
		"exit;"

SEC("tc")
__description("may_goto unwinds: the task in r1 alone is released ahead of the one in r6")
__load_if_JITed()
__success __retval(2)
__log_level(2)
__msg("landing pad of may_goto of the program at {{[0-9]+}}: ref@{{[0-9]+}}(r1) ref@{{[0-9]+}}(r6) if not 0 rcu=0 preempt=0")
__not_msg("has hidden slots")
__xlated("...")
__xlated("if r6 == 0x0 goto pc+2")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 0")
__xlated("exit")
__xlated("r1 = r1")
__xlated("call kernel-function")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void new_task_in_r1_old_in_r6(void)
{
	asm volatile (
	NEW_IN_R1_OLD_IN_R6("call %[bpf_task_release];")
		:: __imm(bpf_task_from_pid), __imm(bpf_task_release)
		: __clobber_all);
}

__naked __noinline __used
static void releases_task(void)
{
	asm volatile (
		"call %[bpf_task_release];"
		"exit;"
		:: __imm(bpf_task_release) : __clobber_all);
}

/*
 * A function that is called releases the old task: no store can follow that release in the prog,
 * so it can have no hidden slots for tasks. With the task of r6 released first the prog is
 * rejected: "a handle is in R0-R5 only".
 */
SEC("tc")
__description("may_goto unwinds: the same in a prog that can have no hidden slots")
__load_if_JITed()
__success __retval(2)
__log_level(2)
__msg("landing pad of may_goto of the program at {{[0-9]+}}: ref@{{[0-9]+}}(r1) ref@{{[0-9]+}}(r6) if not 0 rcu=0 preempt=0")
__naked void new_task_in_r1_old_in_r6_no_slots(void)
{
	asm volatile (
	NEW_IN_R1_OLD_IN_R6("call releases_task;")
		:: __imm(bpf_task_from_pid), __imm(bpf_task_release)
		: __clobber_all);
}

static __noinline long spins_in_section(void)
{
	long n = zero;

	bpf_rcu_read_lock();
	while (can_loop)
		n++;
	bpf_rcu_read_unlock();
	return n;
}

/*
 * The time is up in a subprog, which is in an RCU section. Its pad leaves the section and the
 * subprog, the pad of the call in the prog discards the record that the prog holds.
 */
SEC("tc")
__description("may_goto unwinds: a subprog is in an RCU section, its caller holds a reference")
__load_if_JITed()
__success __retval(2)
__log_level(2)
__msg("landing pad of call at {{[0-9]+}}: ref@")
__msg("landing pad of may_goto of the program at {{[0-9]+}}: rcu=1 preempt=0")
int section_in_subprog(void *ctx)
{
	long *p = bpf_ringbuf_reserve(&rb, sizeof(*p), 0);

	if (!p)
		return 1;
	*p = spins_in_section();
	bpf_ringbuf_discard(p, 0);
	return 7;
}

static __noinline long spins_locked(void)
{
	bpf_spin_lock(&lock);
	while (can_loop)
		locked_cnt++;
	bpf_spin_unlock(&lock);
	return locked_cnt;
}

/* The subprog holds the lock, its caller is in a section with preemption off */
SEC("tc")
__description("may_goto unwinds: a subprog holds a lock, its caller has disabled preemption")
__load_if_JITed()
__success __retval(2)
__log_level(2)
__msg("landing pad of call at {{[0-9]+}}: rcu=0 preempt=1")
__msg("landing pad of may_goto of the program at {{[0-9]+}}: spin_lock@")
int lock_in_subprog(void *ctx)
{
	long n;

	bpf_preempt_disable();
	n = spins_locked();
	bpf_preempt_enable();
	return 7 + (n & 1);
}

/* The time is up in the callback of bpf_loop(): the helper leaves through its pad */
static int spins_cb(__u64 i, long *n)
{
	while (can_loop)
		(*n)++;
	return 0;
}

SEC("tc")
__description("may_goto unwinds: the callback of bpf_loop(), its caller is in an RCU section")
__load_if_JITed()
__success __retval(2)
__log_level(2) __msg("landing pad of call at {{[0-9]+}}: rcu=1 preempt=0")
int callback_of_loop(void *ctx)
{
	long n = 0;

	bpf_rcu_read_lock();
	bpf_loop(4, spins_cb, &n, 0);
	bpf_rcu_read_unlock();
	return 7;
}

__noinline long global_spins(void)
{
	long n = zero;

	while (can_loop)
		n++;
	return n;
}

/*
 * The callers of a global function are verified ahead of it. That it is left at its may_goto is
 * expected from the first pass on: no pass is done again when the verifier gets to the function.
 */
SEC("tc")
__description("may_goto unwinds: a global function, its caller expects that in the first pass")
__load_if_JITed()
__success __retval(2)
__log_level(2) __not_msg("pass 1") __msg("landing pad of call at {{[0-9]+}}: rcu=1 preempt=0")
int global_function_spins(void *ctx)
{
	long n;

	bpf_rcu_read_lock();
	n = global_spins();
	bpf_rcu_read_unlock();
	return 7 + (n & 1);
}

/*
 * No pad does for a loop that takes a lock in each trip: the prog is rejected, with the insn and
 * the reason.
 */
SEC("tc")
__description("may_goto unwinds: no landing pad does for the may_goto")
__load_if_JITed()
__failure
__msg("landing pad of may_goto of the program at {{[0-9]+}}: conflict: too much is held")
int no_pad_for_may_goto(void *ctx)
{
	while (can_loop)
		bpf_rcu_read_lock();
	return 0;
}

static __noinline long spins(void)
{
	long n = zero;

	while (can_loop)
		n++;
	return n;
}

#define NINE_TIMES(what) what; what; what; what; what; what; what; what; what

/* Nor for the call above it: a pad leaves eight sections at most */
SEC("tc")
__description("may_goto unwinds: no landing pad does for the call above the may_goto")
__load_if_JITed()
__failure
__msg("what the call at {{[0-9]+}} calls is left at: may_goto of the program")
__msg("landing pad of call at {{[0-9]+}}: conflict: too much is held")
int no_pad_for_call(void *ctx)
{
	long n;

	NINE_TIMES(bpf_rcu_read_lock());
	n = spins();
	NINE_TIMES(bpf_rcu_read_unlock());
	return n & 1;
}

/* Returns 5. If r1 * r1 is not r2 it spins first, until the time is up. One exit. */
__naked __noinline __used
static unsigned long spins_unless_square(void)
{
	asm volatile (
		"r3 = r1;"
		"r3 *= r1;"
		"if r3 == r2 goto 2f;"
	"1:	may_goto 2f;"
		"goto 1b;"
	"2:	r0 = 5;"
		"exit;"
		::: __clobber_all);
}

/*
 * No call gets to the loop: 2 * 2 is 4 and 3 * 3 is 9. The two calls joined do, with 2 or 3 and 4
 * or 9 and nothing that says which goes with which: the function is left at its may_goto, and its
 * caller is in more sections than a landing pad leaves. The calls have to be kept apart for that,
 * and nothing at the call tells: its arguments are constants, and the function has one exit.
 */
SEC("tc")
__description("may_goto unwinds: two calls that skip a loop, only their join gets to it")
__load_if_JITed()
__success __retval(10)
__naked void loop_only_in_join(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r1 = 2;"
		"r2 = 4;"
		"call spins_unless_square;"
		"r6 = r0;"
		"r1 = 3;"
		"r2 = 9;"
		"call spins_unless_square;"
		"r6 += r0;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = r6;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

/*
 * A subprog that cannot unwind: the comparator of bpf_rbtree_add() for a node that takes a lock
 * when it is freed. The kfunc would drop the node under the lock of the tree.
 */
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

private(B) struct bpf_spin_lock tree_lock;
private(B) struct bpf_rb_root tree __contains(node_list, node);

/* No code has an elem: this puts it in BTF, for __contains() above */
void __elem_btf_root(struct elem *e)
{
}

long less_trips, less_went_on;

/* Add two nodes, so that the comparator runs, and take them out again. Returns 0. */
static __always_inline int compare_two_nodes(bool (less)(struct bpf_rb_node *a,
							 const struct bpf_rb_node *b))
{
	struct bpf_rb_node *node;
	struct node_list *n;
	int i;

	for (i = 0; i < 2; i++) {
		n = bpf_obj_new(typeof(*n));
		if (!n)
			return 100;
		n->key = i;
		bpf_spin_lock(&tree_lock);
		bpf_rbtree_add(&tree, &n->node, less);
		bpf_spin_unlock(&tree_lock);
	}
	for (i = 0; i < 2; i++) {
		bpf_spin_lock(&tree_lock);
		node = bpf_rbtree_first(&tree);
		node = node ? bpf_rbtree_remove(&tree, node) : NULL;
		bpf_spin_unlock(&tree_lock);
		if (!node)
			return 101;
		bpf_obj_drop(container_of(node, struct node_list, node));
	}
	return 0;
}

static __noinline bool less_spins(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	long n = zero;

	/* no helpers under the lock */
	while (can_loop)
		n++;
	less_trips = n;
	less_went_on++;
	return false;
}

/*
 * When the time is up the loop of the comparator is left where the program says, the comparator
 * returns, and the prog goes on: it has no may_goto of its own.
 */
SEC("tc")
__description("may_goto jumps: the time is up in a subprog that cannot unwind, the prog goes on")
__load_if_JITed()
__success __retval(15)
__log_level(2) __not_msg("landing pad of may_goto of the program")
__msg("func#1 cannot unwind, the call at {{[0-9]+}} has no landing pad for it: its may_goto jumps, its arena accesses are skipped")
int stuck_comparator_goes_on(void *ctx)
{
	int err;

	less_trips = less_went_on = 0;
	err = compare_two_nodes(less_spins);
	if (err)
		return err;
	return 7 + (less_went_on == 1) * 8 + (less_trips < 100000) * 16;
}

/*
 * The same in a prog that is loaded without CAP_PERFMON, where no function can unwind: the loop of
 * the prog is left where the program says, and the prog returns its own value.
 */
SEC("socket")
__description("may_goto jumps: the time is up in a prog that is loaded without CAP_PERFMON, the prog goes on")
__load_if_JITed()
__success __retval(0)
__caps_unpriv(CAP_BPF) __success_unpriv __retval_unpriv(7)
int no_perfmon_goes_on(void *ctx)
{
	long n = zero;

	while (can_loop)
		n++;
	return n ? 7 : 8;
}

/* The jump of may_goto leads to a load that no prog may make */
static __naked __noinline __used bool bad_behind_may_goto(struct bpf_rb_node *a,
							  const struct bpf_rb_node *b)
{
	asm volatile (
"1:	may_goto 2f;"
	"goto 1b;"
"2:	r0 = *(u64 *)(r10 + 0);"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/* Where the function can unwind the jump is not taken, and the load is dead code */
SEC("tc")
__description("may_goto unwinds: what is behind the jump is not verified")
__load_if_JITed()
__success __retval(2)
int behind_the_jump(void *ctx)
{
	struct bpf_rb_node *node = NULL;

	return 7 + bad_behind_may_goto(node, node);
}

/* As a comparator that cannot unwind it takes the jump: it is verified, as it always was */
SEC("tc")
__description("may_goto jumps: in a subprog that cannot unwind the jump is verified")
__load_if_JITed()
__failure __msg("invalid read from stack R10 off=0 size=8")
int stuck_comparator_is_verified(void *ctx)
{
	return compare_two_nodes(bad_behind_may_goto);
}

static __noinline int counts_to_1000(void)
{
	int i, cnt = zero;

	for (i = zero; i < 1000 && can_loop; i++)
		cnt++;
	return cnt;
}

/*
 * The time that is up stays up for the invocation. After the comparator has used it the next
 * may_goto in a subprog that can unwind ends the prog, in its first trip.
 */
SEC("tc")
__description("may_goto jumps: the time is up in a subprog that cannot unwind, the next may_goto unwinds")
__load_if_JITed()
__success __retval(2)
int stuck_comparator_then_unwind(void *ctx)
{
	int err;

	err = compare_two_nodes(less_spins);
	if (err)
		return err;
	return 7 + counts_to_1000();
}

static bool less_calls(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	less_trips = spins();
	less_went_on++;
	return false;
}

/*
 * What a subprog that cannot unwind calls cannot unwind either: the loop of spins() is left where
 * the program says. The same function in a prog without the comparator unwinds, see
 * no_pad_for_call().
 */
SEC("tc")
__description("may_goto jumps: the time is up in a function that a subprog that cannot unwind calls")
__load_if_JITed()
__success __retval(15)
__log_level(2)
__msg("func#1 cannot unwind, the call at {{[0-9]+}} has no landing pad for it: its may_goto jumps, its arena accesses are skipped")
__msg("func#2 cannot unwind, func#1 calls it at {{[0-9]+}} and cannot unwind: its may_goto jumps, its arena accesses are skipped")
int stuck_comparator_calls(void *ctx)
{
	int err;

	less_trips = less_went_on = 0;
	err = compare_two_nodes(less_calls);
	if (err)
		return err;
	return 7 + (less_went_on == 1) * 8 + (less_trips < 100000) * 16;
}

/*
 * The prog calls less_spins() itself before the verifier gets to bpf_rbtree_add(): states have
 * left the function at its may_goto when it turns out that it cannot unwind. The pass is done
 * again, and the jump is taken in both uses: the call returns too.
 */
SEC("tc")
__description("may_goto jumps: a function is called, then it is a comparator that cannot unwind")
__load_if_JITed()
__success __retval(15)
__log_level(2) __msg("to kexit of func#1") __msg("pass 1")
__not_msg("landing pad of may_goto of the program")
int called_then_stuck(void *ctx)
{
	struct bpf_rb_node *node = NULL;
	int err;

	less_trips = less_went_on = 0;
	if (never)
		less_spins(node, node);
	err = compare_two_nodes(less_spins);
	if (err)
		return err;
	return 7 + (less_went_on == 1) * 8 + (less_trips < 100000) * 16;
}

/*
 * The call of less_spins() is in nine RCU sections, and no pad leaves them: that is an error when
 * the verifier gets there, as it is in no_pad_for_call(). Then the function turns out to be a
 * comparator that cannot unwind. It does not come back unwound to any call, the error was none,
 * and the pass is done again without it.
 */
SEC("tc")
__description("may_goto jumps: a conflict at the call of a function that cannot unwind after all")
__load_if_JITed()
__success __retval(15)
int conflict_then_stuck(void *ctx)
{
	struct bpf_rb_node *node = NULL;
	int err;

	less_trips = less_went_on = 0;
	if (never) {
		NINE_TIMES(bpf_rcu_read_lock());
		less_spins(node, node);
		NINE_TIMES(bpf_rcu_read_unlock());
	}
	err = compare_two_nodes(less_spins);
	if (err)
		return err;
	return 7 + (less_went_on == 1) * 8 + (less_trips < 100000) * 16;
}

/*
 * The same with spins(), which the comparator calls: what a subprog that cannot unwind calls cannot
 * unwind either, from the call on. The error was none, and the pass is done again without it.
 */
SEC("tc")
__description("may_goto jumps: a conflict at the call of a function that a subprog that cannot unwind calls")
__load_if_JITed()
__success __retval(15)
int conflict_then_stuck_below(void *ctx)
{
	int err;

	less_trips = less_went_on = 0;
	if (never) {
		NINE_TIMES(bpf_rcu_read_lock());
		spins();
		NINE_TIMES(bpf_rcu_read_unlock());
	}
	err = compare_two_nodes(less_calls);
	if (err)
		return err;
	return 7 + (less_went_on == 1) * 8 + (less_trips < 100000) * 16;
}

/* With a task it releases the task between its loops. With none it has one loop. */
static __noinline long counts_and_releases(struct task_struct *t)
{
	long i, n = zero;

	for (i = zero; i < 1000 && can_loop; i++)
		n++;
	if (!t)
		return n;
	bpf_task_release(t);
	for (i = zero; i < 1000 && can_loop; i++)
		n++;
	return n;
}

static bool less_counts(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	less_trips = counts_and_releases(NULL);
	less_went_on++;
	return false;
}

/*
 * The function is left while its caller holds the task, and when the task is gone. No pad of the
 * caller can tell, which shows when the pass is over: an error of the pass if the function could
 * unwind. The comparator calls it too, so it cannot.
 */
SEC("tc")
__description("may_goto jumps: a conflict after the pass at the call of a function that cannot unwind")
__load_if_JITed()
__success __retval(31)
int late_conflict_then_stuck_below(void *ctx)
{
	struct task_struct *t;
	int err;

	less_trips = less_went_on = 0;
	if (never) {
		t = bpf_task_from_pid(1);
		if (t)
			counts_and_releases(t);
	}
	err = compare_two_nodes(less_counts);
	if (err)
		return err;
	return 7 + (less_went_on == 1) * 8 + (less_trips == 1000) * 16;
}

#define NINE(what) what(1) what(2) what(3) what(4) what(5) what(6) what(7) what(8) what(9)
#define ITER_NEW(i) bpf_iter_num_new(&it##i, 0, 1);
#define ITER_DESTROY(i) bpf_iter_num_destroy(&it##i);

/* Nine iterators are more than a landing pad destroys */
static __noinline long spins_with_nine_iters(void)
{
	struct bpf_iter_num it1, it2, it3, it4, it5, it6, it7, it8, it9;
	long n = zero;

	NINE(ITER_NEW)
	while (can_loop)
		n++;
	NINE(ITER_DESTROY)
	return n;
}

static bool less_calls_nine_iters(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	less_trips = spins_with_nine_iters();
	less_went_on++;
	return false;
}

/*
 * No pad would do for the may_goto of the function, see no_pad_for_may_goto(). It needs none: only
 * the comparator calls it, and the loop is left where the program says.
 */
SEC("tc")
__description("may_goto jumps: a function that a subprog that cannot unwind calls holds too much")
__load_if_JITed()
__success __retval(15)
int stuck_comparator_calls_too_much(void *ctx)
{
	int err;

	less_trips = less_went_on = 0;
	err = compare_two_nodes(less_calls_nine_iters);
	if (err)
		return err;
	return 7 + (less_went_on == 1) * 8 + (less_trips < 100000) * 16;
}

static __noinline long counts(void)
{
	long i, n = zero;

	for (i = zero; i < 1000 && can_loop; i++)
		n++;
	return n;
}

/* It has no site of its own, and holds more than a pad releases where its callee is left */
static __noinline long counts_with_nine_iters(void)
{
	struct bpf_iter_num it1, it2, it3, it4, it5, it6, it7, it8, it9;
	long n;

	NINE(ITER_NEW)
	n = counts();
	NINE(ITER_DESTROY)
	return n;
}

static __noinline long counts_if(long yes)
{
	return yes ? counts_with_nine_iters() : 0;
}

static bool less_does_not_count(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	less_trips = counts_if(0);
	less_went_on++;
	return false;
}

/*
 * counts_with_nine_iters() is verified on its own for the call of the prog: counts() comes back
 * unwound to a call in nine iterators, an error of the pass. Then the comparator calls counts_if(),
 * which is stuck from there on, and so is what it calls: when the prog calls counts_if() that is
 * counts_with_nine_iters(). The call is one more of the function that was verified on its own, so
 * it is not walked again, and nothing tells counts() that it is stuck too. The pass is done again
 * for that: the function made a call before it was stuck. Then the loop of counts() is left where
 * the program says, nothing comes back unwound, and the error was none.
 */
SEC("tc")
__description("may_goto jumps: a function makes a call on its own, then a function that cannot unwind calls it")
__load_if_JITed()
__success __retval(31)
__log_level(2)
/* the function, counts(), the comparator, counts_if(): each line names the call that told */
__msg("func#1 cannot unwind, func#4 calls it at {{[0-9]+}} and cannot unwind: its may_goto jumps")
__msg("func#2 cannot unwind, func#1 calls it at {{[0-9]+}} and cannot unwind: its may_goto jumps")
__msg("func#3 cannot unwind, the call at {{[0-9]+}} has no landing pad for it: its may_goto jumps")
__msg("func#4 cannot unwind, func#3 calls it at {{[0-9]+}} and cannot unwind: its may_goto jumps")
int on_its_own_then_stuck(void *ctx)
{
	long n = counts_with_nine_iters();
	int err;

	less_trips = less_went_on = 0;
	err = compare_two_nodes(less_does_not_count);
	if (err)
		return err;
	n += counts_if(never);
	return 7 + (less_went_on == 1) * 8 + (n == 1000) * 16;
}

/*
 * may_goto jumps back over 8191 divisions, 32764 insns once each of them is guarded by a patch of
 * 4 insns. In a subprog that cannot unwind it jumps where the program says, and that does not fit
 * the 16 bits of the jump that may_goto expands to: it becomes gotol. Where the subprog can unwind
 * the insn goes forward to its landing pad, see verifier_patch_list.c.
 */
static __naked __noinline __used bool less_jumps_far_back(struct bpf_rb_node *a,
							   const struct bpf_rb_node *b)
{
	asm volatile (
		"r1 = %[one_div] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"r0 = 1;"
		"r6 = 0;"
		"goto 2f;"
	"1:	r0 = 0;"
		"exit;"
	"2:	if r6 != 0 goto 1b;"
		".rept 8191;"
		"r0 /= r1;"
		".endr;"
		"r6 = 1;"
		"may_goto 2b;"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(one_div)
		: __clobber_all);
}

SEC("tc")
__description("may_goto jumps: a far jump back in a subprog that cannot unwind becomes gotol")
__load_if_JITed()
__success __retval(7)
__xlated("...")
__xlated("if r13 == 0x0 goto pc+1")
__xlated("goto pc+1")
__xlated("gotol pc-{{[0-9]+}}")
int stuck_comparator_jumps_far_back(void *ctx)
{
	return compare_two_nodes(less_jumps_far_back) + 7;
}

/*
 * may_goto that jumps over nothing is no site: it is removed, and the prog has no pad. A cast that
 * is removed is nothing too: verifier_arena_cast has that, an arena cannot be made without a JIT.
 */
SEC("tc")
__description("may_goto jumps: may_goto +0 and may_goto over it are removed")
__success __retval(7)
__xlated("0: r0 = 7")
__xlated("1: exit")
__naked void may_goto_0_is_no_site(void)
{
	asm volatile (
	"may_goto 1f;"
	"may_goto 1f;"
"1:	r0 = 7;"
	"may_goto 2f;"
"2:	exit;"
	::: __clobber_all);
}

#endif

/*
 * Without a JIT may_goto counts trips in its frame: BPF_MAX_LOOPS of them are a bound of the loop,
 * not a time that is up. The insn jumps where the program says and the prog goes on.
 */
SEC("tc")
__description("may_goto jumps: the form that counts trips")
__load_if_no_JITed()
__success __retval(15)
__xlated("...")
__xlated("r13 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("if r13 == 0x0 goto pc+{{[0-9]+}}")
__xlated("r13 -= 1")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r13")
int counting_form_goes_on(void *ctx)
{
	long n = zero;

	while (can_loop)
		n++;
	return 7 + (n == 8 * 1024 * 1024) * 8;
}

static __noinline long counts_in_subprog(void)
{
	long n = zero;

	while (can_loop)
		n++;
	return n;
}

/* The same in a subprog, which cannot unwind without a JIT: each frame has its count */
SEC("tc")
__description("may_goto jumps: the form that counts trips, in a subprog and in the prog")
__load_if_no_JITed()
__success __retval(31)
int counting_form_in_subprog(void *ctx)
{
	long n = counts_in_subprog(), m = zero;

	while (can_loop)
		m++;
	return 7 + (n == 8 * 1024 * 1024) * 8 + (m == 8 * 1024 * 1024) * 16;
}
