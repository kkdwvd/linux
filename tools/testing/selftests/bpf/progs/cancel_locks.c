// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * A frame that is cancelled leaves through a pad that the verifier generated, see cancel.c. The
 * pad releases what the frame holds. Here that is locks, IRQ flags, RCU read sections and
 * preemption-disabled sections: the pad unlocks and restores, what was taken last first, and
 * leaves the sections that its frame entered.
 *
 * A program is cancelled at one of two points. dives() calls itself until the stack has no room:
 * the frame that holds something waits in a call then, and the pad of the call releases it. Or
 * the frame spins in a loop that only may_goto of the verifier ends, for the 250 ms of the time
 * slice: the frame at the point holds something, and the pad of may_goto releases it.
 *
 * Nothing of a program runs behind the point, so a program cannot tell what its pads did. The
 * runner in prog_tests/cancel_locks.c runs every program twice. The second run takes the locks of
 * the first, and enter() notes for both what the kernel was like when the program was entered: a
 * pad that released in the wrong order left interrupts off, one that left a section too few is
 * found by the preempt count or by the RCU nesting of the task.
 *
 * A program that is cancelled returns the cancel value of its type: TC_ACT_SHOT for the tc
 * programs, and 0 for the syscall programs, which are the ones that may sleep. A program in which
 * a cancellation gets to a frame that holds what no pad releases is not loaded: the verifier names
 * the insn and the limit.
 *
 * "cancel sites S padded P declined ..." in the stats of the verifier is explained in cancel.c.
 * It takes the JIT of x86-64 or arm64, CAP_BPF and CAP_PERFMON.
 */

#define TC_ACT_OK	0
#define TC_ACT_SHOT	2

extern void bpf_local_irq_save(unsigned long *) __weak __ksym;
extern void bpf_local_irq_restore(unsigned long *) __weak __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long one = 1;

/* The frames of a recursion that began, the loops that began, */
unsigned long frames;
unsigned long spins;
/* and how many times the code behind a call or behind a loop ran */
unsigned long behind;
/* The times that a lock was not to be had */
unsigned long lock_err;

/* What a program found when it was entered, see enter() */
struct at_entry {
	int preempt;	/* the preempt count */
	int rcu;	/* how deep the task is in RCU read sections, if the kernel counts that */
	int irq;	/* the bit of the IRQ flags that tells whether interrupts are on */
};

struct at_entry found[2];
unsigned long runs;
/* The times that a bpf_spin_lock was locked when a program was entered */
unsigned long stuck;

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

/*
 * A lock in a global variable is in the only element of an array map. The verifier knows the
 * address, and a pad loads it.
 */
private(A) struct bpf_spin_lock spin_a;
private(B) struct bpf_res_spin_lock res_a;
private(C) struct bpf_res_spin_lock res_b;

/* With two elements only a pointer to the element leads to its lock */
struct spin_elem {
	long pad;
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct spin_elem);
} spin_locks SEC(".maps");

/* @var++, with r1 and r2 */
#define asm_count(var)				\
	"r1 = %[" #var "] ll;"			\
	"r2 = *(u64 *)(r1 + 0);"		\
	"r2 += 1;"				\
	"*(u64 *)(r1 + 0) = r2;"

/* The bit of the flags that bpf_local_irq_save() saves which tells whether interrupts were on */
#if defined(bpf_target_x86)
#define IRQ_FLAG_BIT	9	/* IF of EFLAGS */
#elif defined(bpf_target_arm64)
#define IRQ_FLAG_BIT	7	/* I of DAIF, or of the priority mask where that masks interrupts */
#else
#define IRQ_FLAG_BIT	0
#endif

/* With CONFIG_PREEMPT_RCU the task counts the RCU read sections that it is in */
struct task_struct___rcu {
	int rcu_read_lock_nesting;
} __attribute__((preserve_access_index));

/* The word of a lock. No load of a program may read it, a helper reads whatever it is given. */
static __always_inline __u32 lock_word(void *lock)
{
	__u32 word = 0;

	bpf_probe_read_kernel(&word, sizeof(word), lock);
	return word;
}

/*
 * Every program calls it first. It notes what the program was entered in, for the runner to
 * compare the two runs. Returns 0 if the program may go on: a bpf_spin_lock that the run before
 * left locked would hang this one for good.
 */
static __noinline __used int enter(void)
{
	struct task_struct___rcu *task = (void *)bpf_get_current_task_btf();
	struct at_entry *at = &found[runs++ & 1];
	unsigned long flags, saved = 0;
	struct spin_elem *elem;
	int key = 1;

	/* x86 has need_resched in the top bit of the count */
	at->preempt = get_preempt_count() & 0x7fffffff;
	if (bpf_core_field_exists(task->rcu_read_lock_nesting))
		at->rcu = task->rcu_read_lock_nesting;
	/* the flags that a program saved are not for it to read either */
	bpf_local_irq_save(&flags);
	bpf_probe_read_kernel(&saved, sizeof(saved), &flags);
	bpf_local_irq_restore(&flags);
	at->irq = (saved >> IRQ_FLAG_BIT) & 1;

	elem = bpf_map_lookup_elem(&spin_locks, &key);
	if (!elem || lock_word(&elem->lock) || lock_word(&spin_a)) {
		stuck++;
		return 1;
	}
	return 0;
}

/*
 * It calls itself until the stack has no room, see cancel.c. Every frame counts itself on the
 * way down, and what is behind the call counts when the call comes back: with pads none does.
 */
__naked __noinline __used
static unsigned long dives(void)
{
	asm volatile (
		"r1 = %[frames] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"*(u64 *)(r10 - 128) = r2;"
		"call dives;"
		"r1 = %[behind] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"exit;"
		:
		: __imm_addr(frames),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * RCU read sections and preemption-disabled sections. The verifier counts them, and the pad of a
 * frame leaves the sections that the frame entered, or that a callee entered and returned in: one
 * call for each section, behind what unlocks and restores, and four of a kind at most.
 */
SEC("tc")
__description("cancel: an RCU read section, entered at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int rcu_at_call(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	bpf_rcu_read_lock();
	dives();
	bpf_rcu_read_unlock();
	behind++;
	return TC_ACT_OK;
}

SEC("tc")
__description("cancel: a preemption-disabled section, entered at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int preempt_at_call(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	bpf_preempt_disable();
	dives();
	bpf_preempt_enable();
	behind++;
	return TC_ACT_OK;
}

/* Four of each kind, the most that a pad leaves. It leaves the RCU read sections first. */
SEC("tc")
__description("cancel: four RCU read sections and four preemption-disabled sections at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int sections_max_at_call(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	bpf_rcu_read_lock();
	bpf_preempt_disable();
	bpf_rcu_read_lock();
	bpf_preempt_disable();
	bpf_rcu_read_lock();
	bpf_preempt_disable();
	bpf_rcu_read_lock();
	bpf_preempt_disable();
	dives();
	bpf_preempt_enable();
	bpf_rcu_read_unlock();
	bpf_preempt_enable();
	bpf_rcu_read_unlock();
	bpf_preempt_enable();
	bpf_rcu_read_unlock();
	bpf_preempt_enable();
	bpf_rcu_read_unlock();
	behind++;
	return TC_ACT_OK;
}

/* One more than a pad leaves */
SEC("tc")
__description("cancel: five RCU read sections at a call are rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(section)")
int rcu_over_max_at_call(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	bpf_rcu_read_lock();
	bpf_rcu_read_lock();
	bpf_rcu_read_lock();
	bpf_rcu_read_lock();
	bpf_rcu_read_lock();
	dives();
	bpf_rcu_read_unlock();
	bpf_rcu_read_unlock();
	bpf_rcu_read_unlock();
	bpf_rcu_read_unlock();
	bpf_rcu_read_unlock();
	behind++;
	return TC_ACT_OK;
}

SEC("tc")
__description("cancel: five preemption-disabled sections at a call are rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(section)")
int preempt_over_max_at_call(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	bpf_preempt_disable();
	bpf_preempt_disable();
	bpf_preempt_disable();
	bpf_preempt_disable();
	bpf_preempt_disable();
	dives();
	bpf_preempt_enable();
	bpf_preempt_enable();
	bpf_preempt_enable();
	bpf_preempt_enable();
	bpf_preempt_enable();
	behind++;
	return TC_ACT_OK;
}

/* It returns in the sections, for the caller to leave them */
static __noinline int enters_sections(void)
{
	bpf_rcu_read_lock();
	bpf_preempt_disable();
	return 0;
}

/* The call of the callee has no pad, nothing gets there. The call of dives() leaves the two. */
SEC("tc")
__description("cancel: sections that a callee entered and returned in, at a call of the caller")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int sections_of_callee_at_call(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	enters_sections();
	dives();
	bpf_preempt_enable();
	bpf_rcu_read_unlock();
	behind++;
	return TC_ACT_OK;
}

static __noinline int enters_sections_and_dives(void)
{
	bpf_preempt_disable();
	bpf_rcu_read_lock();
	dives();
	bpf_rcu_read_unlock();
	bpf_preempt_enable();
	behind++;
	return 0;
}

/* The callee is entered inside of a section, which is not for its pad to leave */
SEC("tc")
__description("cancel: sections that a caller and its callee entered")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 4 padded 4 declined")
__stderr("ERROR: Program was cancelled")
int sections_in_two_frames(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	bpf_rcu_read_lock();
	enters_sections_and_dives();
	bpf_rcu_read_unlock();
	behind++;
	return TC_ACT_OK;
}

/*
 * A program that may sleep is in no RCU read section of the kernel, and its preemption is on:
 * the sections that it enters are all there is. Its pads call the same kfuncs.
 */
SEC("syscall")
__description("cancel: RCU read sections of a program that may sleep, at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(0) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int sleepable_rcu_at_call(void *ctx)
{
	if (enter())
		return 1;
	bpf_rcu_read_lock();
	bpf_rcu_read_lock();
	dives();
	bpf_rcu_read_unlock();
	bpf_rcu_read_unlock();
	behind++;
	return 1;
}

SEC("syscall")
__description("cancel: preemption-disabled sections of a program that may sleep, at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(0) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int sleepable_preempt_at_call(void *ctx)
{
	if (enter())
		return 1;
	bpf_preempt_disable();
	bpf_preempt_disable();
	dives();
	bpf_preempt_enable();
	bpf_preempt_enable();
	behind++;
	return 1;
}

SEC("syscall")
__description("cancel: five RCU read sections of a program that may sleep are rejected at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(section)")
int sleepable_rcu_over_max_at_call(void *ctx)
{
	if (enter())
		return 1;
	bpf_rcu_read_lock();
	bpf_rcu_read_lock();
	bpf_rcu_read_lock();
	bpf_rcu_read_lock();
	bpf_rcu_read_lock();
	dives();
	bpf_rcu_read_unlock();
	bpf_rcu_read_unlock();
	bpf_rcu_read_unlock();
	bpf_rcu_read_unlock();
	bpf_rcu_read_unlock();
	behind++;
	return 1;
}

static __noinline int leaves_rcu_and_dives(void)
{
	bpf_rcu_read_unlock();
	dives();
	behind++;
	return 0;
}

/*
 * The pad of the call in the main program would leave the section once more. Like the callee
 * that unlocks for its caller, this one is verified without its callers first, and the log names
 * its call of dives() as well.
 */
SEC("tc")
__description("cancel: a callee that leaves the RCU read section of its caller is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(foreign)")
int callee_leaves_rcu(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	bpf_rcu_read_lock();
	leaves_rcu_and_dives();
	behind++;
	return TC_ACT_OK;
}

/*
 * One state gets to the call in one section, the other one in two, and a pad makes a fixed
 * number of calls.
 */
SEC("tc")
__description("cancel: RCU read sections that two visits of a call count differently are rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(cond)")
__naked void rcu_counts_differ(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 3f;"
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"r7 = 0;"
		"call %[bpf_rcu_read_lock];"
		"if r6 == 0 goto 1f;"
		"r7 = 1;"
		"call %[bpf_rcu_read_lock];"
	"1:"
		"call dives;"
		"if r7 == 0 goto 2f;"
		"call %[bpf_rcu_read_unlock];"
	"2:"
		"call %[bpf_rcu_read_unlock];"
		asm_count(behind)
	"3:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock),
		  __imm_addr(zero),
		  __imm_addr(behind)
		: __clobber_all
	);
}

char _license[] SEC("license") = "GPL";
