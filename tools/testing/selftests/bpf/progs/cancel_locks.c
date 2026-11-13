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

struct res_elem {
	long pad;
	struct bpf_res_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct res_elem);
} res_locks SEC(".maps");

/* What the asm below adds to a pointer to an element */
_Static_assert(__builtin_offsetof(struct spin_elem, lock) == 8, "the lock is not at 8");
_Static_assert(__builtin_offsetof(struct res_elem, lock) == 8, "the lock is not at 8");

/* r0 = element 1 of @map, or NULL. The key is at r10 - 4. */
#define asm_lookup(map)				\
	"r1 = 1;"				\
	"*(u32 *)(r10 - 4) = r1;"		\
	"r2 = r10;"				\
	"r2 += -4;"				\
	"r1 = %[" #map "] ll;"			\
	"call %[bpf_map_lookup_elem];"

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

/* The sites: the stack check of dives(), its call of itself, and the call in the main program */
SEC("tc")
__description("cancel: bpf_spin_lock in a global variable, held at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int spin_lock_global_at_call(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	bpf_spin_lock(&spin_a);
	dives();
	bpf_spin_unlock(&spin_a);
	behind++;
	return TC_ACT_OK;
}

/* r6 points to the element across the call, and the pad adds the 8 bytes to the lock */
SEC("tc")
__description("cancel: bpf_spin_lock in a map value, a register points to the value at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
__naked void spin_lock_in_map_at_call(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_lookup(spin_locks)
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
		"r1 = r6;"
		"r1 += 8;"
		"call %[bpf_spin_lock];"
		"call dives;"
		"r1 = r6;"
		"r1 += 8;"
		"call %[bpf_spin_unlock];"
		asm_count(behind)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm_addr(spin_locks),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* No register keeps the pointer: the pad reads the slot that it was spilled to */
SEC("tc")
__description("cancel: bpf_spin_lock in a map value, a stack slot points to the value at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
__naked void spin_lock_spilled_at_call(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_lookup(spin_locks)
		"if r0 == 0 goto 1f;"
		"*(u64 *)(r10 - 16) = r0;"
		"r1 = r0;"
		"r1 += 8;"
		"call %[bpf_spin_lock];"
		"call dives;"
		"r1 = *(u64 *)(r10 - 16);"
		"r1 += 8;"
		"call %[bpf_spin_unlock];"
		asm_count(behind)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm_addr(spin_locks),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * Both paths to the call have the pointer in the slot. One of them has it in r6 as well, which
 * a visit picks first, and the other one has something else there. The pad reads the slot.
 */
SEC("tc")
__description("cancel: bpf_spin_lock in a map value, a register points to the value on one path only")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
__xlated("exit")
__xlated("r1 = *(u64 *)(r10 -16)")
__xlated("r1 += 8")
__xlated("call unknown")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void spin_lock_two_places(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 2f;"
		asm_lookup(spin_locks)
		"if r0 == 0 goto 2f;"
		"*(u64 *)(r10 - 16) = r0;"
		"r6 = r0;"
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 1f;"
		"r6 = r10;"
	"1:"
		"r1 = *(u64 *)(r10 - 16);"
		"r1 += 8;"
		"call %[bpf_spin_lock];"
		"call dives;"
		"r1 = *(u64 *)(r10 - 16);"
		"r1 += 8;"
		"call %[bpf_spin_unlock];"
		/* r6 is live at the call */
		"r7 = r6;"
		asm_count(behind)
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm_addr(spin_locks),
		  __imm_addr(zero),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* r1: a pointer to a slot of the caller. It writes to the slot and dives. */
__naked __noinline __used
static unsigned long fills_slot_and_dives(void)
{
	asm volatile (
		"r2 = 7;"
		"*(u64 *)(r1 + 0) = r2;"
		"call dives;"
		"r0 = 0;"
		"exit;"
		:
		:
		: __clobber_all
	);
}

/*
 * The pointer to the element is in a stack slot only, and the callee is given a pointer to
 * another slot. It is verified with the frame of its caller in the state, and every site in
 * there finds the pointer to the element as the call left it: the pad of the call reads it.
 */
SEC("tc")
__description("cancel: bpf_spin_lock in a map value, a slot points to the value and the callee writes to another one")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 4 padded 4 declined")
__stderr("ERROR: Program was cancelled")
__naked void spin_lock_spilled_stack_written(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_lookup(spin_locks)
		"if r0 == 0 goto 1f;"
		"*(u64 *)(r10 - 16) = r0;"
		"r1 = r0;"
		"r1 += 8;"
		"call %[bpf_spin_lock];"
		"r1 = r10;"
		"r1 += -24;"
		"call fills_slot_and_dives;"
		"r1 = *(u64 *)(r10 - 16);"
		"r1 += 8;"
		"call %[bpf_spin_unlock];"
		asm_count(behind)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm_addr(spin_locks),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* A lock that the pad left locked tells the second run so: it is not to be had */
SEC("tc")
__description("cancel: bpf_res_spin_lock in a global variable, held at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int res_lock_global_at_call(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	if (bpf_res_spin_lock(&res_a)) {
		lock_err++;
		return TC_ACT_OK;
	}
	dives();
	bpf_res_spin_unlock(&res_a);
	behind++;
	return TC_ACT_OK;
}

SEC("tc")
__description("cancel: bpf_res_spin_lock in a map value, a register points to the value at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
__naked void res_lock_in_map_at_call(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_lookup(res_locks)
		"if r0 == 0 goto 1f;"
		"r7 = r0;"
		"r1 = r7;"
		"r1 += 8;"
		"call %[bpf_res_spin_lock];"
		"if r0 != 0 goto 2f;"
		"call dives;"
		"r1 = r7;"
		"r1 += 8;"
		"call %[bpf_res_spin_unlock];"
		asm_count(behind)
		"goto 1f;"
	"2:"
		asm_count(lock_err)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm(bpf_res_spin_lock),
		  __imm(bpf_res_spin_unlock),
		  __imm_addr(res_locks),
		  __imm_addr(behind),
		  __imm_addr(lock_err)
		: __clobber_all
	);
}

/*
 * One of two locks in global variables, which the program chose at run time: each visit of
 * the call has a lock at another address, and both have the pointer to it in r7. The pad
 * unlocks through r7.
 */
SEC("tc")
__description("cancel: one of two bpf_res_spin_locks in global variables, a register points to it at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
__xlated("exit")
__xlated("r1 = r7")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void res_lock_one_of_two_at_call(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"r7 = %[res_a] ll;"
		"if r6 == 0 goto 3f;"
		"r7 = %[res_b] ll;"
	"3:"
		"r1 = r7;"
		"call %[bpf_res_spin_lock];"
		"if r0 != 0 goto 2f;"
		"call dives;"
		"r1 = r7;"
		"call %[bpf_res_spin_unlock];"
		asm_count(behind)
		"goto 1f;"
	"2:"
		asm_count(lock_err)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_res_spin_lock),
		  __imm(bpf_res_spin_unlock),
		  __imm_addr(zero),
		  __imm_addr(res_a),
		  __imm_addr(res_b),
		  __imm_addr(behind),
		  __imm_addr(lock_err)
		: __clobber_all
	);
}

/*
 * The same, but the pointer is gone at the call, and the program tells by r6 which lock to
 * unlock. One insn took either lock, so one drop flag would stand for two addresses.
 */
SEC("tc")
__description("cancel: one of two bpf_res_spin_locks in global variables without a pointer at a call is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(places)")
__naked void res_lock_one_of_two_no_pointer(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"r1 = %[res_a] ll;"
		"if r6 == 0 goto 3f;"
		"r1 = %[res_b] ll;"
	"3:"
		"call %[bpf_res_spin_lock];"
		"if r0 != 0 goto 2f;"
		"call dives;"
		"r1 = %[res_a] ll;"
		"if r6 == 0 goto 4f;"
		"r1 = %[res_b] ll;"
	"4:"
		"call %[bpf_res_spin_unlock];"
		asm_count(behind)
		"goto 1f;"
	"2:"
		asm_count(lock_err)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_res_spin_lock),
		  __imm(bpf_res_spin_unlock),
		  __imm_addr(zero),
		  __imm_addr(res_a),
		  __imm_addr(res_b),
		  __imm_addr(behind),
		  __imm_addr(lock_err)
		: __clobber_all
	);
}

/* One call of the pad unlocks and restores the flags that the lock was taken with */
SEC("tc")
__description("cancel: bpf_res_spin_lock_irqsave, held at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int res_lock_irqsave_at_call(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	if (bpf_res_spin_lock_irqsave(&res_a, &flags)) {
		lock_err++;
		return TC_ACT_OK;
	}
	dives();
	bpf_res_spin_unlock_irqrestore(&res_a, &flags);
	behind++;
	return TC_ACT_OK;
}

SEC("tc")
__description("cancel: IRQ flags, saved at a call")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int irq_save_at_call(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	bpf_local_irq_save(&flags);
	dives();
	bpf_local_irq_restore(&flags);
	behind++;
	return TC_ACT_OK;
}

/*
 * The flags that were saved last found interrupts off. The pad restores them first, or it would
 * turn interrupts on and then off for good. It is behind the exit of the main program: two calls
 * of bpf_local_irq_restore(), then what tells that the program was cancelled.
 */
SEC("tc")
__description("cancel: IRQ flags that were saved twice, the slot of the first one above")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("exit")
__xlated("r1 = r10")
__xlated("r1 += -16")
__xlated("call kernel-function")
__xlated("r1 = r10")
__xlated("r1 += -8")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void irq_save_twice_at_call(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_save];"
		"call dives;"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
		asm_count(behind)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_local_irq_save),
		  __imm(bpf_local_irq_restore),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* The other way around: the order is that of the saves, and not of the slots */
SEC("tc")
__description("cancel: IRQ flags that were saved twice, the slot of the first one below")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("exit")
__xlated("r1 = r10")
__xlated("r1 += -8")
__xlated("call kernel-function")
__xlated("r1 = r10")
__xlated("r1 += -16")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void irq_save_twice_slots_swapped(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
		"call dives;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_restore];"
		asm_count(behind)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_local_irq_save),
		  __imm(bpf_local_irq_restore),
		  __imm_addr(behind)
		: __clobber_all
	);
}

static __noinline int saves_and_dives(void)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	dives();
	bpf_local_irq_restore(&flags);
	behind++;
	return 0;
}

/* Each frame restores the flags that it saved: the pad of the callee, then the pad of the caller */
SEC("tc")
__description("cancel: IRQ flags that a caller and its callee saved")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 4 padded 4 declined")
__stderr("ERROR: Program was cancelled")
int irq_save_in_two_frames(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	bpf_local_irq_save(&flags);
	saves_and_dives();
	bpf_local_irq_restore(&flags);
	behind++;
	return TC_ACT_OK;
}

/*
 * bpf_spin_lock() saves the IRQ flags too, and bpf_spin_unlock() restores what it found:
 * interrupts that bpf_local_irq_save() turned off. The pad calls the helper, then the kfunc.
 */
SEC("tc")
__description("cancel: bpf_spin_lock that was taken with IRQ flags saved")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("exit")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -8")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void spin_lock_in_irq_save_at_call(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
		"r1 = %[spin_a] ll;"
		"call %[bpf_spin_lock];"
		"call dives;"
		"r1 = %[spin_a] ll;"
		"call %[bpf_spin_unlock];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
		asm_count(behind)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_local_irq_save),
		  __imm(bpf_local_irq_restore),
		  __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm_addr(spin_a),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * The flags of the inner lock found the interrupts that the outer one turned off. In the order
 * of the kinds the pad would unlock the outer one first.
 */
SEC("tc")
__description("cancel: bpf_res_spin_lock_irqsave that was taken under bpf_spin_lock")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int res_lock_irqsave_in_spin_lock_at_call(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	bpf_spin_lock(&spin_a);
	if (bpf_res_spin_lock_irqsave(&res_a, &flags)) {
		bpf_spin_unlock(&spin_a);
		lock_err++;
		return TC_ACT_OK;
	}
	dives();
	bpf_res_spin_unlock_irqrestore(&res_a, &flags);
	bpf_spin_unlock(&spin_a);
	behind++;
	return TC_ACT_OK;
}

/*
 * Two locks of one kind, at addresses that the pad loads. Whatever else could order them, one of
 * this program and the next takes them the other way around.
 */
SEC("tc")
__description("cancel: two bpf_res_spin_lock_irqsave, the first variable first")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int res_locks_irqsave_ab_at_call(struct __sk_buff *ctx)
{
	unsigned long flags_a, flags_b;

	if (enter())
		return TC_ACT_OK;
	if (bpf_res_spin_lock_irqsave(&res_a, &flags_a)) {
		lock_err++;
		return TC_ACT_OK;
	}
	if (bpf_res_spin_lock_irqsave(&res_b, &flags_b)) {
		bpf_res_spin_unlock_irqrestore(&res_a, &flags_a);
		lock_err++;
		return TC_ACT_OK;
	}
	dives();
	bpf_res_spin_unlock_irqrestore(&res_b, &flags_b);
	bpf_res_spin_unlock_irqrestore(&res_a, &flags_a);
	behind++;
	return TC_ACT_OK;
}

SEC("tc")
__description("cancel: two bpf_res_spin_lock_irqsave, the second variable first")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int res_locks_irqsave_ba_at_call(struct __sk_buff *ctx)
{
	unsigned long flags_a, flags_b;

	if (enter())
		return TC_ACT_OK;
	if (bpf_res_spin_lock_irqsave(&res_b, &flags_b)) {
		lock_err++;
		return TC_ACT_OK;
	}
	if (bpf_res_spin_lock_irqsave(&res_a, &flags_a)) {
		bpf_res_spin_unlock_irqrestore(&res_b, &flags_b);
		lock_err++;
		return TC_ACT_OK;
	}
	dives();
	bpf_res_spin_unlock_irqrestore(&res_a, &flags_a);
	bpf_res_spin_unlock_irqrestore(&res_b, &flags_b);
	behind++;
	return TC_ACT_OK;
}

/* Three kinds in one pad: the lock with its flags, the lock without, the flags of the frame */
SEC("tc")
__description("cancel: bpf_res_spin_lock and bpf_res_spin_lock_irqsave with IRQ flags saved")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: Program was cancelled")
int res_locks_in_irq_save_at_call(struct __sk_buff *ctx)
{
	unsigned long flags, flags_b;

	if (enter())
		return TC_ACT_OK;
	bpf_local_irq_save(&flags);
	if (bpf_res_spin_lock(&res_a)) {
		bpf_local_irq_restore(&flags);
		lock_err++;
		return TC_ACT_OK;
	}
	if (bpf_res_spin_lock_irqsave(&res_b, &flags_b)) {
		bpf_res_spin_unlock(&res_a);
		bpf_local_irq_restore(&flags);
		lock_err++;
		return TC_ACT_OK;
	}
	dives();
	bpf_res_spin_unlock_irqrestore(&res_b, &flags_b);
	bpf_res_spin_unlock(&res_a);
	bpf_local_irq_restore(&flags);
	behind++;
	return TC_ACT_OK;
}

/*
 * What no pad releases. A cancellation gets to a site where the frame holds something that its
 * pad has no way to release, or would release once more: the program is not loaded. The log has
 * a line for the site, with the kind of insn, the limit, and the word of the stats for the reason.
 */

/* It returns with the flags saved, for the caller to restore them */
static __noinline int saves_for_caller_and_dives(unsigned long *flags)
{
	bpf_local_irq_save(flags);
	dives();
	behind++;
	return 0;
}

/*
 * The frame that saved the flags is to restore them when it is cancelled, but the slot that they
 * are in is in the frame of its caller: its pad has no address for them.
 */
SEC("tc")
__description("cancel: IRQ flags that a callee saved to a slot of its caller are rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(lock)")
int irq_flags_in_slot_of_caller(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	saves_for_caller_and_dives(&flags);
	bpf_local_irq_restore(&flags);
	behind++;
	return TC_ACT_OK;
}

/* r1: the element. It returns with the lock taken, and keeps no pointer to the element. */
__naked __noinline __used
static unsigned long locks_for_caller_and_dives(void)
{
	asm volatile (
		"r1 += 8;"
		"call %[bpf_spin_lock];"
		"call dives;"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_spin_lock)
		: __clobber_all
	);
}

/* Only the caller has a pointer to the element, and the pad of the callee is to unlock */
SEC("tc")
__description("cancel: bpf_spin_lock in a map value that only a caller has a pointer to is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(lock)")
__naked void spin_lock_pointer_with_caller(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_lookup(spin_locks)
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
		"r1 = r6;"
		"call locks_for_caller_and_dives;"
		"r1 = r6;"
		"r1 += 8;"
		"call %[bpf_spin_unlock];"
		asm_count(behind)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm(bpf_spin_unlock),
		  __imm_addr(spin_locks),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * The pointer to the element is in a stack slot only, and r1 points to the stack at the call. A
 * callee that is given such a pointer may write to the slot, so the pad of the call may not read
 * it. dives() does nothing with r1 and is verified on its own, without the frame of its caller
 * in the state: nothing shows there what becomes of the slot.
 */
SEC("tc")
__description("cancel: bpf_spin_lock in a map value whose pointer a callee may overwrite is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(lock)")
__naked void spin_lock_spilled_stack_passed(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_lookup(spin_locks)
		"if r0 == 0 goto 1f;"
		"*(u64 *)(r10 - 16) = r0;"
		"r1 = r0;"
		"r1 += 8;"
		"call %[bpf_spin_lock];"
		"r1 = r10;"
		"r1 += -4;"
		"call dives;"
		"r1 = *(u64 *)(r10 - 16);"
		"r1 += 8;"
		"call %[bpf_spin_unlock];"
		asm_count(behind)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm_addr(spin_locks),
		  __imm_addr(behind)
		: __clobber_all
	);
}

static __noinline int unlocks_and_dives(void)
{
	bpf_spin_unlock(&spin_a);
	dives();
	behind++;
	return 0;
}

/*
 * The pad of the call in the main program would unlock once more, and the callee has nothing to
 * tell it by: it got no pointer to the lock in an argument register. The callee is verified
 * without its callers first: it cannot be cancelled, whoever calls it, and the log names its
 * call of dives() for that. Then the call in the main program is found, and the log names it too.
 */
SEC("tc")
__description("cancel: a callee that unlocks the bpf_spin_lock of its caller is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(foreign)")
int callee_unlocks(struct __sk_buff *ctx)
{
	if (enter())
		return TC_ACT_OK;
	bpf_spin_lock(&spin_a);
	unlocks_and_dives();
	behind++;
	return TC_ACT_OK;
}

static __noinline int restores_and_dives(unsigned long *flags)
{
	bpf_local_irq_restore(flags);
	dives();
	behind++;
	return 0;
}

/*
 * A callee that is given a pointer to the stack is verified with its callers only. The log names
 * the call in the main program and no other insn.
 */
SEC("tc")
__description("cancel: a callee that restores the IRQ flags of its caller is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(foreign)")
int callee_restores_irq_flags(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	bpf_local_irq_save(&flags);
	restores_and_dives(&flags);
	behind++;
	return TC_ACT_OK;
}

/*
 * What only some of the states that get to a site hold. Only the run of the program knows which
 * of them it is in, so the frame gets a drop flag for such a lock or such IRQ flags: a hidden
 * byte of its stack that is 1 while the frame holds them. The verifier sets it behind the call
 * that takes them and clears it in front of the call that gives them back, and the pad releases
 * them under a test of the flag. The runner takes both ways to the site.
 *
 * Two states get to the call with the same flags in the same slots. One saved the upper slot
 * first, the other one the lower slot. These are four entries, each with the flag of the call
 * that saved it: the pad has the two that were saved second first, and restores the two that
 * this run saved, in its order.
 */
SEC("tc")
__description("cancel: IRQ flags that two visits of a call saved in another order")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("exit")
__xlated("r1 = *(u8 *)(r10 -{{[0-9]+}})")
__xlated("if r1 == 0x0 goto pc+3")
__xlated("r1 = r10")
__xlated("r1 += -16")
__xlated("call kernel-function")
__xlated("r1 = *(u8 *)(r10 -{{[0-9]+}})")
__xlated("if r1 == 0x0 goto pc+3")
__xlated("r1 = r10")
__xlated("r1 += -8")
__xlated("call kernel-function")
__xlated("r1 = *(u8 *)(r10 -{{[0-9]+}})")
__xlated("if r1 == 0x0 goto pc+3")
__xlated("r1 = r10")
__xlated("r1 += -16")
__xlated("call kernel-function")
__xlated("r1 = *(u8 *)(r10 -{{[0-9]+}})")
__xlated("if r1 == 0x0 goto pc+3")
__xlated("r1 = r10")
__xlated("r1 += -8")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void irq_save_orders_differ(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 5f;"
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"r7 = 0;"
		"if r6 != 0 goto 1f;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_save];"
		"goto 2f;"
	"1:"
		"r7 = 1;"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
	"2:"
		"call dives;"
		"if r7 != 0 goto 3f;"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
		"goto 4f;"
	"3:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_restore];"
	"4:"
		asm_count(behind)
	"5:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_local_irq_save),
		  __imm(bpf_local_irq_restore),
		  __imm_addr(zero),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * One of the two states that get to the call holds the lock. The flag is the byte at fp-1: set
 * behind bpf_spin_lock(), cleared in front of bpf_spin_unlock(), and tested by the pad, which
 * is behind the exit of the main program.
 */
SEC("tc")
__description("cancel: bpf_spin_lock that one of two visits of a call holds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("r7 = 1")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("call unknown")
__xlated("*(u8 *)(r10 -1) = 1")
__xlated("call pc+{{[0-9]+}}")
__xlated("cancel_goto pc+{{[0-9]+}}")
__xlated("if r7 == 0x0 goto pc+4")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("*(u8 *)(r10 -1) = 0")
__xlated("call unknown")
__xlated("...")
__xlated("exit")
__xlated("r1 = *(u8 *)(r10 -1)")
__xlated("if r1 == 0x0 goto pc+3")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("call unknown")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void spin_lock_in_one_visit(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 3f;"
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"r7 = 0;"
		"if r6 == 0 goto 1f;"
		"r7 = 1;"
		"r1 = %[spin_a] ll;"
		"call %[bpf_spin_lock];"
	"1:"
		"call dives;"
		"if r7 == 0 goto 2f;"
		"r1 = %[spin_a] ll;"
		"call %[bpf_spin_unlock];"
	"2:"
		asm_count(behind)
	"3:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm_addr(zero),
		  __imm_addr(spin_a),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * bpf_res_spin_lock() may fail, and R0 tells: the flag is set behind the call if R0 is 0, and
 * a lock that was not to be had leaves it clear.
 */
SEC("tc")
__description("cancel: bpf_res_spin_lock that one of two visits of a call holds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("call kernel-function")
__xlated("if w0 != 0x0 goto pc+1")
__xlated("*(u8 *)(r10 -1) = 1")
__xlated("...")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("*(u8 *)(r10 -1) = 0")
__xlated("call kernel-function")
__xlated("...")
__xlated("r1 = *(u8 *)(r10 -1)")
__xlated("if r1 == 0x0 goto pc+3")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void res_lock_in_one_visit(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 3f;"
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"r7 = 0;"
		"if r6 == 0 goto 1f;"
		"r1 = %[res_a] ll;"
		"call %[bpf_res_spin_lock];"
		"if r0 != 0 goto 4f;"
		"r7 = 1;"
	"1:"
		"call dives;"
		"if r7 == 0 goto 2f;"
		"r1 = %[res_a] ll;"
		"call %[bpf_res_spin_unlock];"
	"2:"
		asm_count(behind)
	"3:"
		"r0 = 0;"
		"exit;"
	"4:"
		asm_count(lock_err)
		"goto 3b;"
		:
		: __imm(bpf_res_spin_lock),
		  __imm(bpf_res_spin_unlock),
		  __imm_addr(zero),
		  __imm_addr(res_a),
		  __imm_addr(behind),
		  __imm_addr(lock_err)
		: __clobber_all
	);
}

/*
 * bpf_res_spin_lock_irqsave() takes the lock and saves IRQ flags, and one call gives both back.
 * The two are one resource: one flag, the byte below the slot of the IRQ flags, which is set if
 * R0 is 0, and one entry of the pad, which unlocks and restores with one call.
 */
SEC("tc")
__description("cancel: bpf_res_spin_lock_irqsave that one of two visits of a call holds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("call kernel-function")
__xlated("if w0 != 0x0 goto pc+1")
__xlated("*(u8 *)(r10 -9) = 1")
__xlated("...")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("r2 = r10")
__xlated("r2 += -8")
__xlated("*(u8 *)(r10 -9) = 0")
__xlated("call kernel-function")
__xlated("...")
__xlated("r1 = *(u8 *)(r10 -9)")
__xlated("if r1 == 0x0 goto pc+5")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("r2 = r10")
__xlated("r2 += -8")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void res_lock_irqsave_in_one_visit(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 3f;"
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"r7 = 0;"
		"if r6 == 0 goto 1f;"
		"r1 = %[res_a] ll;"
		"r2 = r10;"
		"r2 += -8;"
		"call %[bpf_res_spin_lock_irqsave];"
		"if r0 != 0 goto 4f;"
		"r7 = 1;"
	"1:"
		"call dives;"
		"if r7 == 0 goto 2f;"
		"r1 = %[res_a] ll;"
		"r2 = r10;"
		"r2 += -8;"
		"call %[bpf_res_spin_unlock_irqrestore];"
	"2:"
		asm_count(behind)
	"3:"
		"r0 = 0;"
		"exit;"
	"4:"
		asm_count(lock_err)
		"goto 3b;"
		:
		: __imm(bpf_res_spin_lock_irqsave),
		  __imm(bpf_res_spin_unlock_irqrestore),
		  __imm_addr(zero),
		  __imm_addr(res_a),
		  __imm_addr(behind),
		  __imm_addr(lock_err)
		: __clobber_all
	);
}

/* r1: a slot of the caller for the IRQ flags. r0 = 0 if it returns with the lock and the flags. */
__naked __noinline __used
static unsigned long locks_irqsave_for_caller(void)
{
	asm volatile (
		"r2 = r1;"
		"r1 = %[res_a] ll;"
		"call %[bpf_res_spin_lock_irqsave];"
		"exit;"
		:
		: __imm(bpf_res_spin_lock_irqsave),
		  __imm_addr(res_a)
		: __clobber_all
	);
}

/*
 * Where no flag can tell, the program is not loaded. Here a callee returns with the lock and
 * the IRQ flags: its call brought two entries to the frame, and that is not known to be one
 * resource like the two of one bpf_res_spin_lock_irqsave() are.
 */
SEC("tc")
__description("cancel: bpf_res_spin_lock_irqsave that a callee returned with in one of two visits is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(multi)")
__naked void res_lock_irqsave_of_callee_in_one_visit(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"r7 = 0;"
		"if r6 == 0 goto 1f;"
		"r1 = r10;"
		"r1 += -8;"
		"call locks_irqsave_for_caller;"
		"if r0 != 0 goto 2f;"
		"r7 = 1;"
	"1:"
		"call dives;"
		"if r7 == 0 goto 2f;"
		"r1 = %[res_a] ll;"
		"r2 = r10;"
		"r2 += -8;"
		"call %[bpf_res_spin_unlock_irqrestore];"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_res_spin_unlock_irqrestore),
		  __imm_addr(zero),
		  __imm_addr(res_a)
		: __clobber_all
	);
}

/*
 * One state saved the flags of the upper slot before those of the lower slot, the other one
 * saved the lower slot only. The lower slot is restored first in the one and second in the
 * other, which is two entries of the pad for what one call saved: its flag would restore twice.
 */
SEC("tc")
__description("cancel: IRQ flags that one of two visits of a call saved under one more are rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(places)")
__naked void irq_save_under_one_more(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"r7 = 0;"
		"if r6 == 0 goto 1f;"
		"r7 = 1;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
	"1:"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_save];"
		"call dives;"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_restore];"
		"if r7 == 0 goto 2f;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
	"2:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_local_irq_save),
		  __imm(bpf_local_irq_restore),
		  __imm_addr(zero)
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

/*
 * All of it together. A lock is taken inside of saved IRQ flags, and both inside of a section:
 * the kfuncs that save the flags and enter a section are not for a program that holds a lock.
 * The pad goes the same way back. Behind the exit of the main program it unlocks with the helper,
 * restores the flags and leaves the section with the two kfuncs, then tells that the program was
 * cancelled.
 */
SEC("tc")
__description("cancel: bpf_spin_lock inside of saved IRQ flags inside of an RCU read section")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("exit")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -8")
__xlated("call kernel-function")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void spin_lock_in_irq_save_in_rcu_at_call(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"call %[bpf_rcu_read_lock];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
		"r1 = %[spin_a] ll;"
		"call %[bpf_spin_lock];"
		"call dives;"
		"r1 = %[spin_a] ll;"
		"call %[bpf_spin_unlock];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
		"call %[bpf_rcu_read_unlock];"
		asm_count(behind)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock),
		  __imm(bpf_local_irq_save),
		  __imm(bpf_local_irq_restore),
		  __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm_addr(spin_a),
		  __imm_addr(behind)
		: __clobber_all
	);
}

static __noinline int locks_and_dives(void)
{
	bpf_spin_lock(&spin_a);
	dives();
	bpf_spin_unlock(&spin_a);
	behind++;
	return 0;
}

/* The pad of the callee unlocks, and then the pad of the caller restores and leaves */
SEC("tc")
__description("cancel: bpf_spin_lock of a callee inside of IRQ flags and a section of its caller")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 4 padded 4 declined")
__stderr("ERROR: Program was cancelled")
int spin_lock_in_irq_save_in_rcu_two_frames(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	bpf_rcu_read_lock();
	bpf_local_irq_save(&flags);
	locks_and_dives();
	bpf_local_irq_restore(&flags);
	bpf_rcu_read_unlock();
	behind++;
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
