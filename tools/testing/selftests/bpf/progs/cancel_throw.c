// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * The frames of bpf_throw() leave through the pads that a cancellation takes, see cancel.c:
 * every frame releases what it holds, and the pad of the main prog calls the exception
 * callback with the cookie and returns what that returns, or returns the cookie when the prog
 * has no callback. So a prog may throw with locks, IRQ flags, sections, references and
 * iterators held, in the frame that throws and in the frames that wait in calls.
 *
 * The exception callback runs behind all pads, in the frame of the main prog: it sees what
 * they left. enter(), which every prog calls first, notes what the prog was entered in and
 * what it is about to take, and thrown() notes the same again. The runner in
 * prog_tests/cancel_throw.c wants the two to agree: interrupts are on again, the preempt count
 * and the RCU nesting are what they were, the locks are free and the references to the task
 * are as many as before. A prog without a callback is followed by look(), which notes for it.
 *
 * It takes the JIT of x86-64 or arm64, CAP_BPF and CAP_PERFMON, like every pad.
 */

#define TC_ACT_OK	0
#define TC_ACT_SHOT	2

/* What thrown() adds to the cookie: __retval() of the tests has the sum */
#define THROWN		100

extern void bpf_local_irq_save(unsigned long *) __weak __ksym;
extern void bpf_local_irq_restore(unsigned long *) __weak __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;
extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long dive;

/* The frames of a recursion that began, and how many times the code behind a throw ran */
unsigned long frames;
unsigned long behind;
/* How many times the exception callback ran, and the cookie that it got last */
unsigned long callbacks;
unsigned long cookie;

/* What a prog is in, as far as its pads have a say in it */
struct held_state {
	int preempt;	/* the preempt count */
	int rcu;	/* how deep the task is in RCU read sections, if the kernel counts that */
	int irq;	/* the bit of the IRQ flags that tells whether interrupts are on */
	int users;	/* the references to the task that runs the prog */
	int spin;	/* the word of spin_a: not 0 while it is locked */
	int res;	/* the same for res_a and res_b together */
};

/* When the prog was entered, and when the frames were gone */
struct held_state before, after;

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

/* A lock in a global variable is at an address that the verifier knows, and a pad loads it */
private(A) struct bpf_spin_lock spin_a;
private(B) struct bpf_res_spin_lock res_a;
private(C) struct bpf_res_spin_lock res_b;

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

/* The word of a lock. No load of a prog may read it, a helper reads whatever it is given. */
static __always_inline __u32 lock_word(void *lock)
{
	__u32 word = 0;

	bpf_probe_read_kernel(&word, sizeof(word), lock);
	return word;
}

static __always_inline void note(struct held_state *s)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_struct___rcu *rcu = (void *)task;
	unsigned long flags, saved = 0;

	/* x86 has need_resched in the top bit of the count */
	s->preempt = get_preempt_count() & 0x7fffffff;
	if (bpf_core_field_exists(rcu->rcu_read_lock_nesting))
		s->rcu = rcu->rcu_read_lock_nesting;
	/* the flags that a prog saved are not for it to read */
	bpf_local_irq_save(&flags);
	bpf_probe_read_kernel(&saved, sizeof(saved), &flags);
	bpf_local_irq_restore(&flags);
	s->irq = (saved >> IRQ_FLAG_BIT) & 1;
	s->users = task->rcu_users.refs.counter;
	s->spin = lock_word(&spin_a);
	s->res = lock_word(&res_a) | lock_word(&res_b);
}

/* Every prog calls it first. Returns 0 if the prog may go on: a lock that is held would hang it. */
static __noinline __used int enter(void)
{
	note(&before);
	return before.spin || before.res;
}

/*
 * The exception callback of the progs below. All frames but that of the main prog are gone,
 * and that one holds nothing any more.
 */
__noinline int thrown(u64 c)
{
	note(&after);
	callbacks++;
	cookie = c;
	return c + THROWN;
}

/* For the progs that have no callback: the runner runs it behind them */
SEC("tc")
int look(struct __sk_buff *ctx)
{
	note(&after);
	return TC_ACT_OK;
}

/*
 * The frame that throws holds the lock and the IRQ flags. bpf_throw() is no call that the
 * lock is in the way of: the insn goes to the pad, which keeps the cookie in a slot of the
 * frame while it unlocks and restores, and then calls the callback with it.
 */
SEC("tc")
__description("cancel throw: a spin lock and IRQ flags of the frame that throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(101) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("goto pc+")
__xlated("...")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r1")
__xlated("r1 = 0x")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -{{[0-9]+}}")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("call pc+")
__xlated("exit")
__exception_cb(thrown)
int irq_and_lock_in_main(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	bpf_local_irq_save(&flags);
	bpf_spin_lock(&spin_a);
	if (!zero)
		bpf_throw(1);
	behind++;
	bpf_spin_unlock(&spin_a);
	bpf_local_irq_restore(&flags);
	return TC_ACT_OK;
}

/* It throws under a lock that it took with IRQ flags of its own, and under what its caller holds */
static __noinline int throws_under_lock(u64 c)
{
	unsigned long flags;

	if (bpf_res_spin_lock_irqsave(&res_b, &flags))
		return 0;
	if (!zero)
		bpf_throw(c);
	behind++;
	bpf_res_spin_unlock_irqrestore(&res_b, &flags);
	return 0;
}

/*
 * Two frames hold: the pad of the callee leaves with the cookie in r0 and CANCEL_THROWN in
 * r2, and the pad of the call keeps the cookie over its releases. Only throws get to it, so
 * it does not look at r2. It unlocks and restores first, and leaves the sections last.
 */
SEC("tc")
__description("cancel throw: locks, IRQ flags and sections of two frames")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(102) __log_level(4)
__msg("cancel sites 2 padded 2 declined")
__xlated("cancel_goto pc+")
__xlated("...")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r0")
__xlated("r1 = 0x")
__xlated("call kernel-function")
__xlated("r1 = r10")
__xlated("r1 += -{{[0-9]+}}")
__xlated("call kernel-function")
__xlated("call kernel-function")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("call pc+")
__xlated("exit")
__xlated("...")
__xlated("w2 |= -2147483648")
__xlated("r0 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("cancel_exit")
__exception_cb(thrown)
int locks_in_two_frames(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	bpf_rcu_read_lock();
	bpf_preempt_disable();
	bpf_local_irq_save(&flags);
	if (bpf_res_spin_lock(&res_a))
		goto out;
	throws_under_lock(2);
	behind++;
	bpf_res_spin_unlock(&res_a);
out:
	bpf_local_irq_restore(&flags);
	bpf_preempt_enable();
	bpf_rcu_read_unlock();
	return TC_ACT_OK;
}

/*
 * The frame that throws holds a reference. Nothing behind bpf_throw() reads the handle, and
 * the pad does: bpf_throw() keeps the registers and the slots live that may have a handle.
 */
SEC("tc")
__description("cancel throw: a reference of the frame that throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(103) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__exception_cb(thrown)
int task_in_main(struct __sk_buff *ctx)
{
	struct task_struct *task;

	if (enter())
		return TC_ACT_OK;
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return TC_ACT_OK;
	if (!zero)
		bpf_throw(3);
	behind++;
	bpf_task_release(task);
	return TC_ACT_OK;
}

/*
 * The handle is in r0 alone when the prog throws, which no call keeps: the pad moves it to
 * r6 and releases from there. The cookie is in r1 at bpf_throw(), and in its slot first.
 */
SEC("tc")
__description("cancel throw: a reference in r0 at bpf_throw()")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(104) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r1")
__xlated("r6 = r0")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("call pc+")
__xlated("exit")
__exception_cb(thrown)
__naked void task_in_r0(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 == 0 goto 1f;"
		"r1 = 4;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire),
		  __imm(bpf_throw)
		: __clobber_all
	);
}

/*
 * An iterator and a reference of each round of its loop are held where the prog throws. The
 * pad destroys the iterator, which is a jump for a bpf_iter_num, in the pad as in the prog.
 */
SEC("tc")
__description("cancel throw: an iterator and a reference of the frame that throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(105) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r1")
__xlated("r1 = r10")
__xlated("r1 += -{{[0-9]+}}")
__xlated("goto pc+0")
__xlated("r1 = r{{[6-9]}}")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("call pc+")
__xlated("exit")
__exception_cb(thrown)
int iter_and_task_in_main(struct __sk_buff *ctx)
{
	struct task_struct *task;
	int i;

	if (enter())
		return TC_ACT_OK;
	bpf_for(i, 0, 8) {
		task = bpf_task_acquire(bpf_get_current_task_btf());
		if (!task)
			break;
		if (i == 3 && !zero)
			bpf_throw(5);
		bpf_task_release(task);
	}
	behind++;
	return TC_ACT_OK;
}

static __noinline int throws(u64 c)
{
	if (!zero)
		bpf_throw(c);
	behind++;
	return 0;
}

/* It holds a reference and is in an RCU read section while its callee throws */
static __noinline int holds_and_calls(u64 c)
{
	struct task_struct *task;

	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return 0;
	bpf_rcu_read_lock();
	throws(c);
	behind++;
	bpf_rcu_read_unlock();
	bpf_task_release(task);
	return 0;
}

/* Three frames, of which the two that wait in calls hold: a reference each, and more */
SEC("tc")
__description("cancel throw: references, IRQ flags and a section of the frames that wait in calls")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(106) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__exception_cb(thrown)
int holds_through_frames(struct __sk_buff *ctx)
{
	struct task_struct *task;
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return TC_ACT_OK;
	bpf_local_irq_save(&flags);
	holds_and_calls(6);
	behind++;
	bpf_local_irq_restore(&flags);
	bpf_task_release(task);
	return TC_ACT_OK;
}

/* A global function is verified on its own. Its callers go by the pads of their calls. */
__noinline int global_holds_and_calls(u64 c)
{
	return holds_and_calls(c);
}

SEC("tc")
__description("cancel throw: through a global function, with what its caller holds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(107) __log_level(4)
__exception_cb(thrown)
int holds_through_global(struct __sk_buff *ctx)
{
	struct task_struct *task;
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return TC_ACT_OK;
	bpf_local_irq_save(&flags);
	global_holds_and_calls(7);
	behind++;
	bpf_local_irq_restore(&flags);
	bpf_task_release(task);
	return TC_ACT_OK;
}

/* It calls itself until the stack has no room, see cancel.c */
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
		"exit;"
		:
		: __imm_addr(frames)
		: __clobber_all
	);
}

static __noinline int dives_or_throws(u64 c)
{
	if (dive)
		dives();
	else
		bpf_throw(c);
	behind++;
	return 0;
}

/*
 * A cancellation or a throw gets to the pad of the call, which the callee tells by
 * CANCEL_THROWN in r2. The pad releases, and keeps both r2 and the cookie over that: it
 * reports and returns the cancel value, or calls the callback.
 */
SEC("tc")
__description("cancel throw: a pad that a cancellation and a throw get to")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 5 padded 5 declined")
__xlated("cancel_goto pc+")
__xlated("...")
__xlated("*(u32 *)(r10 -{{[0-9]+}}) = r2")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r0")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r2 = *(u32 *)(r10 -{{[0-9]+}})")
__xlated("if w2 & 0x80000000 goto pc+3")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__xlated("r1 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("call pc+")
__xlated("exit")
__exception_cb(thrown)
int cancelled_or_thrown(struct __sk_buff *ctx)
{
	struct task_struct *task;

	if (enter())
		return TC_ACT_OK;
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return TC_ACT_OK;
	dives_or_throws(8);
	behind++;
	bpf_task_release(task);
	return TC_ACT_OK;
}

/* The frame between holds nothing: its pad passes on what its callee left in r0 and r2 */
static __noinline int passes_on(u64 c)
{
	dives_or_throws(c);
	behind++;
	return 0;
}

SEC("tc")
__description("cancel throw: a frame that holds nothing passes on a cancellation or a throw")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__xlated("cancel_goto pc+")
__xlated("...")
__xlated("w2 &= -2147483648")
__xlated("cancel_exit")
__exception_cb(thrown)
int passed_on(struct __sk_buff *ctx)
{
	struct task_struct *task;

	if (enter())
		return TC_ACT_OK;
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return TC_ACT_OK;
	passes_on(9);
	behind++;
	bpf_task_release(task);
	return TC_ACT_OK;
}

/* Without a callback the pad of the main prog returns the cookie itself */
SEC("tc")
__description("cancel throw: a prog without a callback returns the cookie")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(10) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("cancel_goto pc+")
__xlated("...")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r0")
__xlated("r1 = r10")
__xlated("r1 += -{{[0-9]+}}")
__xlated("call kernel-function")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("exit")
int no_callback(struct __sk_buff *ctx)
{
	struct task_struct *task;
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return TC_ACT_OK;
	bpf_local_irq_save(&flags);
	holds_and_calls(10);
	behind++;
	bpf_local_irq_restore(&flags);
	bpf_task_release(task);
	return TC_ACT_OK;
}

/*
 * The frame has lost the handle of its reference when it throws. A prog that returned there
 * would be rejected for the leak, and so is one that throws: no pad can release.
 */
SEC("tc")
__description("cancel throw: a reference whose handle is gone at bpf_throw() is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("no throw can leave the frame at this bpf_throw(): no register or stack slot that a pad can read has a reference of the frame as it was acquired")
__msg("(place)")
__naked void handle_gone(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 == 0 goto 1f;"
		"r0 = 0;"
		"r1 = 0;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire),
		  __imm(bpf_throw)
		: __clobber_all
	);
}

/*
 * bpf_throw() reads those of r0 and r6-r9 that may have a handle for the pad, and its cookie
 * in r1. It reads no other register: r2-r5 of a static subprog would count as its arguments
 * then. A handle that is there alone is in no place.
 */
SEC("tc")
__description("cancel throw: a reference whose handle is in r2 alone at bpf_throw() is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("no throw can leave the frame at this bpf_throw(): no register or stack slot that a pad can read has a reference of the frame as it was acquired")
__msg("(place)")
__naked void handle_in_r2(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 == 0 goto 1f;"
		"r2 = r0;"
		"r0 = 0;"
		"r1 = 0;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire),
		  __imm(bpf_throw)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long always_throws(void)
{
	asm volatile (
		"r1 = 0;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_throw)
		: __clobber_all
	);
}

/*
 * The callee never returns and nothing behind the call reads r6, so the register is dead at
 * the call: the states that get there are not told apart by it, and it is no place for the
 * pad of the call.
 */
SEC("tc")
__description("cancel throw: a reference that nothing reads behind a call that throws is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("no throw can leave the frame at this call: no register or stack slot that a pad can read has a reference of the frame as it was acquired")
__msg("(place)")
__naked void handle_dead_at_call(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
		"call always_throws;"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire)
		: __clobber_all
	);
}

/*
 * A prog without CAP_PERFMON has no pads, see cancel.c, and nothing else takes the frames of
 * bpf_throw() away where pads do.
 */
SEC("tc")
__description("cancel throw: bpf_throw() needs CAP_PERFMON")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
__failure_unpriv __caps_unpriv(CAP_BPF|CAP_NET_ADMIN)
__msg_unpriv("bpf_throw() needs CAP_PERFMON")
__naked void without_perfmon(void)
{
	asm volatile (
		"r1 = 0;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_throw)
		: __clobber_all
	);
}

char _license[] SEC("license") = "GPL";
