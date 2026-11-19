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
/* Which of two ways a prog takes. The runner takes both. */
unsigned long path;

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
	int res;	/* the same for res_a, res_b and the lock in res_locks together */
};

/* When the prog was entered, and when the frames were gone */
struct held_state before, after;

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

/* A lock in a global variable is at an address that the verifier knows, and a pad loads it */
private(A) struct bpf_spin_lock spin_a;
private(B) struct bpf_res_spin_lock res_a;
private(C) struct bpf_res_spin_lock res_b;

/* With two elements only a pointer to the element leads to its lock */
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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

/* r0 = the element of @map that the progs lock */
#define asm_lookup(map)				\
	"r1 = 1;"				\
	"*(u32 *)(r10 - 4) = r1;"		\
	"r2 = r10;"				\
	"r2 += -4;"				\
	"r1 = %[" #map "] ll;"			\
	"call %[bpf_map_lookup_elem];"

/* r0 = a reference to the task that runs the prog, NULL if there is none to have */
#define asm_acquire				\
	"call %[bpf_get_current_task_btf];"	\
	"r1 = r0;"				\
	"call %[bpf_task_acquire];"

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

/* The word of the lock in an element of res_locks */
static __always_inline __u32 elem_lock_word(int key)
{
	struct res_elem *elem = bpf_map_lookup_elem(&res_locks, &key);

	return elem ? lock_word(&elem->lock) : 0;
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
	s->res |= elem_lock_word(0) | elem_lock_word(1);
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

/*
 * The progs below throw where nothing behind bpf_throw() reads the handle, as behind a call
 * that a compiler knows not to return. bpf_throw() reads for the pads: the registers and the
 * stack slots that may have a handle, and no others, see "Handles" in liveness.c. Each prog has
 * its handle where another insn left it.
 */

/* The kfunc left it in r0, and a move in r6 */
SEC("tc")
__description("cancel throw: a reference in r6 that nothing reads behind bpf_throw()")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(111) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("call pc+")
__exception_cb(thrown)
__naked void handle_in_r6(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_acquire
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
		"r0 = 0;"
		"r1 = 11;"
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

/* A spill left it in a slot */
SEC("tc")
__description("cancel throw: a reference in a stack slot that nothing reads behind bpf_throw()")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(112) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void handle_in_slot(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_acquire
		"if r0 == 0 goto 1f;"
		"*(u64 *)(r10 - 8) = r0;"
		"r0 = 0;"
		"r1 = 12;"
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

/* A fill left it in r6, and a number took its place in the slot */
SEC("tc")
__description("cancel throw: a reference that was filled from the stack")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(126) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("exit")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r1")
__xlated("r1 = r6")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void handle_filled(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_acquire
		"if r0 == 0 goto 1f;"
		"*(u64 *)(r10 - 8) = r0;"
		"call %[bpf_get_prandom_u32];"
		"r6 = *(u64 *)(r10 - 8);"
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = 26;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire),
		  __imm(bpf_get_prandom_u32),
		  __imm(bpf_throw)
		: __clobber_all
	);
}

/* A store through a pointer to the stack left it in a slot, which the insn does not name */
SEC("tc")
__description("cancel throw: a reference that was spilled through a pointer to the stack")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(113) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void handle_through_pointer(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_acquire
		"if r0 == 0 goto 1f;"
		"r2 = r10;"
		"r2 += -16;"
		"*(u64 *)(r2 + 8) = r0;"
		"r0 = 0;"
		"r1 = 13;"
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

static __noinline __used struct task_struct *acquires(void)
{
	return bpf_task_acquire(bpf_get_current_task_btf());
}

/* A static subprog returned it */
SEC("tc")
__description("cancel throw: a reference that a subprog returned")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(114) __log_level(4)
__xlated("r1 = r6")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void handle_returned(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"call acquires;"
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
		"r0 = 0;"
		"r1 = 14;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_throw)
		: __clobber_all
	);
}

/* It gets a reference in r1 and the cookie in r2, and throws with the reference in r6 */
__naked __noinline __used
static unsigned long throws_with(void)
{
	asm volatile (
		"r6 = r1;"
		"r7 = r2;"
		"call %[bpf_get_prandom_u32];"
		"r1 = r7;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32),
		  __imm(bpf_throw)
		: __clobber_all
	);
}

/*
 * The caller gave it away in an argument, see bpf_cancel_ref_moves(): it is the callee's, in
 * a register that the callee moved its argument to.
 */
SEC("tc")
__description("cancel throw: a reference that the frame got in an argument")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(115) __log_level(4)
__xlated("r1 = r6")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void handle_given_to_callee(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_acquire
		"if r0 == 0 goto 1f;"
		"r1 = r0;"
		"r2 = 15;"
		"call throws_with;"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire)
		: __clobber_all
	);
}

#ifdef CAN_USE_CALLX
/* callx calls a subprog whose address is taken, and each of them gets what callx passes */
SEC("tc")
__description("cancel throw: a reference that the frame got in an argument of callx")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(127) __log_level(4)
__xlated("r1 = r6")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void handle_given_through_callx(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_acquire
		"if r0 == 0 goto 1f;"
		"r1 = r0;"
		"r2 = 27;"
		"r3 = %[throws_with] ll;"
		"callx r3;"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire),
		  __imm_addr(throws_with)
		: __clobber_all
	);
}
#endif

/* It stores a reference where r1 points, and returns whether it did */
__naked __noinline __used
static unsigned long acquires_into(void)
{
	asm volatile (
		"r6 = r1;"
		asm_acquire
		"if r0 == 0 goto 1f;"
		"*(u64 *)(r6 + 0) = r0;"
		"r0 = 1;"
	"1:"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire)
		: __clobber_all
	);
}

/* A callee stored it into a slot of the frame, through the pointer that it was given */
SEC("tc")
__description("cancel throw: a reference that a callee stored into the stack of the frame")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(116) __log_level(4)
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void handle_stored_by_callee(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"r1 = r10;"
		"r1 += -8;"
		"call acquires_into;"
		"if r0 == 0 goto 1f;"
		"r1 = 16;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_throw)
		: __clobber_all
	);
}

/* It reads the stack of its caller through r1 and throws the cookie in r2 */
__naked __noinline __used
static unsigned long reads_and_throws(void)
{
	asm volatile (
		"r3 = *(u64 *)(r1 + 0);"
		"r1 = r2;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_throw)
		: __clobber_all
	);
}

/*
 * The frame that waits in the call has it in a slot, and nothing reads the slot behind the
 * call, which does not return. The callee has a pointer to that stack, so its bpf_throw()
 * reads there too: the slot that may have a handle, fp-8.
 */
SEC("tc")
__description("cancel throw: a reference in a stack slot of the frame below")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(117) __log_level(4)
__msg("cancel sites 2 padded 2 declined")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void handle_in_slot_below(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_acquire
		"if r0 == 0 goto 1f;"
		"*(u64 *)(r10 - 8) = r0;"
		"r1 = 0;"
		"*(u64 *)(r10 - 16) = r1;"
		"r1 = r10;"
		"r1 += -16;"
		"r2 = 17;"
		"call reads_and_throws;"
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
 * A lock in one of two elements of a map: the pad unlocks through a pointer into the element.
 * The lookup left one in r0, and a move and an addition the pointer to the lock in r6.
 */
SEC("tc")
__description("cancel throw: a lock in a map value, a register points to the lock")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(118) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("exit")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r1")
__xlated("r1 = r6")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void lock_in_map_value(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_lookup(res_locks)
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
		"r6 += 8;"
		"r1 = r6;"
		"call %[bpf_res_spin_lock];"
		"if r0 != 0 goto 1f;"
		"r1 = 18;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm(bpf_res_spin_lock),
		  __imm(bpf_throw),
		  __imm_addr(res_locks)
		: __clobber_all
	);
}

/* The callback of bpf_for_each_map_elem(): it keeps the first value for its caller */
static __noinline __used int keeps_value(struct bpf_map *map, int *key, struct res_elem *val,
					  struct res_elem **out)
{
	*out = val;
	return 1;
}

/*
 * The helper passed the pointer to the element to its callback, which stored it into the
 * stack of the frame, through the pointer that the helper passed on. A fill and an addition
 * left the pointer to the lock in r6.
 */
SEC("tc")
__description("cancel throw: a lock in a map value that a callback stored the pointer to")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(128) __log_level(4)
__xlated("exit")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r1")
__xlated("r1 = r6")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void lock_pointer_from_callback(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = %[res_locks] ll;"
		"r2 = %[keeps_value] ll;"
		"r3 = r10;"
		"r3 += -8;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		"r6 = *(u64 *)(r10 - 8);"
		"if r6 == 0 goto 1f;"
		"r6 += 8;"
		"r1 = r6;"
		"call %[bpf_res_spin_lock];"
		"if r0 != 0 goto 1f;"
		"r1 = 28;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_for_each_map_elem),
		  __imm(bpf_res_spin_lock),
		  __imm(bpf_throw),
		  __imm_addr(res_locks),
		  __imm_addr(keeps_value)
		: __clobber_all
	);
}

/*
 * One of two locks in global variables, which the prog chose at run time: each visit of
 * bpf_throw() holds a lock at another address, and both have the pointer to it in r6, where
 * ld_imm64 left it. The pad unlocks through r6.
 */
SEC("tc")
__description("cancel throw: one of two locks in global variables, a register points to it")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(119) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r1 = r6")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void lock_chosen_at_run_time(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"r6 = %[res_a] ll;"
		"r1 = %[path] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 2f;"
		"r6 = %[res_b] ll;"
	"2:"
		"r1 = r6;"
		"call %[bpf_res_spin_lock];"
		"if r0 != 0 goto 1f;"
		"r1 = 19;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_res_spin_lock),
		  __imm(bpf_throw),
		  __imm_addr(res_a),
		  __imm_addr(res_b),
		  __imm_addr(path)
		: __clobber_all
	);
}

/*
 * The paths that meet in front of bpf_throw() have the handle in different slots, and a number
 * in the other one. Both slots may have a handle, so both are live there: the states stay
 * apart, and no pad is right for both. If the slots were dead the states would be one, with
 * its handle in a place that the other path has a number in.
 */
SEC("tc")
__description("cancel throw: a reference in one of two stack slots is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("no throw can leave the frame at this bpf_throw(): the frame holds a resource on some paths only, in more than one place")
__msg("(places)")
__naked void handle_in_one_of_two_slots(void)
{
	asm volatile (
		asm_acquire
		"if r0 == 0 goto 1f;"
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"*(u64 *)(r10 - 16) = r1;"
		"r1 = %[path] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 2f;"
		"*(u64 *)(r10 - 8) = r0;"
		"goto 3f;"
	"2:"
		"*(u64 *)(r10 - 16) = r0;"
	"3:"
		"r0 = 0;"
		"r1 = 20;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire),
		  __imm(bpf_throw),
		  __imm_addr(path)
		: __clobber_all
	);
}

/*
 * One path has a second copy of the handle in a slot and the other one in r6, and both have
 * one in r7. All three places are live at bpf_throw(), the states stay apart, and their visits
 * agree on r7, see cancel_agree_on_places().
 */
SEC("tc")
__description("cancel throw: a reference in a slot or in a register, and in one more on both paths")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(121) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r1 = r7")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void handle_in_slot_or_reg(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		asm_acquire
		"if r0 == 0 goto 1f;"
		"r7 = r0;"
		"r6 = 0;"
		"*(u64 *)(r10 - 8) = r6;"
		"r1 = %[path] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 2f;"
		"*(u64 *)(r10 - 8) = r0;"
		"goto 3f;"
	"2:"
		"r6 = r0;"
	"3:"
		"r0 = 0;"
		"r1 = 21;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire),
		  __imm(bpf_throw),
		  __imm_addr(path)
		: __clobber_all
	);
}

/*
 * One path holds a reference, in r6, and the other one has 0 there and holds nothing. The
 * frame has a drop flag for the reference, and the pad releases from r6 if the flag is set.
 */
SEC("tc")
__description("cancel throw: a reference that one path holds takes a drop flag")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(122) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r1 = *(u8 *)(r10 -{{[0-9]+}})")
__xlated("if r1 == 0x0 goto pc+")
__xlated("r1 = r6")
__xlated("call kernel-function")
__exception_cb(thrown)
__naked void held_on_one_path(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"r6 = 0;"
		"r1 = %[path] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 2f;"
		asm_acquire
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
	"2:"
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 3f;"
		"if r6 == 0 goto 1f;"
		"r1 = r6;"
		"call %[bpf_task_release];"
	"1:"
		"r0 = 0;"
		"exit;"
	"3:"
		"r1 = 22;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_acquire),
		  __imm(bpf_task_release),
		  __imm(bpf_throw),
		  __imm_addr(path),
		  __imm_addr(zero)
		: __clobber_all
	);
}

/* It throws in a round of its loop, with the iterator and a reference of the round */
static __noinline int loops_and_throws(u64 c)
{
	struct task_struct *task;
	int i;

	bpf_for(i, 0, 8) {
		task = bpf_task_acquire(bpf_get_current_task_btf());
		if (!task)
			break;
		if (i == 3 && !zero)
			bpf_throw(c);
		bpf_task_release(task);
	}
	behind++;
	return 0;
}

/*
 * The iterator is in the stack of the callee, whose pad destroys it. An iterator is found by
 * its address, in slots that are compared whether they are live or not: bpf_throw() reads
 * none of them for it.
 */
SEC("tc")
__description("cancel throw: an iterator and a reference of a callee, IRQ flags of its caller")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(123) __log_level(4)
__msg("cancel sites 2 padded 2 declined")
__exception_cb(thrown)
int iter_in_callee(struct __sk_buff *ctx)
{
	unsigned long flags;

	if (enter())
		return TC_ACT_OK;
	bpf_local_irq_save(&flags);
	loops_and_throws(23);
	behind++;
	bpf_local_irq_restore(&flags);
	return TC_ACT_OK;
}

/* A helper acquired it: a record of a ringbuf, which the pad discards */
SEC("tc")
__description("cancel throw: a ringbuf record in r6 that nothing reads behind bpf_throw()")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(124) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r1 = r6")
__xlated("r2 = 0")
__xlated("call unknown")
__exception_cb(thrown)
__naked void ringbuf_record_in_r6(void)
{
	asm volatile (
		"call enter;"
		"if r0 != 0 goto 1f;"
		"r1 = %[ringbuf] ll;"
		"r2 = 8;"
		"r3 = 0;"
		"call %[bpf_ringbuf_reserve];"
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
		"r0 = 0;"
		"r1 = 24;"
		"call %[bpf_throw];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_ringbuf_reserve),
		  __imm(bpf_throw),
		  __imm_addr(ringbuf)
		: __clobber_all
	);
}

/*
 * A helper made it of the reference: bpf_sk_fullsock() returns the socket that it was given,
 * with the id of its reference. It is the only handle that is left when the prog throws.
 */
SEC("tc")
__description("cancel throw: a socket that bpf_sk_fullsock() returned for a reference")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(0) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("exit")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r1")
__xlated("r1 = r6")
__xlated("call unknown")
__naked void socket_cast_in_r6(void)
{
	asm volatile (
		"r6 = r1;"
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"*(u64 *)(r10 - 16) = r1;"
		"r1 = r6;"
		"r2 = r10;"
		"r2 += -16;"
		"r3 = %[tuple_size];"
		"r4 = %[netns];"
		"r5 = 0;"
		"call %[bpf_sk_lookup_tcp];"
		"if r0 == 0 goto 1f;"
		"r7 = r0;"
		"r1 = r7;"
		"call %[bpf_sk_fullsock];"
		"if r0 == 0 goto 2f;"
		"r6 = r0;"
		"r7 = 0;"
		"r1 = 0;"
		"call %[bpf_throw];"
	"2:"
		"r1 = r7;"
		"call %[bpf_sk_release];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_sk_lookup_tcp),
		  __imm(bpf_sk_fullsock),
		  __imm(bpf_sk_release),
		  __imm(bpf_throw),
		  __imm_const(tuple_size, sizeof(((struct bpf_sock_tuple *)0)->ipv4)),
		  __imm_const(netns, BPF_F_CURRENT_NETNS)
		: __clobber_all
	);
}

char _license[] SEC("license") = "GPL";
