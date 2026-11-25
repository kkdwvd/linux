// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

/*
 * The verifier adds may_goto to a loop that it cannot count and a check of
 * the stack to a recursive subprog. What the program does when it is out of budget:
 * it unwinds, frame by frame, up to the main prog or an async callback, which end. No landing
 * pad that a caller has in the program is on that way: the kernel unwinds with kexit, and the
 * verifier adds kgoto after each call. What a frame holds takes a landing pad, which it emits.
 * If no landing pad will do the program is rejected.
 *
 * It takes unwinding, per-cpu insns and timed may_goto in JIT. Some of the progs never end
 * on their own.
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

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;
extern void bpf_local_irq_save(unsigned long *flags) __ksym;
extern void bpf_local_irq_restore(unsigned long *flags) __ksym;

struct bpf_res_spin_lock {
	__u32 val;
};

extern int bpf_res_spin_lock_irqsave(struct bpf_res_spin_lock *lock, unsigned long *flags) __ksym;
extern void bpf_res_spin_unlock_irqrestore(struct bpf_res_spin_lock *lock,
					   unsigned long *flags) __ksym;

struct task_struct {};
extern struct task_struct *bpf_task_from_pid(int pid) __ksym;
extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
struct cgroup {};
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;
extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;
extern int bpf_list_push_front_impl(struct bpf_list_head *head, struct bpf_list_node *node,
				    void *meta, __u64 off) __ksym;
extern struct bpf_list_node *bpf_list_pop_front(struct bpf_list_head *head) __ksym;
struct bpf_iter_task {
	__u64 opaque[3];
};

extern int bpf_iter_task_new(struct bpf_iter_task *it, struct task_struct *task,
			     unsigned int flags) __ksym;
extern void bpf_iter_task_destroy(struct bpf_iter_task *it) __ksym;
extern int bpf_dynptr_clone(const struct bpf_dynptr *ptr, struct bpf_dynptr *clone) __ksym;
struct file {};
extern struct file *bpf_get_task_exe_file(struct task_struct *task) __ksym;
extern void bpf_put_file(struct file *file) __ksym;
extern int bpf_dynptr_from_file(struct file *file, __u32 flags, struct bpf_dynptr *ptr) __ksym;
extern int bpf_dynptr_file_discard(struct bpf_dynptr *ptr) __ksym;
extern void bpf_throw(__u64 cookie) __ksym;

extern int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) __ksym;
extern int *bpf_iter_num_next(struct bpf_iter_num *it) __ksym;
extern void bpf_iter_num_destroy(struct bpf_iter_num *it) __ksym;

struct bpf_iter_kmem_cache {
	__u64 opaque[1];
};

struct kmem_cache {};
extern int bpf_iter_kmem_cache_new(struct bpf_iter_kmem_cache *it) __ksym;
extern struct kmem_cache *bpf_iter_kmem_cache_next(struct bpf_iter_kmem_cache *it) __ksym;
extern void bpf_iter_kmem_cache_destroy(struct bpf_iter_kmem_cache *it) __ksym;

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long one = 1;
unsigned long no_index = 4;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, long);
} empty SEC(".maps");

SEC("socket")
__description("budget: a loop in the main prog ends it")
__arch_x86_64
__arch_arm64
__success __retval(1)
__naked void loop_in_main(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: a loop in the main prog ends it, the last exit is dead code")
__arch_x86_64
__arch_arm64
__success __retval(1)
__naked void loop_in_main_dead_exit(void)
{
	asm volatile (
		"r6 = 0;"
		"if r6 != 0 goto 2f;"
		"r6 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
	"2:"
		"r0 = 2;"
		"exit;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

/* 0 is not what this prog may return */
SEC("cgroup/recvmsg4")
__description("budget: a loop in the main prog that can only return 1 ends it with 1")
__arch_x86_64
__arch_arm64
__success
__xlated("...")
__xlated("r0 = 1")
__xlated("exit")
__xlated("r0 = 1")
__xlated("exit")
__naked void loop_in_main_retval(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

/* 0 is BPF_OK: the packet would go on */
SEC("lwt_in")
__description("budget: a loop in the main prog of lwt ends it with BPF_DROP")
__arch_x86_64
__arch_arm64
__success __retval(2)
int loop_in_main_lwt(struct __sk_buff *skb)
{
	while (*(volatile unsigned long *)&one)
		;
	return 7;
}

/* The prog has no exit insn. Out of budget it is unwound all the same. */
SEC("tc")
__description("budget: a loop that is left only through bpf_throw()")
__arch_x86_64
__arch_arm64
__success __retval(2)
int loop_left_through_throw(struct __sk_buff *skb)
{
	for (;;)
		if (!*(volatile unsigned long *)&one)
			bpf_throw(3);
}

/* 0 lets the operation go on */
SEC("lsm/file_mprotect")
__description("budget: a loop in the main prog on an LSM hook ends it with -EPERM")
__arch_x86_64
__arch_arm64
__success
__xlated("...")
__xlated("r0 = -13")
__xlated("exit")
__xlated("r0 = -1")
__xlated("exit")
__naked void loop_in_main_lsm(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = -13;"
		"exit;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

/*
 * 0 tells user space that the prog did what it was run for: a loader that was stopped halfway
 * would report that all is loaded. BPF_PROG_TEST_RUN hands out -ECANCELED.
 */
SEC("syscall")
__description("budget: a loop in the main prog of a syscall prog ends it with -ECANCELED")
__arch_x86_64
__arch_arm64
__success __retval(-125)
__xlated("...")
__xlated("r0 = 7")
__xlated("exit")
__xlated("r0 = -125")
__xlated("exit")
__naked void loop_in_main_syscall(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 == 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

/*
 * rcu_read_lock(); do { p = lookup(); } while (!p); v = *p; rcu_read_unlock(); return v;
 * may_goto must not go where the loop goes when it's over: p may be NULL. It ends the prog, by way
 * of a landing pad that leaves the RCU section.
 */
SEC("socket")
__description("budget: an RCU section is held and the code behind the loop counts on its exit")
__arch_x86_64
__arch_arm64
__success __retval(0)
__xlated("...")
__xlated("r0 = r6")
__xlated("exit")
__xlated("call kernel-function")
__xlated("r0 = 0")
__xlated("exit")
__naked void exit_of_loop_checks_null_rcu(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"call %[bpf_rcu_read_lock];"
	"1:"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[empty] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 1b;"
		"r6 = *(u64 *)(r0 + 0);"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
		:
		: __imm_addr(empty),
		  __imm(bpf_map_lookup_elem),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

struct locked {
	struct bpf_spin_lock lock;
	long t[4];
};

struct locked locked_global SEC(".data.locked") __hidden;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct { struct bpf_res_spin_lock lock; long t[4]; });
} res_locked SEC(".maps");

/* r6 = a value of @map */
#define LOOKUP(map)					\
		"r1 = 0;"				\
		"*(u32 *)(r10 - 4) = r1;"		\
		"r2 = r10;"				\
		"r2 += -4;"				\
		"r1 = %[" #map "] ll;"			\
		"call %[bpf_map_lookup_elem];"		\
		"if r0 != 0 goto +1;"			\
		"exit;"					\
		"r6 = r0;"

/* may_goto must not go where the loop goes when it's over: i may be anything */
SEC("tc")
__description("budget: a spin lock is held and the code behind the loop counts on its exit")
__arch_x86_64
__arch_arm64
__success __retval(2)
__xlated("...")
__xlated("exit")
__xlated("r1 = 0x{{.*}}")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
int lock_in_global(void *ctx)
{
	unsigned long i;
	long v;

	bpf_spin_lock(&locked_global.lock);
	do {
		i = *(volatile unsigned long *)&no_index;
	} while (i > 3);
	v = locked_global.t[i];
	bpf_spin_unlock(&locked_global.lock);
	return v + 1;
}

#define SAVES_IRQ_FLAGS(name)				\
__naked __noinline __used				\
static unsigned long name(unsigned long *flags)		\
{							\
	asm volatile (					\
		"call %[bpf_local_irq_save];"		\
		"r0 = 0;"				\
		"exit;"					\
		:					\
		: __imm(bpf_local_irq_save)		\
	);						\
}

SAVES_IRQ_FLAGS(saves_first)
SAVES_IRQ_FLAGS(saves_second)

#define IRQ_FLAGS(off, func)				\
		"r1 = r10;"				\
		"r1 += " #off ";"			\
		"call " #func ";"

/* Irq flags are restored youngest first, and a landing pad has one order */
SEC("tc")
__description("budget: a loop holds irq flags which were saved in two orders")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the order of the releases differs")
__naked void loop_with_irq_flags_in_two_orders(void)
{
	asm volatile (
		"r7 = %[one] ll;"
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"if r6 == 0 goto 1f;"
	IRQ_FLAGS(-8, saves_first)
	IRQ_FLAGS(-16, saves_second)
		"goto 2f;"
	"1:"
	IRQ_FLAGS(-16, saves_second)
	IRQ_FLAGS(-8, saves_first)
	"2:"
		"r1 = *(u64 *)(r7 + 0);"
		"if r1 != 0 goto 2b;"
		"if r6 == 0 goto 3f;"
	IRQ_FLAGS(-16, %[bpf_local_irq_restore])
	IRQ_FLAGS(-8, %[bpf_local_irq_restore])
		"goto 4f;"
	"3:"
	IRQ_FLAGS(-8, %[bpf_local_irq_restore])
	IRQ_FLAGS(-16, %[bpf_local_irq_restore])
	"4:"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm_addr(zero),
		  __imm(bpf_local_irq_restore)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long spins(void)
{
	asm volatile (
		"r2 = %[one] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one)
	);
}

/* the same, for the tests that call it another way */
__naked __noinline __used
static unsigned long spins_caught(void)
{
	asm volatile (
		"r2 = %[one] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one)
	);
}

__naked __noinline __used
static unsigned long counts_to_ten(void)
{
	asm volatile (
		"r0 = 0;"
	"1:"
		"r0 += 1;"
		"if r0 < 10 goto 1b;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * The first pass takes the edge of may_goto in every loop: it knows the trip count when it ends.
 * A loop that has one gets no may_goto, so its function is not left there, and what a state
 * found on that way does not count: here, that the caller holds more than a landing pad
 * releases, 9 RCU sections.
 */
SEC("tc")
__description("budget: a counted loop in a subprog, no landing pad would do for the caller")
__arch_x86_64 __arch_arm64
__success __retval(10)
__log_level(2)
__not_msg("{{landing pad of|pass 1}}")
__xlated("8: call kernel-function")
__xlated("9: call pc+")
__xlated("10: r6 = r0")
__xlated("11: call kernel-function")
__naked void counted_loop_no_pad_will_do(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"call counts_to_ten;"
		"r6 = r0;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = r6;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

/* r0 = 0; do r0 += r1; while (r0 != r2); */
__naked __noinline __used
static unsigned long counts_by(void)
{
	asm volatile (
		"r0 = 0;"
	"1:"
		"r0 += r1;"
		"if r0 != r2 goto 1b;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * Each call alone has a trip count. The two calls joined have none: the step is 1 or -1 and the
 * end is one of two numbers, with nothing that says which goes with which. So the loop of the
 * joined calls gets may_goto, the function is left there, and its caller holds more than a landing
 * pad releases. The calls have to be kept apart for that: then no call is left at may_goto.
 */
SEC("tc")
__description("budget: two calls of a counted loop, only their join has no trip count")
__arch_x86_64 __arch_arm64
__success __retval(7)
__naked void later_counted_loop_no_pad_will_do(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r1 = 1;"
		"r2 = 1000000;"
		"call counts_by;"
		"r6 = r0;"
		"r1 = -1;"
		"r2 = -999993;"
		"call counts_by;"
		"r6 += r0;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = r6;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

/* It calls itself r1 times */
__naked __noinline __used
static unsigned long calls_itself(void)
{
	asm volatile (
		"if r1 == 0 goto 1f;"
		"r1 += -1;"
		"call calls_itself;"
	"1:	r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

/* Returns 5. If r1 * r1 is not r2 it calls a function that calls itself first. One exit. */
__naked __noinline __used
static unsigned long recurses_unless_square(void)
{
	asm volatile (
		"r3 = r1;"
		"r3 *= r1;"
		"if r3 == r2 goto 1f;"
		"r1 = 3;"
		"call calls_itself;"
	"1:	r0 = 5;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * No call gets to the function that calls itself: 2 * 2 is 4 and 3 * 3 is 9. The two calls joined
 * do, and that function is left where it checks its recursion, which is no insn of the program and
 * no loop: the call of it is where the frame above is left. The jump that skips that call is what
 * has to be kept apart.
 */
SEC("tc")
__description("budget: two calls that skip a recursion, only their join gets to it")
__arch_x86_64 __arch_arm64
__success __retval(10)
__naked void recursion_only_in_join(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r1 = 2;"
		"r2 = 4;"
		"call recurses_unless_square;"
		"r6 = r0;"
		"r1 = 3;"
		"r2 = 9;"
		"call recurses_unless_square;"
		"r6 += r0;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = r6;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

/* r0 = 0; for (;;) for (r4 = 0; r4 < 2; r4++) { r0 += r1; if (r0 == r2) return r0; } */
__naked __noinline __used
static unsigned long counts_by_in_pairs(void)
{
	asm volatile (
		"r0 = 0;"
	"1:	r4 = 0;"
	"2:	r0 += r1;"
		"if r0 == r2 goto 3f;"
		"r4 += 1;"
		"if r4 < 2 goto 2b;"
		"goto 1b;"
	"3:	exit;"
		::: __clobber_all
	);
}

/*
 * The same where the loop that gets may_goto has no jump of its own that leaves it: its way out is
 * in the loop inside it, which has a trip count whatever the arguments are.
 */
SEC("tc")
__description("budget: two calls of a counted loop that is left from a loop inside it")
__arch_x86_64 __arch_arm64
__success __retval(2)
__naked void later_nested_counted_loop_no_pad_will_do(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r1 = 1;"
		"r2 = 5;"
		"call counts_by_in_pairs;"
		"r6 = r0;"
		"r1 = -1;"
		"r2 = -3;"
		"call counts_by_in_pairs;"
		"r6 += r0;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = r6;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long unwinds_at_once(void)
{
	asm volatile (
		"r0 = 0;"
		unwind_exit
		:
		: __imm_unwind_exit
		: __clobber_all
	);
}

/*
 * The subprog has unwind_exit of its own. That is no site which a state would have noted when the
 * conflict of its call is an error of the pass: the log names it all the same.
 */
SEC("tc")
__description("budget: no landing pad would do for the call of a subprog that has unwind_exit")
__arch_x86_64 __arch_arm64
__failure
__msg("what the call at {{[0-9]+}} calls is left at: unwind_exit")
__msg("landing pad of call at {{[0-9]+}} for unwind_exit: conflict: too much is held")
__naked void unwind_exit_no_pad_will_do(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"call unwinds_at_once;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: a loop in a subprog unwinds, the verifier adds kgoto")
__arch_x86_64
__arch_arm64
__success __retval(0)
__xlated("...")
__xlated("call pc+4")
__xlated("kgoto pc+1")
__xlated("exit")
__xlated("r0 = 0")
__xlated("exit")
__xlated("...")
__xlated("r0 = 7")
__xlated("exit")
__xlated("r0 = 0")
__xlated("r2 = 0")
__xlated("kexit")
__naked void loop_in_subprog(void)
{
	asm volatile (
		"call spins;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * 16 bits don't get may_goto and kgoto to the landing pad that they share. gotol does it for
 * may_goto. kgoto has 32 bits: nothing is added to the way from the call to the next insn.
 */
SEC("socket")
__description("budget: a loop and a call that are far from their landing pad")
__arch_x86_64
__arch_arm64
__success __retval(0)
__xlated("...")
__xlated("goto pc+1")
__xlated("gotol pc+33006")
__xlated("if r1 != 0x0 goto pc-")
__xlated("call pc+")
__xlated("kgoto pc+33003")
__xlated("call kernel-function")
__naked void far_from_the_pad(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"r2 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"call spins;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		".rept 33000;"
		"r0 += 1;"
		".endr;"
		"exit;"
		:
		: __imm_addr(zero),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

/* @reg = a task, which has to be released */
#define ACQUIRE_TASK(reg)				\
		"r1 = 1;"				\
		"call %[bpf_task_from_pid];"		\
		"if r0 != 0 goto +1;"			\
		"exit;"					\
		#reg " = r0;"

#define SPIN						\
		"r2 = %[one] ll;"			\
	"1:"						\
		"r1 = *(u64 *)(r2 + 0);"		\
		"if r1 != 0 goto 1b;"

/*
 * r1: a lock. r9 and r6, which is dead at the jump, point 8 bytes behind it. r2: where its irq flags
 * go, in the stack of the caller. A stack slot points into the record.
 */
__naked __noinline __used
static unsigned long spins_with_resources(void)
{
	asm volatile (
		"r6 = r1;"
		"r7 = r2;"
		"r9 = r1;"
		"r9 += 8;"
		"r1 = %[ringbuf] ll;"
		"r2 = 16;"
		"r3 = 0;"
		"call %[bpf_ringbuf_reserve];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r0 += 8;"
		"*(u64 *)(r10 - 8) = r0;"
		"call %[bpf_rcu_read_lock];"
	IRQ_FLAGS(-16, %[bpf_local_irq_save])
		"r1 = r6;"
		"r2 = r7;"
		"call %[bpf_res_spin_lock_irqsave];"
		"if r0 != 0 goto 2f;"
		"r2 = %[one] ll;"
	"1:"
		"r6 = r9;"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r1 = r9;"
		"r1 += -8;"
		"r2 = r7;"
		"call %[bpf_res_spin_unlock_irqrestore];"
	"2:"
	IRQ_FLAGS(-16, %[bpf_local_irq_restore])
		"call %[bpf_rcu_read_unlock];"
		"r1 = *(u64 *)(r10 - 8);"
		"r1 += -8;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(ringbuf), __imm_addr(one),
		  __imm(bpf_ringbuf_reserve), __imm(bpf_ringbuf_discard),
		  __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock),
		  __imm(bpf_local_irq_save), __imm(bpf_local_irq_restore),
		  __imm(bpf_res_spin_lock_irqsave), __imm(bpf_res_spin_unlock_irqrestore)
		: __clobber_all
	);
}

/* Each frame releases its own: locks and irq flags, youngest first, sections, pointers if not NULL */
SEC("tc")
__description("budget: the subprog with the loop and its caller hold resources")
__arch_x86_64
__arch_arm64
__success __retval(2)
__xlated("...")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r0 = 7")
__xlated("exit")
__xlated("call kernel-function")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__xlated("...")
__xlated("r0 = 7")
__xlated("exit")
__xlated("r1 = r9")
__xlated("r1 += -8")
__xlated("r2 = r7")
__xlated("call kernel-function")
__xlated("r1 = r10")
__xlated("r1 += -16")
__xlated("call kernel-function")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("r1 += -8")
__xlated("r2 = 0")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__naked void resources_in_two_frames(void)
{
	asm volatile (
	LOOKUP(res_locked)
		"r7 = r6;"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"r6 = r0;"
		"call %[bpf_preempt_disable];"
		"r1 = r7;"
		"r2 = r10;"
		"r2 += -16;"
		"call spins_with_resources;"
		"call %[bpf_preempt_enable];"
		"if r6 == 0 goto +2;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(res_locked), __imm(bpf_map_lookup_elem),
		  __imm(bpf_task_from_pid), __imm(bpf_task_release),
		  __imm(bpf_preempt_disable), __imm(bpf_preempt_enable)
		: __clobber_all
	);
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct { struct task_struct __kptr *task; });
} tasks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct { struct cgroup __kptr *cgrp; });
} cgroups SEC(".maps");

/* One insn takes a task or a cgroup out of a map. A landing pad has one call for what it finds. */
SEC("tc")
__description("budget: a task or a cgroup from one insn in the same register")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: a resource is held on some paths only")
int two_releases_for_one_place(void *ctx)
{
	unsigned long is_task = zero;
	int key = 0;
	void *p;

	p = bpf_map_lookup_elem(is_task ? (void *)&tasks : (void *)&cgroups, &key);
	if (!p)
		return 0;
	p = bpf_kptr_xchg(p, NULL);
	if (!p)
		return 0;
	while (*(volatile unsigned long *)&one)
		;
	if (is_task)
		bpf_task_release(p);
	else
		bpf_cgroup_release(p);
	return 7;
}

/*
 * The caller has the irq flags of the lock. The only pointer to them is in r1, where the lock has
 * to go. The frame has irq flags of its own too.
 */
__naked __noinline __used
static unsigned long locks_and_spins_with_flags_in_r1(void)
{
	asm volatile (
		"r6 = r1;"
		"r7 = r2;"
	IRQ_FLAGS(-8, %[bpf_local_irq_save])
		"r1 = r6;"
		"r2 = r7;"
		"call %[bpf_res_spin_lock_irqsave];"
		"if r0 != 0 goto 2f;"
		"r1 = r7;"
		"r2 = %[one] ll;"
	"1:"
		"r3 = *(u64 *)(r2 + 0);"
		"if r3 != 0 goto 1b;"
		"r2 = r1;"
		"r1 = r6;"
		"call %[bpf_res_spin_unlock_irqrestore];"
	"2:"
	IRQ_FLAGS(-8, %[bpf_local_irq_restore])
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm(bpf_local_irq_save),
		  __imm(bpf_local_irq_restore),
		  __imm(bpf_res_spin_lock_irqsave),
		  __imm(bpf_res_spin_unlock_irqrestore)
		: __clobber_all
	);
}

SEC("tc")
__description("budget: the second argument of a release is in r1 only")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: a handle is in R0-R5 only")
__naked void second_argument_in_r1(void)
{
	asm volatile (
	LOOKUP(res_locked)
		"r1 = r6;"
		"r2 = r10;"
		"r2 += -16;"
		"call locks_and_spins_with_flags_in_r1;"
		"exit;"
		:
		: __imm_addr(res_locked),
		  __imm(bpf_map_lookup_elem)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: a task is held, the type of the prog has no bpf_task_release()")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the program can call nothing that releases a resource")
int task_without_release(void *ctx)
{
	unsigned long x = bpf_get_prandom_u32() & 1;
	int key = 0;
	void *p;

	p = bpf_map_lookup_elem(&tasks, &key);
	if (!p)
		return 0;
	p = bpf_kptr_xchg(p, NULL);
	if (!p)
		return 0;
	while (x < 2)
		asm volatile ("" : "+r"(x));
	return (long)p;
}

struct with_lock_and_more {
	struct bpf_spin_lock lock;
	long a, b;
};

struct with_lock {
	struct bpf_spin_lock lock;
	long a;
};

#define SPIN_WITH_OBJECT(type) ({					\
	type *o = bpf_obj_new_impl(bpf_core_type_id_local(type), NULL);	\
	if (!o)								\
		return 1;						\
	while (*(volatile unsigned long *)&one)				\
		bpf_get_prandom_u32();					\
	bpf_obj_drop_impl(o, NULL);					\
})

/* Two pads. They differ in the type only, which the verifier adds as the second argument. */
SEC("tc")
__description("budget: objects of two types in the same register")
__arch_x86_64
__arch_arm64
__success __retval(2)
__xlated("...")
__xlated("r0 = 2{{$}}")
__xlated("exit")
__xlated("r1 = r{{[6-9]}}")
__xlated("r2 = 0x{{[0-9a-f]*[1-9a-f][0-9a-f]*}}")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
int objects_of_two_types(void *ctx)
{
	if (*(volatile unsigned long *)&zero)
		SPIN_WITH_OBJECT(struct with_lock_and_more);
	else
		SPIN_WITH_OBJECT(struct with_lock);
	return 7;
}

struct with_task {
	struct task_struct __kptr *task;
};

/*
 * The call that releases a socket follows from the helper that looked it up, as long as what is in
 * the register is a socket. That is what tells a state from another one: the insn is not compared.
 */
SEC("tc")
__description("budget: a socket is held, the landing pad calls bpf_sk_release()")
__arch_x86_64
__arch_arm64
__success __retval(1)
__log_level(2)
__msg("landing pad of may_goto at {{[0-9]+}}: ref@{{[0-9]+}}({{[^)]+}}) rcu=0 preempt=0")
__xlated("...")
__xlated("exit")
__xlated("r1 = r{{[0-9]}}")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
int socket_held(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return 1;
	while (*(volatile unsigned long *)&one)
		;
	bpf_sk_release(sk);
	return 0;
}

/* What a helper has cast the socket to is a place of the same reference, and of another type */
SEC("tc")
__description("budget: a socket and its cast are held, the landing pad calls bpf_sk_release()")
__arch_x86_64
__arch_arm64
__success __retval(1)
__log_level(2)
__msg("landing pad of may_goto at {{[0-9]+}}: ref@{{[0-9]+}}({{[^)]+}}) rcu=0 preempt=0")
__xlated("...")
__xlated("exit")
__xlated("r1 = r{{[0-9]}}")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
int cast_socket_held(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct tcp_sock *tp;
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return 1;
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		bpf_sk_release(sk);
		return 3;
	}
	while (*(volatile unsigned long *)&one)
		;
	barrier_var(tp);
	bpf_sk_release(sk);
	return 0;
}

/* bpf_obj_drop() of this type is refused to a tracing prog, so no landing pad calls it */
SEC("raw_tp")
__description("budget: a tracing prog holds an object with a field that is not NMI safe")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the program can call nothing that releases a resource")
int object_of_tracing_prog(void *ctx)
{
	struct with_task *o = bpf_obj_new_impl(bpf_core_type_id_local(struct with_task), NULL);
	unsigned long x = bpf_get_prandom_u32() & 1;

	if (!o)
		return 0;
	while (x < 2)
		asm volatile ("" : "+r"(x));
	return (long)o;
}

/*
 * The type of a pointer behind __percpu_kptr can have a field that the kernel looks after, here a
 * reference count. No object of that type exists: bpf_percpu_obj_new() makes none. And
 * bpf_percpu_obj_drop() frees without a description of the fields, so no landing pad calls it for
 * such a type.
 */
struct counted {
	struct bpf_refcount ref;
	long x;
};

struct has_counted {
	struct counted __percpu_kptr *counted;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct has_counted);
} has_counted SEC(".maps");

SEC("tc")
__description("budget: a per-cpu pointer to a type that has a reference count is held")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the program can call nothing that releases a resource")
int percpu_pointer_with_field(void *ctx)
{
	struct has_counted *v;
	struct counted *p;
	unsigned long x;
	int key = 0;

	v = bpf_map_lookup_elem(&has_counted, &key);
	if (!v)
		return 0;
	p = bpf_kptr_xchg(&v->counted, NULL);
	if (!p)
		return 0;
	/* the pointer is in a register that a call keeps */
	x = bpf_get_prandom_u32() & 1;
	while (x < 2)
		asm volatile ("" : "+r"(x));
	return (long)p;
}

struct in_list {
	struct bpf_list_node node;
	long a;
} *in_list __hidden; /* brings the type to BTF */

struct bpf_spin_lock list_lock SEC(".data.list") __hidden;
struct bpf_list_head list_head SEC(".data.list") __hidden
	__attribute__((btf_decl_tag("contains:in_list:node")));

struct list_in_list {
	struct bpf_list_node node;
	struct bpf_spin_lock lock;
	struct bpf_list_head head __attribute__((btf_decl_tag("contains:in_list:node")));
};

struct bpf_spin_lock outer_lock SEC(".data.outer") __hidden;
struct bpf_list_head outer_head SEC(".data.outer") __hidden
	__attribute__((btf_decl_tag("contains:list_in_list:node")));

static __noinline int pops_a_list_and_spins(void)
{
	struct bpf_list_node *n = bpf_list_pop_front(&outer_head);

	if (!n)
		return 1;
	while (*(volatile unsigned long *)&one)
		asm volatile ("" ::: "r0", "r1", "r2", "r3", "r4", "r5");
	bpf_list_push_front_impl(&outer_head, n, NULL, 0);
	return 7;
}

/*
 * To free this object takes the lock in it, and all bpf_spin_locks of a cpu keep the irq flags in
 * one word: no landing pad does that under the lock of the caller.
 */
SEC("tc")
__description("budget: an object with a list is held under the lock of the caller")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the program can call nothing that releases a resource")
int list_under_lock_of_caller(void *ctx)
{
	struct list_in_list *o;
	int ret;

	o = bpf_obj_new_impl(bpf_core_type_id_local(struct list_in_list), NULL);
	if (!o)
		return 1;
	bpf_spin_lock(&outer_lock);
	bpf_list_push_front_impl(&outer_head, &o->node, NULL, 0);
	ret = pops_a_list_and_spins();
	bpf_spin_unlock(&outer_lock);
	return ret;
}

/* Under the lock of its caller: the prog can call nothing there that releases the task */
static __noinline struct task_struct *takes_a_task_and_spins(void *v)
{
	struct task_struct *task = bpf_kptr_xchg(v, NULL);

	if (!task)
		return NULL;
	while (*(volatile unsigned long *)&one)
		asm volatile ("" ::: "r0", "r1", "r2", "r3", "r4", "r5");
	return task;
}

/* So no landing pad releases it there either: the caller does, behind its unlock */
SEC("tc")
__description("budget: a task is held under the lock of the caller")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the program can call nothing that releases a resource")
int task_under_lock_of_caller(void *ctx)
{
	struct task_struct *task;
	int key = 0;
	void *v;

	v = bpf_map_lookup_elem(&tasks, &key);
	if (!v)
		return 1;
	bpf_spin_lock(&outer_lock);
	task = takes_a_task_and_spins(v);
	bpf_spin_unlock(&outer_lock);
	if (task)
		bpf_task_release(task);
	return 7;
}

/* Under a resilient lock a prog can call as little */
SEC("tc")
__description("budget: a task is held under the resilient lock of the caller")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the program can call nothing that releases a resource")
int task_under_res_lock_of_caller(void *ctx)
{
	struct task_struct *task;
	unsigned long flags;
	int key = 0;
	void *v, *l;

	v = bpf_map_lookup_elem(&tasks, &key);
	l = bpf_map_lookup_elem(&res_locked, &key);
	if (!v || !l)
		return 1;
	if (bpf_res_spin_lock_irqsave(l, &flags))
		return 1;
	task = takes_a_task_and_spins(v);
	bpf_res_spin_unlock_irqrestore(l, &flags);
	if (task)
		bpf_task_release(task);
	return 7;
}

struct task_in_list {
	struct bpf_list_node node;
	struct task_struct __kptr *task;
} *task_in_list __hidden; /* brings the type to BTF */

struct bpf_spin_lock task_list_lock SEC(".data.task_list") __hidden;
struct bpf_list_head task_list_head SEC(".data.task_list") __hidden
	__attribute__((btf_decl_tag("contains:task_in_list:node")));

static __noinline int pops_a_task_and_spins(void)
{
	struct bpf_list_node *n = bpf_list_pop_front(&task_list_head);

	if (!n)
		return 1;
	while (*(volatile unsigned long *)&one)
		asm volatile ("" ::: "r0", "r1", "r2", "r3", "r4", "r5");
	bpf_list_push_front_impl(&task_list_head, n, NULL, 0);
	return 7;
}

/* To free this object releases its task, which is the same call under the lock of the caller */
SEC("tc")
__description("budget: an object with a task is held under the lock of the caller")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the program can call nothing that releases a resource")
int obj_with_task_under_lock_of_caller(void *ctx)
{
	int ret;

	bpf_spin_lock(&task_list_lock);
	ret = pops_a_task_and_spins();
	bpf_spin_unlock(&task_list_lock);
	return ret;
}

/*
 * An iterator that RCU protects is destroyed ahead of the locks of the frame, while its section is
 * not left yet: under the lock that the frame took itself, where the prog cannot make that call.
 */
SEC("tc")
__description("budget: an iterator that RCU protects is held under the lock of the frame itself")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the program can call nothing that releases a resource")
int rcu_iterator_under_own_lock(void *ctx)
{
	struct bpf_iter_task it;

	bpf_rcu_read_lock();
	bpf_iter_task_new(&it, NULL, 0);
	bpf_spin_lock(&outer_lock);
	while (*(volatile unsigned long *)&one)
		asm volatile ("" ::: "r0", "r1", "r2", "r3", "r4", "r5");
	bpf_spin_unlock(&outer_lock);
	bpf_iter_task_destroy(&it);
	bpf_rcu_read_unlock();
	return 0;
}

/*
 * It owns the node that the caller points to, and what it calls leaves with unwind_exit: the
 * verifier emits its landing pad, which goes on to the one of the prog.
 */
static __noinline __used int pops_and_unwinds(void)
{
	struct bpf_list_node *n = bpf_list_pop_front(&list_head);

	if (!n)
		return 1;
	if (*(volatile unsigned long *)&one)
		unwinds_at_once();
	bpf_list_push_front_impl(&list_head, n, NULL, 0);
	return 7;
}

/* The landing pad of the prog runs after that of the subprog, which frees the node */
SEC("tc")
__description("budget: the landing pad frees a node under the lock of the caller, who points to it")
__arch_x86_64
__arch_arm64
__failure __msg("R6 invalid mem access 'scalar'")
__naked void node_of_caller_under_lock(void)
{
	asm volatile (
		"r1 = %[list_lock] ll;"
		"call %[bpf_spin_lock];"
		"r1 = %[list_head] ll;"
		"call %[bpf_list_pop_front];"
		"r6 = r0;"
		"if r6 == 0 goto 1f;"
		"r1 = %[list_head] ll;"
		"r2 = r6;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_list_push_front_impl];"
		"call pops_and_unwinds;"
		unwind_goto(5)
	"1:"
		"r1 = %[list_lock] ll;"
		"call %[bpf_spin_unlock];"
		"r0 = 0;"
		"exit;"
		"r7 = *(u64 *)(r6 + 24);"
		"goto 1b;"
		:
		: __imm_addr(list_lock), __imm_addr(list_head),
		  __imm(bpf_spin_lock), __imm(bpf_spin_unlock),
		  __imm(bpf_list_pop_front), __imm(bpf_list_push_front_impl),
		  __imm_unwind_goto(5)
		: __clobber_all
	);
}

/*
 * In its RCU section it gives a task out of the map to the caller. What it calls there leaves with
 * unwind_exit.
 */
static __noinline __used int enters_section_and_unwinds(struct task_struct * volatile *p)
{
	struct with_task *v;
	int key = 0;

	v = bpf_map_lookup_elem(&tasks, &key);
	if (!v)
		return 0;
	bpf_rcu_read_lock();
	*p = v->task;
	if (*(volatile unsigned long *)&one)
		unwinds_at_once();
	*p = NULL;
	bpf_rcu_read_unlock();
	return 7;
}

/* The landing pad of the prog runs after that of the subprog, which leaves the section */
SEC("syscall")
__description("budget: the landing pad leaves the section, the caller has an RCU pointer")
__arch_x86_64
__arch_arm64
__failure __msg("R1 must be a rcu pointer")
__naked void pointer_of_caller_under_rcu(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = r10;"
		"r1 += -8;"
		"call enters_section_and_unwinds;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		"r1 = *(u64 *)(r10 - 8);"
		"if r1 == 0 goto +1;"
		"call %[bpf_task_acquire];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_task_acquire),
		  __imm_unwind_goto(2)
		: __clobber_all
	);
}

/*
 * The iterator is destroyed first: the irq flags, which are younger, would do to protect it. The
 * record is discarded after the RCU section.
 */
SEC("tc")
__description("budget: an iterator in an RCU section, irq flags and a dynptr are held")
__arch_x86_64
__arch_arm64
__success __retval(2)
__xlated("...")
__xlated("r0 = 7")
__xlated("exit")
__xlated("r1 = r10")
__xlated("r1 += -56")
__xlated("call kernel-function")
__xlated("r1 = r10")
__xlated("r1 += -64")
__xlated("call kernel-function")
__xlated("call kernel-function")
__xlated("r1 = r10")
__xlated("r1 += -16")
__xlated("r2 = 0")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void objects_in_the_stack(void)
{
	asm volatile (
		"r1 = %[ringbuf] ll;"
		"r2 = 8;"
		"r3 = 0;"
		"r4 = r10;"
		"r4 += -16;"
		"call %[bpf_ringbuf_reserve_dynptr];"
		"call %[bpf_rcu_read_lock];"
		"r1 = r10;"
		"r1 += -56;"
		"r2 = 0;"
		"r3 = 0;"
		"call %[bpf_iter_task_new];"
	IRQ_FLAGS(-64, %[bpf_local_irq_save])
	SPIN
	IRQ_FLAGS(-64, %[bpf_local_irq_restore])
		"r1 = r10;"
		"r1 += -56;"
		"call %[bpf_iter_task_destroy];"
		"call %[bpf_rcu_read_unlock];"
		"r1 = r10;"
		"r1 += -16;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard_dynptr];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(ringbuf), __imm_addr(one),
		  __imm(bpf_ringbuf_reserve_dynptr), __imm(bpf_ringbuf_discard_dynptr),
		  __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock),
		  __imm(bpf_local_irq_save), __imm(bpf_local_irq_restore),
		  __imm(bpf_iter_task_new), __imm(bpf_iter_task_destroy)
		: __clobber_all
	);
}

/* fp-8: Option<T>, not r8: its upper half is dead. r7: the test comes first. r6: not tested yet. */
SEC("tc")
__description("budget: references are held on some paths or may be NULL")
__arch_x86_64
__arch_arm64
__success __retval(2)
__xlated("...")
__xlated("r0 = 7")
__xlated("exit")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = r7")
__xlated("if r1 == 0x0 goto pc+3")
__xlated("r1 += -8")
__xlated("r2 = 0")
__xlated("call unknown")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void references_or_null(void)
{
	asm volatile (
		"r7 = 0;"
		"w8 = 0;"
		"*(u64 *)(r10 - 8) = r7;"
		"call %[bpf_get_prandom_u32];"
		"if r0 == 0 goto 2f;"
	ACQUIRE_TASK(r6)
		"r8 = r6;"
		"*(u64 *)(r10 - 8) = r6;"
		"r1 = %[ringbuf] ll;"
		"r2 = 16;"
		"r3 = 0;"
		"call %[bpf_ringbuf_reserve];"
		"if r0 == 0 goto 2f;"
		"r7 = r0;"
		"r7 += 8;"
	"2:"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"r6 = r0;"
	SPIN
		"if r6 == 0 goto +2;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"if r7 == 0 goto +4;"
		"r1 = r7;"
		"r1 += -8;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard];"
		"r1 = *(u64 *)(r10 - 8);"
		"if r1 == 0 goto +1;"
		"call %[bpf_task_release];"
		"w0 = w8;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(ringbuf), __imm_addr(one), __imm(bpf_get_prandom_u32),
		  __imm(bpf_ringbuf_reserve), __imm(bpf_ringbuf_discard),
		  __imm(bpf_task_from_pid), __imm(bpf_task_release)
		: __clobber_all
	);
}

/* Nothing can destroy it any more, no landing pad either. The main pass finds no other way out. */
SEC("syscall")
__description("budget: an iterator is held, its RCU section is over")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: no place has the handle on all paths")
int iterator_out_of_rcu_section(void *ctx)
{
	unsigned long x = bpf_get_prandom_u32() & 1;
	struct bpf_iter_task it;

	bpf_rcu_read_lock();
	bpf_iter_task_new(&it, NULL, 0);
	bpf_rcu_read_unlock();
	while (x < 2)
		asm volatile ("" : "+r"(x));
	return 0;
}

/*
 * The dynptr is made from the file that is held and has to be discarded first, or it is older than
 * that file and made from another one: then nothing says which of the two goes first. The landing
 * pad has one order, the one of the path that has one, whichever path gets to the loop first.
 */
SEC("lsm.s/file_open")
__description("budget: a dynptr is made from the file that is held on some paths")
__arch_x86_64
__arch_arm64
__success
__log_level(2)
__msg("landing pad of may_goto at {{[0-9]+}}: dynptr@{{[0-9]+}}(fp-16) ref@{{[0-9]+}}(r6) rcu=0 preempt=0")
int dynptr_and_file_in_two_orders(__u64 *ctx)
{
	struct file *f, *opened = (struct file *)ctx[0];
	struct bpf_dynptr d;

	if (*(volatile unsigned long *)&zero) {
		f = bpf_get_task_exe_file(bpf_get_current_task_btf());
		if (!f)
			return 0;
		bpf_dynptr_from_file(f, 0, &d);
	} else {
		bpf_dynptr_from_file(opened, 0, &d);
		f = bpf_get_task_exe_file(bpf_get_current_task_btf());
		if (!f)
			goto out;
	}
	while (*(volatile unsigned long *)&one)
		;
	bpf_dynptr_file_discard(&d);
	bpf_put_file(f);
	return 0;
out:
	bpf_dynptr_file_discard(&d);
	return 0;
}

/*
 * The main pass does not get to the fill after the loop, so nothing but a landing pad would read
 * fp-8 of the longer pattern, and its store would go. fp-8 is no place: a hidden slot has the task.
 */
SEC("syscall")
__description("budget: a reference is in the slot of a bpf_fastcall spill only")
__arch_x86_64
/* -ECANCELED */
__success __retval(-125)
__xlated("...")
__xlated("r1 = *(u64 *)(r10 -24)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = -125")
__xlated("exit")
__naked void reference_in_fastcall_spill(void)
{
	asm volatile (
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"if r0 == 0 goto 2f;"
		"r1 = r0;"
		"r2 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"*(u64 *)(r10 - 16) = r2;"
		"call %[bpf_get_smp_processor_id];"
		"r2 = *(u64 *)(r10 - 16);"
		"r1 = *(u64 *)(r10 - 8);"
		"*(u64 *)(r10 - 16) = r2;"
		"call %[bpf_get_smp_processor_id];"
		"r2 = *(u64 *)(r10 - 16);"
		"r2 = %[one] ll;"
	"1:"
		"r3 = *(u64 *)(r2 + 0);"
		"r3 |= 1;"
		"if r3 != 0 goto 1b;"
		"r1 = *(u64 *)(r10 - 8);"
		"call %[bpf_task_release];"
	"2:"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one), __imm(bpf_task_from_pid), __imm(bpf_task_release),
		  __imm(bpf_get_smp_processor_id)
		: __clobber_all
	);
}

/* @reg = a task to release if @own is 1, else current: neither the pc nor a NULL test tells */
#define TASK_OR_CURRENT(reg, own)			\
		"r1 = 1;"				\
		"call %[bpf_task_from_pid];"		\
		#own " = 1;"				\
		"if r0 != 0 goto +2;"			\
		#own " = 0;"				\
		"call %[bpf_get_current_task_btf];"	\
		#reg " = r0;"

#define RELEASE_IF_OWN(reg, own)			\
		"if " #own " == 0 goto +2;"		\
		"r1 = " #reg ";"			\
		"call %[bpf_task_release];"

#define __imm_task_or_current				\
		__imm(bpf_task_from_pid), __imm(bpf_get_current_task_btf), __imm(bpf_task_release)

struct in_list_at_8 {
	long a;
	struct bpf_list_node node;
} *in_list_at_8 __hidden; /* brings the type to BTF */

struct bpf_spin_lock list_lock_8 SEC(".data.list_8") __hidden;
struct bpf_list_head list_head_8 SEC(".data.list_8") __hidden
	__attribute__((btf_decl_tag("contains:in_list_at_8:node")));

/* The slot has what bpf_list_pop_front() returned, the node. bpf_obj_drop() takes the object. */
SEC("tc")
__description("budget: a node of a list is held on some paths, the object is what is dropped")
__arch_x86_64
__arch_arm64
__success __retval(2)
__xlated("...")
__xlated("r0 = *(u64 *)(r10 -8)")
__xlated("r0 += -8")
__xlated("if r0 != r1 goto pc+1")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("...")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("if r1 == 0x0 goto pc+4")
__xlated("r1 += -8")
__naked void node_on_some_paths(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		"r7 = 0;"
		"r1 = %[list_lock_8] ll;"
		"call %[bpf_spin_lock];"
		"r1 = %[list_head_8] ll;"
		"call %[bpf_list_pop_front];"
		"r8 = r0;"
		"r1 = %[list_lock_8] ll;"
		"call %[bpf_spin_unlock];"
		"if r8 == 0 goto 2f;"
		"r6 = r8;"
		"r7 = 1;"
	"2:"
	SPIN
		"if r7 == 0 goto +4;"
		"r1 = r6;"
		"r1 += -8;"
		"r2 = 0;"
		"call %[bpf_obj_drop_impl];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one), __imm_addr(list_lock_8), __imm_addr(list_head_8),
		  __imm(bpf_spin_lock), __imm(bpf_spin_unlock), __imm(bpf_list_pop_front),
		  __imm(bpf_obj_drop_impl)
		: __clobber_all
	);
}

/* It may unwind, so its call gets unwind_goto */
__naked __noinline __used
static unsigned long waits_and_gets_task(void)
{
	asm volatile (
		"r2 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"exit;"
		:
		: __imm_addr(zero), __imm(bpf_task_from_pid)
		: __clobber_all
	);
}

/*
 * The back edge goes past the stores at the entry, the jump past those after its call: r0 is no
 * task there. A call in a loop has one slot more than the frame holds. r8 goes by its slot too.
 */
SEC("tc")
__description("budget: calls in a loop that starts at the first insn acquire, a jump goes past one")
__arch_x86_64
__arch_arm64
__success __retval(2)
__log_level(2)
__msg("may_goto at 15: ref@10(*fp-24) if not 0 ref@10(*fp-16) if not 0 ref@0(*fp-8) if not 0 rcu=0 preempt=0")
__xlated("...")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("*(u64 *)(r10 -16) = 0")
__xlated("*(u64 *)(r10 -24) = 0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("*(u64 *)(r10 -8) = r0")
__xlated("...")
__xlated("if r7 != 0x0 goto pc+9")
__xlated("r1 = 1")
__xlated("call kernel-function")
__xlated("r13 = *(u64 *)(r10 -16)")
__xlated("if r13 != 0x0 goto pc+2")
__xlated("*(u64 *)(r10 -16) = r0")
__xlated("goto pc+3")
__xlated("r13 = *(u64 *)(r10 -24)")
__xlated("if r13 != 0x0 goto pc+1")
__xlated("*(u64 *)(r10 -24) = r0")
__xlated("r6 = r0")
__xlated("...")
__xlated("if r0 != 0x0 goto pc-75")
__naked void calls_in_a_loop_acquire(void)
{
	asm volatile (
	"3:"
		"call waits_and_gets_task;"
		"if r0 != 0 goto +1;"
		"exit;"
		"r8 = r0;"
		"r7 = %[one] ll;"
		"r7 = *(u64 *)(r7 + 0);"
		"r0 = r7;"
		"if r7 != 0 goto +2;"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"r6 = r0;"
	SPIN
		"if r7 != 0 goto +3;"
		"if r6 == 0 goto +2;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r1 = r8;"
		"call %[bpf_task_release];"
		"call %[bpf_get_prandom_u32];"
		"if r0 != 0 goto 3b;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one), __imm(bpf_task_from_pid), __imm(bpf_task_release),
		  __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

/* The second word has the address of the flags, the pad reads it only if the first one is not 0 */
SEC("tc")
__description("budget: a lock with irq flags that may fail is held on some paths")
__arch_x86_64
__arch_arm64
__success __retval(2)
__xlated("...")
__xlated("r2 += -16")
__xlated("*(u64 *)(r10 -24) = r1")
__xlated("*(u64 *)(r10 -32) = r2")
__xlated("call kernel-function")
__xlated("if w0 == 0x0 goto pc+1")
__xlated("*(u64 *)(r10 -24) = 0")
__xlated("if r0 != 0x0 goto pc+1")
__xlated("...")
__xlated("r0 = 7")
__xlated("exit")
__xlated("r1 = *(u64 *)(r10 -24)")
__xlated("if r1 == 0x0 goto pc+2")
__xlated("r2 = *(u64 *)(r10 -32)")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void res_lock_irq_flags_on_some_paths(void)
{
	asm volatile (
	LOOKUP(res_locked)
		"r7 = 0;"
		"r1 = r6;"
		"r2 = r10;"
		"r2 += -16;"
		"call %[bpf_res_spin_lock_irqsave];"
		"if r0 != 0 goto +1;"
		"r7 = 1;"
	SPIN
		"if r7 == 0 goto +4;"
		"r1 = r6;"
		"r2 = r10;"
		"r2 += -16;"
		"call %[bpf_res_spin_unlock_irqrestore];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(res_locked), __imm_addr(one), __imm(bpf_map_lookup_elem),
		  __imm(bpf_res_spin_lock_irqsave), __imm(bpf_res_spin_unlock_irqrestore)
		: __clobber_all
	);
}

/* A section has no handle: its slot has 1, and leaving one clears the first slot that is not 0 */
SEC("tc")
__description("budget: the prog is in one RCU section or in two")
__arch_x86_64
__arch_arm64
__success __retval(2)
__log_level(2)
__msg("may_goto at 9: rcu@5(*fp-16) if not 0 rcu@0(*fp-8) if not 0 rcu=0 preempt=0")
__xlated("...")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("*(u64 *)(r10 -16) = 0")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("call kernel-function")
__xlated("...")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+2")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("goto pc+3")
__naked void one_section_or_two(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"r9 = %[zero] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"if r9 == 0 goto +1;"
		"call %[bpf_rcu_read_lock];"
	SPIN
		"call %[bpf_rcu_read_unlock];"
		"if r9 == 0 goto +1;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(zero), __imm_addr(one), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

/*
 * The counted loop is in one section or in two. The first pass leaves the prog there too, and a pad
 * there would take hidden slots. The loop gets no may_goto: the prog has no slot and no store, and
 * the pad of the loop that it does have leaves the one section that all states are in.
 */
SEC("tc")
__description("budget: no hidden slots for a counted loop that is in one RCU section or in two")
__arch_x86_64
__arch_arm64
__success __retval(2)
__log_level(2)
__not_msg("if not 0")
__msg("landing pad of may_goto at {{[0-9]+}}: rcu=1 preempt=0")
__not_msg("if not 0")
__xlated("...")
__xlated("if r9 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r6 = 0")
__xlated("r6 += 1")
__xlated("if r6 < 0xa goto pc-2")
__xlated("call kernel-function")
__xlated("if r9 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 7")
__xlated("exit")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void counted_loop_one_section_or_two(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
	SPIN
		"r9 = %[zero] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"if r9 == 0 goto +1;"
		"call %[bpf_rcu_read_lock];"
		"r6 = 0;"
	"1:"
		"r6 += 1;"
		"if r6 < 10 goto 1b;"
		"call %[bpf_rcu_read_unlock];"
		"if r9 == 0 goto +1;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(zero), __imm_addr(one), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long releases_task(void)
{
	asm volatile (
		"call %[bpf_task_release];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_task_release)
		: __clobber_all
	);
}

/* The release is in another function, which cannot clear the slot */
SEC("tc")
__description("budget: a subprog releases what its caller holds on some paths")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of {{may_goto|call}} at {{[0-9]+}}: conflict: a resource is held on some paths only")
__naked void subprog_releases_reference_of_caller(void)
{
	asm volatile (
	TASK_OR_CURRENT(r6, r7)
	SPIN
		"if r7 == 0 goto +2;"
		"r1 = r6;"
		"call releases_task;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one), __imm(bpf_task_from_pid), __imm(bpf_get_current_task_btf)
		: __clobber_all
	);
}

/* A slot would have the address of the first dynptr. With a clone the prog may write there. */
SEC("tc")
__description("budget: a dynptr that is held on some paths is cloned")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of {{may_goto|call}} at {{[0-9]+}}: conflict: a resource is held on some paths only")
__naked void dynptr_on_some_paths_is_cloned(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"if r6 == 0 goto 2f;"
		"r1 = %[ringbuf] ll;"
		"r2 = 8;"
		"r3 = 0;"
		"r4 = r10;"
		"r4 += -16;"
		"call %[bpf_ringbuf_reserve_dynptr];"
	"2:"
	SPIN
		"if r6 == 0 goto 3f;"
		"r1 = r10;"
		"r1 += -16;"
		"r2 = r10;"
		"r2 += -32;"
		"call %[bpf_dynptr_clone];"
		"r1 = r10;"
		"r1 += -32;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard_dynptr];"
	"3:"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one), __imm_addr(ringbuf), __imm(bpf_ringbuf_reserve_dynptr),
		  __imm(bpf_dynptr_clone), __imm(bpf_ringbuf_discard_dynptr)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long unwinds_with_task(void)
{
	asm volatile (
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"if r0 != 0 goto +1;"
		"exit;"
		unwind_exit
		:
		: __imm_unwind_exit, __imm(bpf_task_from_pid)
		: __clobber_all
	);
}

/* unwind_exit of the prog goes to unwind_goto, past a store behind it */
SEC("tc")
__description("budget: a subprog unwinds with a reference")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of {{may_goto|call}} at {{[0-9]+}}: conflict: a resource is held on some paths only")
__naked void subprog_unwinds_with_reference(void)
{
	asm volatile (
		"call unwinds_with_task;"
		unwind_goto(4)
		"call %[bpf_get_current_task_btf];"
		"r6 = r0;"
		"r7 = 0;"
		"goto +2;"
		"r6 = r0;"
		"r7 = 1;"
	SPIN
	RELEASE_IF_OWN(r6, r7)
		"r0 = 7;"
		"exit;"
		:
		: __imm_unwind_goto(4), __imm_addr(one), __imm(bpf_get_current_task_btf),
		  __imm(bpf_task_release)
		: __clobber_all
	);
}

static __noinline struct bpf_list_node *pops_a_list(void)
{
	return bpf_list_pop_front(&outer_head);
}

/*
 * A subprog returns an object to a function that holds a lock of its own, and no register keeps it:
 * the hidden slot of the call has it. To free the object takes the lock in it. The landing pad
 * unlocks first, so the lock of the function is no reason to refuse the slot, as the lock of a
 * caller is.
 */
SEC("tc")
__description("budget: a subprog returns an object with a list under the lock of the function itself")
__arch_x86_64
__arch_arm64
__success
__log_level(2)
__msg("landing pad of bpf_throw at {{[0-9]+}}: spin_lock@{{[0-9]+}}({{[^)]+}}) ref@{{[0-9]+}}(*fp-8) if not 0 rcu=0 preempt=0")
__xlated("...")
__xlated("exit")
__xlated("*(u64 *)(r10 -16) = r1")
__xlated("r1 = 0x{{.*}}")
__xlated("call unknown")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("if r1 == 0x0 goto pc+3")
__xlated("r2 = 0x{{.*}}")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -16)")
__xlated("exit")
int list_from_subprog_under_own_lock(void *ctx)
{
	struct bpf_list_node *n;

	bpf_spin_lock(&outer_lock);
	n = pops_a_list();
	if (n) {
		asm volatile ("r6 = 0; r7 = 0; r8 = 0; r9 = 0;" ::: "r6", "r7", "r8", "r9");
		bpf_throw(0);
	}
	bpf_spin_unlock(&outer_lock);
	return 0;
}

SEC("tc")
__description("budget: no room in the stack for a slot")
__arch_x86_64
__arch_arm64
__failure __msg("landing pad of {{may_goto|call}} at {{[0-9]+}}: conflict: a resource is held on some paths only")
__naked void no_room_for_slot(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u64 *)(r10 - 2048) = r1;"
	TASK_OR_CURRENT(r6, r7)
	SPIN
	RELEASE_IF_OWN(r6, r7)
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one), __imm_task_or_current
		: __clobber_all
	);
}

__noinline int global_spins(void)
{
	while (*(volatile unsigned long *)&one)
		;
	return 7;
}

/* A global subprog is verified after its callers. They find out late that it unwinds. */
SEC("socket")
__description("budget: a loop in a global subprog, the caller is in an RCU section")
__arch_x86_64
__arch_arm64
__success __retval(0)
__xlated("...")
__xlated("call pc+")
__xlated("kgoto pc+4")
__xlated("...")
__xlated("exit")
__xlated("call kernel-function")
__xlated("r0 = 0")
__xlated("exit")
__naked void loop_in_global(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call global_spins;"
		"r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

/*
 * unwind_goto of the prog is for unwind_exit, which the prog has. The kernel unwinds with kexit:
 * the landing pad of the prog is not entered, and the prog returns what the kernel says, not 42.
 * Nothing gets to that unwind_goto: it is dead code, and so is the pad.
 */
SEC("socket")
__description("budget: a loop in a subprog unwinds past unwind_goto of the prog")
__arch_x86_64
__arch_arm64
__success __retval(0)
__xlated("...")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r0 = 0")
__xlated("exit")
__naked void loop_in_subprog_caught(void)
{
	asm volatile (
		"call spins_caught;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long spins_caught3(void)
{
	asm volatile (
		"r2 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(zero)
	);
}

/*
 * Nothing in the subprog leaves with unwind_exit, and may_goto that is added does not lead to the
 * pad of the prog, which would forget the section: the pad of the verifier leaves it. The loop
 * ends at once here.
 */
SEC("socket")
__description("budget: the pad of the prog forgets what the caller holds, it is not entered")
__arch_x86_64
__arch_arm64
__success __retval(7)
__naked void pad_forgets(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call spins_caught3;"
		unwind_goto(4)
		"r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(4),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

/* The verifier emits the pad for what the subprog took itself. It goes on to the pad of the caller. */
__naked __noinline __used
static unsigned long spins_locked(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"r2 = %[one] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
	);
}

SEC("socket")
__description("budget: a loop in a subprog leaves the section and unwinds past the pad of the prog")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void loop_in_subprog_locked(void)
{
	asm volatile (
		"call spins_locked;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

/* r1: how deep to go. Returns the sum of 1 .. r1 */
__naked __noinline __used
static unsigned long sum_to(void)
{
	asm volatile (
		"if r1 != 0 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:"
		"r6 = r1;"
		"r1 += -1;"
		"call sum_to;"
		"r0 += r6;"
		"exit;"
		::: __clobber_all
	);
}

SEC("socket")
__description("budget: recursion")
__arch_x86_64
__arch_arm64
__success __retval(55)
__naked void recursion(void)
{
	asm volatile (
		"r1 = 10;"
		"call sum_to;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * A recursion is refused in a tracing prog, when the pass is over and the call graph is checked. The
 * landing pad of this prog keeps the cookie of bpf_throw() over the release of the task, in a hidden
 * word of the frame. Whether the stack has room for it is asked ahead of time, by the same check:
 * its error about the recursion is no lack of room.
 */
SEC("fentry/bpf_fentry_test1")
__description("budget: an error of the call graph is not taken for a stack without room")
__arch_x86_64
__arch_arm64
__failure
__not_msg("no room in the stack")
__msg("recursive sum_to() in a tracing program")
__naked void call_graph_error_not_no_room(void)
{
	asm volatile (
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"if r0 != 0 goto +2;"
		"r0 = 0;"
		"exit;"
		"r6 = r0;"
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto +2;"
		"r1 = 0;"
		"call %[bpf_throw];"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r1 = 3;"
		"call sum_to;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(zero), __imm(bpf_task_from_pid), __imm(bpf_task_release),
		  __imm(bpf_throw)
		: __clobber_all
	);
}

/* The one that is called too deep unwinds them all */
SEC("socket")
__description("budget: recursion that is too deep unwinds, the verifier adds kgoto")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void recursion_too_deep(void)
{
	asm volatile (
		"r1 = 1000;"
		"call sum_to;"
		"r0 = 1;"
		"exit;"
		::: __clobber_all
	);
}

/* Another start, and the frames in between pass nothing else on: a syscall prog returns -ECANCELED */
SEC("syscall")
__description("budget: recursion that is too deep ends a syscall prog with -ECANCELED")
__arch_x86_64
__arch_arm64
__success __retval(-125)
__naked void recursion_too_deep_syscall(void)
{
	asm volatile (
		"r1 = 1000;"
		"call sum_to;"
		"r0 = 1;"
		"exit;"
		::: __clobber_all
	);
}

/* The exception callback gets the same value for its cookie */
__noinline int negates(__u64 cookie)
{
	return -cookie;
}

SEC("syscall")
__description("budget: the exception callback of a syscall prog gets -ECANCELED when the kernel unwinds")
__arch_x86_64
__arch_arm64
__success __retval(125)
__exception_cb(negates)
__naked void recursion_too_deep_syscall_exception_cb(void)
{
	asm volatile (
		"r1 = 1000;"
		"call sum_to;"
		"r0 = 1;"
		"exit;"
		::: __clobber_all
	);
}

unsigned long lowest_r10;

__naked __noinline __used
static unsigned long goes_down(void)
{
	asm volatile (
		"r2 = %[lowest_r10] ll;"
		"*(u64 *)(r2 + 0) = r10;"
		"call goes_down;"
		"exit;"
		:
		: __imm_addr(lowest_r10)
		: __clobber_all
	);
}

/* What the prog returns is up to the exception callback, which runs when the frames are gone */
__noinline int lowest_is_in_the_middle(__u64 cookie)
{
	return ((lowest_r10 + 64) & 8191) < 256;
}

/*
 * The stack of a task is aligned to its size, 16K at least. r10 of the last frame whose body
 * runs is right above the middle. No code of the prog runs behind the call once the kernel
 * unwinds.
 */
SEC("socket")
__description("budget: recursion ends in the middle of the kernel stack")
__arch_x86_64
__arch_arm64
__success __retval(1)
__exception_cb(lowest_is_in_the_middle)
__naked void recursion_ends_in_the_middle(void)
{
	asm volatile (
		"call goes_down;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

__naked __noinline __used
static unsigned long has_large_frame(void)
{
	asm volatile (
		"*(u64 *)(r10 - 1024) = r1;"
		"call has_large_frame;"
		"exit;"
		::: __clobber_all
	);
}

/* The limit on the stack of a chain of calls has the frame of a recursive subprog in it */
SEC("socket")
__description("budget: one frame of a recursive subprog counts in the depth of the stack")
__arch_x86_64
__arch_arm64
__failure __msg("combined stack size of 2 calls is 2560. Too large")
__naked void recursion_with_large_frames(void)
{
	asm volatile (
		"*(u64 *)(r10 - 1536) = r1;"
		"call has_large_frame;"
		"exit;"
		::: __clobber_all
	);
}

__naked __noinline __used
static unsigned long sum_to_caught(void)
{
	asm volatile (
		"if r1 != 0 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:"
		"r6 = r1;"
		"r1 += -1;"
		"call sum_to_caught;"
		unwind_goto(2)
		"r0 += r6;"
		"exit;"
		"r0 = 0;"
		unwind_exit
		:
		: __imm_unwind_goto(2),
		  __imm_unwind_exit
		: __clobber_all
	);
}

SEC("socket")
__description("budget: recursion with unwind_goto")
__arch_x86_64
__arch_arm64
__success __retval(55)
__naked void recursion_caught(void)
{
	asm volatile (
		"r1 = 10;"
		"call sum_to_caught;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

/* Each frame has a landing pad of the prog, and so has the prog. The kernel unwinds past them. */
SEC("socket")
__description("budget: recursion that is too deep unwinds past the pads of the prog")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void recursion_too_deep_caught(void)
{
	asm volatile (
		"r1 = 1000;"
		"call sum_to_caught;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

/* r1: how deep to go. It calls itself twice: 2^r1 calls */
__naked __noinline __used
static unsigned long calls_itself_twice(void)
{
	asm volatile (
		"if r1 != 0 goto 1f;"
		"r0 = 1;"
		"exit;"
	"1:"
		"r6 = r1;"
		"r1 += -1;"
		"call calls_itself_twice;"
		"r7 = r0;"
		"r1 = r6;"
		"r1 += -1;"
		"call calls_itself_twice;"
		"r0 += r7;"
		"exit;"
		::: __clobber_all
	);
}

SEC("socket")
__description("budget: recursion that is not deep, 2^10 calls")
__arch_x86_64
__arch_arm64
__success __retval(1024)
__naked void recursion_tree(void)
{
	asm volatile (
		"r1 = 10;"
		"call calls_itself_twice;"
		"exit;"
		::: __clobber_all
	);
}

/* 61 frames fit in the stack. The check begins with may_goto: the time is limited too. */
SEC("socket")
__description("budget: recursion that is not deep, 2^60 calls")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void recursion_tree_forever(void)
{
	asm volatile (
		"r1 = 60;"
		"call calls_itself_twice;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

/* The time slice is for an invocation of the prog, not for the call that starts a recursion */
SEC("socket")
__description("budget: a loop that calls a subprog that calls itself 2^60 times")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void loop_calls_recursion_tree(void)
{
	asm volatile (
		"r8 = %[one] ll;"
	"1:"
		"r1 = 60;"
		"call calls_itself_twice;"
		"r1 = *(u64 *)(r8 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

/*
 * Every frame loops forever and calls itself in every trip. The call that finds no room in the
 * stack unwinds them all.
 */
__naked __noinline __used
static unsigned long calls_itself_in_a_loop(void)
{
	asm volatile (
		"r6 = %[one] ll;"
	"1:"
		"call calls_itself_in_a_loop;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(one)
	);
}

SEC("socket")
__description("budget: a subprog that calls itself in a loop that never ends")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void recursion_in_a_loop(void)
{
	asm volatile (
		"call calls_itself_in_a_loop;"
		"r0 = 1;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * calls_loop() -> bpf_loop() -> loop_cb() -> calls_loop(): the frames of the helper are on
 * the stack too
 */
static int loop_cb(__u32 i, void *ctx);

static __noinline int calls_loop(int x)
{
	bpf_loop(1, loop_cb, NULL, zero);
	return 0;
}

static __noinline int loop_cb(__u32 i, void *ctx)
{
	return calls_loop(i);
}

SEC("socket")
__description("budget: recursion through a helper that calls a callback")
__arch_x86_64
__arch_arm64
__success __retval(0)
int recursion_through_callback(void *ctx)
{
	return calls_loop(0);
}

struct timer {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct timer);
} timers SEC(".maps");

__naked __noinline __used
static int arms_itself(void)
{
	asm volatile (
		"r1 = r3;"
		"r2 = %[arms_itself] ll;"
		"call %[bpf_timer_set_callback];"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(arms_itself), __imm(bpf_timer_set_callback)
		: __clobber_all
	);
}

/* The helper keeps the callback for later. There is nothing to count, on any architecture. */
SEC("socket")
__description("budget: a callback that arms itself again is not a recursion")
__success
__xlated("...")
__xlated("exit")
__xlated("r1 = r3")
__naked void callback_arms_itself(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[timers] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 1f;"
		"r1 = r0;"
		"r2 = %[arms_itself] ll;"
		"call %[bpf_timer_set_callback];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(timers), __imm_addr(arms_itself), __imm(bpf_map_lookup_elem),
		  __imm(bpf_timer_set_callback)
		: __clobber_all
	);
}

static __used int spins_in_rcu(void *map, int *key, void *value)
{
	bpf_rcu_read_lock();
	while (*(volatile unsigned long *)&one)
		;
	bpf_rcu_read_unlock();
	return 0;
}

/* The kernel calls the callback: there is nothing to unwind to */
SEC("socket")
__description("budget: the landing pad of a callback that only the kernel calls ends in exit")
__arch_x86_64
__arch_arm64
__success
__xlated("...")
__xlated("= r13")
__xlated("...")
__xlated("call kernel-function")
__xlated("{{[rw]}}0 = 0")
__xlated("exit")
__xlated("call kernel-function")
__xlated("r0 = 0")
__xlated("{{[0-9]+}}: exit")
__naked void loop_in_timer_callback(void)
{
	asm volatile (
	LOOKUP(timers)
		"r1 = r6;"
		"r2 = %[spins_in_rcu] ll;"
		"call %[bpf_timer_set_callback];"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(timers), __imm_addr(spins_in_rcu), __imm(bpf_map_lookup_elem),
		  __imm(bpf_timer_set_callback)
		: __clobber_all
	);
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, long);
} hash SEC(".maps");

static __noinline int sleeps_at_the_bottom(int n, void *user_ptr)
{
	char buf[8];

	if (n)
		return sleeps_at_the_bottom(n - 1, user_ptr) + 1;
	return bpf_copy_from_user(buf, sizeof(buf), user_ptr);
}

static int calls_what_sleeps(void *map, void *key, void *value, void *ctx)
{
	return sleeps_at_the_bottom(1, (void *)zero) & 1;
}

SEC("syscall")
__description("budget: recursion in a sleepable prog can sleep")
__arch_x86_64
__arch_arm64
__success
int recursion_sleeps(void *ctx)
{
	return sleeps_at_the_bottom(1, (void *)zero) & 1;
}

/* The frames of the callers are not there when a recursive subprog is verified */
SEC("syscall")
__description("budget: recursion in a callback that runs under rcu_read_lock() cannot sleep")
__arch_x86_64
__arch_arm64
__failure __msg("sleepable helper bpf_copy_from_user#148 in callback running under rcu_read_lock")
int recursion_sleeps_in_rcu_callback(void *ctx)
{
	bpf_for_each_map_elem(&hash, calls_what_sleeps, NULL, 0);
	return 0;
}

/*
 * may_goto of the program stops the loop that it leaves. This one goes to itself
 * when it is out of budget. The loop spins until may_goto that is added ends the prog.
 */
SEC("socket")
__description("budget: may_goto that doesn't leave the loop")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void may_goto_stays_in_loop(void)
{
	asm volatile (
		"r6 = %[one] ll;"
	"1:"
		".8byte %[may_goto_self];"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm_insn(may_goto_self, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, -1, 0))
		: __clobber_all
	);
}

/* The jump to itself has to go through may_goto that is added in front of it */
SEC("socket")
__description("budget: a conditional jump to itself")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void jump_to_itself(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		"r1 = *(u64 *)(r6 + 0);"
	"1:"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

/* A cycle with two entries: there is no insn that every way into it goes through */
SEC("socket")
__description("budget: a loop with two entries")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void loop_with_two_entries(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 2f;"
	"1:"
		"r2 = *(u64 *)(r6 + 0);"
		"if r2 == 0 goto 3f;"
	"2:"
		"r3 = *(u64 *)(r6 + 0);"
		"if r3 != 0 goto 1b;"
	"3:"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

/*
 * bpf_iter_num_next() stops the loop that the program leaves when there is nothing left.
 * This one goes on. When it is out of budget the landing pad destroys the iterator.
 */
SEC("socket")
__description("budget: a loop that goes on when its iterator is drained")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void loop_after_iter_is_drained(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
		"r6 = %[one] ll;"
	"1:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_next];"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_destroy];"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm(bpf_iter_num_new),
		  __imm(bpf_iter_num_next),
		  __imm(bpf_iter_num_destroy)
		: __clobber_all
	);
}

/*
 * bpf_iter_num_next() stops the loops that the program entered after it made the iterator.
 * The loop around bpf_for() makes a new one in every trip, so it gets may_goto. It ends on its own
 * after a time that is much longer than the budget.
 */
unsigned long trips, sum;
unsigned long many = 1UL << 32;

SEC("socket")
__description("budget: the iterator of bpf_for() doesn't stop the loop around it")
__arch_x86_64
__arch_arm64
__success __retval(0)
int loop_around_bpf_for(void *ctx)
{
	volatile unsigned long *cnt = &trips, *max = &many;
	int i;

	do {
		bpf_for(i, 0, 2)
			sum += i;
		(*cnt)++;
	} while (*cnt < *max);
	return 1;
}

/*
 * The first time the outer loop counts on bpf_iter_num_next(): its trips are joined, r7 is not
 * known and the store is refused. All is done again, the loop is walked, r7 is 27 and the store is
 * dead code. Where the first time got to doesn't count.
 */
SEC("socket")
__description("budget: an insn that is reached only before all is done again is dead code")
__arch_x86_64
__arch_arm64
__success
__xlated("...")
__xlated("if r6 < 0x3 goto pc-{{[0-9]+}}")
__xlated("r0 = 0")
__xlated("exit")
__naked void insn_of_dropped_round(void)
{
	asm volatile (
		"r6 = 0;"
		"r7 = 1;"
	"1:"
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
	"2:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_next];"
		"if r0 != 0 goto 2b;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_destroy];"
		"r7 *= 3;"
		"r6 += 1;"
		"if r6 == 1 goto 1b;"
		"if r6 < 3 goto 1b;"
		"if r7 == 27 goto 3f;"
		"r1 = 0;"
		"*(u64 *)(r1 + 0) = r1;"
	"3:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_iter_num_new),
		  __imm(bpf_iter_num_next),
		  __imm(bpf_iter_num_destroy)
		: __clobber_all
	);
}

/*
 * The loop at 3: spins. It has no jump that every trip goes through, so may_goto is at its head.
 * The loop at 1: around it has no may_goto of its own: bpf_iter_num_next() stops it.
 */
SEC("socket")
__description("budget: may_goto at the head of a loop leaves the loops around it too")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void guard_at_head_of_nested_loop(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		"r9 = %[zero] ll;"
		"r7 = 0;"
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 0;"
		"r3 = 2;"
		"call %[bpf_iter_num_new];"
		"call %[bpf_rcu_read_lock];"
		"r7 += 1;"
		"goto 1f;"
	"2:"
		"r7 += 1;"
		"r1 = *(u64 *)(r9 + 0);"
		"if r1 != 0 goto 4f;"
		"r1 = *(u64 *)(r9 + 0);"
		"if r1 != 0 goto 4f;"
	"1:"
		"r7 += 1;"
		"r1 = *(u64 *)(r6 + 0);"
	"5:"
		"if r1 == 0 goto 5b;"
	"3:"
		"r1 = *(u64 *)(r9 + 0);"
		"if r1 != 0 goto +0;"
	"4:"
		"r7 += 1;"
		"r1 = *(u64 *)(r9 + 0);"
		"if r1 == 0 goto 3b;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_next];"
		"if r0 == 0 goto 6f;"
		"r1 = *(u64 *)(r9 + 0);"
		"if r1 == 0 goto 2b;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 4b;"
	"6:"
		"call %[bpf_rcu_read_unlock];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_destroy];"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm_addr(zero),
		  __imm(bpf_iter_num_new),
		  __imm(bpf_iter_num_next),
		  __imm(bpf_iter_num_destroy),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

#define NEST(n, body)	#n ": call %[bpf_get_prandom_u32];" body "if r0 == " #n " goto " #n "b;"
#define NEST4(a, b, c, d, body)	NEST(a, NEST(b, NEST(c, NEST(d, body))))

/* It's refused before anything goes up the nest from each of its insns */
SEC("socket")
__description("budget: a nest of 17 loops")
__failure __msg("Too many nested loops at")
__naked void nest_of_17_loops(void)
{
	asm volatile (
		NEST4(1, 2, 3, 4, NEST4(5, 6, 7, 8, NEST4(9, 10, 11, 12,
		NEST4(13, 14, 15, 16, NEST(17, "")))))
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_get_prandom_u32) : __clobber_all);
}

/*
 * The loop has no jump that every trip goes through, so may_goto is at its head. Only the loop sets
 * r6.
 */
__naked __noinline __used
static unsigned long spins_and_makes_unset(void)
{
	asm volatile (
		"r8 = %[zero] ll;"
	"1:"
		"r1 = *(u64 *)(r8 + 0);"
		"if r1 == 1 goto 1b;"
		"r6 = 5;"
		"if r1 != 2 goto 1b;"
		"r0 = r6;"
		"exit;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: may_goto at the head of a loop, a register that only the loop sets")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void guard_at_head_unset_reg(void)
{
	asm volatile (
		"call spins_and_makes_unset;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * if (x) lock(); do { p = lookup(); } while (!p); if (x) { unlock(); return 0; } return *p;
 * looks(0) holds nothing at may_goto, looks(1) is in a section: the program counter does not tell
 * the landing pad what to do.
 */
__naked __noinline __used
static unsigned long looks(unsigned long x)
{
	asm volatile (
		"r6 = r1;"
		"if r6 == 0 goto 1f;"
		"call %[bpf_rcu_read_lock];"
	"1:"
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[empty] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 1b;"
		"if r6 == 0 goto 2f;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
	"2:"
		"r0 = *(u64 *)(r0 + 0);"
		"exit;"
		:
		: __imm_addr(empty),
		  __imm(bpf_map_lookup_elem),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: a subprog is in a section on some paths")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void unwinds_then_cannot(void)
{
	asm volatile (
		"r1 = 0;"
		"call looks;"
		unwind_goto(5)
		"r1 = 1;"
		"call looks;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(5),
		  __imm_unwind_goto(2)
		: __clobber_all
	);
}

SEC("socket")
__description("budget: a loop without an exit")
__arch_x86_64
__arch_arm64
__failure __msg("never exits")
__naked void loop_without_exit(void)
{
	asm volatile (
		"r0 = 0;"
	"1:"
		"r0 += 1;"
		"goto 1b;"
		::: __clobber_all
	);
}

/*
 * may_goto keeps the address of its count in a register that is dead. What is live in front
 * of the insn that gets may_goto is live in front of may_goto.
 */
SEC("socket")
__description("budget: may_goto in front of a jump keeps R0")
__arch_x86_64
__arch_arm64
__success __retval(7)
__naked void guard_keeps_r0(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
		"r0 = 7;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"exit;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

#define ALL_REGS_LIVE_IN_LOOP(var)			\
		"r9 = %[" #var "] ll;"			\
		"r0 = 1;"				\
		"r2 = 2;"				\
		"r3 = 3;"				\
		"r4 = 4;"				\
		"r5 = 5;"				\
		"r6 = 6;"				\
		"r7 = 7;"				\
		"r8 = 8;"				\
	"1:"						\
		"r1 = *(u64 *)(r9 + 0);"		\
		"if r1 != 0 goto 1b;"			\
		"r0 += r1;"				\
		"r0 += r2;"				\
		"r0 += r3;"				\
		"r0 += r4;"				\
		"r0 += r5;"				\
		"r0 += r6;"				\
		"r0 += r7;"				\
		"r0 += r8;"				\
		"r9 = *(u64 *)(r9 + 0);"		\
		"r0 += r9;"				\
		"exit;"					\
		:					\
		: __imm_addr(var)			\
		: __clobber_all

/* No register is dead: R0 waits in the stack */
SEC("socket")
__description("budget: may_goto where all registers are live")
__arch_x86_64
__arch_arm64
__success __retval(36)
__xlated("...")
__xlated("*(u64 *)(r10 -8) = r0")
__xlated("r0 = 0x{{.*}}")
__xlated("r0 = &(void __percpu *)(r0)")
__xlated("r13 = *(u64 *)(r0 +0)")
__xlated("...")
__xlated("*(u64 *)(r0 +0) = r13")
__xlated("r0 = *(u64 *)(r10 -8)")
__xlated("if r1 != 0x0 goto pc-{{[0-9]+}}")
__naked void guard_all_regs_live(void)
{
	asm volatile (
		ALL_REGS_LIVE_IN_LOOP(zero)
	);
}

__naked __noinline __used
static unsigned long spins_all_regs_live(void)
{
	asm volatile (
		ALL_REGS_LIVE_IN_LOOP(one)
	);
}

/* The time is up */
SEC("socket")
__description("budget: may_goto where all registers are live, out of budget")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void guard_all_regs_live_spins(void)
{
	asm volatile (
		"call spins_all_regs_live;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * A loop that has no count is looked at trip by trip for a while. A state that is within a state of
 * an earlier trip is dropped, wherever that is. Then nothing says that the loop ends, it gets
 * may_goto, and all is done again. None of the loops below ends on its own.
 */
SEC("socket")
__description("budget: every second trip leaves everything as it was")
__arch_x86_64
__arch_arm64
__success __retval(0) __log_level(2)
__msg("processed {{[0-9][0-9]}} insns")
__naked void trips_of_period_two(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		"r7 = 1;"
	"1:"
		"r7 ^= 3;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 == 0 goto 2f;"
		"if r7 != 7 goto 1b;"
	"2:"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

/*
 * r7 is 0 at the head in the first trip and 5 in the second one. It's dead at 2, where the second
 * trip is dropped. Nothing comes back to the head that is within what is there.
 */
SEC("socket")
__description("budget: a trip is dropped in the middle of the loop")
__arch_x86_64
__arch_arm64
__success __retval(0) __log_level(2)
__msg("processed {{[0-9][0-9]}} insns")
__naked void trip_dropped_in_the_middle(void)
{
	asm volatile (
		"r6 = %[one] ll;"
		"r7 = 0;"
	"1:"
		"if r7 == 7 goto 3f;"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 == 0 goto 3f;"
		"if r1 == 2 goto 2f;"
		"r1 = 0;"
	"2:"
		"r7 = 5;"
		"goto 1b;"
	"3:"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

/* n ? zero_at_the_bottom(n - 1) : zero */
__naked __noinline __used
static unsigned long zero_at_the_bottom(unsigned long n)
{
	asm volatile (
		"if r1 == 0 goto 1f;"
		"r1 += -1;"
		"call zero_at_the_bottom;"
		"exit;"
	"1:"
		"r1 = %[zero] ll;"
		"r0 = *(u64 *)(r1 + 0);"
		"exit;"
		:
		: __imm_addr(zero)
		: __clobber_all
	);
}

/*
 * The call of a recursive subprog waits for what comes out of it. The call of the second trip is
 * within the one that waits. The check at the entry of the recursive subprog doesn't stop the
 * loop: the recursion is not deep.
 */
SEC("socket")
__description("budget: a trip is dropped at a call that waits")
__arch_x86_64
__arch_arm64
__success __retval(0) __log_level(2)
__msg("processed {{[0-9][0-9]}} insns")
__naked void trip_dropped_at_a_call(void)
{
	asm volatile (
		"r7 = 0;"
	"1:"
		"if r7 == 7 goto 2f;"
		"r1 = 3;"
		"call zero_at_the_bottom;"
		"r7 = 5;"
		"if r0 == 0 goto 1b;"
	"2:"
		"r0 = 1;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * Every trip goes through bpf_iter_num_next(), so the loop is taken for bounded at first, and
 * through may_goto of the program. The iterator is made in the loop, and may_goto stays in it:
 * neither of them stops it. The program doesn't end on its own.
 */
SEC("socket")
__description("budget: may_goto that stays in the loop doesn't stop it")
__arch_x86_64
__arch_arm64
__success __retval(0)
__naked void may_goto_stays_in_the_loop(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"if r6 != 0 goto 4f;"
	"1:"
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 0;"
		"r3 = 2;"
		"call %[bpf_iter_num_new];"
	"2:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_next];"
		"if r0 != 0 goto 2b;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_destroy];"
		".8byte %[may_goto];"
		"if r6 == 0 goto 1b;"
	"4:"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(zero),
		  __imm(bpf_iter_num_new),
		  __imm(bpf_iter_num_next),
		  __imm(bpf_iter_num_destroy),
		  __imm_insn(may_goto, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, 0 /* offset */, 0))
		: __clobber_all
	);
}

/* The loop has no trip count and no error asks for peeling: may_goto is added */
SEC("socket")
__description("budget: ten trips that differ")
__success __retval(10) __log_level(2)
__msg("processed {{[0-9][0-9]}} insns")
__xlated("r8 += 1")
__xlated("r7 <<= 1")
__xlated("...")
__xlated("if r13 == 0x0 goto")
__xlated("...")
__xlated("if r7 != 0x400 goto pc-{{[0-9]+}}")
__naked void ten_trips_that_differ(void)
{
	asm volatile (
		"r7 = 1;"
		"r8 = 0;"
	"1:"
		"r8 += 1;"
		"r7 <<= 1;"
		"if r7 != 1024 goto 1b;"
		"r0 = r8;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * BTF FUNC records are not generated for kfuncs referenced
 * from inline assembly. These records are necessary for
 * libbpf to link the program. The function below is a hack
 * to ensure that BTF FUNC records are generated.
 */
/* It is called in a section with preemption disabled, and spins where it has left that section */
__naked __noinline __used
static unsigned long leaves_section_and_spins(void)
{
	asm volatile (
		"call %[bpf_preempt_enable];"
	SPIN
		"call %[bpf_preempt_disable];"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(one), __imm(bpf_preempt_enable), __imm(bpf_preempt_disable)
		: __clobber_all
	);
}

/*
 * A frame is unwound with the sections of its call. The subprog is called under a lock of the
 * prog, as a function that drops the lock, waits and takes it again. When the loop is out of time
 * the frame is in one section less than it was called in: its pad enters the section, and the pad
 * of the call leaves it, as it does when the subprog is unwound anywhere else.
 */
SEC("tc")
__description("budget: a subprog that has left the section of its caller enters it when it is unwound")
__arch_x86_64
__arch_arm64
__success __retval(2)
__log_level(2)
__msg("landing pad of call at 1: rcu=0 preempt=1")
__msg("landing pad of may_goto at {{[0-9]+}}: rcu=0 preempt=-1")
__xlated("call kernel-function")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("call kernel-function")
__xlated("r0 = 7")
__xlated("exit")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__xlated("call kernel-function")
__xlated("...")
__xlated("exit")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__naked void callee_left_section_of_caller(void)
{
	asm volatile (
		"call %[bpf_preempt_disable];"
		"call leaves_section_and_spins;"
		"call %[bpf_preempt_enable];"
		"r0 = 7;"
		"exit;"
		:
		: __imm(bpf_preempt_disable), __imm(bpf_preempt_enable)
		: __clobber_all
	);
}

/* The same, but it has left the section of its caller on one path to the loop only */
__naked __noinline __used
static unsigned long may_leave_section_and_spins(void)
{
	asm volatile (
		"r9 = %[zero] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"if r9 == 0 goto +1;"
		"call %[bpf_preempt_enable];"
	SPIN
		"if r9 == 0 goto +1;"
		"call %[bpf_preempt_disable];"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(zero), __imm_addr(one),
		  __imm(bpf_preempt_enable), __imm(bpf_preempt_disable)
		: __clobber_all
	);
}

/*
 * The pad of the loop would enter the section on one path and nothing on the other. A function
 * that leaves a section of a caller gets no hidden slots for it.
 */
SEC("tc")
__description("budget: a subprog has left the section of its caller on some paths only")
__arch_x86_64
__arch_arm64
__failure
__msg("landing pad of may_goto at {{[0-9]+}}: conflict: the number of sections differs")
__naked void callee_may_have_left_section_of_caller(void)
{
	asm volatile (
		"call %[bpf_preempt_disable];"
		"call may_leave_section_and_spins;"
		"call %[bpf_preempt_enable];"
		"r0 = 7;"
		"exit;"
		:
		: __imm(bpf_preempt_disable), __imm(bpf_preempt_enable)
		: __clobber_all
	);
}

/*
 * It is called in a section with preemption disabled. It leaves the section, as it has to for an
 * iterator whose kfuncs may sleep, and spins in the section again while it has the iterator.
 */
__naked __noinline __used
static unsigned long spins_with_iter_that_sleeps(void)
{
	asm volatile (
		"call %[bpf_preempt_enable];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_kmem_cache_new];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_kmem_cache_next];"
		"call %[bpf_preempt_disable];"
	SPIN
		"call %[bpf_preempt_enable];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_kmem_cache_destroy];"
		"call %[bpf_preempt_disable];"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(one), __imm(bpf_preempt_enable), __imm(bpf_preempt_disable),
		  __imm(bpf_iter_kmem_cache_new), __imm(bpf_iter_kmem_cache_next),
		  __imm(bpf_iter_kmem_cache_destroy)
		: __clobber_all
	);
}

/*
 * The frame is in as many sections as it was called in, and the destructor takes a mutex. The pad
 * does what the subprog does where it returns: it leaves the section of the caller, destroys the
 * iterator, and enters the section again.
 */
SEC("syscall")
__description("budget: a subprog is in the section of its caller again and holds what may sleep")
__arch_x86_64
__arch_arm64
__success __retval(-125)
__log_level(2)
__msg("landing pad of call at 1: rcu=0 preempt=1")
__msg("landing pad of may_goto at {{[0-9]+}}: iter@{{[0-9]+}}(fp-8) rcu=0 preempt=0 sleeps outside rcu=0 preempt=1")
__xlated("call kernel-function")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("call kernel-function")
__xlated("r0 = 7")
__xlated("exit")
__xlated("call kernel-function")
__xlated("r0 = -125")
__xlated("exit")
__xlated("...")
__xlated("exit")
__xlated("call kernel-function")
__xlated("r1 = r10")
__xlated("r1 += -8")
__xlated("call kernel-function")
__xlated("call kernel-function")
__xlated("r0 = -125")
__xlated("r2 = 0")
__xlated("kexit")
__naked void callee_sleeps_in_section_of_caller(void)
{
	asm volatile (
		"call %[bpf_preempt_disable];"
		"call spins_with_iter_that_sleeps;"
		"call %[bpf_preempt_enable];"
		"r0 = 7;"
		"exit;"
		:
		: __imm(bpf_preempt_disable), __imm(bpf_preempt_enable)
		: __clobber_all
	);
}

/* The same, but it makes the iterator on one path to the loop only */
__naked __noinline __used
static unsigned long spins_with_iter_that_sleeps_on_one_path(void)
{
	asm volatile (
		"call %[bpf_preempt_enable];"
		"r9 = %[zero] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"if r9 == 0 goto 2f;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_kmem_cache_new];"
	"2:"
		"call %[bpf_preempt_disable];"
	SPIN
		"call %[bpf_preempt_enable];"
		"if r9 == 0 goto 3f;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_kmem_cache_destroy];"
	"3:"
		"call %[bpf_preempt_disable];"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(zero), __imm_addr(one),
		  __imm(bpf_preempt_enable), __imm(bpf_preempt_disable),
		  __imm(bpf_iter_kmem_cache_new), __imm(bpf_iter_kmem_cache_destroy)
		: __clobber_all
	);
}

/*
 * The pad would leave the section of the caller on the path that has the iterator, and nothing
 * says that the frame may be out of it on the other one.
 */
SEC("syscall")
__description("budget: a subprog in the section of its caller holds what may sleep on some paths only")
__arch_x86_64
__arch_arm64
__failure
__msg("landing pad of may_goto at {{[0-9]+}}: conflict: the number of sections differs")
__naked void callee_may_sleep_in_section_of_caller(void)
{
	asm volatile (
		"call %[bpf_preempt_disable];"
		"call spins_with_iter_that_sleeps_on_one_path;"
		"call %[bpf_preempt_enable];"
		"r0 = 7;"
		"exit;"
		:
		: __imm(bpf_preempt_disable), __imm(bpf_preempt_enable)
		: __clobber_all
	);
}

/*
 * It is called in an RCU section. It leaves that section, enters one of its own with preemption
 * disabled, and gives a task out of the map to the caller there. What it calls leaves with
 * unwind_exit.
 */
static __noinline __used int own_section_and_unwinds(struct task_struct * volatile *p)
{
	struct with_task *v;
	int key = 0;

	v = bpf_map_lookup_elem(&tasks, &key);
	if (!v)
		return 0;
	bpf_rcu_read_unlock();
	bpf_preempt_disable();
	*p = v->task;
	if (*(volatile unsigned long *)&one)
		unwinds_at_once();
	*p = NULL;
	bpf_preempt_enable();
	bpf_rcu_read_lock();
	return 7;
}

/*
 * The landing pad of the subprog leaves the section of the subprog and then enters the one of the
 * prog: nothing protects the task in between, so the landing pad of the prog cannot use it.
 */
SEC("syscall")
__description("budget: the landing pad enters the section of the caller, the caller has an RCU pointer")
__arch_x86_64
__arch_arm64
__failure __msg("R1 must be a rcu pointer")
__naked void pointer_of_caller_under_section_of_callee(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"call %[bpf_rcu_read_lock];"
		"r1 = r10;"
		"r1 += -8;"
		"call own_section_and_unwinds;"
		unwind_goto(3)
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
		"r1 = *(u64 *)(r10 - 8);"
		"if r1 == 0 goto 1f;"
		"call %[bpf_task_acquire];"
		"if r0 == 0 goto 1f;"
		"r1 = r0;"
		"call %[bpf_task_release];"
	"1:"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock),
		  __imm(bpf_task_acquire), __imm(bpf_task_release),
		  __imm_unwind_goto(3)
		: __clobber_all
	);
}

/* r1: where the irq flags go, in the stack of the caller. Nothing reads it behind the call. */
__naked __noinline __used
static unsigned long saves_irq_of_caller_and_spins(void)
{
	asm volatile (
		"call %[bpf_local_irq_save];"
	SPIN
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(one), __imm(bpf_local_irq_save)
		: __clobber_all
	);
}

/*
 * The subprog saves irq flags for its caller, as the function that takes a lock does, and no
 * register of its frame has their address when the loop is out of time. The hidden slot of the
 * call that saved them has it.
 */
SEC("tc")
__description("budget: irq flags in the stack of the caller, no place has their address")
__arch_x86_64
__arch_arm64
__success __retval(2)
__log_level(2)
__msg("landing pad of may_goto at {{[0-9]+}}: irq@{{[0-9]+}}(*fp-8) if not 0 rcu=0 preempt=0")
__msg("func#1 has hidden slots for: locks")
__xlated("...")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("*(u64 *)(r10 -8) = r1")
__xlated("call kernel-function")
__xlated("...")
__xlated("exit")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__naked void irq_flags_in_caller_no_place(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"call saves_irq_of_caller_and_spins;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
		"r0 = 7;"
		"exit;"
		:
		: __imm(bpf_local_irq_restore)
		: __clobber_all
	);
}

void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_preempt_disable();
	bpf_preempt_enable();
	bpf_local_irq_save(0);
	bpf_local_irq_restore(0);
	bpf_res_spin_lock_irqsave(0, 0);
	bpf_res_spin_unlock_irqrestore(0, 0);
	bpf_task_from_pid(0);
	bpf_task_acquire(0);
	bpf_task_release(0);
	bpf_cgroup_release(0);
	bpf_list_pop_front(0);
	bpf_iter_task_new(0, 0, 0);
	bpf_iter_task_destroy(0);
	bpf_dynptr_clone(0, 0);
	bpf_iter_num_new(0, 0, 0);
	bpf_iter_num_next(0);
	bpf_iter_num_destroy(0);
	bpf_iter_kmem_cache_new(0);
	bpf_iter_kmem_cache_next(0);
	bpf_iter_kmem_cache_destroy(0);
}

char _license[] SEC("license") = "GPL";
