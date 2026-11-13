// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

/*
 * The pads of the progs in cancel.c leave frames that hold nothing. Here the frame at the
 * cancellation point, or a frame below it that waits in a call, holds something, and its pad
 * releases that: the prog returns the cancel value of its type, nothing of it runs behind the
 * point, and the runner finds what was held released.
 *
 * Most progs call dives(), which calls itself until the stack has no room: that is over at
 * once. A loop that only may_goto of the verifier ends spins for 250 ms, so there are few.
 *
 * Where it matters which register or stack slot has a handle the prog is in assembly, and the
 * insns of its pad are matched: the pad of a main program is behind its last insn.
 *
 * The line of the stats, the JITs and the capabilities are those of cancel.c. The runner sets
 * the globals that tell what to take, so the test loader only loads the progs.
 */

#define TC_ACT_OK	0
#define AF_INET		2

char _license[] SEC("license") = "GPL";

/* The frames of a recursion that began, and how many times the code behind a call ran */
unsigned long frames;
unsigned long behind;
/* How many times the code behind a loop ran */
unsigned long after;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

/* @var++ in assembly, with r1 and r2 */
#define COUNT(var)				\
	"r1 = %[" #var "] ll;"			\
	"r2 = *(u64 *)(r1 + 0);"		\
	"r2 += 1;"				\
	"*(u64 *)(r1 + 0) = r2;"

/* It calls itself until the stack has no room, see cancel.c */
__naked __noinline __used
static unsigned long dives(void)
{
	asm volatile (
		COUNT(frames)
		"*(u64 *)(r10 - 128) = r2;"
		"call dives;"
		COUNT(behind)
		"exit;"
		:
		: __imm_addr(frames),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * An iterator is in the stack of its frame. The pad calls bpf_iter_<type>_destroy() with its
 * address: here the one at fp-8. The prog itself keeps the address in r6. Nothing is to be done
 * for a bpf_iter_num, so the fixups make a jump of that call, in the pad as in the prog.
 */
SEC("tc")
__description("cancel refs: the iterator of a frame that waits in a call is destroyed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("r1 = r10")
__xlated("r1 += -8")
__xlated("goto pc+0")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void num_iter_at_call(void)
{
	asm volatile (
		"r6 = r10;"
		"r6 += -8;"
		"r1 = r6;"
		"r2 = 0;"
		"r3 = 3;"
		"call %[bpf_iter_num_new];"
		"call dives;"
		COUNT(behind)
		"r1 = r6;"
		"call %[bpf_iter_num_destroy];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_iter_num_new),
		  __imm(bpf_iter_num_destroy),
		  __imm_addr(behind)
		: __clobber_all
	);
}

struct bpf_iter_testmod_seq {
	u64 :64;
	u64 :64;
};

extern int bpf_iter_testmod_seq_new(struct bpf_iter_testmod_seq *it, s64 value, int cnt) __ksym;
extern void bpf_iter_testmod_seq_destroy(struct bpf_iter_testmod_seq *it) __ksym;

/* The pad calls the kfunc of a module through the BTF that the call of _new() names */
SEC("tc")
__description("cancel refs: the iterator of a module is destroyed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int testmod_iter_at_call(struct __sk_buff *skb)
{
	struct bpf_iter_testmod_seq it;

	bpf_iter_testmod_seq_new(&it, 5, 3);
	dives();
	behind++;
	bpf_iter_testmod_seq_destroy(&it);
	return TC_ACT_OK;
}

int seen_pid;

/*
 * An iterator over tasks is made in an RCU section and destroyed in it. The pad destroys it
 * first and leaves the section behind that. A cancelled syscall prog returns 0.
 */
SEC("syscall")
__description("cancel refs: an iterator that needs RCU is destroyed in the section of its frame")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int task_iter_in_rcu(void *ctx)
{
	struct task_struct *pos;

	bpf_rcu_read_lock();
	bpf_for_each(task, pos, NULL, BPF_TASK_ITER_ALL_PROCS) {
		seen_pid = pos->pid;
		dives();
		behind++;
		break;
	}
	bpf_rcu_read_unlock();
	return 1;
}

/*
 * A prog that may sleep is in an RCU section also while it has interrupts off, and may make
 * the iterator then. The pad restores the IRQ flags of its frame in front of everything else,
 * so the iterator would be destroyed outside of any section: the prog is not loaded, and the
 * log names the call and the limit.
 */
SEC("?syscall")
__description("cancel refs: an iterator that needs RCU is rejected when IRQ flags stand for the section")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(iter)")
int task_iter_in_irq(void *ctx)
{
	struct task_struct *pos;
	unsigned long flags;

	bpf_local_irq_save(&flags);
	bpf_for_each(task, pos, NULL, BPF_TASK_ITER_ALL_PROCS) {
		seen_pid = pos->pid;
		dives();
		behind++;
		break;
	}
	bpf_local_irq_restore(&flags);
	return 1;
}

__naked __noinline __used
static unsigned long makes_iter(void)
{
	asm volatile (
		"r2 = 0;"
		"r3 = 3;"
		"call %[bpf_iter_num_new];"
		"call dives;"
		COUNT(behind)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_iter_num_new),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * makes_iter() makes the iterator in the stack of its caller, and is the frame that is to
 * destroy it until it returns. Its pad has no address for it.
 */
SEC("?tc")
__description("cancel refs: an iterator in the stack of the caller is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(iter)")
__naked void iter_in_callers_stack(void)
{
	asm volatile (
		"r6 = r10;"
		"r6 += -8;"
		"r1 = r6;"
		"call makes_iter;"
		"r1 = r6;"
		"call %[bpf_iter_num_destroy];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_iter_num_destroy)
		: __clobber_all
	);
}

/*
 * A dynptr that holds a ringbuf record is released like the prog does it: the pad calls
 * bpf_ringbuf_discard_dynptr() with the address of the dynptr, fp-16, and 0.
 */
SEC("tc")
__description("cancel refs: the ringbuf dynptr of a frame that waits in a call is discarded")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("r1 = r10")
__xlated("r1 += -16")
__xlated("r2 = 0")
__xlated("call unknown")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void ringbuf_dynptr_at_call(void)
{
	asm volatile (
		"r6 = r10;"
		"r6 += -16;"
		"r1 = %[ringbuf] ll;"
		"r2 = 8;"
		"r3 = 0;"
		"r4 = r6;"
		"call %[bpf_ringbuf_reserve_dynptr];"
		"call dives;"
		COUNT(behind)
		"r1 = r6;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard_dynptr];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_ringbuf_reserve_dynptr),
		  __imm(bpf_ringbuf_discard_dynptr),
		  __imm_addr(ringbuf),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* A dynptr and its clone are one record. The pad discards it once, through one of them. */
SEC("tc")
__description("cancel refs: a ringbuf dynptr that has a clone is discarded once")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int dynptr_clone_at_call(struct __sk_buff *skb)
{
	struct bpf_dynptr ptr, clone;

	bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, &ptr);
	bpf_dynptr_clone(&ptr, &clone);
	dives();
	behind++;
	bpf_ringbuf_discard_dynptr(&clone, 0);
	return TC_ACT_OK;
}

/*
 * The file of a vma is good as long as the iterator stays where it is, so the reader of the
 * file goes first: the pad frees the reader of the dynptr at fp-24, then it destroys the
 * iterator at fp-8. The task is the one that runs the prog, which has a vma with a file.
 */
SEC("tc")
__description("cancel refs: a file dynptr is discarded in front of the iterator that its file is from")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("r1 = r10")
__xlated("r1 += -24")
__xlated("call kernel-function")
__xlated("r1 = r10")
__xlated("r1 += -8")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void file_dynptr_in_vma_loop(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r2 = r0;"
		"r6 = r10;"
		"r6 += -8;"
		"r1 = r6;"
		"r3 = 0;"
		"call %[bpf_iter_task_vma_new];"
	"1:"
		"r1 = r6;"
		"call %[bpf_iter_task_vma_next];"
		"if r0 == 0 goto 2f;"
		"r1 = *(u64 *)(r0 + %[vm_file]);"
		"if r1 == 0 goto 1b;"
		"r7 = r10;"
		"r7 += -24;"
		"r2 = 0;"
		"r3 = r7;"
		"call %[bpf_dynptr_from_file];"
		"call dives;"
		COUNT(behind)
		"r1 = r7;"
		"call %[bpf_dynptr_file_discard];"
	"2:"
		"r1 = r6;"
		"call %[bpf_iter_task_vma_destroy];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_get_current_task_btf),
		  __imm(bpf_iter_task_vma_new),
		  __imm(bpf_iter_task_vma_next),
		  __imm(bpf_iter_task_vma_destroy),
		  __imm(bpf_dynptr_from_file),
		  __imm(bpf_dynptr_file_discard),
		  __imm_const(vm_file, offsetof(struct vm_area_struct, vm_file)),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* clang makes no BTF for a kfunc that only asm calls, and libbpf needs it to link the prog */
void __kfunc_btf_root(void)
{
	bpf_iter_task_vma_new(0, 0, 0);
	bpf_iter_task_vma_next(0);
	bpf_iter_task_vma_destroy(0);
	bpf_dynptr_from_file(0, 0, 0);
	bpf_dynptr_file_discard(0);
}

__naked __noinline __used
static unsigned long makes_dynptr(void)
{
	asm volatile (
		"r4 = r1;"
		"r1 = %[ringbuf] ll;"
		"r2 = 8;"
		"r3 = 0;"
		"call %[bpf_ringbuf_reserve_dynptr];"
		"call dives;"
		COUNT(behind)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_ringbuf_reserve_dynptr),
		  __imm_addr(ringbuf),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* Like iter_in_callers_stack(): the pad of makes_dynptr() has no address for the dynptr */
SEC("?tc")
__description("cancel refs: a dynptr in the stack of the caller is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(dynptr)")
__naked void dynptr_in_callers_stack(void)
{
	asm volatile (
		"r6 = r10;"
		"r6 += -16;"
		"r1 = r6;"
		"call makes_dynptr;"
		"r1 = r6;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard_dynptr];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_ringbuf_discard_dynptr)
		: __clobber_all
	);
}

/* The runner looks at what the progs above held through the next two */

int cur_usage;
int cur_mm_users;

/* The references to the task that runs the progs, and the users of its mm */
SEC("tc")
int probe_current(struct __sk_buff *skb)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct mm_struct *mm = task->mm;

	cur_usage = task->usage.refs.counter;
	cur_mm_users = mm ? mm->mm_users.counter : -1;
	return TC_ACT_OK;
}

/* The ring buffer takes a record and hands it to the consumer */
SEC("tc")
int ringbuf_submit(struct __sk_buff *skb)
{
	long *rec;

	rec = bpf_ringbuf_reserve(&ringbuf, sizeof(*rec), 0);
	if (!rec)
		return TC_ACT_OK;
	*rec = 1;
	bpf_ringbuf_submit(rec, 0);
	return TC_ACT_OK;
}

/*
 * A reference to a kernel object. Its handle is the pointer that the kfunc returned, in a
 * register or in a stack slot of the frame, and the pad makes the call that the prog makes to
 * release it: bpf_task_release(), bpf_cgroup_release() or bpf_cpumask_release().
 */

/* What the progs take: the task with this pid, another task, and the cgroup with this id */
int pid;
int pid2;
__u64 cgid;

SEC("tc")
__description("cancel refs: the task of a frame that waits in a call is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int task_at_call(struct __sk_buff *skb)
{
	struct task_struct *task;

	task = bpf_task_from_pid(pid);
	if (!task)
		return TC_ACT_OK;
	dives();
	behind++;
	bpf_task_release(task);
	return TC_ACT_OK;
}

static __noinline int holds_copy(struct task_struct *task)
{
	struct task_struct *copy;

	copy = bpf_task_acquire(task);
	if (!copy)
		return 0;
	dives();
	behind++;
	bpf_task_release(copy);
	return 1;
}

/*
 * Each frame releases what it took: the pad of holds_copy() the copy, and the pad of the call
 * of holds_copy() here the task.
 */
SEC("tc")
__description("cancel refs: two frames that wait in calls release a task each")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 4 padded 4 declined")
int tasks_in_two_frames(struct __sk_buff *skb)
{
	struct task_struct *task;

	task = bpf_task_from_pid(pid);
	if (!task)
		return TC_ACT_OK;
	holds_copy(task);
	behind++;
	bpf_task_release(task);
	return TC_ACT_OK;
}

/* r0 = bpf_task_from_pid(@var) in assembly */
#define TASK_FROM(var)				\
	"r1 = %[" #var "] ll;"			\
	"r1 = *(u32 *)(r1 + 0);"		\
	"call %[bpf_task_from_pid];"

#define TASK_FROM_PID	TASK_FROM(pid)

/* bpf_task_release() of the task in @reg unless that is NULL, with r1 */
#define RELEASE_TASK(reg)			\
	"if " #reg " == 0 goto 9f;"		\
	"r1 = " #reg ";"			\
	"call %[bpf_task_release];"		\
"9:"

/*
 * The prog did not test the task since bpf_task_from_pid() returned it: there may be none.
 * The pad makes the test and leaves the call out for NULL.
 */
SEC("tc")
__description("cancel refs: a task in r6 that may be NULL is tested and released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void task_maybe_null_in_reg(void)
{
	asm volatile (
		TASK_FROM_PID
		"r6 = r0;"
		"call dives;"
		COUNT(behind)
		RELEASE_TASK(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* The only copy that outlives the call is in the stack. The prog loads it to r2, the pad to r1. */
SEC("tc")
__description("cancel refs: a task in a stack slot that may be NULL is tested and released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void task_maybe_null_spilled(void)
{
	asm volatile (
		TASK_FROM_PID
		"*(u64 *)(r10 - 8) = r0;"
		"call dives;"
		COUNT(behind)
		"r2 = *(u64 *)(r10 - 8);"
		RELEASE_TASK(r2)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * Six references of one frame, in every register that a call keeps and in two stack slots.
 * The pad releases them place by place, the stack first.
 */
SEC("tc")
__description("cancel refs: tasks in r6-r9 and in stack slots are all released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("r1 = *(u64 *)(r10 -16)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = r7")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = r8")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = r9")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void tasks_in_regs_and_slots(void)
{
	asm volatile (
		TASK_FROM_PID
		"r6 = r0;"
		TASK_FROM_PID
		"r7 = r0;"
		TASK_FROM_PID
		"r8 = r0;"
		TASK_FROM_PID
		"r9 = r0;"
		TASK_FROM_PID
		"*(u64 *)(r10 - 8) = r0;"
		TASK_FROM_PID
		"*(u64 *)(r10 - 16) = r0;"
		"call dives;"
		COUNT(behind)
		RELEASE_TASK(r6)
		RELEASE_TASK(r7)
		RELEASE_TASK(r8)
		RELEASE_TASK(r9)
		"r2 = *(u64 *)(r10 - 8);"
		RELEASE_TASK(r2)
		"r2 = *(u64 *)(r10 - 16);"
		RELEASE_TASK(r2)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(behind)
		: __clobber_all
	);
}

SEC("tc")
__description("cancel refs: the cgroup of a frame that waits in a call is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int cgroup_at_call(struct __sk_buff *skb)
{
	struct cgroup *cgrp, *held;

	cgrp = bpf_cgroup_from_id(cgid);
	if (!cgrp)
		return TC_ACT_OK;
	held = bpf_cgroup_acquire(cgrp);
	bpf_cgroup_release(cgrp);
	if (!held)
		return TC_ACT_OK;
	dives();
	behind++;
	bpf_cgroup_release(held);
	return TC_ACT_OK;
}

struct cpumask_val {
	struct bpf_cpumask __kptr *mask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct cpumask_val);
} cpumasks SEC(".maps");

/*
 * The map has a second reference to the cpumask when the prog is cancelled, for the runner to
 * count what is left, see probe_cpumask().
 */
SEC("syscall")
__description("cancel refs: the cpumask of a frame that waits in a call is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int cpumask_at_call(void *ctx)
{
	struct bpf_cpumask *mask, *old;
	struct cpumask_val *v;
	int key = 0;

	v = bpf_map_lookup_elem(&cpumasks, &key);
	if (!v)
		return 1;
	mask = bpf_cpumask_create();
	if (!mask)
		return 1;
	old = bpf_kptr_xchg(&v->mask, bpf_cpumask_acquire(mask));
	if (old)
		bpf_cpumask_release(old);
	dives();
	behind++;
	bpf_cpumask_release(mask);
	return 1;
}

/*
 * A prog is not loaded when a cancellation gets to a site whose pad could not release what the
 * frame holds, or would release it twice. The log has a line for the site, with the limit.
 *
 * A conntrack entry that was allocated and not inserted yet is a nf_conn___init. The only
 * kfunc that takes the reference is bpf_ct_insert_entry(), which returns another one: the type
 * names no kfunc that generated code may call to release it.
 */
SEC("?tc")
__description("cancel refs: a reference to a type without a release kfunc is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(release)")
int no_release_kfunc(struct __sk_buff *skb)
{
	struct bpf_ct_opts opts = { .netns_id = BPF_F_CURRENT_NETNS, .l4proto = IPPROTO_UDP };
	struct bpf_sock_tuple tuple = {};
	struct nf_conn___init *init;
	struct nf_conn *ct;

	init = bpf_skb_ct_alloc(skb, &tuple, sizeof(tuple.ipv4), &opts, sizeof(opts));
	if (!init)
		return TC_ACT_OK;
	dives();
	behind++;
	ct = bpf_ct_insert_entry(init);
	if (ct)
		bpf_ct_release(ct);
	return TC_ACT_OK;
}

/* The runner looks at what the progs above held through the next three */

int task_rcu_users;

/* The references to the task that the progs take, this one among them */
SEC("tc")
int probe_task(struct __sk_buff *skb)
{
	struct task_struct *task;

	task = bpf_task_from_pid(pid);
	if (!task)
		return TC_ACT_OK;
	task_rcu_users = task->rcu_users.refs.counter;
	bpf_task_release(task);
	return TC_ACT_OK;
}

int cgroup_released;

/* The cgroup that cgroup_at_call() took is released, some time after it was removed */
SEC("tp_btf/cgroup_release")
int BPF_PROG(on_cgroup_release, struct cgroup *cgrp, const char *path)
{
	if (cgrp->kn->id == cgid)
		cgroup_released = 1;
	return 0;
}

int cpumask_usage;

/* The references to the cpumask that cpumask_at_call() left in the map, this one among them */
SEC("syscall")
int probe_cpumask(void *ctx)
{
	struct bpf_cpumask *mask;
	struct cpumask_val *v;
	int key = 0;

	v = bpf_map_lookup_elem(&cpumasks, &key);
	if (!v)
		return 1;
	mask = bpf_kptr_xchg(&v->mask, NULL);
	if (!mask)
		return 1;
	cpumask_usage = mask->usage.refs.counter;
	bpf_cpumask_release(mask);
	return 0;
}

/*
 * A socket that a lookup returned and a record of a ring buffer are released by a helper. The
 * pad calls bpf_sk_release() with the socket, bpf_ringbuf_discard() with the record and 0.
 */

/* The connection that the progs look up, as the packets of the peer have it */
__u32 tuple_saddr;
__u32 tuple_daddr;
__u16 tuple_sport;
__u16 tuple_dport;

static __always_inline void fill_tuple(struct bpf_sock_tuple *tuple)
{
	tuple->ipv4.saddr = tuple_saddr;
	tuple->ipv4.daddr = tuple_daddr;
	tuple->ipv4.sport = tuple_sport;
	tuple->ipv4.dport = tuple_dport;
}

/* The prog tests the socket behind the call only: the pad makes the test */
SEC("tc")
__description("cancel refs: a socket that may be NULL is tested and released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int sock_at_call(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	fill_tuple(&tuple);
	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	dives();
	behind++;
	if (sk)
		bpf_sk_release(sk);
	return TC_ACT_OK;
}

SEC("tc")
__description("cancel refs: a socket of bpf_skc_lookup_tcp() is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int skc_at_call(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	fill_tuple(&tuple);
	sk = bpf_skc_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return TC_ACT_OK;
	dives();
	behind++;
	bpf_sk_release(sk);
	return TC_ACT_OK;
}

SEC("tc")
__description("cancel refs: a ringbuf record that may be NULL is tested and discarded")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int ringbuf_at_call(struct __sk_buff *skb)
{
	void *rec;

	rec = bpf_ringbuf_reserve(&ringbuf, 8, 0);
	dives();
	behind++;
	if (rec)
		bpf_ringbuf_discard(rec, 0);
	return TC_ACT_OK;
}

int sock_refcnt;

/* The references to the socket of the connection, this one among them */
SEC("tc")
int probe_sock(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct tcp_sock *tp;
	struct bpf_sock *sk;

	fill_tuple(&tuple);
	sk = bpf_skc_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return TC_ACT_OK;
	tp = bpf_skc_to_tcp_sock(sk);
	if (tp)
		sock_refcnt = tp->inet_conn.icsk_inet.sk.__sk_common.skc_refcnt.refs.counter;
	bpf_sk_release(sk);
	return TC_ACT_OK;
}

/*
 * Kernel objects of other subsystems. Each subsystem registers the release kfunc of its type,
 * and the pad calls it where the prog may: bpf_put_file() in an LSM prog, bpf_ct_release() in
 * tc and XDP, bpf_xdp_xfrm_state_release() in XDP, the ones of a kernel socket and of the
 * wakeup sources in a syscall prog.
 */

/*
 * bpf_kfunc_call_test_acquire() is the kfunc of a module, so r0 has the BTF of the module. The
 * type is one of vmlinux, and bpf_kfunc_call_test_release() is registered for it there.
 */
SEC("tc")
__description("cancel refs: a reference of a module's kfunc to a type of vmlinux is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int test_ref_at_call(struct __sk_buff *skb)
{
	struct prog_test_ref_kfunc *ref;
	unsigned long scalar = 0;

	ref = bpf_kfunc_call_test_acquire(&scalar);
	if (!ref)
		return TC_ACT_OK;
	dives();
	behind++;
	bpf_kfunc_call_test_release(ref);
	return TC_ACT_OK;
}

int test_ref_cnt;

/* The references to the object of bpf_kfunc_call_test_acquire(), this one among them */
SEC("tc")
int probe_test_ref(struct __sk_buff *skb)
{
	struct prog_test_ref_kfunc *ref;
	unsigned long scalar = 0;

	ref = bpf_kfunc_call_test_acquire(&scalar);
	if (!ref)
		return TC_ACT_OK;
	test_ref_cnt = ref->cnt.refs.counter;
	bpf_kfunc_call_test_release(ref);
	return TC_ACT_OK;
}

/*
 * A reference to the memory cgroup of a cgroup keeps the cgroup as well: the runner removes
 * the cgroup and waits for its release, as it does for cgroup_at_call().
 */
SEC("tc")
__description("cancel refs: the memory cgroup of a frame that waits in a call is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int memcg_at_call(struct __sk_buff *skb)
{
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(cgid);
	if (!cgrp)
		return TC_ACT_OK;
	memcg = bpf_get_mem_cgroup(&cgrp->self);
	bpf_cgroup_release(cgrp);
	if (!memcg)
		return TC_ACT_OK;
	dives();
	behind++;
	bpf_put_mem_cgroup(memcg);
	return TC_ACT_OK;
}

/* The thread whose setpriority() the LSM prog is for */
int tid;

/*
 * Only an LSM prog takes a file. It is on the hook of setpriority(): the hook refuses when the
 * prog is cancelled, and the runner gets EPERM.
 */
SEC("lsm/task_setnice")
__description("cancel refs: the file of a frame that waits in a call is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int BPF_PROG(file_at_call, struct task_struct *p, int nice)
{
	struct file *file;

	if ((int)bpf_get_current_pid_tgid() != tid)
		return 0;
	file = bpf_get_task_exe_file(p);
	if (!file)
		return 0;
	dives();
	behind++;
	bpf_put_file(file);
	return 0;
}

long exe_file_refs;

/* The references to the file that the task which runs the progs was executed from, less one */
SEC("tc")
int probe_exe_file(struct __sk_buff *skb)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct mm_struct *mm = task->mm;
	struct file *file;

	if (!mm)
		return TC_ACT_OK;
	file = mm->exe_file;
	if (file)
		exe_file_refs = file->f_ref.refcnt.counter;
	return TC_ACT_OK;
}

struct ksock_val {
	struct bpf_ksock __kptr *ks;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ksock_val);
} ksocks SEC(".maps");

/* As for the cpumask, the map has a second reference when the prog is cancelled */
SEC("syscall")
__description("cancel refs: the kernel socket of a frame that waits in a call is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int ksock_at_call(void *ctx)
{
	struct bpf_ksock_create_opts opts = { .family = AF_INET, .type = SOCK_DGRAM };
	struct bpf_ksock *ks, *held, *old;
	struct ksock_val *v;
	int key = 0, err;

	v = bpf_map_lookup_elem(&ksocks, &key);
	if (!v)
		return 1;
	ks = bpf_ksock_create(&opts, sizeof(opts), &err);
	if (!ks)
		return 1;
	held = bpf_ksock_acquire(ks);
	if (!held) {
		bpf_ksock_release(ks);
		return 1;
	}
	old = bpf_kptr_xchg(&v->ks, held);
	if (old)
		bpf_ksock_release(old);
	dives();
	behind++;
	bpf_ksock_release(ks);
	return 1;
}

int ksock_usage;

/* The references to the socket that ksock_at_call() left in the map, this one among them */
SEC("syscall")
int probe_ksock(void *ctx)
{
	struct bpf_ksock *ks;
	struct ksock_val *v;
	int key = 0;

	v = bpf_map_lookup_elem(&ksocks, &key);
	if (!v)
		return 1;
	ks = bpf_kptr_xchg(&v->ks, NULL);
	if (!ks)
		return 1;
	ksock_usage = ks->usage.refs.counter;
	bpf_ksock_release(ks);
	return 0;
}

/* Put the conntrack entry that the next two progs look up into the table, for 30 s */
SEC("tc")
int ct_insert(struct __sk_buff *skb)
{
	struct bpf_ct_opts opts = { .netns_id = BPF_F_CURRENT_NETNS, .l4proto = IPPROTO_UDP };
	struct bpf_sock_tuple tuple = {};
	struct nf_conn___init *init;
	struct nf_conn *ct;

	fill_tuple(&tuple);
	init = bpf_skb_ct_alloc(skb, &tuple, sizeof(tuple.ipv4), &opts, sizeof(opts));
	if (!init)
		return TC_ACT_OK;
	bpf_ct_set_timeout(init, 30000);
	ct = bpf_ct_insert_entry(init);
	if (ct)
		bpf_ct_release(ct);
	return TC_ACT_OK;
}

SEC("tc")
__description("cancel refs: the conntrack entry of a frame that waits in a call is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int ct_at_call(struct __sk_buff *skb)
{
	struct bpf_ct_opts opts = { .netns_id = BPF_F_CURRENT_NETNS, .l4proto = IPPROTO_UDP };
	struct bpf_sock_tuple tuple = {};
	struct nf_conn *ct;

	fill_tuple(&tuple);
	ct = bpf_skb_ct_lookup(skb, &tuple, sizeof(tuple.ipv4), &opts, sizeof(opts));
	if (!ct)
		return TC_ACT_OK;
	dives();
	behind++;
	bpf_ct_release(ct);
	return TC_ACT_OK;
}

int ct_use;

/* The references to the conntrack entry, this one among them */
SEC("tc")
int probe_ct(struct __sk_buff *skb)
{
	struct bpf_ct_opts opts = { .netns_id = BPF_F_CURRENT_NETNS, .l4proto = IPPROTO_UDP };
	struct bpf_sock_tuple tuple = {};
	struct nf_conn *ct;

	fill_tuple(&tuple);
	ct = bpf_skb_ct_lookup(skb, &tuple, sizeof(tuple.ipv4), &opts, sizeof(opts));
	if (!ct)
		return TC_ACT_OK;
	ct_use = ct->ct_general.use.refs.counter;
	bpf_ct_release(ct);
	return TC_ACT_OK;
}

/* The xfrm state that the progs look up, as the runner added it */
__u32 xfrm_daddr;
__u32 xfrm_spi;

static __always_inline void fill_xfrm_opts(struct bpf_xfrm_state_opts *opts)
{
	opts->netns_id = BPF_F_CURRENT_NETNS;
	opts->daddr.a4 = xfrm_daddr;
	opts->spi = xfrm_spi;
	opts->proto = IPPROTO_ESP;
	opts->family = AF_INET;
}

/* A cancelled XDP prog returns XDP_ABORTED */
SEC("xdp")
__description("cancel refs: the xfrm state of a frame that waits in a call is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int xfrm_state_at_call(struct xdp_md *xdp)
{
	struct bpf_xfrm_state_opts opts = {};
	struct xfrm_state *x;

	fill_xfrm_opts(&opts);
	x = bpf_xdp_get_xfrm_state(xdp, &opts, sizeof(opts));
	if (!x)
		return XDP_PASS;
	dives();
	behind++;
	bpf_xdp_xfrm_state_release(x);
	return XDP_PASS;
}

int xfrm_refcnt;

/* The references to the xfrm state, this one among them */
SEC("xdp")
int probe_xfrm_state(struct xdp_md *xdp)
{
	struct bpf_xfrm_state_opts opts = {};
	struct xfrm_state *x;

	fill_xfrm_opts(&opts);
	x = bpf_xdp_get_xfrm_state(xdp, &opts, sizeof(opts));
	if (!x)
		return XDP_PASS;
	xfrm_refcnt = x->refcnt.refs.counter;
	bpf_xdp_xfrm_state_release(x);
	return XDP_PASS;
}

/*
 * The lock of the wakeup sources is an SRCU read lock, and the reference is its index plus
 * one. A wakeup source is not removed while the lock is held, which is how the runner tells
 * that the pad released it.
 */
SEC("syscall")
__description("cancel refs: the lock of the wakeup sources is released")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int ws_lock_at_call(void *ctx)
{
	struct bpf_ws_lock *lock;

	lock = bpf_wakeup_sources_read_lock();
	dives();
	behind++;
	bpf_wakeup_sources_read_unlock(lock);
	return 1;
}

/*
 * An object that the prog owns: one of bpf_obj_new() or bpf_percpu_obj_new(), a reference of
 * bpf_refcount_acquire() to it, or a node that was popped from a list. The pad drops it the
 * way bpf_obj_drop() does, with the fields of its type.
 *
 * All but the per-CPU object keep the task of the runner in a kptr, which the last reference
 * to the object releases when it is dropped. So the runner counts the references to the task.
 */

struct holder {
	struct task_struct __kptr *task;
};

struct counted {
	struct bpf_refcount ref;
	struct task_struct __kptr *task;
};

struct pcpu_val {
	long a;
	long b;
};

/* The node of a list is the first member of its object, */
struct elem {
	struct bpf_list_node node;
	struct task_struct __kptr *task;
};

/* or it is not: then a pointer to the node points into the object */
struct elem_tail {
	struct task_struct __kptr *task;
	struct bpf_list_node node;
};

struct stash_val {
	struct counted __kptr *counted;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct stash_val);
} stash SEC(".maps");

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))

private(L) struct bpf_spin_lock list_lock;
private(L) struct bpf_list_head list_head __contains(elem, node);
private(T) struct bpf_spin_lock tail_lock;
private(T) struct bpf_list_head tail_head __contains(elem_tail, node);

/* Put a reference to the task of the runner into @field, the kptr of an object */
static __always_inline void hold_task(void *field)
{
	struct task_struct *task, *old;

	task = bpf_task_from_pid(pid);
	if (!task)
		return;
	old = bpf_kptr_xchg(field, task);
	if (old)
		bpf_task_release(old);
}

SEC("tc")
__description("cancel refs: an object of bpf_obj_new() is dropped with what its fields hold")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int obj_at_call(struct __sk_buff *skb)
{
	struct holder *h;

	h = bpf_obj_new(typeof(*h));
	if (!h)
		return TC_ACT_OK;
	hold_task(&h->task);
	dives();
	behind++;
	bpf_obj_drop(h);
	return TC_ACT_OK;
}

/*
 * The object has two references: one goes to the map, and the frame holds the other one when
 * it is cancelled. The pad drops that, and the object stays until drop_stashed() runs.
 */
SEC("tc")
__description("cancel refs: a reference of bpf_refcount_acquire() is dropped")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int refcounted_at_call(struct __sk_buff *skb)
{
	struct counted *c, *held, *old;
	struct stash_val *v;
	int key = 0;

	v = bpf_map_lookup_elem(&stash, &key);
	if (!v)
		return TC_ACT_OK;
	c = bpf_obj_new(typeof(*c));
	if (!c)
		return TC_ACT_OK;
	hold_task(&c->task);
	held = bpf_refcount_acquire(c);
	old = bpf_kptr_xchg(&v->counted, c);
	if (old)
		bpf_obj_drop(old);
	dives();
	behind++;
	bpf_obj_drop(held);
	return TC_ACT_OK;
}

/* A per-CPU object has no fields that hold anything */
SEC("tc")
__description("cancel refs: an object of bpf_percpu_obj_new() is dropped")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int percpu_obj_at_call(struct __sk_buff *skb)
{
	struct pcpu_val __percpu_kptr *p;

	p = bpf_percpu_obj_new(struct pcpu_val);
	if (!p)
		return TC_ACT_OK;
	dives();
	behind++;
	bpf_percpu_obj_drop(p);
	return TC_ACT_OK;
}

/*
 * The prog tests what it popped behind the call only. The pointer to the node is the pointer
 * to the object, so the pad tests it and drops the object.
 */
SEC("tc")
__description("cancel refs: a node that was popped from a list is dropped")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int list_node_at_call(struct __sk_buff *skb)
{
	struct bpf_list_node *n;

	bpf_spin_lock(&list_lock);
	n = bpf_list_pop_front(&list_head);
	bpf_spin_unlock(&list_lock);
	dives();
	behind++;
	if (n)
		bpf_obj_drop(container_of(n, struct elem, node));
	return TC_ACT_OK;
}

/*
 * The frame has the pointer to the node, 8 bytes into the object, and no pointer to the
 * object until the prog has made one behind the call. The pad makes it: it tests the pointer
 * to the node, takes the 8 bytes off and drops the object.
 */
SEC("tc")
__description("cancel refs: a node that is not the first member is dropped with its object")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int list_node_not_first(struct __sk_buff *skb)
{
	struct bpf_list_node *n;

	bpf_spin_lock(&tail_lock);
	n = bpf_list_pop_front(&tail_head);
	bpf_spin_unlock(&tail_lock);
	dives();
	behind++;
	if (n)
		bpf_obj_drop(container_of(n, struct elem_tail, node));
	return TC_ACT_OK;
}

/* The same with the pointer to the node in a stack slot, where the insns of the pad show */
SEC("tc")
__description("cancel refs: a node in a stack slot is dropped with the object that it is in")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("exit")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("if r1 == 0x0 goto pc+5")
__xlated("r1 += -8")
__xlated("r2 = 0x{{.*}}")
__xlated("r3 = 0")
__xlated("call unknown")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__naked void list_node_spilled(void)
{
	asm volatile (
		"r1 = %[tail_lock] ll;"
		"call %[bpf_spin_lock];"
		"r1 = %[tail_head] ll;"
		"call %[bpf_list_pop_front];"
		"*(u64 *)(r10 - 8) = r0;"
		"r1 = %[tail_lock] ll;"
		"call %[bpf_spin_unlock];"
		"call dives;"
		COUNT(behind)
		"r1 = *(u64 *)(r10 - 8);"
		"if r1 == 0 goto 1f;"
		"r1 += -8;"
		"call %[bpf_obj_drop];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm(bpf_list_pop_front),
		  __imm(bpf_obj_drop),
		  __imm_addr(tail_lock),
		  __imm_addr(tail_head),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * Only an object that the prog owns is found through a pointer into it. A kernel object is
 * released by a kfunc that takes the pointer which was acquired, and the frame has no such
 * pointer at the call.
 */
SEC("?tc")
__description("cancel refs: a pointer into a task is rejected")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure
__msg("the program cannot be cancelled at this call:")
__msg("(place)")
__naked void pointer_into_task(void)
{
	asm volatile (
		TASK_FROM_PID
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
		"r6 += 8;"
		"call dives;"
		"r6 += -8;"
		"r1 = r6;"
		"call %[bpf_task_release];"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid)
		: __clobber_all
	);
}

/*
 * One frame holds something of every kind. The pad discards the dynptr, destroys the
 * iterator and releases the three references, each the way of its kind.
 */
SEC("tc")
__description("cancel refs: an iterator, a dynptr, a task, a record and an object of one frame")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int several_kinds_at_call(struct __sk_buff *skb)
{
	struct task_struct *task;
	struct bpf_dynptr ptr;
	struct bpf_iter_num it;
	struct holder *h;
	void *rec;

	bpf_iter_num_new(&it, 0, 3);
	bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, &ptr);
	task = bpf_task_from_pid(pid);
	rec = bpf_ringbuf_reserve(&ringbuf, 8, 0);
	h = bpf_obj_new(typeof(*h));
	if (!h)
		goto out;
	hold_task(&h->task);
	dives();
	behind++;
	bpf_obj_drop(h);
out:
	if (rec)
		bpf_ringbuf_discard(rec, 0);
	if (task)
		bpf_task_release(task);
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	bpf_iter_num_destroy(&it);
	return TC_ACT_OK;
}

/* The runner sets the lists up and clears the map with the next three */

/* A node that holds the task, for list_node_at_call() to pop */
SEC("tc")
int list_push(struct __sk_buff *skb)
{
	struct elem *e;

	e = bpf_obj_new(typeof(*e));
	if (!e)
		return TC_ACT_OK;
	hold_task(&e->task);
	bpf_spin_lock(&list_lock);
	bpf_list_push_front(&list_head, &e->node);
	bpf_spin_unlock(&list_lock);
	return TC_ACT_OK;
}

/* and one for list_node_not_first() and list_node_spilled() */
SEC("tc")
int tail_push(struct __sk_buff *skb)
{
	struct elem_tail *e;

	e = bpf_obj_new(typeof(*e));
	if (!e)
		return TC_ACT_OK;
	hold_task(&e->task);
	bpf_spin_lock(&tail_lock);
	bpf_list_push_front(&tail_head, &e->node);
	bpf_spin_unlock(&tail_lock);
	return TC_ACT_OK;
}

/* Drop the reference that refcounted_at_call() left in the map */
SEC("tc")
int drop_stashed(struct __sk_buff *skb)
{
	struct stash_val *v;
	struct counted *c;
	int key = 0;

	v = bpf_map_lookup_elem(&stash, &key);
	if (!v)
		return TC_ACT_OK;
	c = bpf_kptr_xchg(&v->counted, NULL);
	if (c)
		bpf_obj_drop(c);
	return TC_ACT_OK;
}
