// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

/* The verifier doesn't know what is in there */
unsigned long one = 1;

/* The count of the task that runs the progs, which bpf_task_acquire() raises */
SEC("syscall")
int task_usage(void *ctx)
{
	return bpf_get_current_task_btf()->rcu_users.refs.counter;
}

/* The same while the prog holds one more: the count sees a reference that is held */
SEC("syscall")
int task_usage_holding(void *ctx)
{
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf());
	int usage;

	if (!t)
		return 0;
	usage = t->rcu_users.refs.counter;
	bpf_task_release(t);
	return usage;
}

/* The loop is out of time while the prog holds one more reference: its landing pad releases it */
SEC("syscall")
int guard_holds_task(void *ctx)
{
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf());

	if (!t)
		return 1;
	while (*(volatile unsigned long *)&one)
		;
	bpf_task_release(t);
	return 7;
}

/* The same with may_goto that the prog has: its time is up, and it ends the prog */
SEC("syscall")
int may_goto_holds_task(void *ctx)
{
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf());

	if (!t)
		return 1;
	while (can_loop)
		;
	bpf_task_release(t);
	return 7;
}

static __noinline int spins(void)
{
	while (can_loop)
		;
	return 0;
}

/* It is up in a subprog: the pad of the call in the prog releases what the prog holds */
SEC("syscall")
int callee_may_goto_caller_holds_task(void *ctx)
{
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf());
	int ret;

	if (!t)
		return 1;
	ret = spins();
	bpf_task_release(t);
	return 7 + ret;
}

SEC("syscall")
int throw_holds_task(void *ctx)
{
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf());

	if (!t)
		return 1;
	if (one)
		bpf_throw(0);
	bpf_task_release(t);
	return 7;
}

static __naked __noinline __used void frame_of_64(void)
{
	asm volatile (
	"*(u64 *)(r10 - 64) = 0;"
	"r0 = 0;"
	"exit;");
}

/*
 * The pass that joins is good and has the landing pad of the loop. The range of the offset says
 * how long the context must be, so a pass that keeps the 1 << 14 offsets apart follows. It does
 * not get to bpf_loop() in its budget, and the good pass comes back with its landing pad.
 * @loop: a loop that gets may_goto of the verifier, or one that has may_goto of the program.
 */
#define GOOD_PASS_RESTORED(name, loop)							\
SEC("syscall")										\
__naked void name(void)									\
{											\
	asm volatile (									\
	"r6 = r1;"									\
	"*(u64 *)(r10 - 64) = 0;"							\
	"call %[bpf_get_prandom_u32];"							\
	"r5 = 1;"									\
	"r7 = 0;"									\
	".rept 14;"									\
	"r0 >>= 1;"									\
	"if r0 & 1 goto +1;"								\
	"r7 += r5;"									\
	"r5 <<= 1;"									\
	".endr;"									\
	"r1 = r6;"									\
	"r1 += r7;"									\
	"r2 = 8;"									\
	"r3 = 0;"									\
	"call %[bpf_probe_read_kernel];"						\
	"r1 = 2;"									\
	"r2 = frame_of_64 ll;"								\
	"r3 = 0;"									\
	"r4 = 0;"									\
	"call %[bpf_loop];"								\
	"call %[bpf_get_current_task_btf];"						\
	"r1 = r0;"									\
	"call %[bpf_task_acquire];"							\
	"if r0 != 0 goto +2;"								\
	"r0 = 1;"									\
	"exit;"										\
	"r6 = r0;"									\
	loop										\
	"r1 = r6;"									\
	"call %[bpf_task_release];"							\
	"r0 = 7;"									\
	"exit;"										\
	:: __imm(bpf_get_prandom_u32), __imm(bpf_probe_read_kernel), __imm(bpf_loop),	\
	   __imm(bpf_get_current_task_btf), __imm(bpf_task_acquire), __imm(bpf_task_release), \
	   __imm_addr(one)								\
	: __clobber_all);								\
}

GOOD_PASS_RESTORED(good_pass_restored_holds_task,
		   "1: r1 = %[one] ll;"
		   "r1 = *(u64 *)(r1 + 0);"
		   "if r1 != 0 goto 1b;")
GOOD_PASS_RESTORED(good_pass_restored_may_goto_holds_task,
		   "1: may_goto 2f;"
		   "goto 1b;"
		   "2:")

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 8);
} arena SEC(".maps");

/*
 * A load from the arena, where no page is: it faults, and the prog is unwound. r2 becomes an
 * address in arena by addr_space_cast(r2, 0x0, 0x1), which the assembler of GCC doesn't know.
 */
#define FAULT()								\
	asm volatile (							\
		"r1 = %[arena] ll;"					\
		"r2 = 0x1000;"						\
		".8byte 0x1000122bf;"					\
		"r2 = *(u32 *)(r2 + 0);"				\
		:: __imm_addr(arena) : "r1", "r2")

/* The access faults while the prog holds one more reference: the landing pad releases it */
SEC("syscall")
int fault_holds_task(void *ctx)
{
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf());

	if (!t)
		return 1;
	FAULT();
	bpf_task_release(t);
	return 7;
}

/* User space says whether the progs below take a reference: the verifier doesn't know */
unsigned long take = 1;

/*
 * The prog holds the reference on some paths, and its pointer is to a task on all of them: no
 * place tells, a hidden slot does. The pad releases what the slot has, and nothing where the
 * prog took no reference.
 */
SEC("syscall")
int fault_slot_holds_task(void *ctx)
{
	struct task_struct *t = NULL, *cur = bpf_get_current_task_btf();
	bool own;

	if (take)
		t = bpf_task_acquire(cur);
	own = !!t;
	barrier_var(own);
	if (!t)
		t = cur;
	barrier_var(t);
	FAULT();
	if (own)
		bpf_task_release(t);
	return 7;
}

static __noinline int faults(void)
{
	FAULT();
	return 0;
}

/* The same with the access in a callee: the pad of the call in the prog reads the slot */
SEC("syscall")
int callee_faults_caller_slot(void *ctx)
{
	struct task_struct *t = NULL, *cur = bpf_get_current_task_btf();
	bool own;
	int ret;

	if (take)
		t = bpf_task_acquire(cur);
	own = !!t;
	barrier_var(own);
	if (!t)
		t = cur;
	barrier_var(t);
	ret = faults();
	if (own)
		bpf_task_release(t);
	return 7 + ret;
}

static __noinline int waits(void)
{
	while (*(volatile unsigned long *)&one)
		;
	return 0;
}

/* The callee is unwound, and the pad of the call in the prog releases what the prog holds */
SEC("syscall")
int callee_unwinds_caller_holds_task(void *ctx)
{
	struct task_struct *t = bpf_task_acquire(bpf_get_current_task_btf());
	int ret;

	if (!t)
		return 1;
	ret = waits();
	bpf_task_release(t);
	return 7 + ret;
}
