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

/* clang makes no BTF for a kfunc that only asm calls, and libbpf needs it to link the prog */
void __kfunc_btf_root(void)
{
	bpf_iter_num_new(0, 0, 0);
	bpf_iter_num_destroy(0);
}

/* What the progs take: the task with this pid, another task, and the cgroup with this id */
int pid;
int pid2;
__u64 cgid;
