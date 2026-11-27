// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

/*
 * What verifier_kunwind.c has, in a prog with an arena. An arena takes a JIT, and a map that
 * cannot be made fails every test of its object: the tests that also run without a JIT stay there.
 */
#define unwind_goto(off) ".8byte %[insn_unwind_goto_" #off "];"
#define unwind_exit ".8byte %[insn_unwind_exit];"

#define __imm_unwind_goto(off) \
	__imm_insn(insn_unwind_goto_##off, \
		   BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, off, 0))
#define __imm_unwind_exit \
	__imm_insn(insn_unwind_exit, \
		   BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* kfuncs that only asm calls need BTF */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
}

/* The verifier doesn't know what is in there */
unsigned long two = 2;

/*
 * In a prog that has an arena the callers of a global subprog expect the kernel to unwind it, from
 * the first pass on. This one is left at no site of the kernel. It has unwind_exit, and that says
 * nothing about kexit: the state that the callers expect holds more than a pad of the verifier
 * leaves, and it is dropped, since no kexit comes back to the call. The pad of the prog is for
 * unwind_exit, and it leaves all nine sections.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

/* Not naked: a global function needs BTF, and the branch keeps the return reachable */
__noinline int global_unwinds_or_returns(void)
{
	if (two == 2)
		asm volatile ("r0 = 5;" unwind_exit :: __imm_unwind_exit : "r0");
	return 7;
}

SEC("tc")
__description("kunwind: unwind_exit of a global subprog does not make its kexit certain")
__success __retval(47)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void global_unwind_exit_in_arena_prog(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"call global_unwinds_or_returns;"
		unwind_goto(12)
		"r6 = r0;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = r6;"
		"exit;"
		"r6 = r0;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = r6;"
		"r0 += 42;"
		"exit;"
		:: __imm_addr(arena), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock),
		   __imm_unwind_goto(12) : __clobber_all);
}

char _license[] SEC("license") = "GPL";
