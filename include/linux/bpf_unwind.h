/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_UNWIND_H
#define _LINUX_BPF_UNWIND_H

/*
 * A helper that calls a callback is a C frame between the callback and the BPF
 * code that called the helper. unwind_exit of the callback returns to the pad of
 * its caller when the caller has one, so a helper lets its callback unwind by
 * having one: bpf_call_cb() calls the callback with an extable entry at the
 * return address that points to a label in the helper. There the helper drops
 * what it holds and leaves the way a BPF frame leaves at unwind_exit, with
 * bpf_unwind_leave(): its return address becomes the pad of its caller, which
 * the verifier insists on, and r0 is what the callback unwound with, since the
 * output of the call is valid on both edges. The slot that holds the return
 * address is where the compiler knows it to be, at the canonical frame address
 * of the helper, so nothing is looked up and nothing is saved beforehand. That
 * makes the pad part of the frame that the BPF code called, or of one called
 * with a pad in turn: a body that two entry points share is inlined into both,
 * not called by them, and a function with a pad is noinline, so that the
 * compiler neither inlines it into another frame nor splits the pad, cold as it
 * is, out of it into a part of its own, as gcc's ipa-split otherwise does. It
 * is notrace and on the kprobe blacklist as well: the trampoline of an fexit or
 * fmod_ret program, the function graph tracer, an fprobe and a kretprobe put a
 * return address of their own in the slot, and the pad would miss. Only fentry
 * may attach to a subprog that unwinds, for the same reason, and that goes too.
 *
 * The call is the one the compiler would make, kCFI check included: against
 * the type of a callback, or, with __bpf_call_cb(), against the type of a
 * function declared with BPF_CB_PAD_TYPE(). The entry is EX_TYPE_BPF, keyed at
 * the return address: bpf_unwind_target() looks it up, and takes no other kind
 * from the kernel tables. fixup_exception() searches the same table and would
 * take the entry for one of a JIT. So the insn after bpf_call_cb() must be one
 * that cannot fault and has no fixup of its own, which holds in the helpers.
 * objtool reads __ex_table and wants the key to be an insn, which is why it
 * isn't ret_addr - 1 as in the JITs.
 *
 * The outputs of an asm goto are valid on the way to a label as well as on the
 * way out with every compiler that has them and that the kernel takes, see
 * CC_HAS_ASM_GOTO_OUTPUT. So r0 is what the callback left on either edge.
 * Without asm goto outputs, or on an arch whose JIT does no unwinding, the
 * callback is called the plain way and BPF_HAS_CB_PADS tells the verifier that
 * a callback cannot unwind.
 *
 * A callback leaves in two ways, and the helper has to leave the way its
 * callback did: with unwind_exit when the program unwinds, which goes to
 * unwind_goto after the call of the helper, and with kexit when the kernel
 * unwinds the program, which goes to kgoto and never to a landing pad that the
 * program has. A return address has one entry in the table, so the entry
 * points to a stub with two ways in, BPF_CB_PAD_OFF and BPF_CB_KPAD_OFF bytes
 * from its start: the first one is where unwind_exit returns to, the second one
 * is where kexit does, see bpf_kunwind_target(). The stub tells the label which
 * one it was, in 'kind', and bpf_unwind_leave() looks for the pad of the same
 * kind. The stub is out of line: the helper pays nothing for it when the
 * callback returns. Nothing else of the callback gets through the frame of a
 * helper: R2 after kexit is not what the callback left there. Kernel code that
 * does not leave with bpf_unwind_leave() after kexit ends the invocation
 * itself, see bpf_prog_unwound_to_kernel() for what it has to do then.
 */

#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/kprobes.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/stringify.h>

/* UML on x86-64 has no JIT, and the x86 headers below are not for it */
#if defined(CONFIG_X86_64) && !defined(CONFIG_UML) && defined(CONFIG_CC_HAS_ASM_GOTO_OUTPUT)

#include <asm/asm.h>
#include <asm/extable_fixup_types.h>
#include <asm/nospec-branch.h>

#define BPF_HAS_CB_PADS 1

#ifdef CONFIG_CFI
/*
 * The kCFI check of the compiler, byte for byte: the hash where the compiler
 * and the JIT put it, the trap in .kcfi_traps, the target in r11 for the
 * FineIBT form. apply_fineibt() and handle_cfi_failure() take the site for one
 * of the compiler's. The type id is the symbol clang emits for a declaration
 * of that type once its address is taken, which BPF_CB_PAD_TYPE() sees to, and
 * the assembler negates it, since the symbol is absolute.
 */
#define BPF_CB_PAD_TYPE(name, type)						\
	extern type name;							\
	__ADDRESSABLE(name)

#ifdef CONFIG_CALL_PADDING
#define BPF_KCFI_HASH_OFF	(4 + CONFIG_FUNCTION_PADDING_CFI)
#else
#define BPF_KCFI_HASH_OFF	4
#endif

#define BPF_KCFI_CHECK(type)							\
	"	movl $-__kcfi_typeid_" #type ", %%r10d\n"			\
	"	addl -" __stringify(BPF_KCFI_HASH_OFF) "(%%r11), %%r10d\n"	\
	"	je 2f\n"							\
	"3:	ud2\n"								\
	"	.pushsection .kcfi_traps, \"ao\", @progbits, .text\n"		\
	"	.long 3b - .\n"							\
	"	.popsection\n"							\
	"2:\n"
#else
#define BPF_CB_PAD_TYPE(name, type)
#define BPF_KCFI_CHECK(type)
#endif

/*
 * How far the two ways into the stub are from its start. unwind_exit returns behind
 * an int3: a stack walk looks up the insn in front of a return address, and for
 * the frame of the helper that has to be an insn of the stub. Without one it
 * is the end of whatever stands in front of the stub in the section, and a
 * sample that is taken between the store of the new return address and the
 * return goes wrong above the callback. Nothing runs the int3. It is no nop
 * because a kprobe in front of the stub can be optimized into a jump of 5
 * bytes, which takes in the insns behind the probe: with a nop it could end
 * behind the way in, and unwind_exit would return into the jump. No such jump
 * takes in an int3, see copy_optimized_instructions(), or the jnc in front of
 * the way in of kexit. kexit returns behind clc and jnc.
 */
#define BPF_CB_PAD_OFF	1
#define BPF_CB_KPAD_OFF	4

/*
 * The registers the call clobbers are outputs, so that none of them can be an
 * operand of anything else. r0 is rax, on the way out and on the way to the pad.
 * The return address stays the byte after the call through what
 * apply_retpolines() and apply_fineibt() make of the call: they pad in front of
 * it, never behind it. The arguments are evaluated before the register variables
 * are set: a call among them, instrumentation included, would clobber what the
 * variables hold, which the compiler does not keep across a call.
 *
 * The stub is behind the code of the section, where nothing falls into it.
 * unwind_exit returns behind the int3 at 4, with the carry flag clear from there
 * on, kexit to 5, which sets it, and 'kind' is 0 or not from the flag: rcx is
 * clobbered by the call anyway. objtool gets to 4 by the table and to 5 by what
 * it takes for the other edge of the jump, which is always taken. The jump is
 * spelled in bytes, for the distance not to depend on what an assembler makes
 * of it.
 */
#define __bpf_call_cb(type, fn, a1, a2, a3, a4, a5, r0, kind, unwound)		\
do {										\
	u64 __f = (u64)(long)(fn), __1 = (u64)(long)(a1), __2 = (u64)(long)(a2),	\
	    __3 = (u64)(long)(a3), __4 = (u64)(long)(a4), __5 = (u64)(long)(a5);	\
	register u64 __fn asm("r11") = __f;					\
	register u64 __a5 asm("r8") = __5;					\
	register u64 __c5 asm("r8");						\
	register u64 __c11 asm("r11");						\
	u64 __c1, __c2, __c3;							\
										\
	asm_goto_output(BPF_KCFI_CHECK(type)					\
		 "	" CALL_NOSPEC "\n"					\
		 "1:\n"								\
		 "	.subsection 1\n"					\
		 "4:	int3\n"							\
		 "	clc\n"							\
		 "	.byte 0x73, 0x01\n"	/* jnc 6f */			\
		 "5:	stc\n"							\
		 "6:	sbb %%ecx, %%ecx\n"					\
		 "	jmp %l[" __stringify(unwound) "]\n"			\
		 "	.previous\n"						\
		 _ASM_EXTABLE_TYPE(1b, 4b, EX_TYPE_BPF)				\
		 : "=a"(r0), "=D"(__c1), "=S"(__c2), "=d"(__c3), "=c"(kind),	\
		   "=r"(__c5), "=r"(__c11)					\
		 : [thunk_target] "r"(__fn), "D"(__1), "S"(__2), "d"(__3),	\
		   "c"(__4), "r"(__a5)						\
		 : "r9", "r10", "memory", "cc"					\
		 : unwound);							\
} while (0)

/*
 * The return address of the helper is the word below its canonical frame
 * address. The pad is in the frame that BPF code called, see above, so there is
 * a pad to go to. It is the return address itself after 'unwind_goto +0': the
 * JIT emits no code for unwind_goto, so the same address says nothing of a miss.
 * @kind: what the stub of bpf_call_cb() left, not 0 if the callback left with
 * kexit. Then the pad is the one of kgoto.
 * The store is the last thing before the return, into the frame of the function
 * itself, which a compiler may take for a dead store: hence WRITE_ONCE(), as
 * lkdtm writes its return address through a volatile pointer.
 */
static __always_inline void bpf_unwind_leave(u64 kind)
{
	unsigned long *slot = (unsigned long *)__builtin_dwarf_cfa() - 1;

	WRITE_ONCE(*slot, kind ? bpf_kunwind_target(*slot) : bpf_unwind_target(*slot));
}

#elif defined(CONFIG_ARM64) && defined(CONFIG_CC_HAS_ASM_GOTO_OUTPUT)

#include <linux/scs.h>
#include <asm/asm-extable.h>
#include <asm/brk-imm.h>
#include <asm/compiler.h>

#define BPF_HAS_CB_PADS 1

#ifdef CONFIG_CFI
/*
 * The kCFI check of the compiler: the type id comes in w17, the target is in
 * x15, and the brk says so. The hash of the callee is the word before it.
 */
#define BPF_CB_PAD_TYPE(name, type)						\
	extern type name;							\
	__ADDRESSABLE(name)

#define BPF_KCFI_CHECK(type)							\
	"	ldur w16, [x15, #-4]\n"						\
	"	movz w17, #:abs_g0_nc:__kcfi_typeid_" #type "\n"		\
	"	movk w17, #:abs_g1_nc:__kcfi_typeid_" #type "\n"		\
	"	cmp w16, w17\n"							\
	"	b.eq 2f\n"							\
	"	brk #" __stringify((CFI_BRK_IMM_BASE | (17 << 5) | 15)) "\n"	\
	"2:\n"
#else
#define BPF_CB_PAD_TYPE(name, type)
#define BPF_KCFI_CHECK(type)
#endif

/*
 * With a shadow call stack x18 holds it, the callee keeps it, and the compiler
 * has it reserved. Without one it's a temporary like the rest.
 */
#ifdef CONFIG_SHADOW_CALL_STACK
#define BPF_CB_CLOBBER_X18
#else
#define BPF_CB_CLOBBER_X18	"x18",
#endif

/* How far the two ways into the stub are from its start: the second one is two insns in */
#define BPF_CB_PAD_OFF	0
#define BPF_CB_KPAD_OFF	8

/*
 * r0 is x0, which only a register variable can name, and gcc does not keep what
 * such a variable holds across a call. KCOV puts a call at the head of each
 * block, and an asm goto ends its block, so C code after it reads x0 too late on
 * either edge. Hence the asm moves x0 to r0 itself, behind the call and where
 * the callback unwinds to, out of line. For the same reason the arguments are
 * evaluated before the register variables are set.
 * unwind_exit returns to 3 and kexit to 4. Each goes to a label of its own in
 * here, where 'kind' is set, and from there to the label of the helper: a
 * register that says which one it was would have to be one that the call keeps,
 * and the helper would save it also when the callback returns.
 */
#define __bpf_call_cb(type, fn, a1, a2, a3, a4, a5, r0, kind, unwound)		\
do {										\
	__label__ __prog, __kern;						\
	u64 __f = (u64)(long)(fn), __1 = (u64)(long)(a1), __2 = (u64)(long)(a2),	\
	    __3 = (u64)(long)(a3), __4 = (u64)(long)(a4), __5 = (u64)(long)(a5);	\
	register u64 __fn asm("x15") = __f;					\
	register u64 __a0 asm("x0") = __1;					\
	register u64 __a1 asm("x1") = __2;					\
	register u64 __a2 asm("x2") = __3;					\
	register u64 __a3 asm("x3") = __4;					\
	register u64 __a4 asm("x4") = __5;					\
	register u64 __c0 asm("x0");						\
	register u64 __c1 asm("x1");						\
	register u64 __c2 asm("x2");						\
	register u64 __c3 asm("x3");						\
	register u64 __c4 asm("x4");						\
	register u64 __c15 asm("x15");						\
										\
	asm_goto_output(BPF_KCFI_CHECK(type)					\
		 "	blr x15\n"						\
		 "1:	mov %[ret], x0\n"					\
		 "	.subsection 1\n"					\
		 "3:	mov %[ret], x0\n"					\
		 "	b %l[__prog]\n"						\
		 "4:	mov %[ret], x0\n"					\
		 "	b %l[__kern]\n"						\
		 "	.previous\n"						\
		 __ASM_EXTABLE_RAW("1b", "3b", __stringify(EX_TYPE_BPF), "0")	\
		 : [ret] "=r"(r0), "=r"(__c0), "=r"(__c1), "=r"(__c2),		\
		   "=r"(__c3), "=r"(__c4), "=r"(__c15)				\
		 : "r"(__fn), "r"(__a0), "r"(__a1), "r"(__a2), "r"(__a3),	\
		   "r"(__a4)							\
		 : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",	\
		   "x14", "x16", "x17", BPF_CB_CLOBBER_X18 "x30", "memory", "cc"	\
		 : __prog, __kern);						\
	break;									\
__prog:										\
	(kind) = 0;								\
	goto unwound;								\
__kern:										\
	(kind) = 1;								\
	goto unwound;								\
} while (0)

/*
 * The return address of the helper is the second word of its frame record. The
 * pad is in the frame that BPF code called, see above, so there is a pad to go
 * to: a miss is a bug, and the exception would be lost in a return.
 *
 * With pointer authentication the return address is signed with the stack
 * pointer at entry, which is the canonical frame address, so the new one is
 * signed the same way; pacia1716 is a hint, a nop without pointer
 * authentication, like paciasp. clang has __builtin_dwarf_cfa() stand for the
 * frame pointer on arm64 and __builtin_sponentry() for the stack pointer at
 * entry. The shadow call stack holds a copy, which the epilogue prefers, when
 * it is on: a dynamic one stays off where there is pointer authentication. A
 * static one is on next to it and holds what the compiler pushed: gcc and clang
 * from 21 on sign first, so the copy is the word of the frame record, clang up
 * to 20 pushes first and pops last, so the copy is plain. KASAN has the shadow
 * call stack poisoned, like the compiler the asm is not checked.
 * @kind: see x86-64 above.
 */
static __always_inline void bpf_unwind_leave(u64 kind)
{
	unsigned long *slot = (unsigned long *)__builtin_frame_address(0) + 1;
	unsigned long old = *slot;
	unsigned long from = ptrauth_strip_kernel_insn_pac(old);
	unsigned long to = kind ? bpf_kunwind_target(from) : bpf_unwind_target(from), sig = to;

	WARN_ON_ONCE(to == from);
#ifdef CONFIG_ARM64_PTR_AUTH_KERNEL
	{
		register unsigned long x17 asm("x17") = to;
#ifdef __clang__
		register unsigned long x16 asm("x16") = (unsigned long)__builtin_sponentry();
#else
		register unsigned long x16 asm("x16") = (unsigned long)__builtin_dwarf_cfa();
#endif

		asm("pacia1716" : "+r"(x17) : "r"(x16));
		sig = x17;
	}
#endif
	/* the store is the last before the return, see x86-64 above */
	WRITE_ONCE(*slot, sig);
#ifdef CONFIG_SHADOW_CALL_STACK
	if (scs_is_enabled()) {
		unsigned long copy;

		asm volatile("ldur %0, [x18, #-8]" : "=r"(copy));
		asm volatile("stur %0, [x18, #-8]"
			     : : "r"(copy == old ? sig : to) : "memory");
	}
#endif
}

#else

#define BPF_HAS_CB_PADS 0
#define BPF_CB_PAD_OFF	0
#define BPF_CB_KPAD_OFF	0

#define BPF_CB_PAD_TYPE(name, type)

#define __bpf_call_cb(type, fn, a1, a2, a3, a4, a5, r0, kind, unwound)		\
do {										\
	(r0) = ((bpf_callback_t)(void *)(fn))((u64)(long)(a1), (u64)(long)(a2),	\
					      (u64)(long)(a3), (u64)(long)(a4),	\
					      (u64)(long)(a5));			\
	(kind) = 0;								\
	if (0)									\
		goto unwound;							\
} while (0)

static __always_inline void bpf_unwind_leave(u64 kind)
{
}

#endif

/* A callback: bpf_callback_t */
BPF_CB_PAD_TYPE(__bpf_callback_fn, typeof(*(bpf_callback_t)0));

#define bpf_call_cb(fn, a1, a2, a3, a4, a5, r0, kind, unwound)			\
	__bpf_call_cb(__bpf_callback_fn, fn, a1, a2, a3, a4, a5, r0, kind, unwound)

#endif /* _LINUX_BPF_UNWIND_H */
