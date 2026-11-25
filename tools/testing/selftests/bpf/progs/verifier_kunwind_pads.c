// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * A landing pad of the program that only cleans up and resumes runs when the kernel unwinds its
 * frame. Which pads those are is found on the control flow graph, see bpf_find_kernel_pads():
 * from the pad no insn that returns to the caller is reached, and unwind_exit is. The shapes are
 * those that LLVM makes of C++ and Rust. See prog_tests/kunwind_pads.c for what runs.
 */
/* BPF_JMP | BPF_JCOND with BPF_UNWIND_GOTO in src_reg, and BPF_JMP | BPF_EXIT with BPF_UNWIND_EXIT */
#define unwind_goto(label) ".8byte ((((" #label " - .) / 8 - 1) & 0xffff) << 16) | 0x10e5;"
#define unwind_exit ".8byte 0x1095;"

/* kfuncs that only asm calls need BTF */
void __kfunc_btf_root(void)
{
	bpf_res_spin_lock(NULL);
	bpf_res_spin_unlock(NULL);
	bpf_local_irq_save(NULL);
	bpf_local_irq_restore(NULL);
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_task_release(bpf_task_acquire(bpf_get_current_task_btf()));
	bpf_cgroup_release(bpf_cgroup_from_id(1));
	bpf_res_spin_lock_irqsave(NULL, NULL);
	bpf_res_spin_unlock_irqrestore(NULL, NULL);
	bpf_iter_num_new(NULL, 0, 0);
	bpf_iter_num_destroy(NULL);
	bpf_throw(0);
}

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long one = 1;
unsigned long flag;

/*
 * r1 == 0: returns 7. r1 == 1: a loop that nothing ends, the kernel unwinds it when its time is
 * up. Otherwise it leaves with unwind_exit, r0 = 5.
 */
__naked __noinline __used
static unsigned long leaves(void)
{
	asm volatile (
		"if r1 == 0 goto 2f;"
		"if r1 != 1 goto 3f;"
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	"2:	r0 = 7;"
		"exit;"
	"3:	r0 = 5;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

/* What a destructor does: it writes to memory of the program */
__naked __noinline __used
static void dtor(void)
{
	asm volatile (
		"r1 = %[flag] ll;"
		"r2 = 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"exit;"
		:: __imm_addr(flag) : __clobber_all);
}

/* The personality routine of C++ says in memory whether a clause takes the exception */
__naked __noinline __used
static unsigned long personality(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r0 = *(u64 *)(r1 + 0);"
		"exit;"
		:: __imm_addr(zero) : __clobber_all);
}

/* The kernel unwinds what is called */
#define CALL_LEAVES					\
		"r1 = %[one] ll;"			\
		"r1 = *(u64 *)(r1 + 0);"		\
		"call leaves;"

/* ~Guard(): 'r6 = r0; call dtor; r0 = r6; unwind_exit' */
__naked __noinline __used
static unsigned long with_dtor(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

/*
 * The kernel enters the pad: kgoto behind the call goes to the entry, which sets the hidden word K
 * of the frame and jumps to the pad. unwind_exit of the pad is a jump to code that tests K and
 * leaves with kexit and the value of the kernel, TC_ACT_SHOT. The pad of the verifier in the prog
 * returns that value.
 * Nothing clears K where the function begins: its first insn follows the pad of the prog. The call
 * is not in pad code. So its entry stores without a test, and unwind_goto of the prog goes to a
 * stub behind the function that clears K on the way to the pad.
 */
SEC("tc")
__description("kunwind pads: the kernel enters a pad that only resumes")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__msg("to the landing pad at {{[0-9]+}} of func#1: the kernel unwinds")
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it")
__msg("landing pad of unwind_exit at {{[0-9]+}} in a frame that the kernel unwinds: rcu=0 preempt=0")
__xlated("...")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+6")
__xlated("kgoto pc+7")
__xlated("exit")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("r0 = r6")
__xlated("gotol pc+5")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-6")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-9")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
/*
 * What the normal path pays: a frame for K in a function that had no stack, and no store. The
 * first insn of the prog follows the pushes. The gotos behind the call are no code: the next insn
 * of the prog follows the call. The call of the prog is the one behind the load of its argument:
 * with KASAN the JIT calls a check in front of that load.
 */
__arch_x86_64
__jited("...")
__jited("	subq	$0x8, %rsp")
__jited("	pushq	%rbx")
__jited("	movabsq	${{.*}}, %rdi")
__jited("...")
__jited("	movq	(%rdi), %rdi")
__jited("	callq	0x{{.*}}")
__jited("L{{.*}}:	popq	%rbx")
__jited("	leave")
__arch_arm64
__naked void dtor_only_resumes(void)
{
	asm volatile (
		"call with_dtor;"
		"exit;"
		::: __clobber_all);
}

/* catch (...): the pad goes on with the function. kgoto goes to a pad of the verifier. */
SEC("tc")
__description("kunwind pads: a pad that catches all returns")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at 6 of the call at 3 returns")
__xlated("...")
__xlated("call pc+")
__xlated("unwind_goto pc+2")
__xlated("kgoto pc+3")
__xlated("exit")
__xlated("r0 = 42")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
__naked void catch_all_returns(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r0 = 42;"
		"exit;"
		:: __imm_addr(one) : __clobber_all);
}

/* catch (T &): the personality routine decides between the handler and the resume */
SEC("tc")
__description("kunwind pads: a pad with a typed catch returns")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at 6 of the call at 3 returns")
__naked void typed_catch_returns(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
		"call personality;"
		"if r0 != 1 goto 2f;"
		"r0 = 42;"
		"exit;"
	"2:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

/* noexcept: the pad calls std::terminate(), which is bpf_throw(0). What follows is dead code. */
__naked __noinline __used
static unsigned long with_terminate(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r1 = 0;"
		"call %[bpf_throw];"
		"exit;"
		:: __imm_addr(one), __imm(bpf_throw) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad that terminates has no unwind_exit")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} has no unwind_exit")
__naked void terminate_has_no_unwind_exit(void)
{
	asm volatile (
		"call with_terminate;"
		"exit;"
		::: __clobber_all);
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

/*
 * A tail call that is taken returns to the caller of the frame, whatever insn follows it: the
 * only exit of the pad is unwind_exit, and still the kernel does not enter it.
 */
__naked __noinline __used
static unsigned long with_tail_call(void *ctx)
{
	asm volatile (
		"r6 = r1;"
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r1 = r6;"
		"r2 = %[jmp_table] ll;"
		"r3 = 0;"
		"call %[bpf_tail_call];"
		"r0 = 0;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(jmp_table), __imm(bpf_tail_call) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad with a tail call returns")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} returns")
__xlated("...")
__xlated("r6 = r1")
__xlated("...")
__xlated("call pc+")
__xlated("unwind_goto pc+2")
__xlated("kgoto pc+8")
__xlated("exit")
__xlated("r1 = r6")
__xlated("...")
__xlated("call bpf_tail_call")
__xlated("r0 = 0")
__xlated("unwind_exit")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__naked void tail_call_returns(void)
{
	asm volatile (
		"call with_tail_call;"
		"exit;"
		::: __clobber_all);
}

/* LD_ABS that fails returns 0 to the caller of the frame */
__naked __noinline __used
static unsigned long with_ld_abs(void *ctx)
{
	asm volatile (
		"r6 = r1;"
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r0 = *(u8 *)skb[0];"
		"r0 = 0;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad with LD_ABS returns")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} returns")
__xlated("...")
__xlated("r6 = r1")
__xlated("...")
__xlated("call pc+")
__xlated("unwind_goto pc+2")
__xlated("kgoto pc+9")
__xlated("exit")
__xlated("...")
__xlated("r0 = 0")
__xlated("unwind_exit")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__naked void ld_abs_returns(void)
{
	asm volatile (
		"call with_ld_abs;"
		"exit;"
		::: __clobber_all);
}

/*
 * One function with a destructor and a try block: clang makes one resume block, and the pad of the
 * try goes there when no clause takes the exception. Each pad is judged from its first insn: the
 * kernel enters the first one, and goes past the second one. unwind_exit that both get to tests K.
 * So unwind_goto of each call goes to a stub of its own that clears K: the pad of the try is no
 * pad code, and it gets to where K is read all the same.
 */
__naked __noinline __used
static unsigned long shares_resume(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
	CALL_LEAVES
		unwind_goto(2f)
		"exit;"
		/* the pad of the first call: the destructor */
	"1:	r6 = r0;"
		"call dtor;"
		"goto 3f;"
		/* the pad of the second call: the try */
	"2:	r6 = r0;"
		"call personality;"
		"if r0 != 1 goto 3f;"
		"r0 = 42;"
		"exit;"
	"3:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: two pads share the resume, one returns and one only resumes")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} returns")
__xlated("...")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+18")
__xlated("kgoto pc+21")
__xlated("...")
__xlated("call pc+")
__xlated("unwind_goto pc+14")
__xlated("kgoto pc+18")
__xlated("exit")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("goto pc+5")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("if r0 != 0x1 goto pc+2")
__xlated("r0 = 42")
__xlated("exit")
__xlated("r0 = r6")
__xlated("gotol pc+10")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-12")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-11")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-17")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void shared_resume(void)
{
	asm volatile (
		"call shares_resume;"
		"exit;"
		::: __clobber_all);
}

/* It leaves with unwind_exit and a pointer to memory of the program in r0, or the kernel unwinds it */
__naked __noinline __used
static unsigned long throws_pointer(void)
{
	asm volatile (
		"r2 = %[one] ll;"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 == 0 goto 2f;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
	"2:	r0 = %[flag] ll;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(flag) : __clobber_all);
}

/*
 * The pad reads the object that was thrown, through r0, and only resumes: the kernel enters it,
 * with 0 in r0. What the pad does then is verified like all that the program does, and a pad that
 * is wrong on that way is an error of the program, not a pad that the kernel goes past.
 */
__naked __noinline __used
static unsigned long reads_exception(void)
{
	asm volatile (
		"call throws_pointer;"
		unwind_goto(1f)
		"exit;"
	"1:	r1 = *(u64 *)(r0 + 0);"
		unwind_exit
		::: __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad that only resumes is wrong when the kernel unwinds")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("the kernel unwinds")
__msg("R0 invalid mem access 'scalar'")
__naked void pad_reads_exception(void)
{
	asm volatile (
		"call reads_exception;"
		"exit;"
		::: __clobber_all);
}

/*
 * The function is in an RCU section, which its pad does not leave when r0 is 0: the kernel is
 * unwinding. The code that stands in for unwind_exit leaves it.
 */
__naked __noinline __used
static unsigned long leaves_section_to_verifier(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
	CALL_LEAVES
		unwind_goto(1f)
		"r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"if r6 == 0 goto +1;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

SEC("tc")
__description("kunwind pads: the verifier leaves the section that the pad stays in")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of unwind_exit at {{[0-9]+}} in a frame that the kernel unwinds: rcu=1 preempt=0")
__xlated("...")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
__xlated("call kernel-function")
__xlated("...")
__xlated("call pc+")
__xlated("unwind_goto pc+11")
__xlated("kgoto pc+12")
__xlated("...")
__xlated("exit")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("if r6 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = r6")
__xlated("gotol pc+5")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-8")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-11")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+4")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void section_left_by_verifier(void)
{
	asm volatile (
		"call leaves_section_to_verifier;"
		"exit;"
		::: __clobber_all);
}

/*
 * The function holds a task in r6, which its pad does not release when r0 is 0. Nothing has the
 * pointer where the pad ends: r6 is not read any more. The entry of the pad has put it into a save
 * word of the frame, and the code in place of unwind_exit releases what the word has.
 */
__naked __noinline __used
static unsigned long leaves_task_to_verifier(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	CALL_LEAVES
		unwind_goto(1f)
		"r7 = r0;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		"exit;"
	"1:	r7 = r0;"
		"call dtor;"
		"if r7 == 0 goto +2;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_get_current_task_btf), __imm(bpf_task_acquire),
		   __imm(bpf_task_release) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the entry keeps the task that the pad leaves, the verifier releases it")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it, saves ref@{{[0-9]+}}(r6)")
__msg("landing pad of unwind_exit at {{[0-9]+}} in a frame that the kernel unwinds: ref@{{[0-9]+}}(*fp-16) if not 0 rcu=0 preempt=0")
__xlated("...")
__xlated("r6 = r0")
__xlated("...")
__xlated("call pc+")
__xlated("unwind_goto pc+13")
__xlated("kgoto pc+14")
__xlated("...")
__xlated("exit")
__xlated("r7 = r0")
__xlated("call pc+")
__xlated("if r7 == 0x0 goto pc+2")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = r7")
__xlated("gotol pc+7")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-9")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = r6")
__xlated("*(u64 *)(r10 -16) = r0")
__xlated("r0 = 0")
__xlated("gotol pc-14")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+6")
__xlated("r1 = *(u64 *)(r10 -16)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void task_left_to_verifier(void)
{
	asm volatile (
		"call leaves_task_to_verifier;"
		"exit;"
		::: __clobber_all);
}

/*
 * The pad releases the task on one of two ways when r0 is 0, by what is in memory. Where it ends
 * the save word has the pointer on both ways, and nothing tells whether the task is still held:
 * the frame that the kernel unwinds has no plan there, and the kernel enters the pad or the
 * program is rejected. The log names the call, the pad, and where what it leaves has no plan.
 */
__naked __noinline __used
static unsigned long releases_on_one_way(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	CALL_LEAVES
		unwind_goto(1f)
		"r7 = r0;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		"exit;"
	"1:	r7 = r0;"
		"if r7 != 0 goto 2f;"
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 3f;"
	"2:	r1 = r6;"
		"call %[bpf_task_release];"
	"3:	r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(zero), __imm(bpf_get_current_task_btf),
		   __imm(bpf_task_acquire), __imm(bpf_task_release) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: released on one way through the pad only")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("the kernel would enter the landing pad at 18 of the call at 11: what the pad leaves at unwind_exit at 27 cannot be released")
__msg("landing pad of unwind_exit at 27 in a frame that the kernel unwinds: conflict: a resource is held on some paths only")
__naked void released_on_one_way(void)
{
	asm volatile (
		"call releases_on_one_way;"
		"exit;"
		::: __clobber_all);
}

/*
 * One task is held at the first call and two at the second one, and the pads leave them when r0
 * is 0. The entry of the first call fills one save word and clears the other, the entry of the
 * second call fills both, and the end that the pads share releases what each word has.
 */
__naked __noinline __used
static unsigned long holds_one_then_two(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	CALL_LEAVES
		unwind_goto(1f)
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +4;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = 0;"
		"exit;"
		"r8 = r0;"
	CALL_LEAVES
		unwind_goto(2f)
		"r7 = r0;"
		"r1 = r8;"
		"call %[bpf_task_release];"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		"exit;"
	"2:	r7 = r0;"
		"if r7 == 0 goto 4f;"
		"r1 = r8;"
		"call %[bpf_task_release];"
		"goto 3f;"
	"1:	r7 = r0;"
		"if r7 == 0 goto 4f;"
	"3:	r1 = r6;"
		"call %[bpf_task_release];"
	"4:	r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_get_current_task_btf), __imm(bpf_task_acquire),
		   __imm(bpf_task_release) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: two calls that hold one task and two share the code behind their pads")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it, saves ref@{{[0-9]+}}(r6)")
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it, saves ref@{{[0-9]+}}(r6) , saves ref@{{[0-9]+}}(r8)")
__xlated("...")
__xlated("if r7 == 0x0 goto pc+2")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = r7")
__xlated("gotol pc+17")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-8")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-15")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = r6")
__xlated("*(u64 *)(r10 -24) = r0")
__xlated("*(u64 *)(r10 -16) = 0")
__xlated("r0 = 0")
__xlated("gotol pc-16")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = r6")
__xlated("*(u64 *)(r10 -24) = r0")
__xlated("r0 = r8")
__xlated("*(u64 *)(r10 -16) = r0")
__xlated("r0 = 0")
__xlated("gotol pc-28")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+9")
__xlated("r1 = *(u64 *)(r10 -16)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -24)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void one_then_two(void)
{
	asm volatile (
		"call holds_one_then_two;"
		"exit;"
		::: __clobber_all);
}

/*
 * Two calls, a task held at the first one and a cgroup at the second one, and one end for both
 * pads. A save word has one kind of thing: nothing has the type of a pointer where the pads end.
 * So the entry of the second call saves nothing, which is no error and has the pass done again,
 * and then what its pad leaves has no place where the pads end: that rejects. The log says both,
 * and names the first pad of the function that gets to that end, since a frame does not know
 * which entry it came through: here both do.
 */
__naked __noinline __used
static unsigned long holds_task_then_cgroup(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	CALL_LEAVES
		unwind_goto(1f)
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r1 = 1;"
		"call %[bpf_cgroup_from_id];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	CALL_LEAVES
		unwind_goto(2f)
		"r7 = r0;"
		"r1 = r6;"
		"call %[bpf_cgroup_release];"
		"r0 = r7;"
		"exit;"
	"2:	r7 = r0;"
		"if r7 == 0 goto 3f;"
		"r1 = r6;"
		"call %[bpf_cgroup_release];"
		"goto 3f;"
	"1:	r7 = r0;"
		"if r7 == 0 goto 3f;"
		"r1 = r6;"
		"call %[bpf_task_release];"
	"3:	r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_get_current_task_btf), __imm(bpf_task_acquire),
		   __imm(bpf_task_release), __imm(bpf_cgroup_from_id), __imm(bpf_cgroup_release)
		: __clobber_all);
}

SEC("tc")
__description("kunwind pads: a save word has one kind of thing")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("the entry of the landing pad of the call at 23 saves nothing: what the frames hold at the call differs")
__msg("pass 1")
__msg("the kernel would enter the landing pad at 35 of the call at 11, and 1 more of func#1: what the pad leaves at unwind_exit at 40 cannot be released")
__msg("the entry of the landing pad of the call at 23 saves nothing")
__msg("landing pad of unwind_exit at 40 in a frame that the kernel unwinds: conflict: no place has the handle on all paths")
__naked void task_then_cgroup(void)
{
	asm volatile (
		"call holds_task_then_cgroup;"
		"exit;"
		::: __clobber_all);
}

/* The same function with a stack that is full: no room for the hidden word, and that rejects */
__naked __noinline __used
static unsigned long full_stack_with_dtor(void)
{
	asm volatile (
		"*(u64 *)(r10 - 2048) = 1;"
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: no room in the stack for the hidden word")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("the kernel would enter the landing pad at 9 of the call at 6: no room in the stack for the hidden words of func#1")
__naked void no_room_for_hidden_word(void)
{
	asm volatile (
		"call full_stack_with_dtor;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long throws_9(void)
{
	asm volatile (
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 1f;"
		"r1 = 9;"
		"call %[bpf_throw];"
	"1:	r0 = 5;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_throw) : __clobber_all);
}

/* In a prog with bpf_throw() the entry keeps the value in a second hidden word */
__naked __noinline __used
static unsigned long with_dtor_below_throw(void)
{
	asm volatile (
		"call throws_9;"
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}

SEC("tc")
__description("kunwind pads: the value of bpf_throw() waits in a hidden word while the pad runs")
__success __retval(9)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__xlated("...")
__xlated("exit")
__xlated("call pc+")
__xlated("unwind_goto pc+6")
__xlated("kgoto pc+7")
__xlated("goto pc-1")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("r0 = r6")
__xlated("gotol pc+6")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-6")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("*(u64 *)(r10 -16) = r0")
__xlated("r0 = 0")
__xlated("gotol pc-10")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = *(u64 *)(r10 -16)")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void value_waits(void)
{
	asm volatile (
		"call with_dtor_below_throw;"
		"exit;"
		::: __clobber_all);
}

/*
 * The destructor loops, in the pad itself, and nothing ends the loop: may_goto of the verifier.
 * The frame gets there when the prog unwinds, and that is where the kernel starts then: the value
 * of the kernel. And it gets there when the kernel unwinds it already: the value of bpf_throw(),
 * which waits in the hidden word. The site has a pad for each, and a test of K picks one.
 */
__naked __noinline __used
static unsigned long loops_in_pad(void)
{
	asm volatile (
		"call throws_9;"
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
		"r2 = %[one] ll;"
	"2:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 2b;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a site in a pad has a pad for each way in which the frame got there")
__success __retval(9)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of may_goto at {{[0-9]+}} in a frame that the kernel unwinds: rcu=0 preempt=0")
__msg("landing pad of may_goto at {{[0-9]+}}: rcu=0 preempt=0")
__xlated("...")
__xlated("exit")
__xlated("call pc+")
__xlated("unwind_goto pc+19")
__xlated("kgoto pc+20")
__xlated("goto pc-1")
__xlated("r6 = r0")
__xlated("...")
__xlated("if r13 == 0x0 goto pc+14")
__xlated("...")
__xlated("if r1 != 0x0 goto pc-12")
__xlated("r0 = r6")
__xlated("gotol pc+14")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-19")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("*(u64 *)(r10 -16) = r0")
__xlated("r0 = 0")
__xlated("gotol pc-23")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = *(u64 *)(r10 -16)")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = *(u64 *)(r10 -16)")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void site_in_pad(void)
{
	asm volatile (
		"call loops_in_pad;"
		"exit;"
		::: __clobber_all);
}

struct bpf_res_spin_lock guard_lock SEC(".data.guard_lock") __hidden;

/*
 * A lock guard, and one more object whose destructor runs first and loops: the pad gets
 * may_goto of the verifier while the lock is held. The loop stands behind unwind_exit of the pad,
 * so its landing pad is the last one of the function.
 */
__naked __noinline __used
static unsigned long lock_guard_loops_in_pad(void)
{
	asm volatile (
		"r1 = %[guard_lock] ll;"
		"call %[bpf_res_spin_lock];"
		"if r0 == 0 goto +1;"
		"exit;"
	CALL_LEAVES
		unwind_goto(1f)
		"r6 = r0;"
		"r1 = %[guard_lock] ll;"
		"call %[bpf_res_spin_unlock];"
		"r0 = r6;"
		"exit;"
	"1:	r6 = r0;"
		"goto 3f;"
	"2:	r1 = %[guard_lock] ll;"
		"call %[bpf_res_spin_unlock];"
		"r0 = r6;"
		unwind_exit
	"3:	r2 = %[one] ll;"
	"4:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 4b;"
		"goto 2b;"
		:: __imm_addr(one), __imm_addr(guard_lock), __imm(bpf_res_spin_lock),
		   __imm(bpf_res_spin_unlock) : __clobber_all);
}

/* The third insn reads the context: the verifier has noted that for the insn */
__naked __noinline __used
static unsigned long reads_ctx(void)
{
	asm volatile (
		"r0 = 0;"
		"r3 = 0;"
		"r2 = *(u32 *)(r1 + 76);"
		"exit;"
		::: __clobber_all);
}

/*
 * The frame gets to the loop in the pad in both ways and holds the lock in both: the two landing
 * pads of may_goto have the same insns, and the site gets one of them, with no test of K. The pad
 * loads the address of the lock, which the verifier notes for the insn. What is emitted to compare
 * the two pads notes nothing, in the pad or behind it: the load of the function that follows the
 * landing pads is still a load from the context, of skb->data.
 */
SEC("tc")
__description("kunwind pads: one pad for both ways of a site, what follows the pads is as it was")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of may_goto at {{[0-9]+}} in a frame that the kernel unwinds: res_lock@{{[0-9]+}}(map#{{[0-9]+}}) rcu=0 preempt=0")
__msg("landing pad of may_goto at {{[0-9]+}}: res_lock@{{[0-9]+}}(map#{{[0-9]+}}) rcu=0 preempt=0")
__xlated("...")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("r0 = 0")
__xlated("r3 = 0")
__xlated("r2 = *(u64 *)(r1 +{{[0-9]+}})")
__xlated("exit")
__naked void one_pad_for_both_ways(void)
{
	asm volatile (
		"r6 = r1;"
		"r1 = 0;"
		"call leaves;"
		"call lock_guard_loops_in_pad;"
		"r1 = r6;"
		"call reads_ctx;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

/*
 * The same where the pad is the last insn of the prog. What was noted behind it then was noted
 * behind the aux data of the prog: KASAN tells.
 */
SEC("tc")
__description("kunwind pads: one pad for both ways of a site is the last insn of the prog")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__xlated("...")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__xlated("r1 = 0x{{[0-9a-f]+}}")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__naked void one_pad_for_both_ways_is_last(void)
{
	asm volatile (
		"r1 = 0;"
		"call leaves;"
		"call lock_guard_loops_in_pad;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

/*
 * The function holds a task on some paths only, and r6 is not 0 on the others: its first call has
 * a pad of the verifier, which cannot tell, so the function has a hidden slot for the task, and
 * every pad of it releases through the slot. The code in place of unwind_exit does too: the pad of
 * the prog leaves the task when r0 is 0, and what the slot has then is released there. The stores
 * around the calls of the prog keep the slot right, also in the pad.
 */
__naked __noinline __used
static unsigned long slot_and_pad(void)
{
	asm volatile (
		"r8 = %[zero] ll;"
		"r8 = *(u64 *)(r8 + 0);"
		"r6 = 5;"
		"if r8 == 0 goto 1f;"
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	"1:"
	CALL_LEAVES
	CALL_LEAVES
		unwind_goto(3f)
		"r7 = r0;"
		"if r8 == 0 goto 2f;"
		"r1 = r6;"
		"call %[bpf_task_release];"
	"2:	r0 = r7;"
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
		"if r7 == 0 goto 4f;"
		"if r8 == 0 goto 4f;"
		"r1 = r6;"
		"call %[bpf_task_release];"
	"4:	r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(zero), __imm(bpf_get_current_task_btf),
		   __imm(bpf_task_acquire), __imm(bpf_task_release) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: what the pad leaves is released through the hidden slot of the function")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("the entry of the landing pad of the call at {{[0-9]+}} saves nothing: what the frames hold at the call differs")
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it")
__msg("landing pad of unwind_exit at {{[0-9]+}} in a frame that the kernel unwinds: ref@{{[0-9]+}}(*fp-8) if not 0 rcu=0 preempt=0")
__msg("func#1 has hidden slots for: refs")
__xlated("...")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("r8 = 0x")
__xlated("...")
__xlated("call kernel-function")
__xlated("*(u64 *)(r10 -8) = r0")
__xlated("...")
__xlated("r0 = r7")
__xlated("exit")
__xlated("r7 = r0")
__xlated("call pc+")
__xlated("if r7 == 0x0 goto pc+6")
__xlated("if r8 == 0x0 goto pc+5")
__xlated("r1 = r6")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 != r1 goto pc+1")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("call kernel-function")
__xlated("r0 = r7")
__xlated("gotol pc+17")
__xlated("*(u64 *)(r10 -24) = 0")
__xlated("gotol pc-13")
__xlated("...")
__xlated("*(u64 *)(r10 -24) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-28")
__xlated("r13 = *(u64 *)(r10 -24)")
__xlated("if r13 == 0x0 goto pc+6")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void slot_behind_pad(void)
{
	asm volatile (
		"call slot_and_pad;"
		"exit;"
		::: __clobber_all);
}

__noinline int adds_100(u64 cookie)
{
	return cookie + 100;
}

/*
 * The prog itself has the pad: unwind_exit is exit there, and what stands in for it calls the
 * exception callback with the value that waited
 */
SEC("tc")
__description("kunwind pads: the pad of the main prog, and the exception callback behind it")
__success __retval(109)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__exception_cb(adds_100)
__xlated("0: call pc+")
__xlated("1: unwind_goto pc+6")
__xlated("2: kgoto pc+7")
__xlated("3: goto pc-1")
__xlated("4: r6 = r0")
__xlated("5: call pc+")
__xlated("6: r0 = r6")
__xlated("7: gotol pc+6")
__xlated("8: *(u64 *)(r10 -8) = 0")
__xlated("9: gotol pc-6")
__xlated("10: *(u64 *)(r10 -8) = 1")
__xlated("11: *(u64 *)(r10 -16) = r0")
__xlated("12: r0 = 0")
__xlated("13: gotol pc-10")
__xlated("14: r13 = *(u64 *)(r10 -8)")
__xlated("15: if r13 == 0x0 goto pc+3")
__xlated("16: r1 = *(u64 *)(r10 -16)")
__xlated("17: call pc+")
__xlated("18: exit")
__xlated("19: unwind_exit")
__naked void pad_in_main(void)
{
	asm volatile (
		"call throws_9;"
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}

/* r1 == 0: returns 7. Otherwise a loop that nothing ends. It never leaves with unwind_exit. */
__naked __noinline __used
static unsigned long spins_or_returns(void)
{
	asm volatile (
		"if r1 == 0 goto 2f;"
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	"2:	r0 = 7;"
		"exit;"
		:: __imm_addr(one) : __clobber_all);
}

#define CALL_SPINS					\
		"r1 = %[one] ll;"			\
		"r1 = *(u64 *)(r1 + 0);"		\
		"call spins_or_returns;"

struct bpf_res_spin_lock top_lock SEC(".data.top_lock") __hidden;

/*
 * The function unlocks what its caller locked, as a guard that adopts a lock does: on its normal
 * path, and in the landing pad of its second call. The landing pad of its first call is the resume
 * block that both share. Only the kernel unwinds what it calls.
 */
__naked __noinline __used
static unsigned long adopts_lock(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(2f)
	CALL_SPINS
		unwind_goto(1f)
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_unlock];"
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_unlock];"
		"r0 = r6;"
	"2:"
		unwind_exit
		:: __imm_addr(one), __imm_addr(top_lock), __imm(bpf_res_spin_unlock)
		: __clobber_all);
}

/*
 * When the kernel unwinds the frame through its first pad the lock of the caller is still held,
 * through the second one it is not: the pad of the verifier in the caller cannot tell, and no
 * hidden slot follows a release that another frame makes. The kernel enters both pads or the
 * program is rejected: the log names the function that came back to the call, and says what a
 * landing pad in it or below it may have done. Which pad it was the verifier does not know.
 */
SEC("tc")
__description("kunwind pads: a pad that unlocks the lock of a caller")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("what the call at 6 calls is left at: a landing pad of the program")
__msg("the kernel would enter a landing pad of the program in or below func#1: it may release or overwrite what a caller holds at the call at 6")
__msg("landing pad of call at 6: conflict: a resource is held on some paths only")
__naked void pad_unlocks_for_caller(void)
{
	asm volatile (
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_lock];"
		"if r0 == 0 goto +2;"
		"r0 = 0;"
		"exit;"
		"call adopts_lock;"
		"exit;"
		:: __imm_addr(top_lock), __imm(bpf_res_spin_lock) : __clobber_all);
}

/*
 * The same with an RCU section of the caller. A frame is unwound with the sections of its call:
 * where the pad of the program has left one of the caller, what stands in for unwind_exit enters
 * it again. Here two pads end in one unwind_exit and only the second one has left the section, so
 * the code there has no one number of sections, and a frame that the kernel unwinds gets no
 * hidden slots.
 */
__naked __noinline __used
static unsigned long leaves_section_of_caller(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(2f)
	CALL_SPINS
		unwind_goto(1f)
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
	"2:"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad that leaves the RCU section of a caller")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("the kernel would enter the landing pad at 19 of the call at 6, and 1 more of func#1: what the pad leaves at unwind_exit at 19 cannot be released")
__msg("landing pad of unwind_exit at 19 in a frame that the kernel unwinds: conflict: the number of sections differs")
__naked void pad_leaves_section_of_caller(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call leaves_section_of_caller;"
		"exit;"
		:: __imm(bpf_rcu_read_lock) : __clobber_all);
}

/*
 * A guard that was moved into the function: every way out leaves the section of the caller, the
 * normal one and the pad. When the kernel unwinds the callee of the function it enters the pad,
 * which leaves the section, and behind it the frame is in one section less than it was called
 * in: what stands in for unwind_exit enters the section again, and the pad of the verifier in the
 * prog leaves it.
 */
__naked __noinline __used
static unsigned long drops_section_of_caller(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: every way out of the function leaves the RCU section of the caller")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of call at 1: rcu=1 preempt=0")
__msg("landing pad of unwind_exit at {{[0-9]+}} in a frame that the kernel unwinds: rcu=-1 preempt=0")
__naked void pad_drops_section_of_caller(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call drops_section_of_caller;"
		"r0 = 7;"
		"exit;"
		:: __imm(bpf_rcu_read_lock) : __clobber_all);
}

/*
 * The function in between has no landing pad: the conflict is two calls above the pads, and the
 * log names the function that came back to the call, below which the pads are
 */
__naked __noinline __used
static unsigned long calls_adopts_lock(void)
{
	asm volatile (
		"call adopts_lock;"
		"exit;"
		::: __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad that unlocks the lock of the caller of its caller")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("what the call at 6 calls is left at: a landing pad of the program")
__msg("the kernel would enter a landing pad of the program in or below func#1: it may release or overwrite what a caller holds at the call at 6")
__msg("landing pad of call at 6: conflict: a resource is held on some paths only")
__naked void pad_unlocks_two_calls_below(void)
{
	asm volatile (
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_lock];"
		"if r0 == 0 goto +2;"
		"r0 = 0;"
		"exit;"
		"call calls_adopts_lock;"
		"exit;"
		:: __imm_addr(top_lock), __imm(bpf_res_spin_lock) : __clobber_all);
}

/*
 * A callback of bpf_loop() with a landing pad that writes to the slot of the irq flags, which its
 * caller has: the helper is between the conflict and the pad.
 */
__naked __noinline __used
static unsigned long cb_overwrites_flags(void)
{
	asm volatile (
		"r6 = r2;"
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 1;"
		"exit;"
	"1:	r1 = 0;"
		"*(u64 *)(r6 + 0) = r1;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the pad of a callback overwrites the irq flags of the caller of the helper")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("what the call at 9 calls is left at: a landing pad of the program")
__msg("the kernel would enter a landing pad of the program in or below func#1: it may release or overwrite what a caller holds at the call at 9")
__msg("landing pad of call at 9: conflict: no place has the handle on all paths")
__naked void pad_of_callback_overwrites_flags(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
		"r1 = 1;"
		"r2 = %[cb_overwrites_flags] ll;"
		"r3 = r10;"
		"r3 += -8;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_local_irq_save), __imm(bpf_local_irq_restore), __imm(bpf_loop),
		   __imm_addr(cb_overwrites_flags) : __clobber_all);
}

/* A landing pad that does nothing: what its frame holds is for the verifier */
__naked __noinline __used
static unsigned long resumes_at_once(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

/*
 * The caller holds more than a pad of the verifier releases, whatever the landing pad of the
 * program below it does: a pad can only take from what a caller holds. That rejects, and the log
 * blames no landing pad for it.
 */
SEC("tc")
__description("kunwind pads: a conflict that is not the work of a pad is one without the pad too")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("what the call at 9 calls is left at: a landing pad of the program")
__not_msg("the kernel would enter")
__msg("landing pad of call at 9: conflict: too much is held")
__naked void conflict_with_and_without_pad(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"call resumes_at_once;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

/* What only the landing pad below calls. It holds more than a pad of the verifier releases. */
__naked __noinline __used
static unsigned long holds_too_much_and_spins(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(one), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

__naked __noinline __used
static unsigned long pad_calls_what_holds_too_much(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call holds_too_much_and_spins;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

/*
 * Nothing but a landing pad calls the function, and nothing but the kernel gets the program into
 * that pad. The kernel does get there, so the function is code of the program like any other, and
 * a site in it that has no plan rejects, as it does in a function that the normal path calls. The
 * log says how the program got to the function.
 */
SEC("tc")
__description("kunwind pads: a conflict in what only a pad calls")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("from 5 to the landing pad at 9 of func#1: the kernel unwinds")
__msg("func#3 is called from a landing pad of the program that the kernel would enter")
__msg("landing pad of may_goto at 32: conflict: too much is held")
__naked void conflict_below_pad_code(void)
{
	asm volatile (
		"call pad_calls_what_holds_too_much;"
		"exit;"
		::: __clobber_all);
}

/* The same in a callback of a helper that only the landing pad calls */
__naked __noinline __used
static unsigned long cb_holds_too_much_and_spins(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = 1;"
		"exit;"
		:: __imm_addr(one), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

__naked __noinline __used
static unsigned long pad_loops_over_what_holds_too_much(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"r1 = 1;"
		"r2 = %[cb_holds_too_much_and_spins] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(cb_holds_too_much_and_spins), __imm(bpf_loop)
		: __clobber_all);
}

SEC("tc")
__description("kunwind pads: a conflict in a callback of a helper that only a pad calls")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("from 5 to the landing pad at 9 of func#1: the kernel unwinds")
__msg("func#3 is called from a landing pad of the program that the kernel would enter")
__msg("landing pad of may_goto at 37: conflict: too much is held")
__naked void conflict_in_callback_below_pad_code(void)
{
	asm volatile (
		"call pad_loops_over_what_holds_too_much;"
		"exit;"
		::: __clobber_all);
}

/* The same function with global linkage, as a helper of the cleanup in another object has it */
__naked __noinline __used
unsigned long global_holds_too_much_and_spins(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(one), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

__naked __noinline __used
static unsigned long pad_calls_global_that_holds_too_much(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call global_holds_too_much_and_spins;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

/*
 * A global function is verified on its own, whoever calls it: also when only frames that the
 * kernel unwinds call it. Its conflict rejects like that of the static function above. No frame
 * of a pass that verifies it knows of the landing pad, so the log has the line of the site alone.
 */
SEC("tc")
__description("kunwind pads: a conflict in a global function that only a pad calls")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__not_msg("the kernel would enter")
__not_msg("is called from a landing pad")
__msg("landing pad of may_goto at 32: conflict: too much is held")
__naked void conflict_in_global_below_pad_code(void)
{
	asm volatile (
		"call pad_calls_global_that_holds_too_much;"
		"exit;"
		::: __clobber_all);
}

/* The normal path calls the global function too: the same conflict, and the same log */
__naked __noinline __used
static unsigned long pad_and_normal_path_call_global(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"call global_holds_too_much_and_spins;"
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call global_holds_too_much_and_spins;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a conflict in a global function that a pad and the normal path call")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__not_msg("the kernel would enter")
__msg("landing pad of may_goto at {{[0-9]+}}: conflict: too much is held")
__naked void conflict_in_global_below_pad_and_normal_path(void)
{
	asm volatile (
		"call pad_and_normal_path_call_global;"
		"exit;"
		::: __clobber_all);
}

/*
 * The landing pad and the normal path both call the function that holds too much: what a frame
 * that the kernel unwinds calls is kept apart from the other calls of the function, and the
 * conflict is there for both. It rejects where the first state gets to it, and which of the two
 * that is is no property of the program: the log has the line of the site, and nothing is
 * expected here of what it says about the landing pad. The test below has both states at the
 * site before the conflict shows.
 */
__naked __noinline __used
static unsigned long pad_and_normal_path_call_what_holds_too_much(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"call holds_too_much_and_spins;"
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call holds_too_much_and_spins;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a conflict in what a pad and the normal path call is one without the pads too")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("landing pad of may_goto at {{[0-9]+}}: conflict: too much is held")
__naked void conflict_below_pad_code_and_normal_path(void)
{
	asm volatile (
		"call pad_and_normal_path_call_what_holds_too_much;"
		"exit;"
		::: __clobber_all);
}

/* In an RCU section if memory says so, around a loop that nothing ends. Its stack is full. */
__naked __noinline __used
static unsigned long loops_in_section_on_one_way_full_stack(void)
{
	asm volatile (
		"*(u64 *)(r10 - 2048) = 1;"
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"if r6 == 0 goto 1f;"
		"call %[bpf_rcu_read_lock];"
	"1:	r2 = %[one] ll;"
	"2:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 2b;"
		"if r6 == 0 goto 3f;"
		"call %[bpf_rcu_read_unlock];"
	"3:	r0 = 0;"
		"exit;"
		:: __imm_addr(zero), __imm_addr(one), __imm(bpf_rcu_read_lock),
		   __imm(bpf_rcu_read_unlock) : __clobber_all);
}

__naked __noinline __used
static unsigned long pad_and_normal_path_call_what_differs(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"call loops_in_section_on_one_way_full_stack;"
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call loops_in_section_on_one_way_full_stack;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

/*
 * Here the conflict shows when the pass is over: the states do not agree on the sections at the
 * loop, and the stack has no room for the hidden slot. States of the normal path and states out
 * of the landing pad have been at the loop by then. The log says that the function is called
 * from a landing pad too, and does not say that the pad is what makes the conflict.
 */
SEC("tc")
__description("kunwind pads: a conflict in what a pad and the normal path call, found when the pass is over")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("func#3 is also called from a landing pad of the program that the kernel would enter")
__msg("landing pad of may_goto at 30: conflict: the number of sections differs")
__naked void conflict_at_settle_below_pad_code_and_normal_path(void)
{
	asm volatile (
		"call pad_and_normal_path_call_what_differs;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static void leaves_section_of_its_caller(void)
{
	asm volatile (
		"call %[bpf_rcu_read_unlock];"
		"exit;"
		:: __imm(bpf_rcu_read_unlock) : __clobber_all);
}

/*
 * The function is in an RCU section on some ways to its loop, so the pad of the loop needs a
 * hidden slot. And its landing pad leaves the section that the normal path leaves, and then one
 * of its caller. A function that is in fewer sections than it was called in has no slot that
 * says so, and gets no hidden slots for its sections. Then the pad of the loop has no plan, in
 * the function of the landing pad itself: that rejects, and the log says what the landing pad
 * has to do with a loop of the normal path.
 */

__naked __noinline __used
static unsigned long pad_keeps_hidden_slots_off(void)
{
	asm volatile (
		"r6 = r1;"
		"if r6 == 0 goto 1f;"
		"call %[bpf_rcu_read_lock];"
	"1:	r2 = %[zero] ll;"
	"2:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 2b;"
		"if r6 == 0 goto 3f;"
		"call %[bpf_rcu_read_unlock];"
	"3:	call %[bpf_rcu_read_lock];"
	CALL_SPINS
		unwind_goto(4f)
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
	"4:	r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(zero), __imm_addr(one), __imm(bpf_rcu_read_lock),
		   __imm(bpf_rcu_read_unlock) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad that keeps its own function from getting hidden slots")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("the kernel would enter a landing pad of the program: what its code releases of a caller may keep func#1 from getting hidden slots")
__msg("landing pad of may_goto at 14: conflict: the number of sections differs")
__naked void pad_keeps_slots_off(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"call pad_keeps_hidden_slots_off;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(one), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

/*
 * Two callers of one function, in nine RCU sections both. The first one entered four of them, its
 * caller the other five: a pad of the verifier does for each frame. The second one entered all
 * nine: that is more than a pad leaves.
 */
#define CALLS_IN_4_OF_9(name, callee, a, b)						\
__naked __noinline __used								\
static unsigned long name(void)								\
{											\
	asm volatile (									\
		".rept 4;"								\
		"call %[bpf_rcu_read_lock];"						\
		".endr;"								\
		"r1 = " #a ";"								\
		"r2 = " #b ";"								\
		"call " #callee ";"							\
		".rept 4;"								\
		"call %[bpf_rcu_read_unlock];"						\
		".endr;"								\
		"r0 = 0;"								\
		"exit;"									\
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all); \
}

#define CALLS_IN_9_OF_9(name, callee, a, b)						\
__naked __noinline __used								\
static unsigned long name(void)								\
{											\
	asm volatile (									\
		".rept 9;"								\
		"call %[bpf_rcu_read_lock];"						\
		".endr;"								\
		"r1 = " #a ";"								\
		"r2 = " #b ";"								\
		"call " #callee ";"							\
		".rept 9;"								\
		"call %[bpf_rcu_read_unlock];"						\
		".endr;"								\
		"r0 = 0;"								\
		"exit;"									\
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all); \
}

/* A function is verified for a call and for the calls before it together: the order matters */
#define TWO_CALLERS(name, first, second)						\
__naked void name(void)									\
{											\
	asm volatile (									\
		".rept 5;"								\
		"call %[bpf_rcu_read_lock];"						\
		".endr;"								\
		"call " #first ";"							\
		".rept 5;"								\
		"call %[bpf_rcu_read_unlock];"						\
		".endr;"								\
		"call " #second ";"							\
		"r0 = 0;"								\
		"exit;"									\
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all); \
}

/* The kernel unwinds what it calls unless r1 is 0 */
__naked __noinline __used
static unsigned long with_dtor_unless_0(void)
{
	asm volatile (
		"if r1 == 0 goto 2f;"
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
	"2:	r0 = 0;"
		"exit;"
		:: __imm_addr(one) : __clobber_all);
}

CALLS_IN_4_OF_9(first_caller_of_dtor, with_dtor_unless_0, 1, 1)
CALLS_IN_9_OF_9(second_caller_of_dtor, with_dtor_unless_0, 0, 0)

/*
 * The caller that holds too much passes 0, and with 0 the function does not get to the call that
 * the kernel unwinds. Verified for both calls together it does, and comes back to both callers
 * through its landing pad. The conflict of the second caller is an error of that pass like any
 * other: the call below it is a cause, the jump that can skip it is what the next passes keep
 * apart, and with the two calls apart the second caller does not get to the conflict. The
 * program loads, and the kernel enters the pad.
 */
SEC("tc")
__description("kunwind pads: a conflict above a pad that goes when two calls are kept apart")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of call at 64: conflict: too much is held")
__msg("landing pad of the program behind the call at 31: the kernel enters it")
__msg("landing pad of unwind_exit at 38 in a frame that the kernel unwinds: rcu=0 preempt=0")
__not_msg("conflict")
__msg("processed {{[0-9]+}} insns")
TWO_CALLERS(conflict_that_two_calls_make, first_caller_of_dtor, second_caller_of_dtor)

/*
 * r0 = 0; do r0 += r1; while (r0 != r2); and then, unless r2 is negative, a call that the kernel
 * unwinds. Each of the two calls below has a trip count for the loop, and their join has none.
 */
__naked __noinline __used
static unsigned long counts_then_spins(void)
{
	asm volatile (
		"r6 = r2;"
		"r0 = 0;"
	"1:	r0 += r1;"
		"if r0 != r2 goto 1b;"
		"if r6 s< 0 goto 2f;"
	CALL_SPINS
	"2:	r0 = 0;"
		"exit;"
		:: __imm_addr(one) : __clobber_all);
}

/* A guard around the call: nothing in this function says whether the kernel unwinds the callee */
__naked __noinline __used
static unsigned long with_dtor_around_count(void)
{
	asm volatile (
		"call counts_then_spins;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}

CALLS_IN_4_OF_9(first_caller_of_count, with_dtor_around_count, 1, 1000000)
CALLS_IN_9_OF_9(second_caller_of_count, with_dtor_around_count, -1, -999993)

/*
 * Here what makes the kernel unwind is below the call that has the landing pad: the loop of the
 * callee has no trip count for the two calls together, and the callee gets to its own call with
 * the end of either. The frame of the guard is not left at its call, the kernel enters the pad
 * there, and the caller that holds too much gets what comes out of the pad. The causes are looked
 * for below a call with an entered pad as below a call at which the frame is left: the jump that
 * leaves the loop and the jump that skips the call, in the callee. Kept apart, the second caller
 * has a trip count and does not get to the call, and the kernel enters the pad for the first one.
 */
SEC("tc")
__description("kunwind pads: a conflict above a pad that goes when what the call below it calls is kept apart")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of call at 69: conflict: too much is held")
__msg("landing pad of the program behind the call at 27: the kernel enters it")
__not_msg("conflict")
__msg("processed {{[0-9]+}} insns")
TWO_CALLERS(conflict_below_entered_call, first_caller_of_count, second_caller_of_count)

/* r0 = 0; do r0 += r1; while (r0 != r2). Only a loop that is out of time leaves it unwound. */
__naked __noinline __used
static unsigned long counts(void)
{
	asm volatile (
		"r0 = 0;"
	"1:	r0 += r1;"
		"if r0 != r2 goto 1b;"
		"exit;"
		::: __clobber_all);
}

/* The two calls of @callee: each has a trip count for the loop of counts(), their join has none */
#define TWO_COUNTS(name, callee, ret)							\
__naked void name(void)									\
{											\
	asm volatile (									\
		"r1 = 1;"								\
		"r2 = 1000000;"								\
		"call " #callee ";"							\
		"r1 = -1;"								\
		"r2 = -999993;"								\
		"call " #callee ";"							\
		"r0 = " #ret ";"							\
		"exit;"									\
		::: __clobber_all);							\
}

__naked __noinline __used
static unsigned long pad_calls_too_much_around_count(void)
{
	asm volatile (
		"call counts;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call holds_too_much_and_spins;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}

/*
 * The landing pad calls what holds too much, as in "a conflict in what only a pad calls", but here
 * no run of the program gets into the pad: counts() ends for each of the two calls. Verified for
 * both together its loop has no trip count, the kernel unwinds it, the pad is entered, and the
 * conflict in what the pad calls is an error of that pass. No call leads from the conflict to
 * the pad, and the frame of the conflict is none that the kernel unwinds. Nothing has to lead
 * there: the calls behind which the kernel entered a landing pad are causes of every error of a
 * pass in which it entered one. What the jump that leaves the loop reads is kept apart, down to
 * the two calls, and the program loads with a pad that the kernel never gets to.
 */
SEC("tc")
__description("kunwind pads: a conflict in what a pad calls that goes when what the call in front of the pad calls is kept apart")
__success __retval(3)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("from 8 to the landing pad at 12 of func#1: the kernel unwinds")
__msg("func#3 is called from a landing pad of the program that the kernel would enter")
__msg("landing pad of may_goto at 32: conflict: too much is held")
__not_msg("the kernel enters it")
__msg("processed {{[0-9]+}} insns")
TWO_COUNTS(conflict_below_pad_of_joined_calls, pad_calls_too_much_around_count, 3)

__naked __noinline __used
static unsigned long pad_calls_what_differs_around_count(void)
{
	asm volatile (
		"call counts;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call loops_in_section_on_one_way_full_stack;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}

/*
 * The same where the conflict in what the pad calls shows when the pass is over: the states do
 * not agree on the sections at a loop, and the stack has no room for the hidden slot. No state
 * has an error there.
 */
SEC("tc")
__description("kunwind pads: a conflict in what a pad calls, found when the pass is over, that goes when the calls are kept apart")
__success __retval(3)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("from 8 to the landing pad at 12 of func#1: the kernel unwinds")
__msg("func#3 is called from a landing pad of the program that the kernel would enter")
__msg("landing pad of may_goto at 29: conflict: the number of sections differs")
__not_msg("the kernel enters it")
__msg("processed {{[0-9]+}} insns")
TWO_COUNTS(conflict_at_settle_below_pad_of_joined_calls, pad_calls_what_differs_around_count, 3)

/* pad_keeps_hidden_slots_off() with counts() in front of its landing pad */
__naked __noinline __used
static unsigned long pad_keeps_slots_off_around_count(void)
{
	asm volatile (
		"r7 = r1;"
		"r8 = r2;"
		"r6 = %[one] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"if r6 == 0 goto 1f;"
		"call %[bpf_rcu_read_lock];"
	"1:	r2 = %[zero] ll;"
	"2:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 2b;"
		"if r6 == 0 goto 3f;"
		"call %[bpf_rcu_read_unlock];"
	"3:	call %[bpf_rcu_read_lock];"
		"r1 = r7;"
		"r2 = r8;"
		"call counts;"
		unwind_goto(4f)
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
	"4:	r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(zero), __imm_addr(one), __imm(bpf_rcu_read_lock),
		   __imm(bpf_rcu_read_unlock) : __clobber_all);
}

/* TWO_COUNTS() in an RCU section of the prog */
#define TWO_COUNTS_IN_SECTION(name, callee, ret)					\
__naked void name(void)									\
{											\
	asm volatile (									\
		"call %[bpf_rcu_read_lock];"						\
		"r1 = 1;"								\
		"r2 = 1000000;"								\
		"call " #callee ";"							\
		"r1 = -1;"								\
		"r2 = -999993;"								\
		"call " #callee ";"							\
		"call %[bpf_rcu_read_unlock];"						\
		"r0 = " #ret ";"							\
		"exit;"									\
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all);	\
}

/*
 * The same for a landing pad that keeps its own function from getting hidden slots: the loop of
 * the function has no plan because of what the pad calls, and the pad is entered only while the
 * two calls are verified together. The site is on the normal path, and no state got to it out of
 * a pad. Kept apart, nothing enters the pad, and the function gets its slot.
 */
SEC("tc")
__description("kunwind pads: no hidden slots because of a pad, which goes when what the call in front of the pad calls is kept apart")
__success __retval(3)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("the kernel would enter a landing pad of the program: what its code releases of a caller may keep func#1 from getting hidden slots")
__msg("landing pad of may_goto at 20: conflict: the number of sections differs")
__not_msg("the kernel enters it")
__msg("func#1 has hidden slots for: rcu")
__msg("processed {{[0-9]+}} insns")
TWO_COUNTS_IN_SECTION(slots_kept_off_by_pad_of_joined_calls, pad_keeps_slots_off_around_count, 3)

__naked __noinline __used
static unsigned long pad_reads_null_around_count(void)
{
	asm volatile (
		"call counts;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r1 = 0;"
		"r1 = *(u64 *)(r1 + 0);"
		unwind_exit
		::: __clobber_all);
}

/*
 * And for an error that is no conflict: the landing pad reads through a pointer that is NULL,
 * which reads nothing that the call returns, so what the insn itself reads keeps no calls
 * apart.
 */
SEC("tc")
__description("kunwind pads: an error in a pad that goes when what the call in front of the pad calls is kept apart")
__success __retval(3)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("from 8 to the landing pad at 12 of func#1: the kernel unwinds")
__msg("R1 invalid mem access 'scalar'")
__not_msg("the kernel enters it")
__msg("processed {{[0-9]+}} insns")
TWO_COUNTS(error_in_pad_of_joined_calls, pad_reads_null_around_count, 3)

/*
 * A task is held around counts(), and the landing pad behind that call releases it when memory
 * says so: where the pad ends nothing tells whether the task is still held. The pad reads
 * nothing that its call left.
 */
__naked __noinline __used
static unsigned long releases_on_one_way_around_count(void)
{
	asm volatile (
		"r8 = r1;"
		"r9 = r2;"
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
		"r1 = r8;"
		"r2 = r9;"
		"call counts;"
		unwind_goto(1f)
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = 0;"
		"exit;"
	"1:	r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 2f;"
		"r1 = r6;"
		"call %[bpf_task_release];"
	"2:	r0 = 0;"
		unwind_exit
		:: __imm_addr(zero), __imm(bpf_get_current_task_btf), __imm(bpf_task_acquire),
		   __imm(bpf_task_release) : __clobber_all);
}

/*
 * Here the conflict is in the frame that the kernel unwinds: what the pad leaves where it ends
 * has no plan, which shows when the pass is over.
 */
SEC("tc")
__description("kunwind pads: what a pad leaves has no plan, which goes when what the call in front of the pad calls is kept apart")
__success __retval(3)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("the kernel would enter the landing pad at 24 of the call at 18: what the pad leaves at unwind_exit at 31 cannot be released")
__msg("landing pad of unwind_exit at 31 in a frame that the kernel unwinds: conflict: a resource is held on some paths only")
__not_msg("the kernel enters it")
__msg("processed {{[0-9]+}} insns")
TWO_COUNTS(one_way_in_pad_of_joined_calls, releases_on_one_way_around_count, 3)

/* A guard around counts() in a function whose stack is full */
__naked __noinline __used
static unsigned long with_dtor_around_count_full_stack(void)
{
	asm volatile (
		"*(u64 *)(r10 - 2048) = 1;"
		"call counts;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}

/*
 * An error that is no conflict of a plan, and that no state has: the function in which the kernel
 * entered the landing pad has no room in its stack for the hidden words, which shows when the pass
 * is over. Nothing about it tells of the pad but that the kernel entered one, and that is enough:
 * the calls behind which it did are causes of any error of such a pass. Kept apart, nothing enters
 * the pad, and the function needs no word.
 */
SEC("tc")
__description("kunwind pads: no room for the hidden words of a pad, which goes when what the call in front of the pad calls is kept apart")
__success __retval(3)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("the kernel would enter the landing pad at 13 of the call at 9: no room in the stack for the hidden words of func#1")
__not_msg("the kernel enters it")
__msg("processed {{[0-9]+}} insns")
TWO_COUNTS(no_room_for_pad_of_joined_calls, with_dtor_around_count_full_stack, 3)

/*
 * The same function, but it picks the numbers itself, by what is in memory: 1 or 2 is added until
 * the sum is 1000000. Either gets there, and for the two together the loop has no trip count.
 */
__naked __noinline __used
static unsigned long with_dtor_around_count_of_two_steps(void)
{
	asm volatile (
		"*(u64 *)(r10 - 2048) = 1;"
		"r3 = %[zero] ll;"
		"r3 = *(u64 *)(r3 + 0);"
		"r1 = 1;"
		"r2 = 1000000;"
		"if r3 == 0 goto 1f;"
		"r1 = 2;"
	"1:	call counts;"
		unwind_goto(2f)
		"r0 = 0;"
		"exit;"
	"2:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(zero) : __clobber_all);
}

/*
 * Here no two calls are verified together: one call, and in front of it a join at which one value
 * differs. The first pass that has the error adds what the jump that leaves the loop reads to
 * what is kept apart, and that does not do: two states that differ in one value are still joined
 * there. The step that keeps disjoint values apart comes later, and it takes what it looks at
 * from the causes of the pass before it. So the calls behind which the kernel entered a landing
 * pad are causes in every pass that has an error, not only in the first one that has them.
 */
SEC("tc")
__description("kunwind pads: no room for the hidden words of a pad, which goes when one value at a join is kept apart")
__success __retval(3)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("the kernel would enter the landing pad at 15 of the call at 11: no room in the stack for the hidden words of func#1")
__not_msg("the kernel enters it")
__msg("processed {{[0-9]+}} insns")
__naked void no_room_for_pad_behind_join(void)
{
	asm volatile (
		"call with_dtor_around_count_of_two_steps;"
		"r0 = 3;"
		"exit;"
		::: __clobber_all);
}

/* The loop of counts() once more, in a function that a landing pad and the normal path call */
__naked __noinline __used
static unsigned long counts_again(void)
{
	asm volatile (
		"r0 = 0;"
	"1:	r0 += r1;"
		"if r0 != r2 goto 1b;"
		"exit;"
		::: __clobber_all);
}

/* The landing pad calls counts_again() with numbers that memory has: no trip count */
__naked __noinline __used
static unsigned long pad_counts_again_around_count(void)
{
	asm volatile (
		"call counts;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"r2 = %[zero] ll;"
		"r2 = *(u64 *)(r2 + 0);"
		"call counts_again;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(zero) : __clobber_all);
}

/*
 * Here the conflict is at a call of the normal path, in a frame that the kernel does not unwind,
 * and what its plan has leads to no landing pad: the program calls counts_again() with a trip
 * count of five while it holds more than a pad of the verifier releases. While the kernel enters
 * the pad of the other function, that pad calls counts_again() with numbers that the verifier
 * does not know. Its loop gets may_goto for them, and may_goto is in the code for every call of
 * the function: the call that holds too much has something to unwind from. Kept apart, the
 * kernel enters no pad, the loop has a trip count for the one call that is left, and the program
 * loads.
 */
SEC("tc")
__description("kunwind pads: a conflict at a call of what a pad calls too, which goes when what the call in front of the pad calls is kept apart")
__success __retval(3)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("from 33 to the landing pad at 37 of func#2: the kernel unwinds")
__msg("what the call at 11 calls is left at: may_goto")
__msg("landing pad of call at 11: conflict: too much is held")
__not_msg("the kernel enters it")
__msg("processed {{[0-9]+}} insns")
__naked void conflict_at_call_of_what_pad_of_joined_calls_calls(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r1 = 1;"
		"r2 = 5;"
		"call counts_again;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r1 = 1;"
		"r2 = 1000000;"
		"call pad_counts_again_around_count;"
		"r1 = -1;"
		"r2 = -999993;"
		"call pad_counts_again_around_count;"
		"r0 = 3;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

/*
 * Two calls with a landing pad each, and each pad has an end of its own. The first pad only
 * runs the destructor: the lock is held where it ends, and the verifier unlocks. The second one
 * unlocks when memory says so, and where it ends nothing tells whether the lock is held.
 */
__naked __noinline __used
static unsigned long two_pads_two_ends(void)
{
	asm volatile (
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_lock];"
		"if r0 == 0 goto +2;"
		"r0 = 0;"
		"exit;"
	CALL_SPINS
		unwind_goto(1f)
	CALL_SPINS
		unwind_goto(2f)
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_unlock];"
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
	"2:	r6 = r0;"
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 3f;"
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_unlock];"
	"3:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(zero), __imm_addr(top_lock),
		   __imm(bpf_res_spin_lock), __imm(bpf_res_spin_unlock) : __clobber_all);
}

/*
 * The kernel enters both pads. The one that the log names for the end that has no plan is the
 * one that gets there, the second: the first pad of the function has nothing to do with it, and
 * is not counted either.
 */
SEC("tc")
__description("kunwind pads: of two pads with an end of their own the log names the one that gets to the conflict")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("the kernel would enter the landing pad at 27 of the call at 16: what the pad leaves at unwind_exit at 36 cannot be released")
__msg("landing pad of unwind_exit at 36 in a frame that the kernel unwinds: conflict: a resource is held on some paths only")
__naked void second_of_two_pads_is_named(void)
{
	asm volatile (
		"call two_pads_two_ends;"
		"exit;"
		::: __clobber_all);
}

/* The landing pad releases the task that the caller passes: the normal path leaves it alone */
__naked __noinline __used
static unsigned long pad_releases_task_of_caller(void)
{
	asm volatile (
		"r7 = r1;"
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"r1 = r7;"
		"call %[bpf_task_release];"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_task_release) : __clobber_all);
}

/*
 * In an RCU section if r1 is not 0, around a loop that nothing ends, and its stack is full. Then
 * it holds a task around a call of the function above.
 */
__naked __noinline __used
static unsigned long loops_in_section_then_task_for_pad(void)
{
	asm volatile (
		"r6 = r1;"
		"*(u64 *)(r10 - 2048) = 1;"
		"if r6 == 0 goto 1f;"
		"call %[bpf_rcu_read_lock];"
	"1:	r2 = %[zero] ll;"
	"2:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 2b;"
		"if r6 == 0 goto 3f;"
		"call %[bpf_rcu_read_unlock];"
	"3:	call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +2;"
		"r0 = 0;"
		"exit;"
		"r7 = r0;"
		"r1 = r7;"
		"call pad_releases_task_of_caller;"
		"r1 = r7;"
		"call %[bpf_task_release];"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(zero), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock),
		   __imm(bpf_get_current_task_btf), __imm(bpf_task_acquire),
		   __imm(bpf_task_release) : __clobber_all);
}

/*
 * A conflict that the function makes by itself, next to a landing pad that takes hidden slots
 * away for something else. The function is in an RCU section on one way to its loop, and its
 * stack has no room for the hidden slot: the number of sections differs. The landing pad below
 * it releases a task of the function, so no function on the stack gets hidden slots for
 * references. The log says that a landing pad keeps a function from getting hidden slots only
 * where the conflict is about the group that pad code took them away for, and sections are not
 * references: no such line here.
 */
SEC("tc")
__description("kunwind pads: a conflict that a function makes by itself is not the work of a pad that releases something else")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__not_msg("the kernel would enter")
__msg("landing pad of may_goto at {{[0-9]+}}: conflict: the number of sections differs")
__naked void conflict_of_another_group_than_pad_releases(void)
{
	asm volatile (
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"call loops_in_section_then_task_for_pad;"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(one) : __clobber_all);
}

/*
 * Two calls that the kernel unwinds: the first one has no landing pad of the program, the second
 * one has a pad that the kernel enters. r1 == 0 skips the first one, r2 == 0 the second one.
 * The pad holds too much where it ends, so no frame that the kernel unwinds leaves through it.
 */
__naked __noinline __used
static unsigned long spins_then_pad(void)
{
	asm volatile (
		"r6 = r1;"
		"r7 = r2;"
		"if r6 == 0 goto 1f;"
	CALL_SPINS
	"1:	if r7 == 0 goto 3f;"
	CALL_SPINS
		unwind_goto(2f)
		"r0 = 0;"
		"exit;"
	"2:	r6 = r0;"
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r0 = r6;"
		unwind_exit
	"3:	r0 = 0;"
		"exit;"
		:: __imm_addr(one), __imm(bpf_rcu_read_lock) : __clobber_all);
}

CALLS_IN_4_OF_9(caller_of_first, spins_then_pad, 1, 0)
CALLS_IN_4_OF_9(caller_of_second, spins_then_pad, 0, 1)
CALLS_IN_9_OF_9(caller_of_none, spins_then_pad, 0, 0)

/*
 * Here the conflict of the caller that holds too much is an error where the state gets to it: what
 * came back was left at the first call, and nothing came back through the landing pad. The calls
 * are kept apart for it, pass by pass, and that caller gets to neither call. Then the pad that has
 * no plan where it ends is all that is left: that rejects, and the conflict of the caller is not
 * back behind those lines of the log.
 */
SEC("tc")
__description("kunwind pads: a conflict above two calls, one with a pad that has no plan at its end")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of call at 88: conflict: too much is held")
__msg("the kernel would enter the landing pad at 43 of the call at 39: what the pad leaves at unwind_exit at 54 cannot be released")
__msg("landing pad of unwind_exit at 54 in a frame that the kernel unwinds: conflict: too much is held")
__not_msg("landing pad of call at {{[0-9]+}}: conflict: too much is held")
__msg("processed {{[0-9]+}} insns")
__naked void conflict_above_two_calls(void)
{
	asm volatile (
		".rept 5;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"call caller_of_first;"
		"call caller_of_second;"
		".rept 5;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"call caller_of_none;"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock) : __clobber_all);
}

/*
 * The caller turned the interrupts off and the flags are in its stack. The landing pad of the
 * function writes to that slot, and only the kernel unwinds what the function calls. A frame that
 * the kernel unwinds through this pad leaves the caller without its flags: the pad of the verifier
 * in the caller has no place for them. That shows where the state gets to the call, and is an
 * error there: the kernel enters the pad or the program is rejected.
 */
__naked __noinline __used
static unsigned long overwrites_flags_of_caller(void)
{
	asm volatile (
		"r6 = r1;"
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r1 = 0;"
		"*(u64 *)(r6 + 0) = r1;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad that overwrites the irq flags of a caller")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("what the call at 5 calls is left at: a landing pad of the program")
__msg("the kernel would enter a landing pad of the program in or below func#1: it may release or overwrite what a caller holds at the call at 5")
__msg("landing pad of call at 5: conflict: no place has the handle on all paths")
__naked void pad_overwrites_flags_of_caller(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -8;"
		"call overwrites_flags_of_caller;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_local_irq_save), __imm(bpf_local_irq_restore) : __clobber_all);
}

/*
 * The pad of the first call and that of the second one both unlock what the caller locked, and so
 * does the normal path: every way out of the function releases the lock, and nothing else unwinds
 * the function. The pad of the verifier in the caller gets a frame that never holds the lock. The
 * program loads, and the kernel enters both pads.
 */
__naked __noinline __used
static unsigned long adopts_lock_on_every_way(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
	CALL_SPINS
		unwind_goto(1f)
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_unlock];"
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_unlock];"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(top_lock), __imm(bpf_res_spin_unlock)
		: __clobber_all);
}

SEC("tc")
__description("kunwind pads: every pad of a function unlocks the lock of a caller")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of call at 6: rcu=0 preempt=0")
__msg("landing pad of the program behind the call at 11: the kernel enters it")
__msg("landing pad of the program behind the call at 16: the kernel enters it")
__msg("landing pad of unwind_exit at 28 in a frame that the kernel unwinds: rcu=0 preempt=0")
__naked void pads_unlock_for_caller(void)
{
	asm volatile (
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_lock];"
		"if r0 == 0 goto +2;"
		"r0 = 0;"
		"exit;"
		"call adopts_lock_on_every_way;"
		"exit;"
		:: __imm_addr(top_lock), __imm(bpf_res_spin_lock) : __clobber_all);
}

/*
 * Its pad unlocks what the caller locked, and so does the normal path. But the function has a
 * loop of its own: the kernel unwinds its frame there too, and no landing pad of the program
 * stands at a loop. The caller gets the lock held on that way and not on the way through the pad.
 */
__naked __noinline __used
static unsigned long adopts_lock_and_loops(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(2f)
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_unlock];"
		"r0 = 0;"
		"exit;"
	"2:	r6 = r0;"
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_unlock];"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(top_lock), __imm(bpf_res_spin_unlock)
		: __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad that unlocks the lock of a caller in a function with a loop of its own")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("what the call at 6 calls is left at: may_goto, a landing pad of the program")
__msg("the kernel would enter a landing pad of the program in or below func#1: it may release or overwrite what a caller holds at the call at 6")
__msg("landing pad of call at 6: conflict: a resource is held on some paths only")
__naked void pad_unlocks_and_loop_does_not(void)
{
	asm volatile (
		"r1 = %[top_lock] ll;"
		"call %[bpf_res_spin_lock];"
		"if r0 == 0 goto +2;"
		"r0 = 0;"
		"exit;"
		"call adopts_lock_and_loops;"
		"exit;"
		:: __imm_addr(top_lock), __imm(bpf_res_spin_lock) : __clobber_all);
}

/* An RCU section that memory says to enter, a loop that nothing ends, and the section is left */
#define LOOP_IN_SECTION_ON_ONE_WAY				\
		"r7 = %[zero] ll;"				\
		"r7 = *(u64 *)(r7 + 0);"			\
		"if r7 == 0 goto +1;"				\
		"call %[bpf_rcu_read_lock];"			\
		"r2 = %[one] ll;"				\
		"r1 = *(u64 *)(r2 + 0);"			\
		"if r1 != 0 goto -2;"				\
		"if r7 == 0 goto +1;"				\
		"call %[bpf_rcu_read_unlock];"

/*
 * On the normal path the pad of such a loop cannot tell whether the frame is in the section, and
 * the function gets a hidden slot for it: a store at the two calls.
 */
__naked __noinline __used
static unsigned long loops_in_section_on_one_way(void)
{
	asm volatile (
	LOOP_IN_SECTION_ON_ONE_WAY
		"r0 = 0;"
		"exit;"
		:: __imm_addr(zero), __imm_addr(one), __imm(bpf_rcu_read_lock),
		   __imm(bpf_rcu_read_unlock) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a loop in a section that one way enters has a hidden slot on the normal path")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("func#1 has hidden slots for: rcu")
__naked void loop_in_section_on_normal_path(void)
{
	asm volatile (
		"call loops_in_section_on_one_way;"
		"exit;"
		::: __clobber_all);
}

/*
 * The same loop in a landing pad that the kernel enters. A frame that the kernel unwinds gets no
 * hidden slots: they are stores on the normal path, for a way that only the kernel takes. So the
 * loop has no plan for such a frame, and the kernel enters the pad or the program is rejected.
 */
__naked __noinline __used
static unsigned long pad_loops_in_section_on_one_way(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
	LOOP_IN_SECTION_ON_ONE_WAY
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(zero), __imm_addr(one), __imm(bpf_rcu_read_lock),
		   __imm(bpf_rcu_read_unlock) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a loop in a section that one way enters has no plan in pad code")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("the kernel would enter the landing pad at 9 of the call at 5: a site in its code has no plan")
__msg("landing pad of may_goto at 18 in a frame that the kernel unwinds: conflict: the number of sections differs")
__naked void loop_in_section_in_pad_code(void)
{
	asm volatile (
		"call pad_loops_in_section_on_one_way;"
		"exit;"
		::: __clobber_all);
}

struct pad_timer {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct pad_timer);
} pad_timers SEC(".maps");

/* The callback of a timer: it holds more than a pad of the verifier releases at its loop */
__naked __noinline __used
static unsigned long timer_cb_holds_too_much(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(one), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

/*
 * The landing pad arms a timer. The callback runs later, in a frame that the kernel calls, and no
 * frame of the pad is below it then: a site in it that has no plan rejects like any other, and the
 * log says nothing about the landing pad.
 */
__naked __noinline __used
static unsigned long pad_arms_timer(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[pad_timers] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 2f;"
		"r1 = r0;"
		"r2 = %[timer_cb_holds_too_much] ll;"
		"call %[bpf_timer_set_callback];"
	"2:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(pad_timers), __imm_addr(timer_cb_holds_too_much),
		   __imm(bpf_map_lookup_elem), __imm(bpf_timer_set_callback) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a conflict in an async callback that a pad arms")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__not_msg("{{the kernel would enter|is called from a landing pad}}")
__msg("landing pad of may_goto at 43: conflict: too much is held")
__naked void conflict_in_async_cb_of_pad_code(void)
{
	asm volatile (
		"call pad_arms_timer;"
		"exit;"
		::: __clobber_all);
}

/* pad_arms_timer() with counts() in front of its landing pad */
__naked __noinline __used
static unsigned long pad_arms_timer_around_count(void)
{
	asm volatile (
		"call counts;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[pad_timers] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 2f;"
		"r1 = r0;"
		"r2 = %[timer_cb_holds_too_much] ll;"
		"call %[bpf_timer_set_callback];"
	"2:	r0 = r6;"
		unwind_exit
		:: __imm_addr(pad_timers), __imm_addr(timer_cb_holds_too_much),
		   __imm(bpf_map_lookup_elem), __imm(bpf_timer_set_callback) : __clobber_all);
}

/*
 * The same callback, armed by a landing pad that no run of the program gets into: counts() ends
 * for each of the two calls. The callback is verified with a frame of its own, which knows
 * nothing of the pad that armed it, and its conflict is an error of the pass in which the kernel
 * entered that pad. Kept apart, nothing arms the timer, the callback is not verified, and the
 * program loads.
 */
SEC("tc")
__description("kunwind pads: a conflict in an async callback that a pad arms, which goes when what the call in front of the pad calls is kept apart")
__success __retval(3)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("from 8 to the landing pad at 12 of func#1: the kernel unwinds")
__msg("landing pad of may_goto at 43: conflict: too much is held")
__not_msg("the kernel enters it")
__msg("processed {{[0-9]+}} insns")
TWO_COUNTS(conflict_in_async_cb_of_pad_of_joined_calls, pad_arms_timer_around_count, 3)

/* A task in the stack slot at @off of the frame, if r6 is @n. The other slots stay 0. */
#define TASK_IF(n, off)						\
		"if r6 != " #n " goto +6;"			\
		"call %[bpf_get_current_task_btf];"		\
		"r1 = r0;"					\
		"call %[bpf_task_acquire];"			\
		"if r0 == 0 goto 9f;"				\
		"*(u64 *)(r10 - " #off ") = r0;"		\
		"goto 8f;"
#define RELEASE_AT(off)						\
		"r1 = *(u64 *)(r10 - " #off ");"		\
		"if r1 == 0 goto +1;"				\
		"call %[bpf_task_release];"

/*
 * Nine ways to the loop, each with one task, each in a slot of its own. No state holds more than
 * one thing. But a place that has the task of one way has nothing on the others, so each way is
 * an entry of the plan, and a pad has eight.
 */
SEC("tc")
__description("kunwind pads: the paths to a site hold more different things than a pad releases")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("landing pad of may_goto at 79: conflict: the paths to the site hold more different things than a pad releases")
__naked void nine_tasks_on_nine_ways(void)
{
	asm volatile (
		"r6 = %[zero] ll;"
		"r6 = *(u64 *)(r6 + 0);"
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"*(u64 *)(r10 - 16) = r1;"
		"*(u64 *)(r10 - 24) = r1;"
		"*(u64 *)(r10 - 32) = r1;"
		"*(u64 *)(r10 - 40) = r1;"
		"*(u64 *)(r10 - 48) = r1;"
		"*(u64 *)(r10 - 56) = r1;"
		"*(u64 *)(r10 - 64) = r1;"
		"*(u64 *)(r10 - 72) = r1;"
	TASK_IF(1, 8)
	TASK_IF(2, 16)
	TASK_IF(3, 24)
	TASK_IF(4, 32)
	TASK_IF(5, 40)
	TASK_IF(6, 48)
	TASK_IF(7, 56)
	TASK_IF(8, 64)
	TASK_IF(9, 72)
	"8:	r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
	RELEASE_AT(8)
	RELEASE_AT(16)
	RELEASE_AT(24)
	RELEASE_AT(32)
	RELEASE_AT(40)
	RELEASE_AT(48)
	RELEASE_AT(56)
	RELEASE_AT(64)
	RELEASE_AT(72)
	"9:	r0 = 0;"
		"exit;"
		:: __imm_addr(zero), __imm_addr(one), __imm(bpf_get_current_task_btf),
		   __imm(bpf_task_acquire), __imm(bpf_task_release) : __clobber_all);
}

/*
 * The function holds a task on some ways to its first call, which has no landing pad of the
 * program: the pad of the verifier there cannot tell, and the function gets a hidden slot for the
 * task. Every pad of the function releases through the slot from then on. Behind the first call
 * the function saves the irq flags eight times and makes a call with a landing pad that only
 * resumes. A frame that the kernel unwinds through that pad holds eight things where the pad ends,
 * which is what a pad releases, and the slot is one more. A pad of the normal path that has no
 * room for the slots keeps the function from getting them. A frame that the kernel unwinds does
 * not: its plan has the conflict.
 */
__naked __noinline __used
static unsigned long slot_and_eight_flags(void)
{
	asm volatile (
		"r8 = %[zero] ll;"
		"r8 = *(u64 *)(r8 + 0);"
		"r6 = 5;"
		"if r8 == 0 goto 1f;"
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	"1:"
	CALL_SPINS
		"if r8 == 0 goto 2f;"
		"r1 = r6;"
		"call %[bpf_task_release];"
	"2:	r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -24;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -32;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -40;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -48;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -56;"
		"call %[bpf_local_irq_save];"
		"r1 = r10;"
		"r1 += -64;"
		"call %[bpf_local_irq_save];"
	CALL_SPINS
		unwind_goto(3f)
		"r7 = r0;"
		"r1 = r10;"
		"r1 += -64;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -56;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -48;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -40;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -32;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -24;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_local_irq_restore];"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_local_irq_restore];"
		"r0 = r7;"
		"exit;"
	"3:"
		unwind_exit
		:: __imm_addr(one), __imm_addr(zero), __imm(bpf_get_current_task_btf),
		   __imm(bpf_task_acquire), __imm(bpf_task_release), __imm(bpf_local_irq_save),
		   __imm(bpf_local_irq_restore) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the hidden slots of a function and what a pad leaves are more than a pad releases")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("the kernel would enter the landing pad at 76 of the call at 47: what the pad leaves at unwind_exit at 76 cannot be released")
__msg("landing pad of unwind_exit at 76 in a frame that the kernel unwinds: conflict: the function has more hidden slots than a pad has entries")
__naked void slots_and_flags_are_too_much(void)
{
	asm volatile (
		"call slot_and_eight_flags;"
		"exit;"
		::: __clobber_all);
}

/*
 * The function holds a task if r2 is the square of r1, and makes the call with the landing pad if
 * r2 is the square of r1: it asks twice, and a product of two ranges tells the verifier nothing.
 * Its pad leaves the task when r0 is 0, as it is when the kernel unwinds: the entry of the pad has
 * to save the pointer, for the code that stands in for unwind_exit.
 */
__naked __noinline __used
static unsigned long leaves_task_if_square(void)
{
	asm volatile (
		"r8 = r1;"
		"r9 = r2;"
		"r6 = 0;"
		"r3 = r8;"
		"r3 *= r8;"
		"if r3 != r9 goto 1f;"
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	"1:	r3 = r8;"
		"r3 *= r8;"
		"if r3 != r9 goto 2f;"
	CALL_SPINS
		unwind_goto(3f)
	"2:	if r6 == 0 goto +2;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = 0;"
		"exit;"
	"3:	r7 = r0;"
		"call dtor;"
		"if r7 == 0 goto 4f;"
		"if r6 == 0 goto 4f;"
		"r1 = r6;"
		"call %[bpf_task_release];"
	"4:	r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_get_current_task_btf), __imm(bpf_task_acquire),
		   __imm(bpf_task_release) : __clobber_all);
}

/*
 * One call passes 2 and 4, the other 3 and 10: neither gets to the call without a task. Verified
 * together the function does. The states do not agree on what the frame holds, the entry saves
 * nothing, and then what the pad leaves has no place where it ends. That is an error of the pass,
 * and what the next passes keep apart for it is what the jumps in front of the call read. With
 * the two calls apart every state that gets to the call has the task. Every state is asked what
 * the frame holds, also where the entry saves nothing: now they agree, so the entry saves again,
 * the pass is done once more with that, and the program loads with the pad entered.
 */
SEC("tc")
__description("kunwind pads: an entry that saves nothing in one pass saves the task when two calls are kept apart")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("the entry of the landing pad of the call at 26 saves nothing: what the frames hold at the call differs")
__msg("the kernel would enter the landing pad at 33 of the call at 26: what the pad leaves at unwind_exit at 40 cannot be released")
__msg("the entry of the landing pad of the call at 26 saves nothing")
__msg("landing pad of unwind_exit at 40 in a frame that the kernel unwinds: conflict: no place has the handle on all paths")
__msg("the entry of the landing pad of the call at 26 saves again")
__msg("landing pad of the program behind the call at 26: the kernel enters it, saves ref@16(r6)")
__msg("landing pad of unwind_exit at 40 in a frame that the kernel unwinds: ref@16(*fp-16) if not 0 rcu=0 preempt=0")
__not_msg("saves nothing")
__msg("processed {{[0-9]+}} insns")
__naked void entry_saves_once_calls_are_apart(void)
{
	asm volatile (
		"r1 = 2;"
		"r2 = 4;"
		"call leaves_task_if_square;"
		"r1 = 3;"
		"r2 = 10;"
		"call leaves_task_if_square;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

/*
 * One task or two are held at the first call, by what is in memory, and one at the second one.
 * The states that get to the first call do not agree on what the frame holds, so its entry saves
 * nothing, and its pad releases all that is held. The entry of the second call saves the task,
 * its pad leaves the task, and the end that the pads share releases it from the save word.
 * @jump: which of the two ways to the first call comes first in the text.
 */
#define HOLDS_ONE_OR_TWO_THEN_ONE(name, jump)						\
__naked __noinline __used								\
static unsigned long name(void)								\
{											\
	asm volatile (									\
		"r7 = 0;"								\
		"call %[bpf_get_current_task_btf];"					\
		"r1 = r0;"								\
		"call %[bpf_task_acquire];"						\
		"if r0 != 0 goto +1;"							\
		"exit;"									\
		"r6 = r0;"								\
		"r8 = %[one] ll;"							\
		"r8 = *(u64 *)(r8 + 0);"						\
		"if r8 " jump " 0 goto 1f;"						\
		"call %[bpf_get_current_task_btf];"					\
		"r1 = r0;"								\
		"call %[bpf_task_acquire];"						\
		"if r0 != 0 goto +4;"							\
		"r1 = r6;"								\
		"call %[bpf_task_release];"						\
		"r0 = 0;"								\
		"exit;"									\
		"r7 = r0;"								\
	"1:"										\
	CALL_SPINS									\
		unwind_goto(3f)								\
		"if r7 == 0 goto 2f;"							\
		"r1 = r7;"								\
		"call %[bpf_task_release];"						\
	"2:"										\
	CALL_SPINS									\
		unwind_goto(4f)								\
		"r1 = r6;"								\
		"call %[bpf_task_release];"						\
		"r0 = 0;"								\
		"exit;"									\
	"3:	r1 = r6;"								\
		"call %[bpf_task_release];"						\
		"if r7 == 0 goto 5f;"							\
		"r1 = r7;"								\
		"call %[bpf_task_release];"						\
		"goto 5f;"								\
	"4:	call dtor;"								\
	"5:	r0 = 0;"								\
		unwind_exit								\
		:: __imm_addr(one), __imm(bpf_get_current_task_btf),			\
		   __imm(bpf_task_acquire), __imm(bpf_task_release) : __clobber_all);	\
}

HOLDS_ONE_OR_TWO_THEN_ONE(holds_one_or_two_then_one, "==")
HOLDS_ONE_OR_TWO_THEN_ONE(holds_two_or_one_then_one, "!=")

/*
 * The two entries, and the code in place of unwind_exit. The first entry sets K and puts 0 into
 * the save word. The second one sets K and stores the task. The end releases what the word has.
 */
#define CLEARS_THEN_SAVES_XLATED							\
__xlated("...")										\
__xlated("*(u64 *)(r10 -8) = 1")							\
__xlated("*(u64 *)(r10 -16) = 0")							\
__xlated("r0 = 0")									\
__xlated("gotol pc-")									\
__xlated("*(u64 *)(r10 -8) = 1")							\
__xlated("r0 = r6")									\
__xlated("*(u64 *)(r10 -16) = r0")							\
__xlated("r0 = 0")									\
__xlated("gotol pc-")									\
__xlated("r13 = *(u64 *)(r10 -8)")							\
__xlated("if r13 == 0x0 goto pc+6")							\
__xlated("r1 = *(u64 *)(r10 -16)")							\
__xlated("if r1 == 0x0 goto pc+1")							\
__xlated("call kernel-function")

/*
 * The function has one save word, which the entry of the second call fills, and a frame that came
 * through the entry of the first call gets to the same end with its task released by the pad. So
 * the entry that saves nothing stores 0 into the word: whether an entry saves is one answer for
 * all its states, and with the answer no the entry has nothing to save from, also where every
 * state that got to its call held a pointer that it could have stored. With the pointer in the
 * word the end would release the task a second time.
 */
SEC("tc")
__description("kunwind pads: an entry that saves nothing clears the save word that another entry fills")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("the entry of the landing pad of the call at 25 saves nothing: what the frames hold at the call differs")
__msg("landing pad of the program behind the call at 25: the kernel enters it")
__msg("landing pad of the program behind the call at 33: the kernel enters it, saves ref@{{[0-9]+}}(r6)")
CLEARS_THEN_SAVES_XLATED
__naked void entry_that_saves_nothing_clears_word(void)
{
	asm volatile (
		"call holds_one_or_two_then_one;"
		"exit;"
		::: __clobber_all);
}

/* The same with the other way to the first call first in the text: the order of the states */
SEC("tc")
__description("kunwind pads: an entry that saves nothing clears the save word, the other state first")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("the entry of the landing pad of the call at 25 saves nothing: what the frames hold at the call differs")
__msg("landing pad of the program behind the call at 25: the kernel enters it")
__msg("landing pad of the program behind the call at 33: the kernel enters it, saves ref@{{[0-9]+}}(r6)")
CLEARS_THEN_SAVES_XLATED
__naked void entry_that_saves_nothing_clears_word_other_order(void)
{
	asm volatile (
		"call holds_two_or_one_then_one;"
		"exit;"
		::: __clobber_all);
}

/* It leaves with unwind_exit of the program, and never in another way: the kernel unwinds it nowhere */
__naked __noinline __used
static unsigned long only_raises(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
		::: __clobber_all);
}

/* What the compiler emits around a call of _Unwind_RaiseException(): a pad that only resumes */
__naked __noinline __used
static unsigned long empty_pad_behind_raise(void)
{
	asm volatile (
		"call only_raises;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:"
		unwind_exit
		::: __clobber_all);
}

/*
 * A landing pad that only resumes behind a call that no kernel unwind comes back to: the kernel
 * has no way into it, and nothing has to be arranged. The program loads whatever the pad does, no
 * line of the log is about entering it, and its function has no hidden word, no stub and no
 * entry. All that the verifier adds is the pad of the prog at 3, for unwind_exit that comes back
 * to the call at 0, and the traps at 2 and 7 behind the calls that never return.
 */
SEC("tc")
__description("kunwind pads: a pad behind a call that only unwinds by itself is left alone")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at 6 of the call at 2 only resumes")
__not_msg("the kernel {{would enter|enters it}}")
__msg("processed {{[0-9]+}} insns")
__xlated("0: call pc+4")
__xlated("1: unwind_goto pc+1")
__xlated("2: goto pc-1")
__xlated("3: r0 = 2")
__xlated("4: exit")
__xlated("5: call pc+3")
__xlated("6: unwind_goto pc+1")
__xlated("7: goto pc-1")
__xlated("8: unwind_exit")
__xlated("9: r0 = 5")
__xlated("10: unwind_exit")
__naked void pad_behind_raise_is_left_alone(void)
{
	asm volatile (
		"call empty_pad_behind_raise;"
		"exit;"
		::: __clobber_all);
}

/*
 * A loop that only ends when its time is up, and then the program ends: may_goto of the program
 * does not go where it says in a function that can unwind. The call behind the loop is on the
 * control flow graph, and its landing pad only resumes, but no state gets there: the pad is one
 * that the kernel never enters, whatever work it has.
 */
__naked __noinline __used
static unsigned long pad_behind_can_loop(void)
{
	asm volatile (
	"1:	may_goto 2f;"
		"goto 1b;"
	"2:"
	CALL_SPINS
		unwind_goto(3f)
		"r0 = 0;"
		"exit;"
	"3:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad behind a call that is dead after a loop of the program is left alone")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__not_msg("the kernel {{would enter|enters it}}")
__msg("processed {{[0-9]+}} insns")
__naked void pad_behind_can_loop_is_left_alone(void)
{
	asm volatile (
		"call pad_behind_can_loop;"
		"exit;"
		::: __clobber_all);
}

/*
 * A function without an exit: it throws what its callee returns. Its pad goes back to the first
 * insn of the function when memory says so. The store that clears K stands in front of that insn,
 * where a call of the function gets to and the jump of the pad does not: a frame that the kernel
 * unwinds is still one when it has gone back. The jump at 36 goes to 13, behind the store at 12.
 * The insns of the guard that the loop gets, in the pad, are those of x86-64.
 */
__naked __noinline __used
static unsigned long starts_again(void)
{
	asm volatile (
	"1:	r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"call leaves;"
		unwind_goto(2f)
		"r0 += 10;"
		unwind_exit
	"2:	r6 = r0;"
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 3f;"
		"goto 1b;"
	"3:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(zero) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad that goes back to the first insn of its function")
__success __retval(2)
__load_if_JITed()
__arch_x86_64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__msg("insn {{[0-9]+}} of func#1 is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("12: *(u64 *)(r10 -8) = 0")
__xlated("13: r1 = 0x{{[0-9a-f]+}}")
__xlated("15: r1 = *(u64 *)(r1 +0)")
__xlated("16: call pc+")
__xlated("17: unwind_goto pc+3")
__xlated("18: kgoto pc+20")
__xlated("19: r0 += 10")
__xlated("20: gotol pc+23")
__xlated("21: r6 = r0")
__xlated("...")
__xlated("35: if r1 == 0x0 goto pc+1")
__xlated("36: goto pc-24")
__xlated("37: r0 = r6")
__xlated("38: gotol pc+5")
__xlated("39: r13 = *(u64 *)(r10 -8)")
__xlated("40: if r13 != 0x0 goto pc+1")
__xlated("41: *(u64 *)(r10 -8) = 1")
__xlated("42: r0 = 0")
__xlated("43: gotol pc-23")
__xlated("44: r13 = *(u64 *)(r10 -8)")
__xlated("45: if r13 == 0x0 goto pc+3")
__xlated("46: r0 = 2")
__xlated("47: r2 = 0")
__xlated("48: kexit")
__xlated("49: unwind_exit")
__naked void pad_goes_back_to_first_insn(void)
{
	asm volatile (
		"call starts_again;"
		"exit;"
		::: __clobber_all);
}

/*
 * The pad leaves the RCU section of the function unless r0 is 0, and then it loops. When the kernel
 * unwinds the frame, the section is still there at may_goto of the loop: the pad of that way
 * leaves it, the pad of the other way has nothing to leave, and a test of K picks one.
 */
__naked __noinline __used
static unsigned long loops_in_section_in_pad(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
	CALL_LEAVES
		unwind_goto(1f)
		"r6 = r0;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		"exit;"
	"1:	r6 = r0;"
		"if r6 == 0 goto +1;"
		"call %[bpf_rcu_read_unlock];"
		"r2 = %[one] ll;"
	"2:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 2b;"
		"if r6 != 0 goto +1;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

SEC("socket")
__description("kunwind pads: a site that has two pads")
__success __retval(0)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of may_goto at {{[0-9]+}}: rcu=0 preempt=0")
__msg("landing pad of may_goto at {{[0-9]+}} in a frame that the kernel unwinds: rcu=1 preempt=0")
__xlated("...")
__xlated("exit")
__xlated("r0 = 0")
__xlated("exit")
__xlated("call kernel-function")
__xlated("...")
__xlated("call pc+")
__xlated("unwind_goto pc+26")
__xlated("kgoto pc+27")
__xlated("...")
__xlated("if r13 == 0x0 goto pc+15")
__xlated("...")
__xlated("r0 = r6")
__xlated("gotol pc+14")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-23")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-26")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+4")
__xlated("call kernel-function")
__xlated("r0 = 0")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("r0 = 0")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 0")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void site_in_pad_has_two_pads(void)
{
	asm volatile (
		"call loops_in_section_in_pad;"
		"exit;"
		::: __clobber_all);
}

struct bpf_res_spin_lock irq_lock SEC(".data.irq_lock") __hidden;

/*
 * The function holds a task, and a lock that it took with the interrupts off: the task, the lock
 * and the irq flags that the lock saved are three of refs[]. The pad unlocks and leaves the task
 * when r0 is 0. Only the task has a save word, and it is the word that the code in place of
 * unwind_exit reads: the entries of the plan of the entry are in no other order than the words.
 */
__naked __noinline __used
static unsigned long leaves_task_under_irqsave_lock(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
		"r1 = %[irq_lock] ll;"
		"r2 = r10;"
		"r2 += -8;"
		"call %[bpf_res_spin_lock_irqsave];"
		"if r0 == 0 goto +4;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = 0;"
		"exit;"
	CALL_LEAVES
		unwind_goto(1f)
		"r7 = r0;"
		"r1 = %[irq_lock] ll;"
		"r2 = r10;"
		"r2 += -8;"
		"call %[bpf_res_spin_unlock_irqrestore];"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		"exit;"
	"1:	r7 = r0;"
		"r1 = %[irq_lock] ll;"
		"r2 = r10;"
		"r2 += -8;"
		"call %[bpf_res_spin_unlock_irqrestore];"
		"if r7 == 0 goto +2;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(irq_lock), __imm(bpf_get_current_task_btf),
		   __imm(bpf_task_acquire), __imm(bpf_task_release),
		   __imm(bpf_res_spin_lock_irqsave), __imm(bpf_res_spin_unlock_irqrestore)
		: __clobber_all);
}

SEC("tc")
__description("kunwind pads: the save word of a task that is held with a lock and its irq flags")
__success
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it, saves ref@{{[0-9]+}}(r6)")
__msg("landing pad of unwind_exit at {{[0-9]+}} in a frame that the kernel unwinds: ref@{{[0-9]+}}(*fp-24) if not 0 rcu=0 preempt=0")
__xlated("...")
__xlated("r6 = r0")
__xlated("...")
__xlated("*(u64 *)(r10 -16) = 1")
__xlated("r0 = r6")
__xlated("*(u64 *)(r10 -24) = r0")
__xlated("r0 = 0")
__xlated("gotol pc-")
__xlated("r13 = *(u64 *)(r10 -16)")
__xlated("if r13 == 0x0 goto pc+6")
__xlated("r1 = *(u64 *)(r10 -24)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void task_under_irqsave_lock(void)
{
	asm volatile (
		"call leaves_task_under_irqsave_lock;"
		"exit;"
		::: __clobber_all);
}

/*
 * A task and a cgroup, and the task, which the function acquires first, stands behind the cgroup
 * in its text. The pad leaves both when r0 is 0. The words go by the order in which the frame got
 * them: the task is in the first one and the cgroup in the second one, at the entry and where the
 * pad ends, and each is released as what it is.
 */
__naked __noinline __used
static unsigned long holds_task_and_cgroup_out_of_order(void)
{
	asm volatile (
		"goto 2f;"
	"1:	r1 = 1;"
		"call %[bpf_cgroup_from_id];"
		"if r0 != 0 goto +4;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = 0;"
		"exit;"
		"r8 = r0;"
	CALL_LEAVES
		unwind_goto(3f)
		"r7 = r0;"
		"r1 = r8;"
		"call %[bpf_cgroup_release];"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		"exit;"
	"3:	r7 = r0;"
		"if r7 == 0 goto 4f;"
		"r1 = r8;"
		"call %[bpf_cgroup_release];"
		"r1 = r6;"
		"call %[bpf_task_release];"
	"4:	r0 = r7;"
		unwind_exit
	"2:	call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
		"goto 1b;"
		:: __imm_addr(one), __imm(bpf_get_current_task_btf), __imm(bpf_task_acquire),
		   __imm(bpf_task_release), __imm(bpf_cgroup_from_id), __imm(bpf_cgroup_release)
		: __clobber_all);
}

SEC("tc")
__description("kunwind pads: the save words of a task and a cgroup that are acquired out of text order")
__success
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of the program behind the call at 14: the kernel enters it, saves ref@33(r6) , saves ref@4(r8)")
__msg("landing pad of unwind_exit at 30 in a frame that the kernel unwinds: ref@33(*fp-24) if not 0 ref@4(*fp-16) if not 0 rcu=0 preempt=0")
__xlated("...")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = r6")
__xlated("*(u64 *)(r10 -24) = r0")
__xlated("r0 = r8")
__xlated("*(u64 *)(r10 -16) = r0")
__xlated("r0 = 0")
__xlated("gotol pc-")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+9")
__xlated("r1 = *(u64 *)(r10 -24)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -16)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void task_and_cgroup_out_of_order(void)
{
	asm volatile (
		"call holds_task_and_cgroup_out_of_order;"
		"exit;"
		::: __clobber_all);
}

/*
 * The pad takes the task to r1 and then waits in a loop, in an RCU section, before it releases.
 * r6 is not read any more there, and r1 is a register that the calls of a pad clobber: the pad of
 * the loop leaves the section first. The save word has the task wherever the frame is left, so it
 * is the place that the pad of the loop takes, and the kernel enters the landing pad.
 */
__naked __noinline __used
static unsigned long waits_with_task_in_r1(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	CALL_SPINS
		unwind_goto(1f)
		"r7 = r0;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		"exit;"
	"1:	r7 = r0;"
		"call %[bpf_rcu_read_lock];"
		"r1 = r6;"
		"r2 = %[zero] ll;"
	"2:	r3 = *(u64 *)(r2 + 0);"
		"if r3 != 0 goto 2b;"
		"call %[bpf_task_release];"
		"call %[bpf_rcu_read_unlock];"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(zero), __imm(bpf_get_current_task_btf),
		   __imm(bpf_task_acquire), __imm(bpf_task_release), __imm(bpf_rcu_read_lock),
		   __imm(bpf_rcu_read_unlock) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the save word is the place where a register of the pad's calls has the task too")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it, saves ref@{{[0-9]+}}(r6)")
__msg("landing pad of may_goto at {{[0-9]+}} in a frame that the kernel unwinds: ref@{{[0-9]+}}(*fp-16) if not 0 rcu=1 preempt=0")
__not_msg("the kernel would enter")
__naked void task_in_r1_and_in_save_word(void)
{
	asm volatile (
		"call waits_with_task_in_r1;"
		"exit;"
		::: __clobber_all);
}

/*
 * The register has the task plus 8. The entry takes the 8 off before it stores, unless the
 * register is 0, and it does that in R0: the constant is one that the program chose, and an insn
 * on R0 is blinded like any other of the program.
 */
__naked __noinline __used
static unsigned long leaves_task_at_offset(void)
{
	asm volatile (
		"call %[bpf_get_current_task_btf];"
		"r1 = r0;"
		"call %[bpf_task_acquire];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
		"r6 += 8;"
	CALL_LEAVES
		unwind_goto(1f)
		"r7 = r0;"
		"r1 = r6;"
		"r1 += -8;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		"exit;"
	"1:	r7 = r0;"
		"if r7 == 0 goto +3;"
		"r1 = r6;"
		"r1 += -8;"
		"call %[bpf_task_release];"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_get_current_task_btf), __imm(bpf_task_acquire),
		   __imm(bpf_task_release) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the entry takes off what the register has more than the pointer")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it, saves ref@{{[0-9]+}}(r6-8)")
__xlated("...")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = r6")
__xlated("if r0 == 0x0 goto pc+1")
__xlated("r0 += -8")
__xlated("*(u64 *)(r10 -16) = r0")
__xlated("r0 = 0")
__xlated("gotol pc-")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+6")
__xlated("r1 = *(u64 *)(r10 -16)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void task_at_offset(void)
{
	asm volatile (
		"call leaves_task_at_offset;"
		"exit;"
		::: __clobber_all);
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

/*
 * A record of a ring buffer in a save word: a helper releases it, which takes flags too. The code
 * in place of unwind_exit discards the record with the flags 0. 'call unknown' is what the insns
 * of a loaded prog show for the helper.
 */
__naked __noinline __used
static unsigned long leaves_record_to_verifier(void)
{
	asm volatile (
		"r1 = %[ringbuf] ll;"
		"r2 = 8;"
		"r3 = 0;"
		"call %[bpf_ringbuf_reserve];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	CALL_LEAVES
		unwind_goto(1f)
		"r7 = r0;"
		"r1 = r6;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard];"
		"r0 = r7;"
		"exit;"
	"1:	r7 = r0;"
		"if r7 == 0 goto +3;"
		"r1 = r6;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard];"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(ringbuf), __imm(bpf_ringbuf_reserve),
		   __imm(bpf_ringbuf_discard) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the entry keeps a record of a ring buffer, a helper with flags releases it")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it, saves ref@{{[0-9]+}}(r6, 0)")
__msg("landing pad of unwind_exit at {{[0-9]+}} in a frame that the kernel unwinds: ref@{{[0-9]+}}(*fp-16, 0) if not 0 rcu=0 preempt=0")
__xlated("...")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = r6")
__xlated("*(u64 *)(r10 -16) = r0")
__xlated("r0 = 0")
__xlated("gotol pc-")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+7")
__xlated("r1 = *(u64 *)(r10 -16)")
__xlated("if r1 == 0x0 goto pc+2")
__xlated("r2 = 0")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void record_left_to_verifier(void)
{
	asm volatile (
		"call leaves_record_to_verifier;"
		"exit;"
		::: __clobber_all);
}

/*
 * The same, and when r0 is 0 the pad moves the pointer to r1 and overwrites r6 right before it
 * ends: the only register that still has the record is one that the calls of a landing pad
 * clobber. The word is the place, and what releases the record is what the word is for, with the
 * flags that the helper takes: not what r2 happens to have.
 */
__naked __noinline __used
static unsigned long moves_record_to_r1(void)
{
	asm volatile (
		"r1 = %[ringbuf] ll;"
		"r2 = 8;"
		"r3 = 0;"
		"call %[bpf_ringbuf_reserve];"
		"if r0 != 0 goto +1;"
		"exit;"
		"r6 = r0;"
	CALL_LEAVES
		unwind_goto(1f)
		"r7 = r0;"
		"r1 = r6;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard];"
		"r0 = r7;"
		"exit;"
	"1:	r7 = r0;"
		"if r7 == 0 goto 2f;"
		"r1 = r6;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard];"
		"r0 = r7;"
		unwind_exit
	"2:	r1 = r6;"
		"r6 = 0;"
		"r2 = 1;"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(ringbuf), __imm(bpf_ringbuf_reserve),
		   __imm(bpf_ringbuf_discard) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the pointer of a save word is in r1 only where the pad ends")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad of unwind_exit at {{[0-9]+}} in a frame that the kernel unwinds: ref@{{[0-9]+}}(*fp-16, 0) if not 0 rcu=0 preempt=0")
__xlated("...")
__xlated("r6 = 0")
__xlated("r2 = 1")
__xlated("r0 = r7")
__xlated("gotol pc+")
__xlated("...")
__xlated("if r13 == 0x0 goto pc+7")
__xlated("r1 = *(u64 *)(r10 -16)")
__xlated("if r1 == 0x0 goto pc+2")
__xlated("r2 = 0")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void record_in_r1_only(void)
{
	asm volatile (
		"call moves_record_to_r1;"
		"exit;"
		::: __clobber_all);
}

/*
 * The function turns the interrupts off, and the flags go where its caller says: into the stack
 * of the caller. When r0 is 0 the pad writes to that slot and leaves the interrupts off. A save
 * word would have the address of the slot, and what is there is no longer the flags: nothing
 * can turn the interrupts on where the pad ends. So the frame has no plan there, and that
 * rejects the program.
 */
__naked __noinline __used
static unsigned long keeps_irq_flags_in_caller(void)
{
	asm volatile (
		"r6 = r1;"
		"call %[bpf_local_irq_save];"
	CALL_LEAVES
		unwind_goto(1f)
		"r7 = r0;"
		"r1 = r6;"
		"call %[bpf_local_irq_restore];"
		"r0 = r7;"
		"exit;"
	"1:	r7 = r0;"
		"if r7 == 0 goto 2f;"
		"r1 = r6;"
		"call %[bpf_local_irq_restore];"
		"goto 3f;"
	"2:	r1 = 0;"
		"*(u64 *)(r6 + 0) = r1;"
	"3:	r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_local_irq_save), __imm(bpf_local_irq_restore)
		: __clobber_all);
}

SEC("tc")
__description("kunwind pads: irq flags in the stack of a caller that the pad overwrites")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("the kernel would enter the landing pad at 16 of the call at 9: what the pad leaves at unwind_exit at 24 cannot be released")
__msg("landing pad of unwind_exit at 24 in a frame that the kernel unwinds: conflict: no place has the handle on all paths")
__naked void irq_flags_in_caller_overwritten(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"call keeps_irq_flags_in_caller;"
		"exit;"
		::: __clobber_all);
}

/* The same with an iterator that the function makes in the stack of its caller */
__naked __noinline __used
static unsigned long makes_iter_in_caller(void)
{
	asm volatile (
		"r6 = r1;"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
	CALL_LEAVES
		unwind_goto(1f)
		"r7 = r0;"
		"r1 = r6;"
		"call %[bpf_iter_num_destroy];"
		"r0 = r7;"
		"exit;"
	"1:	r7 = r0;"
		"if r7 == 0 goto 2f;"
		"r1 = r6;"
		"call %[bpf_iter_num_destroy];"
		"goto 3f;"
	"2:	r1 = 0;"
		"*(u64 *)(r6 + 0) = r1;"
	"3:	r0 = r7;"
		unwind_exit
		:: __imm_addr(one), __imm(bpf_iter_num_new), __imm(bpf_iter_num_destroy)
		: __clobber_all);
}

SEC("tc")
__description("kunwind pads: an iterator in the stack of a caller that the pad overwrites")
__failure
__load_if_JITed()
__arch_x86_64 __arch_arm64
__msg("the kernel would enter the landing pad at {{[0-9]+}} of the call at {{[0-9]+}}: what the pad leaves at unwind_exit at {{[0-9]+}} cannot be released")
__msg("landing pad of unwind_exit at {{[0-9]+}} in a frame that the kernel unwinds: conflict: no place has the handle on all paths")
__naked void iter_in_caller_overwritten(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"call makes_iter_in_caller;"
		"exit;"
		::: __clobber_all);
}

char _license[] SEC("license") = "GPL";

/*
 * The pad of the first call makes a call too, with a landing pad of its own that only resumes.
 * That call is in pad code: a frame that the kernel unwinds already can make it. Its unwind_goto
 * goes to its pad as the prog has it, with no stub that would clear K, and its entry tests K
 * before it stores: the entry of the first call has no test.
 */
__naked __noinline __used
static unsigned long calls_in_pad(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
	CALL_LEAVES
		unwind_goto(2f)
		"goto 3f;"
	"2:	call dtor;"
	"3:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("socket")
__description("kunwind pads: a call in pad code keeps unwind_goto of the prog, and its entry tests K")
__success __retval(0)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__not_msg("is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("exit")
__xlated("r0 = 0")
__xlated("exit")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+13")
__xlated("kgoto pc+14")
__xlated("exit")
__xlated("r6 = r0")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+2")
__xlated("kgoto pc+9")
__xlated("goto pc+1")
__xlated("call pc+")
__xlated("r0 = r6")
__xlated("gotol pc+10")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-13")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-16")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 != 0x0 goto pc+1")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-13")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 0")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void call_in_pad_code(void)
{
	asm volatile (
		"call calls_in_pad;"
		"exit;"
		::: __clobber_all);
}

/* It returns 7 or leaves with unwind_exit, by what is in memory. The kernel unwinds it nowhere. */
__naked __noinline __used
static unsigned long throws_or_returns(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto +2;"
		"r0 = 5;"
		unwind_exit
		"r0 = 7;"
		"exit;"
		:: __imm_addr(zero) : __clobber_all);
}

/*
 * A destructor, and a try block around a call of something that the kernel never unwinds. That
 * call is no site: the verifier has no plan for it, of any kind. Its landing pad is a typed
 * catch, which the kernel does not enter, and which goes on in the resume block when no clause
 * takes the exception. K is read there. So unwind_goto of that call goes to a stub that clears
 * K, like the one of the call with the destructor: the second and the first of the two stubs.
 */
__naked __noinline __used
static unsigned long catch_without_plan(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
		"call throws_or_returns;"
		unwind_goto(2f)
		"exit;"
	"2:	r6 = r0;"
		"call personality;"
		"if r0 != 1 goto 3f;"
		"r0 = 42;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
	"3:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: unwind_goto behind a call that has no plan goes to a stub")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} returns")
__not_msg("is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+13")
__xlated("kgoto pc+16")
__xlated("call pc+")
__xlated("unwind_goto pc+12")
__xlated("exit")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("if r0 != 0x1 goto pc+4")
__xlated("r0 = 42")
__xlated("exit")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("r0 = r6")
__xlated("gotol pc+7")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-6")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-13")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-11")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void call_without_plan(void)
{
	asm volatile (
		"call catch_without_plan;"
		"exit;"
		::: __clobber_all);
}

/* ~Guard() around a call that passes the argument of the function on */
__naked __noinline __used
static unsigned long with_dtor_of_arg(void)
{
	asm volatile (
		"call leaves;"
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		::: __clobber_all);
}

/*
 * All that the normal path of the function has from the verifier, with and without KASAN: the
 * call is its first insn and reads no memory, so nothing may stand between the pushes and the
 * call, and nothing between the call and the insn that follows it. No store that clears K, no
 * jump around a landing.
 */
SEC("tc")
__description("kunwind pads: nothing of the verifier in front of a call with a pad and behind it")
__success __retval(2)
__load_if_JITed()
__arch_x86_64
__jited("...")
__jited("	subq	$0x8, %rsp")
__jited("	pushq	%rbx")
__jited("	callq	0x{{.*}}")
__jited("L{{.*}}:	popq	%rbx")
__jited("	leave")
__naked void normal_path_of_dtor(void)
{
	asm volatile (
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"call with_dtor_of_arg;"
		"exit;"
		:: __imm_addr(one) : __clobber_all);
}

/* The verifier doesn't know what is in there either: leaves() leaves with unwind_exit for it */
unsigned long two = 2;

/* A function that is too long for the guard of its loop: the pad of the guard is behind it */
__naked __noinline __used
static unsigned long too_long_for_its_guard(void)
{
	asm volatile (
		"r2 = %[zero] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		".rept 33000;"
		"r0 = 0;"
		".endr;"
		"exit;"
		:: __imm_addr(zero) : __clobber_all);
}

/*
 * Two calls share a landing pad, and so its stub. The second one is next to the pad. The first one
 * is as far in front of it as 16 bits allow once every jump in between is taken for three insns.
 */
__naked __noinline __used
static unsigned long far_and_near_call(void)
{
	asm volatile (
		"r1 = %[two] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"call leaves;"
		unwind_goto(1f)
		"r7 = %[zero] ll;"
		"r7 = *(u64 *)(r7 + 0);"
		".rept 12000;"
		"if r7 == 1 goto +1;"
		"r0 = 0;"
		".endr;"
		"r1 = %[two] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"call leaves;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(two), __imm_addr(zero) : __clobber_all);
}

/*
 * A jump that is too far for 16 bits anywhere in the program makes long jumps of all that may be
 * too far then: unwind_goto of the first call is one of them, that of the second call is not.
 * Both still go to the one stub of their landing pad, and the stub goes to the pad: the function
 * throws at its first call, the destructor runs, and the prog catches.
 */
SEC("tc")
__description("kunwind pads: a call far in front of the pad that it shares with a call next to it")
__success __retval(42)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__naked void far_and_near_calls_share_stub(void)
{
	asm volatile (
		"call too_long_for_its_guard;"
		"call far_and_near_call;"
		unwind_goto(1f)
		"exit;"
	"1:	r0 = 42;"
		"exit;"
		::: __clobber_all);
}

/* It never returns and never leaves with unwind_exit: the kernel ends its loop, or it throws */
__naked __noinline __used
static unsigned long only_the_kernel_leaves(void)
{
	asm volatile (
		"r2 = %[one] ll;"
	"1:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r1 = 0;"
		"call %[bpf_throw];"
		"exit;"
		:: __imm_addr(one), __imm(bpf_throw) : __clobber_all);
}

/*
 * catch_without_plan() with a third call in the try block, of a function that only the kernel
 * leaves: nothing returns from it, and its landing pad is the typed catch, which the kernel does
 * not enter. So no state gets to unwind_goto of that call. Its landing pad is no dead code: the
 * second call gets there. That is all that a stub asks for, so the insn has the one that the
 * second call has, kgoto of the call stands in front of it, and a trap is all that is left of it:
 * two stubs, each with its jump, where three unwind_goto have one.
 */
__naked __noinline __used
static unsigned long catch_behind_dead_goto(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
		"call throws_or_returns;"
		unwind_goto(2f)
		"call only_the_kernel_leaves;"
		unwind_goto(2f)
		"exit;"
	"2:	r6 = r0;"
		"call personality;"
		"if r0 != 1 goto 3f;"
		"r0 = 42;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
	"3:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: unwind_goto that no state gets to has a stub if its pad is no dead code")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__not_msg("is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+15")
__xlated("kgoto pc+18")
__xlated("call pc+")
__xlated("unwind_goto pc+14")
__xlated("call pc+")
__xlated("kgoto pc+18")
__xlated("goto pc-1")
__xlated("r6 = r0")
__xlated("...")
__xlated("gotol pc+10")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-6")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-13")
__xlated("*(u64 *)(r10 -8) = 1")
__naked void dead_goto_with_live_pad(void)
{
	asm volatile (
		"call catch_behind_dead_goto;"
		"exit;"
		::: __clobber_all);
}

/* The function of kunwind_pads/stale_private_stack: a guard in a frame of 200 bytes */
__naked __noinline __used
static unsigned long guard_in_large_frame(void)
{
	asm volatile (
		"r1 = 0x77;"
		"*(u64 *)(r10 - 200) = r1;"
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

/*
 * In a tracing prog such a frame is in a private stack, and so is its hidden word: the entry of
 * the landing pad sets K through r9, like the store of the function. The test that counts on a
 * word that is the same in every run on a cpu, see prog_tests/kunwind_pads.c, has that frame.
 */
SEC("raw_tp")
__description("kunwind pads: the hidden word of a large frame of a tracing prog is in its private stack")
__success
__load_if_JITed()
__arch_x86_64
__jited("...")
__jited("	movabsq	$0x{{.*}}, %r9")
__jited("	addq	%gs:{{.*}}, %r9")
__jited("	movl	$0x77, %edi")
__jited("	movq	%rdi, -0xc8(%r9)")
__jited("...")
/* the stub, then the entry: KASAN has its check between the label and the store */
__jited("	movq	$0x0, -0xd0(%r9)")
__jited("...")
__jited("	movq	$0x1, -0xd0(%r9)")
__naked void hidden_word_in_private_stack(void)
{
	asm volatile (
		"call guard_in_large_frame;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

/*
 * The handler of a typed catch calls what the kernel can unwind, in a scope with a destructor.
 * The landing pad of the try is no pad code: it can return. So the call of the handler is no call
 * in pad code either, although only unwind_goto gets to it: its unwind_goto goes to a stub, and
 * its entry stores without a test. A frame gets there with K cleared by the stub of the first
 * call, whose kgoto goes to a pad of the verifier.
 */
__naked __noinline __used
static unsigned long calls_in_catch(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
		"call personality;"
		"if r0 != 1 goto 3f;"
	CALL_LEAVES
		unwind_goto(2f)
		"r0 = 42;"
		"exit;"
	"2:	call dtor;"
	"3:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a call in the landing pad of a typed catch is no call in pad code")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} returns")
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__not_msg("is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+16")
__xlated("kgoto pc+19")
__xlated("exit")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("if r0 != 0x1 goto pc+9")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+8")
__xlated("kgoto pc+12")
__xlated("r0 = 42")
__xlated("exit")
__xlated("call pc+")
__xlated("r0 = r6")
__xlated("gotol pc+10")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-16")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-7")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-13")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void call_in_catch(void)
{
	asm volatile (
		"call calls_in_catch;"
		"exit;"
		::: __clobber_all);
}

/*
 * MIXED functions: an insn is in a landing pad that only resumes and on the normal path of its
 * function as well. What reads K can be reached from the first insn of the function with no
 * landing on the way that would write the word. Such a function is as all were before: its entry
 * clears K, unwind_goto of the prog goes to its pad, and every entry tests K. No stub follows
 * unwind_exit of the function: the next insn is the first one of leaves().
 * "a pad that goes back to the first insn of its function" above is one more of them.
 */
/* 'unwind_goto +0': the landing pad is what follows the call, the function throws what it got */
__naked __noinline __used
static unsigned long falls_into_pad(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the normal path falls into a pad, K is cleared at the entry")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__msg("insn {{[0-9]+}} of func#1 is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("r0 = 2")
__xlated("exit")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+1")
__xlated("kgoto pc+4")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("r0 = r6")
__xlated("gotol pc+5")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 != 0x0 goto pc+1")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-9")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__xlated("if r1 == 0x0 goto pc+15")
__naked void falls_into_pad_mixed(void)
{
	asm volatile (
		"call falls_into_pad;"
		"exit;"
		::: __clobber_all);
}

/* A throw that is inlined: the normal path jumps into the landing pad, by what is in memory */
__naked __noinline __used
static unsigned long jumps_into_pad(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto +2;"
		"r0 = 6;"
		"goto 1f;"
	CALL_LEAVES
		unwind_goto(1f)
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(zero) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the normal path jumps into a pad, K is cleared at the entry")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__msg("insn {{[0-9]+}} of func#1 is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("r0 = 2")
__xlated("exit")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("if r1 == 0x0 goto pc+2")
__xlated("r0 = 6")
__xlated("goto pc+7")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+2")
__xlated("kgoto pc+5")
__xlated("exit")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("r0 = r6")
__xlated("gotol pc+5")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 != 0x0 goto pc+1")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-9")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__xlated("if r1 == 0x0 goto pc+15")
__naked void jumps_into_pad_mixed(void)
{
	asm volatile (
		"call jumps_into_pad;"
		"exit;"
		::: __clobber_all);
}

/*
 * A tail call and LD_ABS on the normal path, in functions whose last exit is unwind_exit of the
 * code that resumes: that exit stands for the return of both in the graph, and it is no way from
 * the normal path into pad code. Neither function is mixed.
 */
__naked __noinline __used
static unsigned long tail_call_on_normal_path(void *ctx)
{
	asm volatile (
		"r6 = r1;"
	CALL_LEAVES
		unwind_goto(1f)
		"r1 = r6;"
		"r2 = %[jmp_table] ll;"
		"r3 = 0;"
		"call %[bpf_tail_call];"
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(jmp_table), __imm(bpf_tail_call) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a tail call on the normal path does not make a function mixed")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__not_msg("is on the normal path and in a landing pad that only resumes")
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it")
__naked void tail_call_not_mixed(void)
{
	asm volatile (
		"call tail_call_on_normal_path;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long ld_abs_on_normal_path(void *ctx)
{
	asm volatile (
		"r6 = r1;"
	CALL_LEAVES
		unwind_goto(1f)
		"r0 = *(u8 *)skb[0];"
		"r0 = 0;"
		"exit;"
	"1:	r7 = r0;"
		"call dtor;"
		"r0 = r7;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: LD_ABS on the normal path does not make a function mixed")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__not_msg("is on the normal path and in a landing pad that only resumes")
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it")
__naked void ld_abs_not_mixed(void)
{
	asm volatile (
		"call ld_abs_on_normal_path;"
		"exit;"
		::: __clobber_all);
}

/* What a throw statement is: a call of a function that has no insn which returns */
__naked __noinline __used
static unsigned long always_throws(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
		::: __clobber_all);
}

/*
 * The function throws in its last statement, and the compiler has put the cleanup pad right
 * behind that call: nothing falls from a call that never returns into what follows it, so the pad
 * is no part of the normal path, and the function is not mixed. Its entry does not clear K.
 */
__naked __noinline __used
static unsigned long pad_behind_throw(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(2f)
		"if r0 == 7 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:	call always_throws;"
		unwind_goto(2f)
	"2:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad behind a call that never returns is no part of the normal path")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__not_msg("is on the normal path and in a landing pad that only resumes")
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it")
__naked void pad_behind_throw_not_mixed(void)
{
	asm volatile (
		"call pad_behind_throw;"
		"exit;"
		::: __clobber_all);
}

/*
 * The throw statement is in the landing pad, and its own landing pad calls std::terminate():
 * that one has no unwind_exit, so it is no pad that only resumes. Nothing falls from a call that
 * never returns into what follows it either. It is pad code because unwind_goto of a call in pad
 * code goes there: a frame that the kernel unwinds gets to bpf_throw(), which is a site that
 * reads K.
 */
__naked __noinline __used
static unsigned long throws_in_pad(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 3f;"
		"call always_throws;"
		unwind_goto(2f)
	"2:	r1 = 0;"
		"call %[bpf_throw];"
	"3:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one), __imm_addr(zero), __imm(bpf_throw) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the pad of a call in pad code that never returns is pad code")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} has no unwind_exit")
__not_msg("is on the normal path and in a landing pad that only resumes")
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it")
__msg("landing pad of bpf_throw at {{[0-9]+}} in a frame that the kernel unwinds: rcu=0 preempt=0")
__naked void throw_in_pad_code(void)
{
	asm volatile (
		"call throws_in_pad;"
		"exit;"
		::: __clobber_all);
}

/* The same throw in a function of another object: it is global */
__naked __noinline __used
unsigned long global_always_throws(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
		::: __clobber_all);
}

/*
 * pad_behind_throw() with that throw. The verifier does not look into a global function at its
 * call, but it knows which functions have no path to an exit, see bpf_compute_might_return():
 * nothing goes on behind a call of one, so the pad that follows the call is no part of the normal
 * path here either. The function is not mixed, and its first insn is the one that the prog has
 * there: nothing clears K at its entry.
 */
__naked __noinline __used
static unsigned long pad_behind_global_throw(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(2f)
		"if r0 == 7 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:	call global_always_throws;"
		unwind_goto(2f)
	"2:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad behind a call of a global function that never returns is no part of the normal path")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__not_msg("is on the normal path and in a landing pad that only resumes")
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it")
__xlated("...")
__xlated("r0 = 2")
__xlated("exit")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__naked void pad_behind_global_throw_not_mixed(void)
{
	asm volatile (
		"call pad_behind_global_throw;"
		"exit;"
		::: __clobber_all);
}

/*
 * The same throw, with a return that the verifier cannot rule out: the main pass goes on behind a
 * call of it.
 */
__naked __noinline __used
unsigned long global_throws_or_returns(void)
{
	asm volatile (
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"r0 = 5;"
		"if r1 == 0 goto +1;"
		unwind_exit
		"exit;"
		:: __imm_addr(one) : __clobber_all);
}

/*
 * pad_behind_throw() with that one. For the verifier the normal path falls into the pad that
 * follows the call, and the function is mixed: it clears K at its entry.
 */
__naked __noinline __used
static unsigned long pad_behind_global_throw_or_return(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(2f)
		"if r0 == 7 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:	call global_throws_or_returns;"
		unwind_goto(2f)
	"2:	r6 = r0;"
		"call dtor;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad behind a call of a global function that may return, K is cleared at the entry")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__msg("insn {{[0-9]+}} of func#1 is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("r0 = 2")
__xlated("exit")
__xlated("*(u64 *)(r10 -8) = 0")
__naked void pad_behind_global_throw_or_return_mixed(void)
{
	asm volatile (
		"call pad_behind_global_throw_or_return;"
		"exit;"
		::: __clobber_all);
}

/*
 * The landing pad throws again through the global function that never returns. Nothing goes on
 * behind that call, in a frame that the kernel unwinds as in any other. On the control flow graph,
 * which has the edge behind every call, the pad gets to the unwind_exit that follows the call all
 * the same: it only resumes, and the kernel enters it.
 * What follows the call is dead code: a trap stands there, and nothing in place of unwind_exit. The
 * frame is left at the call, when unwind_exit of the callee comes back to it, with kexit.
 */
__naked __noinline __used
static unsigned long pad_calls_global_throw(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call dtor;"
		"call global_always_throws;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a pad that calls a global function that never returns")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__not_msg("is on the normal path and in a landing pad that only resumes")
__msg("landing pad of the program behind the call at {{[0-9]+}}: the kernel enters it")
__msg("landing pad of call at {{[0-9]+}} for unwind_exit in a frame that the kernel unwinds: rcu=0 preempt=0")
__xlated("...")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("call pc+")
__xlated("unwind_goto pc+6")
__xlated("goto pc-1")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-7")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-10")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__naked void pad_calls_global_throw_loads(void)
{
	asm volatile (
		"call pad_calls_global_throw;"
		"exit;"
		::: __clobber_all);
}

/*
 * What a frame that the kernel unwinds can do behind a call of a global function that may return,
 * as far as the verifier knows: get to a loop that nothing ends, which is a site that reads K.
 */
__naked __noinline __used
static unsigned long pad_loops_behind_global_throw(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call global_throws_or_returns;"
		"r2 = %[one] ll;"
	"2:	r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 2b;"
		"r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: a loop behind a call of a global function that may return is pad code")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__not_msg("is on the normal path and in a landing pad that only resumes")
__msg("landing pad of may_goto at {{[0-9]+}} in a frame that the kernel unwinds: rcu=0 preempt=0")
__naked void pad_loops_behind_global_throw_loads(void)
{
	asm volatile (
		"call pad_loops_behind_global_throw;"
		"exit;"
		::: __clobber_all);
}

/*
 * Or call what the kernel unwinds, with a landing pad that the kernel enters. The frame has been
 * through an entry by then: the entry of this call tests K before it stores, the last five insns
 * in front of the code that stands in for unwind_exit. The entry of the first call has no test.
 */
__naked __noinline __used
static unsigned long pad_spins_behind_global_throw(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call global_throws_or_returns;"
	CALL_SPINS
		unwind_goto(2f)
		"goto 3f;"
	"2:	call dtor;"
	"3:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the entry of a call behind a call of a global function that may return tests K")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__not_msg("is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+16")
__xlated("kgoto pc+17")
__xlated("r0 = 0")
__xlated("exit")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("unwind_goto pc+15")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+2")
__xlated("kgoto pc+12")
__xlated("goto pc+1")
__xlated("call pc+")
__xlated("r0 = r6")
__xlated("gotol pc+13")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-15")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-18")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 != 0x0 goto pc+1")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-16")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void pad_spins_behind_global_throw_loads(void)
{
	asm volatile (
		"call pad_spins_behind_global_throw;"
		"exit;"
		::: __clobber_all);
}

/*
 * Or call what leaves with unwind_exit. A stub would clear K of a frame that the kernel unwinds:
 * unwind_goto of that call goes to its landing pad as the prog has it. The one stub of the
 * function is that of the first call.
 */
__naked __noinline __used
static unsigned long pad_throws_behind_global_throw(void)
{
	asm volatile (
	CALL_SPINS
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:	r6 = r0;"
		"call global_throws_or_returns;"
		"call throws_or_returns;"
		unwind_goto(2f)
		"goto 3f;"
	"2:	call dtor;"
	"3:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: unwind_goto behind a call of a global function that may return gets no stub")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__not_msg("is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("exit")
__xlated("r0 = 2")
__xlated("exit")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+12")
__xlated("kgoto pc+13")
__xlated("r0 = 0")
__xlated("exit")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("unwind_goto pc+11")
__xlated("call pc+")
__xlated("unwind_goto pc+1")
__xlated("goto pc+1")
__xlated("call pc+")
__xlated("r0 = r6")
__xlated("gotol pc+8")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("gotol pc-11")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-14")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__naked void pad_throws_behind_global_throw_loads(void)
{
	asm volatile (
		"call pad_throws_behind_global_throw;"
		"exit;"
		::: __clobber_all);
}

/* The function throws by itself, with unwind_exit that its landing pad ends in too */
__naked __noinline __used
static unsigned long shares_unwind_exit(void)
{
	asm volatile (
	CALL_LEAVES
		unwind_goto(1f)
		"r6 = r0;"
		"goto 2f;"
	"1:	r6 = r0;"
		"call dtor;"
	"2:	r0 = r6;"
		unwind_exit
		:: __imm_addr(one) : __clobber_all);
}

SEC("tc")
__description("kunwind pads: the normal path and a pad share unwind_exit, K is cleared at the entry")
__success __retval(2)
__load_if_JITed()
__arch_x86_64 __arch_arm64
__log_level(2)
__msg("landing pad at {{[0-9]+}} of the call at {{[0-9]+}} only resumes")
__msg("insn {{[0-9]+}} of func#1 is on the normal path and in a landing pad that only resumes")
__xlated("...")
__xlated("r0 = 2")
__xlated("exit")
__xlated("*(u64 *)(r10 -8) = 0")
__xlated("r1 = 0x")
__xlated("r1 = *(u64 *)(r1 +0)")
__xlated("call pc+")
__xlated("unwind_goto pc+3")
__xlated("kgoto pc+6")
__xlated("r6 = r0")
__xlated("goto pc+2")
__xlated("r6 = r0")
__xlated("call pc+")
__xlated("r0 = r6")
__xlated("gotol pc+5")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 != 0x0 goto pc+1")
__xlated("*(u64 *)(r10 -8) = 1")
__xlated("r0 = 0")
__xlated("gotol pc-9")
__xlated("r13 = *(u64 *)(r10 -8)")
__xlated("if r13 == 0x0 goto pc+3")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__xlated("unwind_exit")
__xlated("if r1 == 0x0 goto pc+15")
__naked void shares_unwind_exit_mixed(void)
{
	asm volatile (
		"call shares_unwind_exit;"
		"exit;"
		::: __clobber_all);
}
