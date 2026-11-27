// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf_arena_common.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

/*
 * Programs that the kernel unwinds while a frame on their stack holds a coroutine frame: the
 * landing pad of that frame frees the coroutine frame with bpf_coro_frame_free(). The progs
 * call dives(), which calls itself until the stack has no room. They are in assembly, and the
 * plan of the landing pad and its insns are matched: the pad of a main program is behind its
 * last insn.
 *
 * It takes the JIT of x86-64 or arm64, CAP_BPF and CAP_PERFMON.
 */

#define TC_ACT_OK	0

char _license[] SEC("license") = "GPL";

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

/* The frames of a recursion that began, and how many times the code behind a call ran */
unsigned long frames;
unsigned long behind;

/* @var++ in assembly, with r1 and r2 */
#define COUNT(var)				\
	"r1 = %[" #var "] ll;"			\
	"r2 = *(u64 *)(r1 + 0);"		\
	"r2 += 1;"				\
	"*(u64 *)(r1 + 0) = r2;"

/* It calls itself until the stack has no room, which unwinds the program */
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

/* r0 = bpf_coro_frame_alloc(@size), r0 = 0 and exit if there is none */
#define FRAME_ALLOC(size)			\
	"r1 = " #size ";"			\
	"r2 = 0;"				\
	"call %[bpf_coro_frame_alloc];"		\
	"if r0 != 0 goto 1f;"			\
	"exit;"					\
"1:"

#define FRAME_FREE(reg)				\
	"r1 = " #reg ";"			\
	"call %[bpf_coro_frame_free];"

/* An arena of which only faults_without_task_of_frame() allocates a page, at the start */
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 8);
} arena SEC(".maps");

/*
 * BTF FUNC records are not generated for kfuncs referenced from inline assembly. These
 * records are necessary for libbpf to link the program.
 */
void __kfunc_btf_root(void)
{
	bpf_coro_frame_free(bpf_coro_frame_alloc(0, 0));
	bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	bpf_throw(0);
}

/* The frame is in r6, and the pad frees it from there */
SEC("tc")
__description("coro unwind: the coroutine frame of a frame that waits in a call is freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 6: ref@2(r6) rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void frame_at_call(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		"call dives;"
		COUNT(behind)
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* The only copy of the frame that outlives the call is in the stack */
SEC("tc")
__description("coro unwind: a coroutine frame in a stack slot is freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 6: ref@2(*fp-8) rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void frame_spilled_at_call(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"*(u64 *)(r10 - 8) = r0;"
		"call dives;"
		COUNT(behind)
		"r1 = *(u64 *)(r10 - 8);"
		"call %[bpf_coro_frame_free];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * bpf_throw() takes the frames through the same pads. The prog has no exception callback, and
 * its pad keeps the cookie in a hidden word while it frees the frame, and returns it. The call
 * of bpf_throw() is a jump to the pad, and what was behind it is gone.
 */
SEC("tc")
__description("coro unwind: a coroutine frame is freed when the prog throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3) __log_level(2)
__msg("landing pad of bpf_throw at 7: ref@2(r6) rcu=0 preempt=0")
__xlated("r6 = r0")
__xlated("r1 = 3")
__xlated("gotol pc+0")
__xlated("*(u64 *)(r10 -8) = r1")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -8)")
__xlated("exit")
__naked void frame_at_throw(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		"r1 = 3;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_throw)
		: __clobber_all
	);
}

/*
 * The prog did not test the frame since bpf_coro_frame_alloc() returned it: there may be
 * none. The pad makes the test and leaves the call out for NULL.
 */
SEC("tc")
__description("coro unwind: a coroutine frame that may be NULL is tested and freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 4: ref@2(r6) if not 0 rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void frame_maybe_null_at_call(void)
{
	asm volatile (
		"r1 = 16;"
		"r2 = 0;"
		"call %[bpf_coro_frame_alloc];"
		"r6 = r0;"
		"call dives;"
		COUNT(behind)
		"if r6 == 0 goto 1f;"
		FRAME_FREE(r6)
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * A reference whose handle is in a slot of a coroutine frame. The pad reads it through the
 * pointer to the coroutine frame, releases it, and frees the coroutine frame after it. The plan
 * shows such a place as '[r6+8]'.
 */

/* What the progs take: the task with this pid */
int pid;

/* r0 = bpf_task_from_pid(pid) */
#define TASK_FROM_PID				\
	"r1 = %[pid] ll;"			\
	"r1 = *(u32 *)(r1 + 0);"		\
	"call %[bpf_task_from_pid];"

/* The coroutine frame in r6 has the task at offset 8, and nothing else has it */
SEC("tc")
__description("coro unwind: a task in a coroutine frame is released through the frame")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 16: ref@9([r6+8]) ref@2(r6) rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = *(u64 *)(r6 +8)")
__xlated("call kernel-function")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void task_in_frame_at_call(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		TASK_FROM_PID
		"if r0 != 0 goto 2f;"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
	"2:"
		"*(u64 *)(r6 + 8) = r0;"
		"call dives;"
		COUNT(behind)
		"r1 = *(u64 *)(r6 + 8);"
		"call %[bpf_task_release];"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* The pointer to the coroutine frame is in a stack slot only */
SEC("tc")
__description("coro unwind: a task is released through a coroutine frame in a stack slot")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 16: ref@9([*fp-8+8]) ref@2(*fp-8) rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("r1 = *(u64 *)(r1 +8)")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void task_in_spilled_frame_at_call(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"*(u64 *)(r10 - 8) = r0;"
		TASK_FROM_PID
		"r1 = *(u64 *)(r10 - 8);"
		"if r0 != 0 goto 2f;"
		"call %[bpf_coro_frame_free];"
		"r0 = 0;"
		"exit;"
	"2:"
		"*(u64 *)(r1 + 8) = r0;"
		"call dives;"
		COUNT(behind)
		"r6 = *(u64 *)(r10 - 8);"
		"r1 = *(u64 *)(r6 + 8);"
		"call %[bpf_task_release];"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* The same when the prog throws: the pad of bpf_throw() releases the task through the frame */
SEC("tc")
__description("coro unwind: a task in a coroutine frame is released when the prog throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of bpf_throw at 18: ref@9([r6+8]) ref@2(r6) rcu=0 preempt=0")
__xlated("r1 = 4")
__xlated("gotol pc+0")
__xlated("*(u64 *)(r10 -8) = r1")
__xlated("r1 = *(u64 *)(r6 +8)")
__xlated("call kernel-function")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -8)")
__xlated("exit")
__naked void task_in_frame_at_throw(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		TASK_FROM_PID
		"if r0 != 0 goto 2f;"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
	"2:"
		"*(u64 *)(r6 + 8) = r0;"
		/* bpf_throw() reads all registers: the frame is to have the only copy */
		"r0 = 0;"
		"r1 = 4;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_throw),
		  __imm_addr(pid)
		: __clobber_all
	);
}

__naked __noinline __used
static void throws_five(void)
{
	asm volatile (
		"r1 = 5;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_throw)
		: __clobber_all
	);
}

/*
 * The frame that waits in the call of a subprog that throws has the task in its coroutine
 * frame only. Its pad at the call releases the task through the frame and frees the frame.
 */
SEC("tc")
__description("coro unwind: a task in a coroutine frame is released when a callee throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 16: ref@9([r6+8]) ref@2(r6) rcu=0 preempt=0")
__naked void task_in_frame_callee_throws(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		TASK_FROM_PID
		"if r0 != 0 goto 2f;"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
	"2:"
		"*(u64 *)(r6 + 8) = r0;"
		"call throws_five;"
		COUNT(behind)
		"r1 = *(u64 *)(r6 + 8);"
		"call %[bpf_task_release];"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * It reads what it is given in R1, the pointer to the coroutine frame, so it is verified with
 * the frame of its caller in the state, like a subprog that is given a pointer to the stack
 */
__naked __noinline __used
static void dives_with_frame(void)
{
	asm volatile (
		"r7 = r1;"
		"call dives;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * The callee gets the pointer to the coroutine frame, and may write to the slot that has the
 * task. What it does to the slot shows in the state that comes back to the call, which the plan
 * of the call is made from: it leaves the slot alone, and the pad of the call releases the task
 * through the frame.
 */
SEC("tc")
__description("coro unwind: a task in a coroutine frame that the callee gets is released through the frame")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 17: ref@9([r6+8]) ref@2(r6) rcu=0 preempt=0")
__naked void task_in_frame_given_to_callee(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		TASK_FROM_PID
		"if r0 != 0 goto 2f;"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
	"2:"
		"*(u64 *)(r6 + 8) = r0;"
		"r1 = r6;"
		"call dives_with_frame;"
		COUNT(behind)
		"r1 = *(u64 *)(r6 + 8);"
		"call %[bpf_task_release];"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* It takes the task out of the slot of the coroutine frame for the time of its call */
__naked __noinline __used
static void dives_with_task_of_frame(void)
{
	asm volatile (
		"r7 = r1;"
		"r8 = *(u64 *)(r7 + 8);"
		"r1 = 0;"
		"*(u64 *)(r7 + 8) = r1;"
		"call dives;"
		"*(u64 *)(r7 + 8) = r8;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * The callee writes to the slot that has the task. While it waits in its call, no place of the
 * frame that holds the task has it: the slot has 0 in the state that comes back to the call. An
 * insn of the prog acquired the task, so a hidden slot has it, and the pad releases it from
 * there.
 */
SEC("tc")
__description("coro unwind: a task in a coroutine frame that the callee takes out is in a hidden slot")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 17: ref@9(*fp-16) if not 0 ref@2(*fp-8) if not 0 rcu=0 preempt=0")
__msg("func#0 has hidden slots for: refs")
__naked void task_in_frame_taken_by_callee(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		TASK_FROM_PID
		"if r0 != 0 goto 2f;"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
	"2:"
		"*(u64 *)(r6 + 8) = r0;"
		"r1 = r6;"
		"call dives_with_task_of_frame;"
		"r1 = *(u64 *)(r6 + 8);"
		"call %[bpf_task_release];"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid)
		: __clobber_all
	);
}

/* rN = addr_space_cast(rN, 0x0, 0x1), which the assembler of GCC doesn't know */
#define to_arena(n) ".8byte 0x1000100bf | (0x11 * " #n ") << 8;"

/*
 * It takes the task out of the slot of the coroutine frame of its caller between two accesses to
 * arena, and puts it back behind them. The first one has a page. The second one has none and
 * faults: the frame is unwound, with the task in R8, and the slot has 0. A copy of the state
 * leaves the frame once per stretch of accesses, see check_arena_site(), and the store to the
 * coroutine frame of the caller ends the stretch, as a store to the stack of the caller does: the
 * caller sees the 0 at the call.
 */
__naked __noinline __used
static void faults_without_task_of_frame(void)
{
	asm volatile (
		"r6 = r1;"
		"r1 = %[arena] ll;"
		"r2 = 0;"
		"r3 = 1;"
		"r4 = -1;"
		"r5 = 0;"
		"call %[bpf_arena_alloc_pages];"
		"if r0 == 0 goto 1f;"
		to_arena(0)
		"r1 = *(u64 *)(r0 + 0);"
		"r8 = *(u64 *)(r6 + 8);"
		"r1 = 0;"
		"*(u64 *)(r6 + 8) = r1;"
		"r9 = 0x7000;"
		to_arena(9)
		"r1 = *(u64 *)(r9 + 0);"
		"*(u64 *)(r6 + 8) = r8;"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_arena_alloc_pages),
		  __imm_addr(arena)
		: __clobber_all
	);
}

/*
 * The pad of the call cannot take the task from the slot, and a hidden slot has it, as for a
 * callee that takes it out of the slot for the time of its call above
 */
SEC("tc")
__description("coro unwind: a store to the coroutine frame of a caller ends a stretch of arena")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 17: ref@9(*fp-16) if not 0 ref@2(*fp-8) if not 0 rcu=0 preempt=0")
__msg("func#0 has hidden slots for: refs")
__naked void task_out_of_frame_at_fault(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		TASK_FROM_PID
		"if r0 != 0 goto 2f;"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
	"2:"
		"*(u64 *)(r6 + 8) = r0;"
		"r1 = r6;"
		"call faults_without_task_of_frame;"
		COUNT(behind)
		"r1 = *(u64 *)(r6 + 8);"
		"call %[bpf_task_release];"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * The continuation of a suspended coroutine, see verifier_coro_cont.c, has the task that the
 * coroutine frame carried across the suspension at offset 16 of the frame and nowhere else.
 * bpf_testmod's bpf_kfunc_coro_suspend() resumes the frame after the call, and the
 * continuation is unwound there: its pad releases the task through the frame, frees the frame,
 * and leaves with kexit into the landing pad of bpf_coro_run(). bpf_kfunc_coro_result() tells,
 * see bpf_testmod.c.
 */
#define CONT_ID		12

/* What bpf_testmod says about the resume of the continuation */
SEC("syscall")
int cont_result(void *ctx)
{
	return bpf_kfunc_coro_result(CONT_ID);
}

static __noinline void cont_destroy(void *frame)
{
	__u64 *slots = frame;

	bpf_task_release((struct task_struct *)slots[2]);
	bpf_coro_frame_free(frame);
}

static __noinline void cont_dives(void *frame)
{
	__u64 *slots = frame;

	dives();
	behind++;
	bpf_task_release((struct task_struct *)slots[2]);
	bpf_coro_frame_free(frame);
}

/* Takes the task again on one path, after it released what the frame carried */
unsigned long late;

static __noinline void cont_task_on_one_path(void *frame)
{
	__u64 *slots = frame;

	if (late) {
		bpf_task_release((struct task_struct *)slots[2]);
		slots[2] = 0;
	}
	dives();
	behind++;
	if (slots[2])
		bpf_task_release((struct task_struct *)slots[2]);
	bpf_coro_frame_free(frame);
}

static __always_inline int cont_start(void (*resume)(void *frame))
{
	struct task_struct *task;
	__u64 *slots;

	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots)
		return TC_ACT_OK;
	task = bpf_task_from_pid(pid);
	if (!task) {
		bpf_coro_frame_free(slots);
		return TC_ACT_OK;
	}
	slots[0] = (__u64)resume;
	slots[1] = (__u64)cont_destroy;
	slots[2] = (__u64)task;
	bpf_kfunc_coro_suspend(CONT_ID, slots);
	return TC_ACT_OK;
}

SEC("tc")
__description("coro unwind: a continuation releases its task through the coroutine frame")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 32: ref@8([r6+16]) ref@2(r6) rcu=0 preempt=0")
int cont_task_at_call(struct __sk_buff *skb)
{
	return cont_start(cont_dives);
}

/*
 * No insn of the continuation brings it the task, so no hidden slot has it. The slot of the
 * coroutine frame tells, like a slot of the stack: it is 0 on the visits of the call of dives()
 * that do not hold the task, and the pad tests it.
 */
SEC("tc")
__description("coro unwind: a continuation that has its task on some paths only")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at 40: ref@8([r6+16]) if not 0 ref@2(r6) rcu=0 preempt=0")
int cont_task_some_paths(struct __sk_buff *skb)
{
	return cont_start(cont_task_on_one_path);
}

/*
 * The slot keeps the pointer that was released: it is not 0, and nothing tells the pad. The path
 * that released the task gets to the call of dives() first here, and last in the second one: a
 * plan asks what a slot had on the visits before the one that brings the entry, and what it has
 * on those after it.
 */
__naked __noinline __used
static void cont_task_released_not_cleared(void *frame)
{
	asm volatile (
		"r6 = r1;"
		"r7 = %[late] ll;"
		"r7 = *(u64 *)(r7 + 0);"
		"if r7 == 0 goto 1f;"
		"r1 = *(u64 *)(r6 + 16);"
		"call %[bpf_task_release];"
	"1:"
		"call dives;"
		"if r7 != 0 goto 2f;"
		"r1 = *(u64 *)(r6 + 16);"
		"call %[bpf_task_release];"
	"2:"
		FRAME_FREE(r6)
		"exit;"
		:
		: __imm(bpf_coro_frame_free),
		  __imm(bpf_task_release),
		  __imm_addr(late)
		: __clobber_all
	);
}

__naked __noinline __used
static void cont_task_released_not_cleared_last(void *frame)
{
	asm volatile (
		"r6 = r1;"
		"r7 = %[late] ll;"
		"r7 = *(u64 *)(r7 + 0);"
		"if r7 != 0 goto 3f;"
	"1:"
		"call dives;"
		"if r7 != 0 goto 2f;"
		"r1 = *(u64 *)(r6 + 16);"
		"call %[bpf_task_release];"
	"2:"
		FRAME_FREE(r6)
		"exit;"
	"3:"
		"r1 = *(u64 *)(r6 + 16);"
		"call %[bpf_task_release];"
		"goto 1b;"
		:
		: __imm(bpf_coro_frame_free),
		  __imm(bpf_task_release),
		  __imm_addr(late)
		: __clobber_all
	);
}

#define NOT_CLEARED "conflict: a resource is held on some paths only"

SEC("tc")
__description("coro unwind: a continuation that leaves a released task in the slot")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("landing pad of call at {{[0-9]+}}: " NOT_CLEARED)
int cont_task_not_cleared(struct __sk_buff *skb)
{
	return cont_start(cont_task_released_not_cleared);
}

SEC("tc")
__description("coro unwind: a continuation that leaves a released task in the slot, later")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("landing pad of call at {{[0-9]+}}: " NOT_CLEARED)
int cont_task_not_cleared_last(struct __sk_buff *skb)
{
	return cont_start(cont_task_released_not_cleared_last);
}

/*
 * The task goes to a second coroutine frame, whose pointer goes to the slot of the first one: at
 * the call of @callee a register points to the first frame, its slot to the second one, and that
 * one has the task. A place is a register or a stack slot of the program, or a slot of a
 * coroutine frame that one of them leads to, over a few frames. R7 has the task until the call,
 * and is written behind it.
 */
#define TASK_TWO_FRAMES_DEEP(callee)				\
	asm volatile (						\
		"r6 = r1;"					\
		"r1 = 16;"					\
		"r2 = 0;"					\
		"call %[bpf_coro_frame_alloc];"			\
		"if r0 != 0 goto 1f;"				\
		"r1 = *(u64 *)(r6 + 16);"			\
		"call %[bpf_task_release];"			\
		FRAME_FREE(r6)					\
		"exit;"						\
	"1:"							\
		"r7 = *(u64 *)(r6 + 16);"			\
		"*(u64 *)(r0 + 8) = r7;"			\
		"*(u64 *)(r6 + 16) = r0;"			\
		"call " #callee ";"				\
		"r7 = *(u64 *)(r6 + 16);"			\
		"r1 = *(u64 *)(r7 + 8);"			\
		"call %[bpf_task_release];"			\
		"r1 = *(u64 *)(r6 + 16);"			\
		"call %[bpf_coro_frame_free];"			\
		FRAME_FREE(r6)					\
		"exit;"						\
		:						\
		: __imm(bpf_coro_frame_alloc),			\
		  __imm(bpf_coro_frame_free),			\
		  __imm(bpf_task_release)			\
		: __clobber_all					\
	)

/* It calls dives() unless 'late' says no: it may return */
__naked __noinline __used
static void dives_unless_late(void)
{
	asm volatile (
		"r1 = %[late] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto 1f;"
		"call dives;"
	"1:"
		"exit;"
		:
		: __imm_addr(late)
		: __clobber_all
	);
}

/* The callee may return: R7 is written behind the call before it is read, and is no place */
__naked __noinline __used
static void cont_task_two_frames_deep(void *frame)
{
	TASK_TWO_FRAMES_DEEP(dives_unless_late);
}

/*
 * dives() never returns: no frame runs what is behind the call, and R6-R9 and the stack are live
 * there for the landing pad of the call. R7 is a place of the task, the slot of the first frame
 * one of the second frame.
 */
__naked __noinline __used
static void cont_task_two_frames_deep_r7(void *frame)
{
	TASK_TWO_FRAMES_DEEP(dives);
}

/*
 * The only pointer to the frame points far behind it: a load from the slot would need an offset
 * that an insn has no room for, so the slot is no place, and the task has none.
 */
__naked __noinline __used
static void cont_task_far_frame_ptr(void *frame)
{
	asm volatile (
		"r6 = r1;"
		"r6 += 40000;"
		"call dives;"
		"r6 += -40000;"
		"r1 = *(u64 *)(r6 + 16);"
		"call %[bpf_task_release];"
		FRAME_FREE(r6)
		"exit;"
		:
		: __imm(bpf_coro_frame_free),
		  __imm(bpf_task_release)
		: __clobber_all
	);
}

SEC("tc")
__description("coro unwind: a continuation whose frame pointer is far from the slot")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("landing pad of call at {{[0-9]+}}: conflict: no place has the handle on all paths")
int cont_task_far(struct __sk_buff *skb)
{
	return cont_start(cont_task_far_frame_ptr);
}

/*
 * A coroutine that is suspended with its task in the slot, or with a number there that is not 0,
 * and the fourth slot says which: the pad of the continuation would take the number for a task.
 * Whichever of the two the verifier gets to first, see the comment above.
 */
static __noinline void cont_either_destroy(void *frame)
{
	__u64 *slots = frame;

	if (slots[3])
		bpf_task_release((struct task_struct *)slots[2]);
	bpf_coro_frame_free(frame);
}

static __noinline void cont_either(void *frame)
{
	__u64 *slots = frame;

	dives();
	behind++;
	if (slots[3])
		bpf_task_release((struct task_struct *)slots[2]);
	bpf_coro_frame_free(frame);
}

static __always_inline int cont_start_either(bool task_first)
{
	struct task_struct *task;
	__u64 *slots;

	slots = bpf_coro_frame_alloc(32, NULL);
	if (!slots)
		return TC_ACT_OK;
	slots[0] = (__u64)cont_either;
	slots[1] = (__u64)cont_either_destroy;
	if (!late == task_first) {
		task = bpf_task_from_pid(pid);
		if (!task) {
			bpf_coro_frame_free(slots);
			return TC_ACT_OK;
		}
		slots[2] = (__u64)task;
		slots[3] = 1;
	} else {
		slots[2] = 1;
		slots[3] = 0;
	}
	bpf_kfunc_coro_suspend(CONT_ID, slots);
	return TC_ACT_OK;
}

SEC("tc")
__description("coro unwind: a continuation with a task or a number in the slot")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("landing pad of call at {{[0-9]+}}: " NOT_CLEARED)
int cont_task_or_number(struct __sk_buff *skb)
{
	return cont_start_either(true);
}

SEC("tc")
__description("coro unwind: a continuation with a number or a task in the slot")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("landing pad of call at {{[0-9]+}}: " NOT_CLEARED)
int cont_number_or_task(struct __sk_buff *skb)
{
	return cont_start_either(false);
}

/* The pad follows the pointers: from R6 to the first frame, from its slot to the second one */
SEC("tc")
__description("coro unwind: a continuation that has its task two coroutine frames deep")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at {{[0-9]+}}: ref@{{[0-9]+}}([[r6+16]+8]) ref@{{[0-9]+}}([r6+16]) ref@{{[0-9]+}}(r6) rcu=0 preempt=0")
int cont_task_two_deep(struct __sk_buff *skb)
{
	return cont_start(cont_task_two_frames_deep);
}

SEC("tc")
__description("coro unwind: a continuation that has its task in R7 behind a call that never returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at {{[0-9]+}}: ref@{{[0-9]+}}(r7) ref@{{[0-9]+}}([r6+16]) ref@{{[0-9]+}}(r6) rcu=0 preempt=0")
int cont_task_two_deep_r7(struct __sk_buff *skb)
{
	return cont_start(cont_task_two_frames_deep_r7);
}

/*
 * A slot of a coroutine frame is to a landing pad what a slot of the stack is. What follows has
 * the frame of a plain function hold the coroutine frame, in R6, and what the function keeps
 * there is held on some paths only: 'some' says which.
 */
unsigned long some = 1;

/* The slot is 0 where the task is not held: the pad tests it */
SEC("tc")
__description("coro unwind: a task in a coroutine frame on some paths, the slot tells")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at {{[0-9]+}}: ref@{{[0-9]+}}([r6+8]) if not 0 ref@2(r6) rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("if r6 == 0x0 goto pc+3")
__xlated("r1 = *(u64 *)(r6 +8)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void task_in_frame_some_paths(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		"r1 = 0;"
		"*(u64 *)(r6 + 8) = r1;"
		"r1 = %[some] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 2f;"
		TASK_FROM_PID
		"if r0 == 0 goto 2f;"
		"*(u64 *)(r6 + 8) = r0;"
	"2:"
		"call dives;"
		COUNT(behind)
		"r1 = *(u64 *)(r6 + 8);"
		"if r1 == 0 goto 3f;"
		"call %[bpf_task_release];"
	"3:"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(some),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* The same with the pointer to the coroutine frame in a stack slot */
SEC("tc")
__description("coro unwind: a task in a spilled coroutine frame on some paths")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at {{[0-9]+}}: ref@{{[0-9]+}}([*fp-8+8]) if not 0 ref@2(*fp-8) rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("if r1 == 0x0 goto pc+3")
__xlated("r1 = *(u64 *)(r1 +8)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void task_in_spilled_frame_some_paths(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"*(u64 *)(r10 - 8) = r0;"
		"r1 = 0;"
		"*(u64 *)(r0 + 8) = r1;"
		"r1 = %[some] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 2f;"
		TASK_FROM_PID
		"if r0 == 0 goto 2f;"
		"r1 = *(u64 *)(r10 - 8);"
		"*(u64 *)(r1 + 8) = r0;"
	"2:"
		"call dives;"
		COUNT(behind)
		"r6 = *(u64 *)(r10 - 8);"
		"r1 = *(u64 *)(r6 + 8);"
		"if r1 == 0 goto 3f;"
		"call %[bpf_task_release];"
	"3:"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(some),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * Neither is there on the other paths: R6 is 0, and the pad stops at that before it reads the
 * slot of a frame that is not there
 */
SEC("tc")
__description("coro unwind: a coroutine frame with a task on some paths")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(2)
__msg("landing pad of call at {{[0-9]+}}: ref@{{[0-9]+}}([r6+8]) if not 0 ref@{{[0-9]+}}(r6) if not 0 rcu=0 preempt=0")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("if r6 == 0x0 goto pc+3")
__xlated("r1 = *(u64 *)(r6 +8)")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__naked void frame_with_task_some_paths(void)
{
	asm volatile (
		"r6 = 0;"
		"r1 = %[some] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 2f;"
		"r1 = 16;"
		"r2 = 0;"
		"call %[bpf_coro_frame_alloc];"
		"if r0 == 0 goto 2f;"
		"r6 = r0;"
		"r1 = 0;"
		"*(u64 *)(r6 + 8) = r1;"
		TASK_FROM_PID
		"if r0 == 0 goto 2f;"
		"*(u64 *)(r6 + 8) = r0;"
	"2:"
		"call dives;"
		COUNT(behind)
		"if r6 == 0 goto 4f;"
		"r1 = *(u64 *)(r6 + 8);"
		"if r1 == 0 goto 3f;"
		"call %[bpf_task_release];"
	"3:"
		FRAME_FREE(r6)
	"4:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(pid),
		  __imm_addr(some),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * Coroutine frames that hold one another: each has the pointer to the next one at offset 8, the
 * last one the task. A function builds the chain below the frame that it is given, as far as
 * 'links' and 'some' allow, and another one takes it down. Their caller has the first frame alone
 * in a register over the call of dives(), and its pad follows the slots.
 */
unsigned long links = 3;

static __always_inline __u64 *frame_below(__u64 *last)
{
	__u64 *next = bpf_coro_frame_alloc(16, NULL);

	if (!next)
		return NULL;
	next[1] = 0;
	last[1] = (__u64)next;
	return next;
}

/* @n frames with @first, fewer if 'links' says so, and the task in the last one of @n */
static __always_inline void chain_below(__u64 *first, int n)
{
	struct task_struct *task;
	__u64 *last = first;
	int i;

#pragma clang loop unroll(full)
	for (i = 1; i < n; i++) {
		if (links < i)
			return;
		last = frame_below(last);
		if (!last)
			return;
	}
	if (!some)
		return;
	task = bpf_task_from_pid(pid);
	if (task)
		last[1] = (__u64)task;
}

static __always_inline void task_down(__u64 *last)
{
	struct task_struct *task = (void *)last[1];

	if (task)
		bpf_task_release(task);
	bpf_coro_frame_free(last);
}

static __noinline void chain2_below(__u64 *first)
{
	chain_below(first, 2);
}

static __noinline void chain2_down(__u64 *f1)
{
	__u64 *f2 = (void *)f1[1];

	if (f2)
		task_down(f2);
	bpf_coro_frame_free(f1);
}

static __noinline void chain3_below(__u64 *first)
{
	chain_below(first, 3);
}

static __noinline void chain3_down(__u64 *f1)
{
	__u64 *f2 = (void *)f1[1], *f3;

	if (f2) {
		f3 = (void *)f2[1];
		if (f3)
			task_down(f3);
		bpf_coro_frame_free(f2);
	}
	bpf_coro_frame_free(f1);
}

static __noinline void chain4_below(__u64 *first)
{
	chain_below(first, 4);
}

static __noinline void chain4_down(__u64 *f1)
{
	__u64 *f2 = (void *)f1[1], *f3, *f4;

	if (f2) {
		f3 = (void *)f2[1];
		if (f3) {
			f4 = (void *)f3[1];
			if (f4)
				task_down(f4);
			bpf_coro_frame_free(f3);
		}
		bpf_coro_frame_free(f2);
	}
	bpf_coro_frame_free(f1);
}

#define CHAIN_PROG(name, n, desc, expect...)					\
SEC("tc")									\
__description("coro unwind: " desc)						\
__arch_x86_64									\
__arch_arm64									\
__load_if_JITed()								\
expect										\
int name(struct __sk_buff *skb)							\
{										\
	__u64 *first = bpf_coro_frame_alloc(16, NULL);				\
										\
	if (!first)								\
		return TC_ACT_OK;						\
	first[1] = 0;								\
	chain##n##_below(first);						\
	dives();								\
	behind++;								\
	chain##n##_down(first);							\
	return TC_ACT_OK;							\
}

#define PAD_OF_CALL "landing pad of call at {{[0-9]+}}: "
#define REF "ref@{{[0-9]+}}"
#define REG "r{{[6-9]}}"

/*
 * The task is there on some paths, and so is each frame but the first: every slot on the way is
 * tested, and a 0 ends the way.
 */
CHAIN_PROG(chain_of_two, 2, "a task two coroutine frames deep on some paths",
	   __success __log_level(2)
	   __msg(PAD_OF_CALL REF "([[" REG "+8]+8]) if not 0 " REF "([" REG "+8]) if not 0 "
		 REF "(" REG ") rcu=0 preempt=0"))
CHAIN_PROG(chain_of_three, 3, "a task three coroutine frames deep on some paths",
	   __success __log_level(2)
	   __msg(PAD_OF_CALL REF "([[[" REG "+8]+8]+8]) if not 0 " REF "([[" REG "+8]+8]) if not 0 "
		 REF "([" REG "+8]) if not 0 " REF "(" REG ") rcu=0 preempt=0"))
/* A pad follows three pointers and no more: the task has no place */
CHAIN_PROG(chain_of_four, 4, "a task four coroutine frames deep",
	   __failure __msg(PAD_OF_CALL "conflict: no place has the handle on all paths"))

struct locked {
	struct bpf_spin_lock lock;
	long val;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct locked);
} locked SEC(".maps");

/*
 * The address of a lock in a slot of the coroutine frame: the function keeps the pointer to the
 * map value there and nowhere else while it holds the lock, and a load from arena faults. The pad
 * takes the address from the slot, unlocks, and frees the frame.
 */
SEC("tc")
__description("coro unwind: the address of a lock in a coroutine frame")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2) __log_level(2)
__msg("landing pad of arena access at {{[0-9]+}}: spin_lock@{{[0-9]+}}([r6+8]) ref@2(r6) rcu=0 preempt=0")
__naked void lock_in_frame_at_fault(void)
{
	asm volatile (
		FRAME_ALLOC(16)
		"r6 = r0;"
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[locked] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 != 0 goto 2f;"
		FRAME_FREE(r6)
		"r0 = 0;"
		"exit;"
	"2:"
		"*(u64 *)(r6 + 8) = r0;"
		"r1 = %[arena] ll;"
		"r8 = 0x10000;"
		to_arena(8)
		"r1 = *(u64 *)(r6 + 8);"
		"call %[bpf_spin_lock];"
		"r2 = *(u32 *)(r8 + 0);"
		"r1 = *(u64 *)(r6 + 8);"
		"call %[bpf_spin_unlock];"
		FRAME_FREE(r6)
		"r0 = 7;"
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_map_lookup_elem),
		  __imm(bpf_spin_lock),
		  __imm(bpf_spin_unlock),
		  __imm_addr(locked),
		  __imm_addr(arena)
		: __clobber_all
	);
}

/*
 * What a coroutine frame does not change: a frame of the program releases what it acquired, and a
 * function that takes a task over from its caller, in an argument, did not acquire it. When the
 * kernel unwinds the function before it has released the task, the pad of its call has to, and
 * the caller, which gave the task away, keeps no copy. That is so with the task in a register
 * or the stack of the callee, and the same with the task in a coroutine frame that the callee
 * makes for it, which is how the first run of a coroutine gets a parameter that it owns.
 */
__naked __noinline __used
static void consumes_task(void)
{
	asm volatile (
		"r6 = r1;"
		"r1 = %[arena] ll;"
		"r8 = 0x10000;"
		to_arena(8)
		"r2 = *(u32 *)(r8 + 0);"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"exit;"
		:
		: __imm(bpf_task_release),
		  __imm_addr(arena)
		: __clobber_all
	);
}

__naked __noinline __used
static void consumes_task_in_frame(void)
{
	asm volatile (
		"r6 = r1;"
		"r1 = 16;"
		"r2 = 0;"
		"call %[bpf_coro_frame_alloc];"
		"if r0 != 0 goto 1f;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"exit;"
	"1:"
		"r7 = r0;"
		"*(u64 *)(r7 + 8) = r6;"
		"r1 = %[arena] ll;"
		"r8 = 0x10000;"
		to_arena(8)
		"r2 = *(u32 *)(r8 + 0);"
		"r1 = *(u64 *)(r7 + 8);"
		"call %[bpf_task_release];"
		FRAME_FREE(r7)
		"exit;"
		:
		: __imm(bpf_coro_frame_alloc),
		  __imm(bpf_coro_frame_free),
		  __imm(bpf_task_release),
		  __imm_addr(arena)
		: __clobber_all
	);
}

#define TASK_GIVEN_TO(name, callee, desc)						\
SEC("tc")										\
__description("coro unwind: " desc)							\
__arch_x86_64										\
__arch_arm64										\
__load_if_JITed()									\
__failure __msg(PAD_OF_CALL "conflict: no place has the handle on all paths")		\
__naked void name(void)									\
{											\
	asm volatile (									\
		TASK_FROM_PID								\
		"if r0 != 0 goto 2f;"							\
		"exit;"									\
	"2:"										\
		"r1 = r0;"								\
		"call " #callee ";"							\
		"r0 = 0;"								\
		"exit;"									\
		:									\
		: __imm(bpf_task_from_pid),						\
		  __imm_addr(pid)							\
		: __clobber_all								\
	);										\
}

TASK_GIVEN_TO(task_given_to_callee, consumes_task,
	      "a callee that takes over the task of its caller is unwound")
TASK_GIVEN_TO(task_given_to_coroutine, consumes_task_in_frame,
	      "a callee that takes over a task into a coroutine frame is unwound")

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
