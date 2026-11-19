// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

/*
 * Programs that are cancelled while a frame on their stack holds a coroutine frame, see
 * cancel.c and cancel_refs.c: the pad of that frame frees the coroutine frame with
 * bpf_coro_frame_free(). The progs call dives(), which calls itself until the stack has no
 * room. They are in assembly, and the insns of the pad are matched: the pad of a main program
 * is behind its last insn, 'r0 = 0; exit'.
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

/*
 * BTF FUNC records are not generated for kfuncs referenced from inline assembly. These
 * records are necessary for libbpf to link the program.
 */
void __kfunc_btf_root(void)
{
	bpf_coro_frame_free(bpf_coro_frame_alloc(0, 0));
	bpf_throw(0);
}

/* The frame is in r6, and the pad frees it from there */
SEC("tc")
__description("coro cancel: the coroutine frame of a frame that waits in a call is freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("cancel_goto pc+{{[0-9]+}}")
__xlated("...")
__xlated("r0 = 0")
__xlated("exit")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("call unknown")
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
__description("coro cancel: a coroutine frame in a stack slot is freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("cancel_goto pc+{{[0-9]+}}")
__xlated("...")
__xlated("r0 = 0")
__xlated("exit")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call kernel-function")
__xlated("call unknown")
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
 * its pad keeps the cookie in a slot while it frees the frame, and returns it. The pad is
 * where the call of bpf_throw() was, and what was behind it is gone.
 */
SEC("tc")
__description("coro cancel: a coroutine frame is freed when the prog throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r6 = r0")
__xlated("r1 = 3")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r1")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -{{[0-9]+}})")
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
__description("coro cancel: a coroutine frame that may be NULL is tested and freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("cancel_goto pc+{{[0-9]+}}")
__xlated("...")
__xlated("r0 = 0")
__xlated("exit")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("call unknown")
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
 * pointer to the coroutine frame, releases it, and frees the coroutine frame after it.
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
__description("coro cancel: a task in a coroutine frame is released through the frame")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("cancel_goto pc+{{[0-9]+}}")
__xlated("...")
__xlated("r0 = 0")
__xlated("exit")
__xlated("r1 = *(u64 *)(r6 +8)")
__xlated("call kernel-function")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("call unknown")
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
__description("coro cancel: a task is released through a coroutine frame in a stack slot")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("cancel_goto pc+{{[0-9]+}}")
__xlated("...")
__xlated("r0 = 0")
__xlated("exit")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("r1 = *(u64 *)(r1 +8)")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call kernel-function")
__xlated("call unknown")
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
__description("coro cancel: a task in a coroutine frame is released when the prog throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r1 = 4")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r1")
__xlated("r1 = *(u64 *)(r6 +8)")
__xlated("call kernel-function")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -{{[0-9]+}})")
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
__description("coro cancel: a task in a coroutine frame is released when a callee throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 2 padded 2 declined")
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

/* It reads what it is given in R1, and may write to the coroutine frame that R1 points to */
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
 * task: the slot is no place for the pad of the call. A callee that does not read R1 does not
 * get the pointer, which the other progs leave there.
 */
SEC("tc")
__description("coro cancel: a task in a coroutine frame that the callee gets has no place")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("the program cannot be cancelled at this call: no register or stack slot that a pad can read has a reference of the frame{{.*}}(place)")
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

/*
 * The continuation of a suspended coroutine, see verifier_coro_cont.c, has the task that the
 * coroutine frame carried across the suspension at offset 16 of the frame and nowhere else.
 * bpf_testmod's bpf_kfunc_coro_suspend_now() resumes the frame before it returns, and the
 * continuation is cancelled in there: its pad releases the task through the frame and frees
 * the frame, and returns to the kernel. The program goes on behind the call.
 */

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
	bpf_kfunc_coro_suspend_now(slots);
	return TC_ACT_OK;
}

SEC("tc")
__description("coro cancel: a continuation releases its task through the coroutine frame")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int cont_task_at_call(struct __sk_buff *skb)
{
	return cont_start(cont_dives);
}

/*
 * No insn of the continuation brings it the task, so no drop flag tells whether the frame
 * still has it: the visits of the call of dives() differ, and the site declines.
 */
SEC("tc")
__description("coro cancel: a continuation that has its task on some paths only")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("the program cannot be cancelled at this call: the frame holds a resource on some paths only{{.*}}(inexact)")
int cont_task_some_paths(struct __sk_buff *skb)
{
	return cont_start(cont_task_on_one_path);
}

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
