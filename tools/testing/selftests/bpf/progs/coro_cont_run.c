// SPDX-License-Identifier: GPL-2.0
/*
 * What continuations of suspended coroutines do. bpf_testmod's
 * bpf_kfunc_coro_suspend() resumes a frame after the call that took it, from a
 * work item in softirq context, and bpf_kfunc_coro_result() tells what became
 * of the resume: the runner waits for it, see prog_tests/verifier_coro_cont.c.
 * Each test has its own id, see bpf_testmod.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

#define TC_ACT_OK	0

enum {
	ID_RELEASE = 1,
	ID_AGAIN,
	ID_RETURNED,
	ID_UNWOUND,
	ID_APART_UNWOUND,
	ID_APART_RETURNED,
	ID_DIRECT,
	ID_SELF,
	ID_THROWS,
	ID_THROWS_EXC,
};

int coro_resumed;
int result_id;

/* What bpf_testmod says about the resume of result_id */
SEC("syscall")
int coro_result(void *ctx)
{
	return bpf_kfunc_coro_result(result_id);
}

static __noinline __used void coro_destroy_frame(void *frame)
{
	bpf_coro_frame_free(frame);
}

/* Suspend a frame for @id, to be resumed by @resume, with @arg in slot 2 */
static __always_inline int coro_start(__u32 id, void *resume, __u64 arg)
{
	__u64 *slots;

	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots)
		return -1;
	slots[0] = (__u64)resume;
	slots[1] = (__u64)coro_destroy_frame;
	slots[2] = arg;
	return bpf_kfunc_coro_suspend(id, slots);
}

/* The frame holds an object across the suspension: the continuation drops it. */
struct coro_obj {
	int data;
};

static __noinline __used void coro_destroy_obj(void *frame)
{
	__u64 *slots = frame;

	bpf_obj_drop((struct coro_obj *)slots[2]);
	bpf_coro_frame_free(frame);
}

static __noinline __used void coro_resume_obj(void *frame)
{
	__u64 *slots = frame;
	struct coro_obj *obj = (struct coro_obj *)slots[2];

	coro_resumed = obj->data;
	bpf_obj_drop(obj);
	bpf_coro_frame_free(frame);
}

SEC("tc")
int coro_release(void *ctx)
{
	struct coro_obj *obj;
	__u64 *slots;

	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots)
		return 1;
	obj = bpf_obj_new(typeof(*obj));
	if (!obj) {
		bpf_coro_frame_free(slots);
		return 1;
	}
	obj->data = 42;
	slots[0] = (__u64)coro_resume_obj;
	slots[1] = (__u64)coro_destroy_obj;
	slots[2] = (__u64)obj;
	return bpf_kfunc_coro_suspend(ID_RELEASE, slots);
}

/* Suspends its frame again until slot 2 has counted to 3 */
static __noinline __used void coro_resume_again(void *frame)
{
	__u64 *slots = frame;

	if (slots[2] < 3) {
		slots[2]++;
		bpf_kfunc_coro_suspend(ID_AGAIN, slots);
		return;
	}
	coro_resumed = slots[2];
	bpf_coro_frame_free(frame);
}

SEC("tc")
int coro_again(void *ctx)
{
	return coro_start(ID_AGAIN, coro_resume_again, 0);
}

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

/*
 * Frees the frame, and is unwound in dives() when slot 2 says so. What it leaves in R0 when it
 * returns does not matter.
 */
static __noinline __used void coro_resume_dives(void *frame)
{
	__u64 *slots = frame, dive = slots[2];

	bpf_coro_frame_free(frame);
	if (dive)
		dives();
	coro_resumed += 1;
}

SEC("tc")
int coro_returned(void *ctx)
{
	return coro_start(ID_RETURNED, coro_resume_dives, 0);
}

SEC("tc")
int coro_unwound(void *ctx)
{
	return coro_start(ID_UNWOUND, coro_resume_dives, 1);
}

/*
 * The same continuation is resumed twice, unwound once: each call of bpf_coro_run() has its
 * own landing pad.
 */
SEC("tc")
int coro_apart(void *ctx)
{
	return coro_start(ID_APART_UNWOUND, coro_resume_dives, 1) ?:
	       coro_start(ID_APART_RETURNED, coro_resume_dives, 0);
}

/*
 * The program calls the continuation too. The recursion that runs out of stack in it unwinds
 * it either way: into the landing pad of bpf_coro_run() when the kernel resumes the frame, and
 * into the landing pad of the call in the program, which is unwound in turn.
 */
int direct_runs;

static __noinline __used void coro_resume_direct(void *frame)
{
	bpf_coro_frame_free(frame);
	dives();
	direct_runs += 1;
}

SEC("tc")
int coro_direct(void *ctx)
{
	__u64 *slots;
	int err;

	err = coro_start(ID_DIRECT, coro_resume_direct, 0);
	if (err)
		return err;
	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots)
		return -1;
	coro_resume_direct(slots);
	return 0;
}

/* bpf_throw() unwinds the continuation like the kernel does */
static __noinline __used void coro_resume_throws(void *frame)
{
	bpf_coro_frame_free(frame);
	bpf_throw(7);
	coro_resumed += 1;
}

SEC("tc")
int coro_throws(void *ctx)
{
	return coro_start(ID_THROWS, coro_resume_throws, 0);
}

/*
 * The exception callback chooses what the main program returns. An unwound continuation is an
 * invocation of its own, whose value nobody reads: nothing calls the callback for it.
 */
int exc_cb_ran;

__noinline int coro_exc_cb(u64 cookie)
{
	exc_cb_ran = 1;
	return 0;
}

SEC("tc")
__exception_cb(coro_exc_cb)
int coro_throws_exc(void *ctx)
{
	return coro_start(ID_THROWS_EXC, coro_resume_throws, 0);
}

/* Stores its own address in slot 0 each time it suspends the frame again */
static __noinline __used void coro_resume_self(void *frame)
{
	__u64 *slots = frame;

	if (slots[2] < 3) {
		slots[2]++;
		slots[0] = (__u64)coro_resume_self;
		bpf_kfunc_coro_suspend(ID_SELF, slots);
		return;
	}
	coro_resumed = slots[2];
	bpf_coro_frame_free(frame);
}

SEC("tc")
int coro_self(void *ctx)
{
	return coro_start(ID_SELF, coro_resume_self, 0);
}

char _license[] SEC("license") = "GPL";
