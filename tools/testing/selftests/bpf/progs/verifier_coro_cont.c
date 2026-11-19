// SPDX-License-Identifier: GPL-2.0
/*
 * Continuations of a suspended coroutine, in the shape clang's lowering gives
 * them: the resume and destroy functions take the frame as their only
 * argument, and the frame's first two slots hold their addresses.
 * bpf_testmod's bpf_kfunc_coro_suspend_now() resumes the frame before it
 * returns, so a test sees what the continuation did.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

struct coro_obj {
	int data;
};

int coro_resumed;

static __noinline void coro_destroy(void *frame)
{
	__u64 *slots = frame;

	bpf_obj_drop((struct coro_obj *)slots[2]);
	bpf_coro_frame_free(frame);
}

/* Releases the object the frame holds, then the frame. */
static __noinline void coro_resume(void *frame)
{
	__u64 *slots = frame;
	struct coro_obj *obj = (struct coro_obj *)slots[2];

	coro_resumed = obj->data;
	bpf_obj_drop(obj);
	bpf_coro_frame_free(frame);
}

/* Frees the frame, and with it the only place that holds the object. */
static __noinline void coro_resume_leak(void *frame)
{
	bpf_coro_frame_free(frame);
}

/* Suspend a frame that holds an object with @data, to be resumed by @resume. */
static __always_inline int coro_start(void (*resume)(void *frame), int data)
{
	struct coro_obj *obj;
	__u64 *slots;

	slots = bpf_coro_frame_alloc(32, NULL);
	if (!slots)
		return 1;
	obj = bpf_obj_new(typeof(*obj));
	if (!obj) {
		bpf_coro_frame_free(slots);
		return 1;
	}
	obj->data = data;
	slots[0] = (__u64)resume;
	slots[1] = (__u64)coro_destroy;
	slots[2] = (__u64)obj;
	slots[3] = 0;
	bpf_kfunc_coro_suspend_now(slots);
	return 0;
}

SEC("tc")
__description("coro_cont: the continuation releases what the frame holds")
__success __retval(42)
int coro_cont_release(void *ctx)
{
	coro_resumed = 0;
	if (coro_start(coro_resume, 42))
		return 1;
	return coro_resumed;
}

SEC("tc")
__description("coro_cont: a continuation that frees the frame only leaks the object")
__failure __msg("Unreleased reference id=")
int coro_cont_leak(void *ctx)
{
	return coro_start(coro_resume_leak, 1);
}

SEC("tc")
__description("coro_cont: a frame without a resume function is rejected")
__failure __msg("suspended coro_frame has no resume function in its first slot")
int coro_cont_no_resume(void *ctx)
{
	__u64 *slots;

	slots = bpf_coro_frame_alloc(16, NULL);
	if (!slots)
		return 1;
	slots[0] = 0;
	slots[1] = (__u64)coro_resume_leak;
	bpf_kfunc_coro_suspend_now(slots);
	return 0;
}

SEC("tc")
__description("coro_cont: the context does not survive a suspension")
__failure __msg("coro_frame slot 2 holds ctx which cannot survive a suspension")
int coro_cont_ctx(void *ctx)
{
	__u64 *slots;

	slots = bpf_coro_frame_alloc(24, NULL);
	if (!slots)
		return 1;
	slots[0] = (__u64)coro_resume_leak;
	slots[1] = (__u64)coro_resume_leak;
	slots[2] = (__u64)ctx;
	bpf_kfunc_coro_suspend_now(slots);
	return 0;
}

SEC("tc")
__description("coro_cont: the object moves to the continuation")
__failure __msg("invalid mem access 'scalar'")
int coro_cont_moved(void *ctx)
{
	struct coro_obj *obj;
	__u64 *slots;

	slots = bpf_coro_frame_alloc(32, NULL);
	if (!slots)
		return 1;
	obj = bpf_obj_new(typeof(*obj));
	if (!obj) {
		bpf_coro_frame_free(slots);
		return 1;
	}
	slots[0] = (__u64)coro_resume;
	slots[1] = (__u64)coro_destroy;
	slots[2] = (__u64)obj;
	bpf_kfunc_coro_suspend_now(slots);
	return obj->data;
}

/* Allocates a frame of the size that the suspend point left in slot 2. */
static __noinline __used void coro_resume_alloc(void *frame)
{
	__u64 *slots = frame;
	void *p;

	p = bpf_coro_frame_alloc(slots[2], NULL);
	if (p)
		bpf_coro_frame_free(p);
	bpf_coro_frame_free(frame);
}

static __noinline __used void coro_destroy_frame(void *frame)
{
	bpf_coro_frame_free(frame);
}

/*
 * Two suspend points leave 8 and 16 in slot 2, which the continuation takes
 * as the constant size of a frame. A join of the two would make it a range.
 * In asm, so that the compiler does not make one call of the two.
 */
SEC("tc")
__description("coro_cont: the continuations of two suspend points keep their constants")
__success __retval(0)
__naked int coro_cont_two_sites(void)
{
	asm volatile (
	"r6 = r1;"
	"r1 = 24;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 != 0 goto 1f;"
	"exit;"
"1:"
	"r7 = r0;"
	"r1 = %[coro_resume_alloc] ll;"
	"*(u64 *)(r7 + 0) = r1;"
	"r1 = %[coro_destroy_frame] ll;"
	"*(u64 *)(r7 + 8) = r1;"
	"r2 = *(u32 *)(r6 + %[__sk_buff_len]);"
	"if r2 > 100 goto 2f;"
	"r1 = 8;"
	"*(u64 *)(r7 + 16) = r1;"
	"r1 = r7;"
	"call %[bpf_kfunc_coro_suspend_now];"
	"r0 = 0;"
	"exit;"
"2:"
	"r1 = 16;"
	"*(u64 *)(r7 + 16) = r1;"
	"r1 = r7;"
	"call %[bpf_kfunc_coro_suspend_now];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_coro_frame_alloc),
	  __imm(bpf_kfunc_coro_suspend_now),
	  __imm_addr(coro_resume_alloc),
	  __imm_addr(coro_destroy_frame),
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
