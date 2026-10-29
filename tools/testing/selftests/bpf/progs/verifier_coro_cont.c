// SPDX-License-Identifier: GPL-2.0
/*
 * Continuations of a suspended coroutine at a site where the program may be
 * unwound, in the shape clang's lowering gives them: the resume and destroy
 * functions take the frame as their only argument, and the frame's first two
 * slots hold their addresses. The object the coroutine holds across the
 * suspension lives in the third slot only, so at a site in a continuation
 * it is listed from the frame.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;
/* bpf_testmod: suspends the frame and resumes it before returning. */
extern void bpf_kfunc_coro_suspend_now(void *frame) __ksym;

struct coro_obj {
	int data;
};

__u32 coro_cancel;
__u32 coro_release_early;

/* Spin until the timed may_goto gives up: cancels the program, or exits the loop. */
static __always_inline void spin(void)
{
	for (;;)
		cond_break;
}

static __noinline void coro_cont_destroy(void *frame)
{
	__u64 *slots = frame;

	bpf_obj_drop((struct coro_obj *)slots[2]);
	bpf_coro_frame_free(frame);
}

/* A cancellation point, the may_goto of the spin, while the frame holds the object. */
static __noinline void coro_cont_loop(void *frame)
{
	__u64 *slots = frame;

	spin();
	bpf_obj_drop((struct coro_obj *)slots[2]);
	bpf_coro_frame_free(frame);
}

/* A throw while the frame holds the object. */
static __noinline void coro_cont_throw(void *frame)
{
	__u64 *slots = frame;

	if (coro_cancel)
		bpf_throw(0);
	bpf_obj_drop((struct coro_obj *)slots[2]);
	bpf_coro_frame_free(frame);
}

/* may_goto +1: BPF_JMP | BPF_JCOND, off 1 */
static const struct bpf_insn may_goto_insn = { .code = 0xe5, .off = 1 };

/*
 * The slot holds the object on one path into the spin and a number on the
 * other, at one site: in asm, so that the compiler does not give each path a
 * spin of its own.
 */
__naked __noinline __used static void coro_cont_mixed(void)
{
	asm volatile (
	"r6 = r1;"
	"r1 = %[coro_release_early] ll;"
	"r7 = *(u32 *)(r1 + 0);"
	"if r7 == 0 goto 1f;"
	"r1 = *(u64 *)(r6 + 16);"
	"call %[bpf_obj_drop];"
	"r1 = 1;"
	"*(u64 *)(r6 + 16) = r1;"
	"1: .8byte %[may_goto];"
	"goto 1b;"
	"if r7 != 0 goto 2f;"
	"r1 = *(u64 *)(r6 + 16);"
	"call %[bpf_obj_drop];"
	"2: r1 = r6;"
	"call %[bpf_coro_frame_free];"
	"exit;"
	:
	: __imm_addr(coro_release_early),
	  __imm(bpf_obj_drop),
	  __imm(bpf_coro_frame_free),
	  __imm_insn(may_goto, may_goto_insn)
	: __clobber_all);
}

static __always_inline int coro_start(void (*resume)(void *frame))
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
	slots[0] = (__u64)resume;
	slots[1] = (__u64)coro_cont_destroy;
	slots[2] = (__u64)obj;
	slots[3] = 0;
	bpf_kfunc_coro_suspend_now(slots);
	return 0;
}

SEC("tc")
__description("coro_cont: the frame holds the object at a cancellation point")
__success __retval(0)
int coro_cont_may_goto(void *ctx)
{
	return coro_start(coro_cont_loop);
}

SEC("tc")
__description("coro_cont: the frame holds the object at a throw")
__success __retval(0)
int coro_cont_throw_site(void *ctx)
{
	return coro_start(coro_cont_throw);
}

/*
 * Whichever path the verifier takes into the spin first, the slot is no
 * location for the object: it is withdrawn, or never free to be chosen.
 */
SEC("tc")
__description("coro_cont: a slot holding the object on one path only is no location")
__failure
__msg("frame_desc: {{reference id=[0-9]+ \\(acquired at insn [0-9]+\\) has no location free to be released from|the reference acquired at insn [0-9]+ is at different locations on different paths}}")
int coro_cont_mixed_slot(void *ctx)
{
	return coro_start((void (*)(void *))coro_cont_mixed);
}

char _license[] SEC("license") = "GPL";
