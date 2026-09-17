// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

static __always_inline bool alloc_frames(__u64 **a, __u64 **b)
{
	*a = bpf_coro_frame_alloc(16, NULL);
	if (!*a)
		return false;
	*b = bpf_coro_frame_alloc(16, NULL);
	if (!*b) {
		bpf_coro_frame_free(*a);
		return false;
	}
	**a = 11;
	**b = 22;
	return true;
}

SEC("tc")
__description("coro_frame: consume two later arguments after checking a borrowed alias")
__success __retval(0)
int coro_frames_consume(void *ctx)
{
	__u64 *a, *b;

	if (!alloc_frames(&a, &b))
		return 0;
	return bpf_kfunc_coro_frames(7, a, b, a) != 18;
}

SEC("tc")
__description("coro_frame: explicit KF_RELEASE does not consume the first frame twice")
__success __retval(0)
int coro_frames_explicit_release(void *ctx)
{
	__u64 *a, *b;

	if (!alloc_frames(&a, &b))
		return 0;
	bpf_kfunc_coro_frames_release(a, b);
	return 0;
}

SEC("tc")
__description("coro_frame: duplicate consuming arguments rejected")
__failure __msg("same coroutine frame to multiple consuming arguments")
int coro_frames_duplicate(void *ctx)
{
	__u64 *a = bpf_coro_frame_alloc(16, NULL);

	if (!a)
		return 0;
	*a = 11;
	return bpf_kfunc_coro_frames(7, a, a, a);
}

SEC("tc")
__description("coro_frame: duplicate with explicit KF_RELEASE rejected")
__failure __msg("same coroutine frame to multiple consuming arguments")
int coro_frames_explicit_duplicate(void *ctx)
{
	void *a = bpf_coro_frame_alloc(16, NULL);

	if (!a)
		return 0;
	bpf_kfunc_coro_frames_release(a, a);
	return 0;
}

SEC("tc")
__description("coro_frame: first consumed frame alias invalidated")
__failure __msg("invalid mem access 'scalar'")
int coro_frames_first_alias(void *ctx)
{
	__u64 *a, *b;

	if (!alloc_frames(&a, &b))
		return 0;
	bpf_kfunc_coro_frames(7, a, b, a);
	return *a;
}

SEC("tc")
__description("coro_frame: second consumed frame alias invalidated")
__failure __msg("invalid mem access 'scalar'")
int coro_frames_second_alias(void *ctx)
{
	__u64 *a, *b;

	if (!alloc_frames(&a, &b))
		return 0;
	bpf_kfunc_coro_frames(7, a, b, a);
	return *b;
}

SEC("tc")
__description("coro_frame: unrelated frame remains owned")
__success __retval(0)
int coro_frames_preserve_other(void *ctx)
{
	__u64 *a, *b, *other;
	int result;

	if (!alloc_frames(&a, &b))
		return 0;
	other = bpf_coro_frame_alloc(16, NULL);
	if (other)
		*other = 33;
	bpf_kfunc_coro_frames(7, a, b, a);
	if (!other)
		return 0;
	result = *other != 33;
	bpf_coro_frame_free(other);
	return result;
}

SEC("tc")
__description("coro_frame: later consuming argument requires a non-NULL frame")
__failure __msg("Possibly NULL pointer passed to trusted R3")
int coro_frames_null(void *ctx)
{
	__u64 *a = bpf_coro_frame_alloc(16, NULL);

	if (!a)
		return 0;
	*a = 11;
	return bpf_kfunc_coro_frames(7, a, NULL, a);
}

SEC("tc")
__description("coro_frame: later consuming argument requires a base pointer")
__failure __msg("must have zero offset")
int coro_frames_offset(void *ctx)
{
	__u64 *a, *b;

	if (!alloc_frames(&a, &b))
		return 0;
	return bpf_kfunc_coro_frames(7, a, b + 1, a);
}

#if defined(__BPF_FEATURE_STACK_ARGUMENT)

SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__description("coro_frame: consume register and stack arguments")
__success __retval(0)
int coro_frames_stack(void *ctx)
{
	__u64 *a, *b;

	if (!alloc_frames(&a, &b))
		return 0;
	return bpf_kfunc_coro_frames_stack(a, 1, 2, 3, 4, b) != 10;
}

SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__description("coro_frame: duplicate register and stack arguments rejected")
__failure __msg("same coroutine frame to multiple consuming arguments")
int coro_frames_stack_duplicate(void *ctx)
{
	void *a = bpf_coro_frame_alloc(16, NULL);

	if (!a)
		return 0;
	return bpf_kfunc_coro_frames_stack(a, 1, 2, 3, 4, a);
}

#endif

char _license[] SEC("license") = "GPL";
