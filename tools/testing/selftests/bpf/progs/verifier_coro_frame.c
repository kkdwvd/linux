// SPDX-License-Identifier: GPL-2.0
/*
 * Verifier tests for coroutine frames: bpf_coro_frame_alloc() memory tracked
 * as PTR_TO_CORO_FRAME with stack-like slots.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

/*
 * BTF FUNC records are not generated for kfuncs referenced from inline
 * assembly. These records are necessary for libbpf to link the program.
 * The function below is a hack to ensure that BTF FUNC records are generated.
 */
void __kfunc_btf_root(void)
{
	bpf_coro_frame_free(bpf_coro_frame_alloc(0, 0));
}

/* Allocate a frame of 'size' bytes into r0; exit with r0 = 0 when NULL. */
#define CORO_FRAME_ALLOC(size)			\
	"r1 = " #size ";"			\
	"r2 = 0;"				\
	"call %[bpf_coro_frame_alloc];"		\
	"if r0 != 0 goto 1f;"			\
	"exit;"					\
	"1:"

#define CORO_FRAME_FREE(reg)			\
	"r1 = " #reg ";"			\
	"call %[bpf_coro_frame_free];"

#define CORO_IMMS __imm(bpf_coro_frame_alloc), __imm(bpf_coro_frame_free)

SEC("socket")
__description("coro_frame: alloc and free")
__success __retval(0)
__naked void coro_frame_alloc_free(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(64)
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: zero size rejected")
__failure __msg("coro_frame size 0 out of range [1, 512]")
__naked void coro_frame_size_zero(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(0)
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: oversized frame rejected")
__failure __msg("coro_frame size 520 out of range [1, 512]")
__naked void coro_frame_size_too_large(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(520)
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: maximum size accepted")
__success __retval(0)
__naked void coro_frame_size_max(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(512)
	"r1 = 1;"
	"*(u64 *)(r0 + 504) = r1;"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: non-constant size rejected")
__failure __msg("R1 must be a known constant")
__naked void coro_frame_size_unknown(void)
{
	asm volatile (
	"r1 = *(u32 *)(r1 + %[__sk_buff_len]);"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 == 0 goto l0_%=;"
	CORO_FRAME_FREE(r0)
"l0_%=:"
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS,
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: NULL check required before access")
__failure __msg("R0 invalid mem access 'coro_frame_or_null'")
__naked void coro_frame_null_check_required(void)
{
	asm volatile (
	"r1 = 16;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"r1 = 1;"
	"*(u64 *)(r0 + 0) = r1;"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: leaked frame rejected")
__failure __msg("Unreleased reference id=")
__naked void coro_frame_leak(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: double free rejected")
__failure __msg("release kfunc bpf_coro_frame_free expects referenced")
__naked void coro_frame_double_free(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	CORO_FRAME_FREE(r6)
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: use after free rejected")
__failure __msg("R6 invalid mem access 'scalar'")
__naked void coro_frame_use_after_free(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	CORO_FRAME_FREE(r6)
	"r1 = 1;"
	"*(u64 *)(r6 + 0) = r1;"
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: stack copy invalidated by free")
__failure __msg("R6 invalid mem access 'scalar'")
__naked void coro_frame_stack_copy_invalidated(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"*(u64 *)(r10 - 8) = r0;"
	CORO_FRAME_FREE(r0)
	"r6 = *(u64 *)(r10 - 8);"
	"r1 = *(u64 *)(r6 + 0);"
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: stack copy usable before free")
__success __retval(0)
__naked void coro_frame_stack_copy_ok(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"*(u64 *)(r10 - 8) = r0;"
	"r1 = 7;"
	"*(u64 *)(r0 + 8) = r1;"
	"r6 = *(u64 *)(r10 - 8);"
	"r1 = *(u64 *)(r6 + 8);"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: two frames are tracked independently")
__success __retval(0)
__naked void coro_frame_two_frames(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r1 = 32;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 != 0 goto l0_%=;"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
"l0_%=:"
	"r7 = r0;"
	CORO_FRAME_FREE(r6)
	"r1 = 3;"
	"*(u64 *)(r7 + 24) = r1;"
	"r1 = *(u64 *)(r7 + 24);"
	CORO_FRAME_FREE(r7)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: write past the end rejected")
__failure __msg("invalid access to memory, mem_size=16 off=16 size=8")
__naked void coro_frame_oob_write(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r1 = 1;"
	"*(u64 *)(r0 + 16) = r1;"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: negative offset rejected")
__failure __msg("R6 min value is negative")
__naked void coro_frame_negative_offset(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r6 += -8;"
	"r1 = 1;"
	"*(u64 *)(r6 + 0) = r1;"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: exact odd size is honoured")
__success __retval(0)
__naked void coro_frame_odd_size_ok(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(12)
	"w1 = 1;"
	"*(u32 *)(r0 + 8) = w1;"
	"w1 = *(u32 *)(r0 + 8);"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: odd size does not round up")
__failure __msg("invalid access to memory, mem_size=12 off=8 size=8")
__naked void coro_frame_odd_size_oob(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(12)
	"r1 = 1;"
	"*(u64 *)(r0 + 8) = r1;"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: misaligned access rejected")
__failure __msg("misaligned coro_frame access off 0+4 size 8")
__naked void coro_frame_misaligned(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r1 = 1;"
	"*(u64 *)(r0 + 4) = r1;"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: variable offset within bounds")
__success __retval(0)
__naked void coro_frame_var_off_ok(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[__sk_buff_len]);"
	"r6 &= 7;"
	"r6 <<= 3;"
	CORO_FRAME_ALLOC(64)
	"r7 = r0;"
	"r7 += r6;"
	"r1 = 1;"
	"*(u64 *)(r7 + 0) = r1;"
	"r1 = *(u64 *)(r7 + 0);"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS,
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: variable offset out of bounds rejected")
__failure __msg("invalid access to memory, mem_size=64 off=120 size=8")
__naked void coro_frame_var_off_oob(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[__sk_buff_len]);"
	"r6 &= 15;"
	"r6 <<= 3;"
	CORO_FRAME_ALLOC(64)
	"r7 = r0;"
	"r7 += r6;"
	"r1 = 1;"
	"*(u64 *)(r7 + 0) = r1;"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS,
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: uninitialized read allowed with CAP_PERFMON")
__success __retval(0)
__naked void coro_frame_uninit_read_priv(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r1 = *(u64 *)(r0 + 0);"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: uninitialized read rejected without CAP_PERFMON")
__failure_unpriv __msg_unpriv("invalid read from coro_frame off 0+0 size 8")
__caps_unpriv(CAP_BPF)
__naked void coro_frame_uninit_read(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r1 = *(u64 *)(r0 + 0);"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: partially initialized read rejected without CAP_PERFMON")
__failure_unpriv __msg_unpriv("invalid read from coro_frame off 0+4 size 8")
__caps_unpriv(CAP_BPF)
__naked void coro_frame_partial_init_read(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"w1 = 1;"
	"*(u32 *)(r0 + 0) = w1;"
	"r1 = *(u64 *)(r0 + 0);"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: initialized read allowed without CAP_PERFMON")
__success_unpriv __retval_unpriv(0)
__caps_unpriv(CAP_BPF)
__naked void coro_frame_init_read(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"w1 = 1;"
	"*(u32 *)(r0 + 0) = w1;"
	"*(u32 *)(r0 + 4) = w1;"
	"r1 = *(u64 *)(r0 + 0);"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: zero store reads back as known zero")
__success __retval(0)
__naked void coro_frame_zero_store(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"*(u64 *)(r0 + 8) = 0;"
	"r6 = *(u64 *)(r0 + 8);"
	CORO_FRAME_FREE(r0)
	/* r6 is a known zero, so the stack read below is in bounds */
	"r1 = r10;"
	"r1 += -8;"
	"r1 += r6;"
	"r6 = *(u64 *)(r1 + 0);"
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: atomic operation on initialized slot")
__success __retval(0)
__naked void coro_frame_atomic(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r1 = 1;"
	"*(u64 *)(r0 + 0) = r1;"
	"lock *(u64 *)(r0 + 0) += r1;"
	"r1 = *(u64 *)(r0 + 0);"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: freeing a stack pointer rejected")
__failure __msg("release kfunc bpf_coro_frame_free expects referenced")
__naked void coro_frame_free_stack_ptr(void)
{
	asm volatile (
	"r1 = r10;"
	"r1 += -8;"
	"call %[bpf_coro_frame_free];"
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: freeing an offset frame pointer rejected")
__failure __msg("R1 must have zero offset when passed to release func")
__naked void coro_frame_free_offset_ptr(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r1 = r0;"
	"r1 += 8;"
	"call %[bpf_coro_frame_free];"
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
