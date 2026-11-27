// SPDX-License-Identifier: GPL-2.0
/*
 * Verifier tests for coroutine frames: bpf_coro_frame_alloc() memory tracked
 * as PTR_TO_CORO_FRAME with stack-like slots.
 * bpf_coro_frame_free() is registered without KF_RELEASE, so the lifetime
 * tests also cover ownership consumption inferred from __coro_frame.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;
extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
			       struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, __u64 offset,
			      void *buffer, __u64 buffer__szk) __ksym;

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
__failure __msg("R1 type=scalar expected=coro_frame")
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
__failure __msg("R1 type=fp expected=coro_frame")
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

/*
 * Spill and fill tests. Filled scalars are used as helper size arguments,
 * which are checked against the 8 bytes of the buffer, so the verifier must
 * have restored the spilled constant.
 */

__naked __noinline __used static void coro_frame_loop_cb(void)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

__naked __noinline __used static void coro_frame_store_eight(void)
{
	/* r1 is a frame pointer; store 8 into its first slot */
	asm volatile (
	"r2 = 8;"
	"*(u64 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

__naked __noinline __used static void coro_frame_store_eight_inner(void)
{
	/* r1 is a frame that holds another one at offset 8; store 8 into that */
	asm volatile (
	"r1 = *(u64 *)(r1 + 8);"
	"r2 = 8;"
	"*(u64 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/* Load 'size' bytes of packet data into the 8-byte buffer at fp-8. */
#define SKB_LOAD_BYTES_FROM(ctx_reg, size_reg)	\
	"r1 = " #ctx_reg ";"			\
	"r2 = 0;"				\
	"r3 = r10;"				\
	"r3 += -8;"				\
	"r4 = " #size_reg ";"			\
	"call %[bpf_skb_load_bytes];"

SEC("socket")
__description("coro_frame: scalar spill and fill restores the constant")
__success __retval(0)
__naked void coro_frame_scalar_spill_fill(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"r6 = 8;"
	"*(u64 *)(r0 + 0) = r6;"
	"r7 = *(u64 *)(r0 + 0);"
	CORO_FRAME_FREE(r0)
	SKB_LOAD_BYTES_FROM(r9, r7)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: immediate store spills a known scalar")
__success __retval(0)
__naked void coro_frame_st_imm_spill(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"*(u64 *)(r0 + 8) = 8;"
	"r7 = *(u64 *)(r0 + 8);"
	CORO_FRAME_FREE(r0)
	SKB_LOAD_BYTES_FROM(r9, r7)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: narrow fill of a spilled scalar")
__success __retval(0)
__naked void coro_frame_narrow_fill(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"r6 = 8;"
	"*(u64 *)(r0 + 0) = r6;"
	"w7 = *(u32 *)(r0 + 0);"
	CORO_FRAME_FREE(r0)
	SKB_LOAD_BYTES_FROM(r9, r7)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: zero spill and zero bytes read as known zero")
__success __retval(0)
__naked void coro_frame_mixed_zero_read(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"*(u32 *)(r0 + 4) = 0;"
	"w6 = 0;"
	"*(u32 *)(r0 + 0) = w6;"
	"r7 = *(u64 *)(r0 + 0);"
	CORO_FRAME_FREE(r0)
	/* r7 is a known zero, so the stack read below is in bounds */
	"r1 = r10;"
	"r1 += -8;"
	"r1 += r7;"
	"r6 = *(u64 *)(r1 + 0);"
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: a join of spilled scalars covers both")
__failure __msg("invalid write to stack R3 off=-8 size=8000")
__naked void coro_frame_join_spilled_scalars(void)
{
	asm volatile (
	"r9 = r1;"
	"r6 = *(u32 *)(r1 + %[__sk_buff_len]);"
	CORO_FRAME_ALLOC(16)
	"r7 = r0;"
	/* the paths meet with 8 or 8000 in the slot: the size can be 8000 */
	"if r6 == 0 goto l0_%=;"
	"r8 = 8;"
	"*(u64 *)(r7 + 0) = r8;"
	"goto l1_%=;"
"l0_%=:"
	"r8 = 8000;"
	"*(u64 *)(r7 + 0) = r8;"
"l1_%=:"
	"r6 = *(u64 *)(r7 + 0);"
	CORO_FRAME_FREE(r7)
	SKB_LOAD_BYTES_FROM(r9, r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes),
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: a slot that both paths leave alone keeps its constant")
__success __retval(0) __log_level(2) __msg("ref{{[0-9]+}}[0]=8")
__naked void coro_frame_join_keeps_constant(void)
{
	asm volatile (
	"r9 = r1;"
	"r6 = *(u32 *)(r1 + %[__sk_buff_len]);"
	CORO_FRAME_ALLOC(16)
	"r7 = r0;"
	"r8 = 8;"
	"*(u64 *)(r7 + 0) = r8;"
	"if r6 == 0 goto l0_%=;"
	"r8 = 1;"
"l0_%=:"
	"r6 = *(u64 *)(r7 + 0);"
	CORO_FRAME_FREE(r7)
	SKB_LOAD_BYTES_FROM(r9, r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes),
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} map_hash SEC(".maps");

/* r0 = bpf_map_lookup_elem(&map_hash, &0) */
#define HASH_LOOKUP				\
	"r1 = 0;"				\
	"*(u32 *)(r10 - 4) = r1;"		\
	"r2 = r10;"				\
	"r2 += -4;"				\
	"r1 = %[map_hash] ll;"			\
	"call %[bpf_map_lookup_elem];"

/*
 * The paths meet with NULL or with a pointer in the slot. The two have no
 * join that the program can read, and nothing else tells them apart for the
 * verifier: no register and no stack slot differs.
 */
SEC("socket")
__description("coro_frame: a pointer on one path and NULL on the other stay apart")
__success __retval(0)
__naked void coro_frame_join_ptr_or_null(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[__sk_buff_len]);"
	CORO_FRAME_ALLOC(16)
	"r7 = r0;"
	"r1 = 0;"
	"*(u64 *)(r7 + 0) = r1;"
	"if r6 == 0 goto l0_%=;"
	HASH_LOOKUP
	"if r0 == 0 goto l0_%=;"
	"*(u64 *)(r7 + 0) = r0;"
"l0_%=:"
	"r1 = *(u64 *)(r7 + 0);"
	"if r1 == 0 goto l1_%=;"
	"r1 = *(u64 *)(r1 + 0);"
"l1_%=:"
	CORO_FRAME_FREE(r7)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_map_lookup_elem), __imm_addr(map_hash),
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/*
 * The ids of a state start again with each basic block, and what the state
 * has gets names, see bpf_renumber_ids(). Only the slot has the first value:
 * the test of the second one, which is the first id of its block like the
 * first one was, says nothing about it.
 */
SEC("socket")
__description("coro_frame: the id of a pointer in a slot is not taken for a new one")
__failure __msg("R1 invalid mem access 'map_value_or_null'")
__naked void coro_frame_slot_id_is_named(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[__sk_buff_len]);"
	CORO_FRAME_ALLOC(16)
	"r7 = r0;"
	HASH_LOOKUP
	"*(u64 *)(r7 + 0) = r0;"
	"if r6 == 0 goto l0_%=;"
	"r6 = 1;"
"l0_%=:"
	HASH_LOOKUP
	"if r0 == 0 goto l1_%=;"
	"r1 = *(u64 *)(r7 + 0);"
	"r1 = *(u64 *)(r1 + 0);"
"l1_%=:"
	CORO_FRAME_FREE(r7)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_map_lookup_elem), __imm_addr(map_hash),
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/*
 * The count is in the slot only. The state that comes back to the header of
 * the loop has a larger one each time: it is joined with the state there,
 * then widened like a number on the stack. The jump tests the register, which
 * says nothing about the slot, so the loop has no trip count and gets
 * may_goto.
 */
SEC("socket")
__description("coro_frame: a count in a slot grows in a loop")
__success __retval(0)
__naked void coro_frame_loop_count(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r1 = 0;"
	"*(u64 *)(r6 + 0) = r1;"
"l0_%=:"
	"r1 = *(u64 *)(r6 + 0);"
	"r1 += 1;"
	"*(u64 *)(r6 + 0) = r1;"
	"if r1 < 100 goto l0_%=;"
	"r7 = *(u64 *)(r6 + 0);"
	CORO_FRAME_FREE(r6)
	"r0 = r7;"
	"r0 -= 100;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: context pointer spill and fill")
__success __retval(0)
__naked void coro_frame_ctx_spill_fill(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"*(u64 *)(r0 + 0) = r9;"
	"r1 = *(u64 *)(r0 + 0);"
	"r1 = *(u32 *)(r1 + %[__sk_buff_len]);"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS,
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: partial read of spilled pointer rejected without CAP_PERFMON")
__failure_unpriv __msg_unpriv("invalid size of register fill")
__caps_unpriv(CAP_BPF)
__naked void coro_frame_partial_pointer_read(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"*(u64 *)(r0 + 0) = r9;"
	"w1 = *(u32 *)(r0 + 0);"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: partial overwrite of spilled pointer rejected without CAP_PERFMON")
__failure_unpriv __msg_unpriv("attempt to corrupt spilled pointer on coro_frame")
__caps_unpriv(CAP_BPF)
__naked void coro_frame_partial_pointer_write(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"*(u64 *)(r0 + 0) = r9;"
	"w1 = 0;"
	"*(u32 *)(r0 + 0) = w1;"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: partial overwrite destroys the spilled pointer")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void coro_frame_partial_overwrite_scrubs(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"*(u64 *)(r0 + 0) = r9;"
	"w1 = 0;"
	"*(u32 *)(r0 + 0) = w1;"
	"r1 = *(u64 *)(r0 + 0);"
	"r1 = *(u32 *)(r1 + %[__sk_buff_len]);"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS,
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: stack pointer spill rejected")
__failure __msg("cannot spill stack pointers into coro_frame")
__naked void coro_frame_stack_pointer_spill(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r1 = r10;"
	"r1 += -8;"
	"*(u64 *)(r0 + 0) = r1;"
	CORO_FRAME_FREE(r0)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, __u64);
} coro_dynptr_map SEC(".maps");

/* What it gets is a pointer to the dynptr in the stack of its caller */
__noinline int coro_frame_keeps_dynptr(struct bpf_dynptr *d)
{
	__u64 *slots = bpf_coro_frame_alloc(16, NULL);

	if (!slots)
		return 0;
	slots[0] = (__u64)d;
	bpf_coro_frame_free(slots);
	return 0;
}

SEC("socket")
__description("coro_frame: pointer to a dynptr spill rejected")
__failure __msg("cannot spill stack pointers into coro_frame")
int coro_frame_dynptr_spill(void *ctx)
{
	struct bpf_dynptr d;
	__u64 *v;
	int key = 0;

	v = bpf_map_lookup_elem(&coro_dynptr_map, &key);
	if (!v)
		return 0;
	bpf_dynptr_from_mem(v, sizeof(*v), 0, &d);
	return coro_frame_keeps_dynptr(&d);
}

SEC("socket")
__description("coro_frame: frame pointer spilled into another frame")
__success __retval(0)
__naked void coro_frame_cross_frame_spill(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r1 = 16;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 != 0 goto l0_%=;"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
"l0_%=:"
	"r7 = r0;"
	"*(u64 *)(r7 + 0) = r6;"
	"r8 = *(u64 *)(r7 + 0);"
	"r1 = 1;"
	"*(u64 *)(r8 + 8) = r1;"
	CORO_FRAME_FREE(r6)
	CORO_FRAME_FREE(r7)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: frame copy in another frame invalidated by free")
__failure __msg("R8 invalid mem access 'scalar'")
__naked void coro_frame_cross_frame_invalidated(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r1 = 16;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 != 0 goto l0_%=;"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
"l0_%=:"
	"r7 = r0;"
	"*(u64 *)(r7 + 0) = r6;"
	CORO_FRAME_FREE(r6)
	"r8 = *(u64 *)(r7 + 0);"
	"r1 = *(u64 *)(r8 + 8);"
	CORO_FRAME_FREE(r7)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS
	: __clobber_all);
}

/*
 * The subprog reads the pointer to the frame: like one that gets a pointer
 * to the stack it is verified in the frames of its caller, where its store
 * shows.
 */
SEC("socket")
__description("coro_frame: subprog stores into the caller's frame")
__success __retval(0) __log_level(2)
__not_msg("waits for func#")
__naked void coro_frame_subprog_store(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	/* what the subprog stores replaces this */
	"r1 = 8000;"
	"*(u64 *)(r6 + 0) = r1;"
	"r1 = r6;"
	"call coro_frame_store_eight;"
	"r7 = *(u64 *)(r6 + 0);"
	CORO_FRAME_FREE(r6)
	SKB_LOAD_BYTES_FROM(r9, r7)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes)
	: __clobber_all);
}

__naked __noinline __used static void coro_frame_reads_nothing(void)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/*
 * The subprog does not read R1, so it gets no pointer to the frame: it is
 * verified on its own, without the slots of the frame, which stay with the
 * call.
 */
SEC("socket")
__description("coro_frame: subprog without a pointer to the frame is verified on its own")
__success __retval(0) __log_level(2)
__msg("waits for func#")
__naked void coro_frame_subprog_on_its_own(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r1 = 8;"
	"*(u64 *)(r6 + 0) = r1;"
	"r1 = r6;"
	"call coro_frame_reads_nothing;"
	"r7 = *(u64 *)(r6 + 0);"
	CORO_FRAME_FREE(r6)
	SKB_LOAD_BYTES_FROM(r9, r7)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: subprog stores into a frame held in the caller's frame")
__success __retval(0)
__naked void coro_frame_subprog_store_inner(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r1 = 16;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 != 0 goto l0_%=;"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
"l0_%=:"
	"r7 = r0;"
	"r1 = 8000;"
	"*(u64 *)(r7 + 0) = r1;"
	"*(u64 *)(r6 + 8) = r7;"
	"r1 = r6;"
	"call coro_frame_store_eight_inner;"
	"r8 = *(u64 *)(r7 + 0);"
	CORO_FRAME_FREE(r6)
	CORO_FRAME_FREE(r7)
	SKB_LOAD_BYTES_FROM(r9, r8)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: function pointer spill and fill")
__success __retval(0)
__naked void coro_frame_func_ptr_spill_fill(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r2 = %[coro_frame_loop_cb] ll;"
	"*(u64 *)(r6 + 0) = r2;"
	"r1 = 1;"
	"r2 = *(u64 *)(r6 + 0);"
	"r3 = 0;"
	"r4 = 0;"
	"call %[bpf_loop];"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_loop), __imm_addr(coro_frame_loop_cb)
	: __clobber_all);
}

struct task_struct {} __attribute__((preserve_access_index));

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

void __kfunc_btf_root_task(void)
{
	bpf_task_release(bpf_task_acquire(0));
}

/* Acquire the current task into r0; exit with 0 when the kfunc returns NULL. */
#define TASK_ACQUIRE()				\
	"call %[bpf_get_current_task_btf];"	\
	"r1 = r0;"				\
	"call %[bpf_task_acquire];"		\
	"if r0 != 0 goto 2f;"			\
	"exit;"					\
	"2:"

SEC("tc")
__description("coro_frame: referenced pointer spill, fill, release")
__success __retval(0)
__naked void coro_frame_ref_spill_fill(void)
{
	asm volatile (
	TASK_ACQUIRE()
	"r7 = r0;"
	"r1 = 16;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 != 0 goto l0_%=;"
	"r1 = r7;"
	"call %[bpf_task_release];"
	"r0 = 0;"
	"exit;"
"l0_%=:"
	"r6 = r0;"
	"*(u64 *)(r6 + 0) = r7;"
	"r1 = *(u64 *)(r6 + 0);"
	"call %[bpf_task_release];"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_get_current_task_btf),
	  __imm(bpf_task_acquire), __imm(bpf_task_release)
	: __clobber_all);
}

SEC("tc")
__description("coro_frame: released reference is invalidated in the frame")
__failure __msg("R1 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_")
__naked void coro_frame_ref_release_invalidates_slot(void)
{
	asm volatile (
	TASK_ACQUIRE()
	"r7 = r0;"
	"r1 = 16;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 != 0 goto l0_%=;"
	"r1 = r7;"
	"call %[bpf_task_release];"
	"r0 = 0;"
	"exit;"
"l0_%=:"
	"r6 = r0;"
	"*(u64 *)(r6 + 0) = r7;"
	"r1 = r7;"
	"call %[bpf_task_release];"
	"r1 = *(u64 *)(r6 + 0);"
	"call %[bpf_task_release];"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_get_current_task_btf),
	  __imm(bpf_task_acquire), __imm(bpf_task_release)
	: __clobber_all);
}

SEC("tc")
__description("coro_frame: reference kept only in a freed frame leaks")
__failure __msg("Unreleased reference id=")
__naked void coro_frame_ref_leaked_in_frame(void)
{
	asm volatile (
	TASK_ACQUIRE()
	"r7 = r0;"
	"r1 = 16;"
	"r2 = 0;"
	"call %[bpf_coro_frame_alloc];"
	"if r0 != 0 goto l0_%=;"
	"r1 = r7;"
	"call %[bpf_task_release];"
	"r0 = 0;"
	"exit;"
"l0_%=:"
	"r6 = r0;"
	"*(u64 *)(r6 + 0) = r7;"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_get_current_task_btf),
	  __imm(bpf_task_acquire), __imm(bpf_task_release)
	: __clobber_all);
}

/* Helper memory argument tests. */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} map_ringbuf SEC(".maps");

/* bpf_ringbuf_output(&map_ringbuf, from, size, 0): reads 'size' bytes */
#define RINGBUF_OUTPUT_FROM(from_reg, size)	\
	"r1 = %[map_ringbuf] ll;"		\
	"r2 = " #from_reg ";"			\
	"r3 = " #size ";"			\
	"r4 = 0;"				\
	"call %[bpf_ringbuf_output];"

/* bpf_skb_load_bytes(ctx, 0, to, size): writes 'size' bytes */
#define SKB_LOAD_BYTES_TO(ctx_reg, to_reg, size)	\
	"r1 = " #ctx_reg ";"				\
	"r2 = 0;"					\
	"r3 = " #to_reg ";"				\
	"r4 = " #size ";"				\
	"call %[bpf_skb_load_bytes];"

SEC("socket")
__description("coro_frame: helper reads initialized frame bytes")
__success __retval(0)
__naked void coro_frame_helper_read_init(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r1 = 1;"
	"*(u64 *)(r6 + 0) = r1;"
	"*(u64 *)(r6 + 8) = r1;"
	RINGBUF_OUTPUT_FROM(r6, 16)
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_ringbuf_output), __imm_addr(map_ringbuf)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: helper read of uninitialized bytes rejected without CAP_PERFMON")
__failure_unpriv __msg_unpriv("invalid read from coro_frame R2 off 0+8 size 16")
__caps_unpriv(CAP_BPF)
__naked void coro_frame_helper_read_uninit(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r1 = 1;"
	"*(u64 *)(r6 + 0) = r1;"
	RINGBUF_OUTPUT_FROM(r6, 16)
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_ringbuf_output), __imm_addr(map_ringbuf)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: helper read of spilled pointer rejected without CAP_PERFMON")
__failure_unpriv __msg_unpriv("invalid read from coro_frame R2 off 0+0 size 8")
__caps_unpriv(CAP_BPF)
__naked void coro_frame_helper_read_pointer(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"*(u64 *)(r6 + 0) = r9;"
	RINGBUF_OUTPUT_FROM(r6, 8)
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_ringbuf_output), __imm_addr(map_ringbuf)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: helper read of spilled scalar allowed")
__success_unpriv __retval_unpriv(0)
__caps_unpriv(CAP_BPF)
__naked void coro_frame_helper_read_scalar_spill(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r1 = 5;"
	"*(u64 *)(r6 + 0) = r1;"
	RINGBUF_OUTPUT_FROM(r6, 8)
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_ringbuf_output), __imm_addr(map_ringbuf)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: helper size beyond the frame rejected")
__failure __msg("invalid access to memory, mem_size=16 off=0 size=24")
__naked void coro_frame_helper_read_oob(void)
{
	asm volatile (
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"r1 = 1;"
	"*(u64 *)(r6 + 0) = r1;"
	"*(u64 *)(r6 + 8) = r1;"
	RINGBUF_OUTPUT_FROM(r6, 24)
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_ringbuf_output), __imm_addr(map_ringbuf)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: helper writes into uninitialized frame bytes")
__success __retval(0)
__failure_unpriv __msg_unpriv("invalid read from coro_frame off 8+0 size 8")
__caps_unpriv(CAP_BPF)
__naked void coro_frame_helper_write_uninit(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	SKB_LOAD_BYTES_TO(r9, r6, 16)
	/*
	 * The callee initialized the bytes, so they may be read now. As on the stack, they stay
	 * uninitialized for an unprivileged program.
	 */
	"r1 = *(u64 *)(r6 + 8);"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes)
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: helper write scrubs a spilled pointer")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void coro_frame_helper_write_scrubs_pointer(void)
{
	asm volatile (
	"r9 = r1;"
	CORO_FRAME_ALLOC(16)
	"r6 = r0;"
	"*(u64 *)(r6 + 0) = r9;"
	SKB_LOAD_BYTES_TO(r9, r6, 8)
	"r1 = *(u64 *)(r6 + 0);"
	"r1 = *(u32 *)(r1 + %[__sk_buff_len]);"
	CORO_FRAME_FREE(r6)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes),
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: helper argument with variable offset")
__success __retval(0)
__naked void coro_frame_helper_var_off(void)
{
	asm volatile (
	"r9 = r1;"
	"r7 = *(u32 *)(r1 + %[__sk_buff_len]);"
	"r7 &= 7;"
	"r7 <<= 3;"
	CORO_FRAME_ALLOC(64)
	"r6 = r0;"
	"r8 = r0;"
	SKB_LOAD_BYTES_TO(r9, r6, 64)
	"r6 += r7;"
	RINGBUF_OUTPUT_FROM(r6, 8)
	CORO_FRAME_FREE(r8)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes), __imm(bpf_ringbuf_output),
	  __imm_addr(map_ringbuf),
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

SEC("socket")
__description("coro_frame: helper write with variable offset over uninitialized bytes")
__success __retval(0)
__naked void coro_frame_helper_var_off_uninit(void)
{
	asm volatile (
	"r9 = r1;"
	"r7 = *(u32 *)(r1 + %[__sk_buff_len]);"
	"r7 &= 7;"
	"r7 <<= 3;"
	CORO_FRAME_ALLOC(64)
	"r6 = r0;"
	"r8 = r0;"
	"r6 += r7;"
	SKB_LOAD_BYTES_TO(r9, r6, 8)
	CORO_FRAME_FREE(r8)
	"r0 = 0;"
	"exit;"
	:
	: CORO_IMMS, __imm(bpf_skb_load_bytes),
	  __imm_const(__sk_buff_len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/*
 * bpf_dynptr_slice() returns its buffer when the data of the skb is not
 * contiguous. A store through such a slice is not seen as a store to the
 * frame, and a load through it reads what the frame tracks as plain data.
 */
SEC("tc")
__description("coro_frame: frame memory as the buffer of a dynptr slice rejected")
__failure __msg("the buffer of a dynptr slice cannot be in a coro_frame")
int coro_frame_slice_buffer(struct __sk_buff *skb)
{
	struct bpf_dynptr ptr;
	char *frame, *p;
	int ret = 0;

	frame = bpf_coro_frame_alloc(16, NULL);
	if (!frame)
		return 0;
	if (!bpf_dynptr_from_skb(skb, 0, &ptr)) {
		p = bpf_dynptr_slice(&ptr, 0, frame, 8);
		if (p)
			ret = *p;
	}
	bpf_coro_frame_free(frame);
	return ret;
}

char _license[] SEC("license") = "GPL";
