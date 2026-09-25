// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf_arena_common.h>

#ifdef __TARGET_ARCH_arm64
#define ARENA_VM_START ((1ull << 32) | (~0u - __PAGE_SIZE * 2 + 1))
#else
#define ARENA_VM_START ((1ull << 44) | (~0u - __PAGE_SIZE * 2 + 1))
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 2);
	__ulong(map_extra, ARENA_VM_START);
} arena SEC(".maps");

/* 16-byte slots, default capacity: a 16 KiB typed arena and a mask of 16368 */
struct typed_obj {
	struct task_struct __kptr *task;
	__u64 value;
};

/* 32-byte slots: a 32 KiB typed arena and a mask of 32736 */
struct other_obj {
	struct task_struct __kptr *task;
	__u64 a;
	__u64 b;
};

struct plain_obj {
	__u64 value;
};

struct locked_obj {
	struct bpf_spin_lock lock;
	__u64 value;
};

struct res_locked_obj {
	struct bpf_res_spin_lock lock;
	__u64 value;
};

/* larger than any page the arena can run on */
struct big_obj {
	struct task_struct __kptr *task;
	char pad[65536];
};

/* 16-byte slots at 16 Mi objects need 256 MiB */
struct many_obj {
	struct task_struct __kptr *task;
	__u64 value;
} __arena_capacity(16777216);

#define TYPE_ID(T) ((unsigned long)bpf_core_type_id_local(T))

/*
 * Raw encodings of the special 64-bit moves, byte by byte: the register byte
 * holds dst in its low nibble on little-endian targets and in its high nibble
 * on big-endian ones.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define REGS_R1_R2 "0x21"
#define REGS_R7_R2 "0x27"
#else
#define REGS_R1_R2 "0x12"
#define REGS_R7_R2 "0x72"
#endif
#define REGS_R1_R1 "0x11"
#define MOV64_X(regs, off, imm) ".byte 0xbf, " regs "; .short " #off "; .long " #imm ";"
/* r1 = arena_type_cast(r1, r2) */
#define ARENA_TYPE_CAST MOV64_X(REGS_R1_R2, 2, 0)
/* r1 = addr_space_cast(r1, 0, 1) */
#define CAST_TO_ARENA MOV64_X(REGS_R1_R1, 1, 1)
/* r7 = addr_space_cast(r7, 0, 1) */
#define CAST_R7_TO_ARENA MOV64_X("0x77", 1, 1)

SEC("syscall")
__description("a cast lowers to the slot mask and the typed arena base")
__success __log_level(2)
__msg("typed arena for struct typed_obj: slot 16 bytes, capacity 1024, size 16384 bytes")
__msg("R1=arena_ptr_typed_obj()")
__xlated("r1 &= 16368")
__xlated("r12 = 0x{{[0-9a-f]+}}")
__xlated("r1 += r12")
int cast_lowers_to_mask_and_base(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0x12345;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r0", "r1", "r2");
	return 0;
}

SEC("syscall")
__description("any register value promotes: a raw arena pointer here")
__success
__xlated("r1 &= 16368")
int cast_accepts_raw_arena_pointer(void *ctx)
{
	asm volatile("r1 = %[arena] ll;"
		     "r1 = *(u64 *)(r1 + 0);"
		     CAST_TO_ARENA
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r1", "r2");
	return 0;
}

SEC("syscall")
__description("a typed pointer casts to another type without knowing the source")
__success __log_level(2)
__msg("typed arena for struct typed_obj")
__msg("typed arena for struct other_obj")
__msg("R1=arena_ptr_other_obj()")
__xlated("r1 &= 16368")
__xlated("r12 = 0x{{[0-9a-f]+}}")
__xlated("r1 += r12")
__xlated("...")
__xlated("r1 &= 32736")
__xlated("r12 = 0x{{[0-9a-f]+}}")
__xlated("r1 += r12")
int cast_reannotates_typed_pointer(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0x12345;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     "r2 = %[other_id];"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj)),
		        [other_id] "r"(TYPE_ID(struct other_obj))
		     : "r0", "r1", "r2");
	return 0;
}

SEC("syscall")
__description("one instruction may cast to one type on every path")
__success
int cast_same_type_on_two_paths(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "call %[bpf_get_prandom_u32];"
		     "r1 = r0;"
		     "r2 = %[id];"
		     "if r1 == 0 goto 1f;"
		     "r2 = %[id];"
		     "1:"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), __imm(bpf_get_prandom_u32),
		        [id] "r"(TYPE_ID(struct typed_obj))
		     : "r0", "r1", "r2", "r3", "r4", "r5", "memory");
	return 0;
}

SEC("syscall")
__description("the lowering is per instruction, so two types at one cast are rejected")
__failure __msg("casts to different types on different paths")
int cast_rejects_two_types_at_one_insn(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "call %[bpf_get_prandom_u32];"
		     "r1 = r0;"
		     "r2 = %[id];"
		     "if r1 == 0 goto 1f;"
		     "r2 = %[other_id];"
		     "1:"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), __imm(bpf_get_prandom_u32),
		        [id] "r"(TYPE_ID(struct typed_obj)),
		        [other_id] "r"(TYPE_ID(struct other_obj))
		     : "r0", "r1", "r2", "r3", "r4", "r5", "memory");
	return 0;
}

SEC("syscall")
__description("the cast needs the program's arena")
__failure __msg("arena_type_cast insn can only be used in a program that has an associated arena")
int cast_needs_arena(void *ctx)
{
	asm volatile("r1 = 0;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     :: [id] "r"(TYPE_ID(struct typed_obj))
		     : "r1", "r2");
	return 0;
}

SEC("syscall")
__description("the type ID must be a verifier-known constant")
__failure __msg("R2 must hold a constant type ID for arena_type_cast")
int cast_needs_constant_type_id(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "call %[bpf_get_prandom_u32];"
		     "r2 = r0;"
		     "r1 = 0;"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), __imm(bpf_get_prandom_u32)
		     : "r0", "r1", "r2", "r3", "r4", "r5", "memory");
	return 0;
}

SEC("syscall")
__description("the handle register must be initialized")
__failure __msg("R7 !read_ok")
int cast_reads_handle(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r2 = %[id];"
		     MOV64_X(REGS_R7_R2, 2, 0)
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r0", "r2", "r7");
	return 0;
}

SEC("syscall")
__description("the type must be a struct")
__failure __msg("is not a struct")
int cast_needs_struct(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(int))
		     : "r0", "r1", "r2");
	return 0;
}

SEC("syscall")
__description("a struct without special fields belongs in the raw arena")
__failure __msg("struct plain_obj has no special fields and needs no typed arena")
int cast_rejects_plain_struct(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct plain_obj))
		     : "r0", "r1", "r2");
	return 0;
}

SEC("syscall")
__description("locks are not supported in typed arena objects yet")
__failure __msg("struct locked_obj field bpf_spin_lock is not supported in a typed arena")
int cast_rejects_spin_lock(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct locked_obj))
		     : "r0", "r1", "r2");
	return 0;
}

SEC("syscall")
__description("resilient locks are not supported in typed arena objects yet")
__failure __msg("struct res_locked_obj field bpf_res_spin_lock is not supported in a typed arena")
int cast_rejects_res_spin_lock(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct res_locked_obj))
		     : "r0", "r1", "r2");
	return 0;
}

SEC("syscall")
__description("an object larger than a page has no typed arena yet")
__failure __msg("struct big_obj is too large for a typed arena")
int cast_rejects_large_object(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct big_obj))
		     : "r0", "r1", "r2");
	return 0;
}

SEC("syscall")
__description("a capacity beyond the typed arena size cap is rejected")
__failure __msg("struct many_obj is too large for a typed arena: size 16, capacity 16777216")
int cast_rejects_large_capacity(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct many_obj))
		     : "r0", "r1", "r2");
	return 0;
}

SEC("syscall")
__description("the encoding needs distinct registers")
__failure __msg("arena_type_cast insn needs distinct registers and zero imm")
int cast_rejects_same_register(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0;"
		     MOV64_X(REGS_R1_R1, 2, 0)
		     :: __imm_addr(arena)
		     : "r0", "r1");
	return 0;
}

SEC("syscall")
__description("the encoding reserves imm")
__failure __msg("arena_type_cast insn needs distinct registers and zero imm")
int cast_rejects_nonzero_imm(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0;"
		     "r2 = %[id];"
		     MOV64_X(REGS_R1_R2, 2, 1)
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r0", "r1", "r2");
	return 0;
}

SEC("syscall")
__description("the C macro emits the cast with fixed registers")
__success __log_level(2)
__msg("R1=arena_ptr_typed_obj()")
__xlated("r1 &= 16368")
__xlated("r12 = 0x{{[0-9a-f]+}}")
__xlated("r1 += r12")
int cast_macro(void *ctx)
{
	struct typed_obj *obj;

	if (!bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0))
		return 1;
	obj = bpf_arena_cast(0x12345, struct typed_obj);
	return obj == NULL;
}

SEC("syscall")
__description("a 32-bit copy of a typed pointer is its handle")
__success __log_level(2)
__msg("R3=scalar(smin=smin32=0,smax=umax=smax32=umax32=16368,var_off=(0x0; 0x3ff0))")
__xlated("w3 = w1")
__xlated("w3 &= 16368")
int demote_copy(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0x12345;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     "w3 = w1;"
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r0", "r1", "r2", "r3");
	return 0;
}

SEC("syscall")
__description("a handle promotes again")
__success
__xlated("w3 = w1")
__xlated("w3 &= 16368")
__xlated("r1 = r3")
__xlated("r1 &= 16368")
int demote_then_promote(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0x12345;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     "w3 = w1;"
		     "r1 = r3;"
		     ARENA_TYPE_CAST
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r0", "r1", "r2", "r3");
	return 0;
}

SEC("syscall")
__description("a narrow store of a typed pointer stores its handle, a wide one the pointer")
__success
__xlated("w12 = w1")
__xlated("w12 &= 16368")
__xlated("*(u32 *)(r7 +0) = r12")
__xlated("w12 = w1")
__xlated("w12 &= 16368")
__xlated("*(u16 *)(r7 +4) = r12")
__xlated("w12 = w1")
__xlated("w12 &= 16368")
__xlated("*(u8 *)(r7 +6) = r12")
__xlated("*(u64 *)(r7 +8) = r1")
int demote_store(void *ctx)
{
	asm volatile("r7 = %[arena] ll;"
		     "r7 = *(u64 *)(r7 + 0);"
		     CAST_R7_TO_ARENA
		     "r1 = 0x12345;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     "*(u32 *)(r7 + 0) = r1;"
		     "*(u16 *)(r7 + 4) = r1;"
		     "*(u8 *)(r7 + 6) = r1;"
		     "*(u64 *)(r7 + 8) = r1;"
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r1", "r2", "r7", "memory");
	return 0;
}

SEC("syscall")
__description("a narrow store of a typed pointer to the stack is an invalid spill")
__failure __msg("invalid size of register spill")
int demote_store_to_stack(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0x12345;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     "*(u32 *)(r10 - 8) = r1;"
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r0", "r1", "r2", "memory");
	return 0;
}

SEC("syscall")
__description("a 32-bit compare of a typed pointer sees its handle")
__success
__xlated("w12 = w1")
__xlated("w12 &= 16368")
__xlated("if w12 == w3 goto")
__xlated("w12 = w1")
__xlated("w12 &= 16368")
__xlated("if w3 == w12 goto")
__xlated("w12 = w1")
__xlated("w12 &= 16368")
__xlated("if w12 == 0x10 goto")
__xlated("if w1 == w4 goto")
int demote_compare(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0x12345;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     "w3 = 16;"
		     "r4 = r1;"
		     "if w1 == w3 goto 1f;"
		     "if w3 == w1 goto 1f;"
		     "if w1 == 0x10 goto 1f;"
		     "if w1 == w4 goto 1f;"
		     "1:"
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r0", "r1", "r2", "r3", "r4");
	return 0;
}

SEC("syscall")
__description("a lowered backward compare keeps its target")
__success
__xlated("w12 = w1")
__xlated("w12 &= 16368")
__xlated("if w12 == w3 goto pc-{{[0-9]+}}")
int demote_compare_backward(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "r1 = 0x12345;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     "w3 = 0;"
		     "1:"
		     "w3 += 1;"
		     "if w3 > 2 goto 2f;"
		     "if w1 == w3 goto 1b;"
		     "2:"
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r0", "r1", "r2", "r3");
	return 0;
}

SEC("syscall")
__description("a 32-bit atomic does not see the handle")
__failure __msg("R1 32-bit atomic on a typed arena pointer, copy its handle first")
int demote_atomic(void *ctx)
{
	asm volatile("r7 = %[arena] ll;"
		     "r7 = *(u64 *)(r7 + 0);"
		     CAST_R7_TO_ARENA
		     "r1 = 0x12345;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     "lock *(u32 *)(r7 + 0) += w1;"
		     :: __imm_addr(arena), [id] "r"(TYPE_ID(struct typed_obj))
		     : "r1", "r2", "r7", "memory");
	return 0;
}

SEC("syscall")
__description("one demotion sees one type on every path")
__failure __msg("sees different typed arena pointers on different paths")
int demote_two_types_at_one_insn(void *ctx)
{
	asm volatile("r0 = %[arena] ll;"
		     "call %[bpf_get_prandom_u32];"
		     "r1 = 1;"
		     "if r0 == 0 goto 1f;"
		     "r2 = %[id];"
		     ARENA_TYPE_CAST
		     "goto 2f;"
		     "1:"
		     "r2 = %[other_id];"
		     ARENA_TYPE_CAST
		     "2:"
		     "w3 = w1;"
		     :: __imm_addr(arena), __imm(bpf_get_prandom_u32),
		        [id] "r"(TYPE_ID(struct typed_obj)),
		        [other_id] "r"(TYPE_ID(struct other_obj))
		     : "r0", "r1", "r2", "r3", "r4", "r5", "memory");
	return 0;
}

SEC("syscall")
__description("the C macros demote and compare handles")
__success __retval(0)
int demote_macro(void *ctx)
{
	struct typed_obj *obj, *again;
	__u32 handle;

	if (!bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0))
		return 1;
	obj = bpf_arena_cast(0x12345, struct typed_obj);
	handle = bpf_arena_handle(obj);
	if (handle != (0x12345 & 16368))
		return 2;
	again = bpf_arena_cast(handle, struct typed_obj);
	if (again != obj)
		return 3;
	if (bpf_arena_handle(again) != handle)
		return 4;
	return 0;
}

char _license[] SEC("license") = "GPL";
