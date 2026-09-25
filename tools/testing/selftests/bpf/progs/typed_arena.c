// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

#define NUMA_NO_NODE (-1)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 8);
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32);
#else
	__ulong(map_extra, 0x1ull << 44);
#endif
} arena SEC(".maps");

/* 16-byte slots, 2048 objects: a 32 KiB typed arena of eight pages */
struct obj {
	struct prog_test_ref_kfunc __kptr *ref;
	__u64 value;
} __arena_capacity(2048);

__u32 handle;
__u64 value;
__u64 ref_cnt;

/*
 * A cast needs the program's arena, and a program is associated with an arena
 * by referencing the map. Programs that only cast handles they keep elsewhere
 * reference it explicitly.
 */
#define arena_bind() asm volatile("r0 = %[m] ll" :: [m] "i"(&arena) : "r0")

SEC("syscall")
int alloc(void *ctx)
{
	struct obj *obj;

	obj = bpf_arena_typed_alloc_pages(&arena, struct obj, NULL, 1, NUMA_NO_NODE);
	if (!obj)
		return 1;
	handle = bpf_arena_handle(obj);
	return 0;
}

SEC("syscall")
int alloc_at_handle(void *ctx)
{
	struct obj *obj;

	obj = bpf_arena_typed_alloc_pages(&arena, struct obj, bpf_arena_cast(handle, struct obj),
					  1, NUMA_NO_NODE);
	if (!obj)
		return 1;
	return bpf_arena_handle(obj) != handle;
}

SEC("syscall")
int free_page(void *ctx)
{
	bpf_arena_typed_free_pages(&arena, struct obj, bpf_arena_cast(handle, struct obj), 1);
	return 0;
}

SEC("syscall")
int write_value(void *ctx)
{
	struct obj *obj;

	arena_bind();
	obj = bpf_arena_cast(handle, struct obj);

	obj->value = value;
	return 0;
}

SEC("syscall")
int read_value(void *ctx)
{
	struct obj *obj;

	arena_bind();
	obj = bpf_arena_cast(handle, struct obj);

	value = obj->value;
	return 0;
}

/* Leave a reference to the test module's object in the kptr field. */
SEC("syscall")
int stash_ref(void *ctx)
{
	struct prog_test_ref_kfunc *p, *old;
	struct obj *obj;
	unsigned long sp = 0;

	arena_bind();
	p = bpf_kfunc_call_test_acquire(&sp);
	if (!p)
		return 1;
	obj = bpf_arena_cast(handle, struct obj);
	old = bpf_kptr_xchg(&obj->ref, p);
	if (old)
		bpf_kfunc_call_test_release(old);
	return 0;
}

SEC("syscall")
int read_ref_cnt(void *ctx)
{
	struct prog_test_ref_kfunc *p;
	unsigned long sp = 0;

	p = bpf_kfunc_call_test_acquire(&sp);
	if (!p)
		return 1;
	/* the acquire above holds one */
	ref_cnt = p->cnt.refs.counter - 1;
	bpf_kfunc_call_test_release(p);
	return 0;
}

char _license[] SEC("license") = "GPL";
