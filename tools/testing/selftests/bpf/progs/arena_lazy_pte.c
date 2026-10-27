// SPDX-License-Identifier: GPL-2.0
/* On-demand PTE tables: the programs behind prog_tests/arena_lazy_pte.c. */
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf_arena_common.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	/* in pages: 256 MB with 4 KB pages, the 4 GB maximum with 64 KB pages */
	__uint(max_entries, 1 << 16);
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32); /* start of mmap() region */
#else
	__ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
#endif
} arena SEC(".maps");

/* in: byte offset into the arena of the page to work on */
__u64 off;
/* in: pages to allocate or free there */
__u32 cnt;
/* in: value stored after an allocation; out: value loaded by read_page */
__u64 val;
/* out: the allocation's address, NULL when it failed */
void __arena *ptr;
/* out: the compiler cannot build arena pointers, nothing was exercised */
bool skip;
/* volatile to force the scalar reload (see arena_kfunc.c) */
volatile __u64 stash;

static __always_inline int alloc_page_at(__u64 off)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST) || defined(BPF_ARENA_FORCE_ASM)
	char __arena *base = arena_base(&arena);

	ptr = bpf_arena_alloc_pages(&arena, base + off, cnt, NUMA_NO_NODE, 0);
	if (!ptr)
		return 1;
	*(__u64 __arena *)ptr = val;
#else
	skip = true;
#endif
	return 0;
}

/* Allocate @cnt pages at @off and store @val in the first, from a sleepable program. */
SEC("syscall")
int alloc_page(void *ctx)
{
	return alloc_page_at(off);
}

/*
 * The same from a non-sleepable program: bpf_arena_alloc_pages() cannot sleep
 * here, so a PTE table the page needs is allocated without sleeping too.
 */
SEC("raw_tp/sys_enter")
int alloc_page_atomic(void *ctx)
{
	return alloc_page_at(off);
}

SEC("syscall")
int free_page(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST) || defined(BPF_ARENA_FORCE_ASM)
	char __arena *base = arena_base(&arena);

	bpf_arena_free_pages(&arena, base + off, cnt);
#endif
	return 0;
}

/* Load the first word of the page at @off through the arena mapping. */
SEC("syscall")
int read_page(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST) || defined(BPF_ARENA_FORCE_ASM)
	char __arena *base = arena_base(&arena);

	val = *(__u64 __arena *)(base + off);
#endif
	return 0;
}

/*
 * Hand the address at @off to a kfunc that dereferences it. When the page is
 * not allocated, the kernel-side fault is recovered with the scratch page and
 * reported on the program's stderr stream. Only x86-64 and arm64 recover such
 * faults; elsewhere this program must not run.
 */
SEC("syscall")
int kfunc_touch(void *ctx)
{
	struct bpf_arena *ptr = (void *)&arena;
	__u64 user_vm_start;

	/* barrier_var() hides the cast from GCC's bounds checking, see stream.c */
	barrier_var(ptr);
	user_vm_start = ptr->user_vm_start;
	stash = (__u32)(user_vm_start + off);
	val = bpf_kfunc_arena_arg_test((__u64 *)stash);
	return 0;
}

char _license[] SEC("license") = "GPL";
