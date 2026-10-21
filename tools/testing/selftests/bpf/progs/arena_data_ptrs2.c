// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"
#include "arena_data_ptrs.h"

/* defined in arena_data_ptrs1.c */
extern struct ptr_node __arena_global n1;

/*
 * Static, so pointers to it are relative to the section. The linker puts
 * the section after the one of arena_data_ptrs1.c and moves them.
 */
static long __arena_global svals[4] = { 5, 6, 7, 8 };

struct ptr_node __arena_global n3 = { .v = 3, .next = NULL, .pv = &svals[3] };
long __arena *__arena_global psval = &svals[1];
struct ptr_node __arena *__arena_global back = &n1;

static __noinline int add1(int v)
{
	return v + 1;
}

static __noinline int add2(int v)
{
	return v + 2;
}

__noinline int add3(int v)
{
	return v + 3;
}

/*
 * A program can't call through a pointer to a function in arena, so the
 * pointers are NULL. Until then the ones to static functions are their
 * offsets in .text, which are not 0 but for the first function there.
 */
struct ptr_ops __arena_global ops = { .fn = add2, .node = &n3, .global_fn = add3 };
ptr_fn_t __arena_global ops_fn = add1;

SEC("syscall")
int check2(void *ctx)
{
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
	if (n3.next || n3.pv != &svals[3] || psval != &svals[1] || back != &n1)
		return 1;
	if (*n3.pv != 8 || *psval != 6 || back->v != 1 || back->next->next != &n3)
		return 2;
	if (ops.fn || ops.global_fn || ops_fn || ops.node != &n3)
		return 3;
#endif
	return add1(0) + add2(0) + add3(0) - 6;
}

char _license[] SEC("license") = "GPL";
