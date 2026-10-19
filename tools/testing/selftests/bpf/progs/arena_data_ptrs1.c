// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"
#include "arena_data_ptrs.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 4); /* number of pages */
} arena SEC(".maps");

/* Dereferencing an arena global needs the addr_space_cast of clang */
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
bool skip_tests __attribute((__section__(".data"))) = false;
#else
bool skip_tests = true;
#endif

/* defined in arena_data_ptrs2.c */
extern struct ptr_node __arena_global n3;

/*
 * A list through both objects, n1 -> n2 -> n3. n2 is static, so pointers
 * to it are relative to the section.
 */
static struct ptr_node __arena_global n2 = { .v = 2, .next = &n3, .pv = &n3.v };
struct ptr_node __arena_global n1 = { .v = 1, .next = &n2, .pv = &n1.v };

/* pointers to an element and to a field, the offset is in the addend */
long __arena_global vals[4] = { 10, 20, 30, 40 };
long __arena *__arena_global pval = &vals[2];
long __arena *__arena_global pfield = &n2.v;

/* pointers to arena in data that is not in arena */
struct ptr_node __arena *head = &n1;
struct ptr_node __arena *const volatile ro_head = &n2;

SEC("syscall")
int check1(void *ctx)
{
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
	struct ptr_node __arena *n;
	long sum = 0;
	int i;

	/* the pointers are the addresses the program has for the variables */
	if (n1.next != &n2 || n1.pv != &n1.v || n2.next != &n3 || n2.pv != &n3.v)
		return 1;
	if (pval != &vals[2] || pfield != &n2.v)
		return 2;
	if (head != &n1 || ro_head != &n2)
		return 3;

	/* and they lead to the data */
	for (n = head, i = 0; n && i < 4; n = n->next, i++)
		sum += n->v * 100 + *n->pv;
	if (i != 3 || sum != (100 + 1) + (200 + 3) + (300 + 8))
		return 4;
	if (*pval != 30 || *pfield != 2 || ro_head->next->v != 3)
		return 5;
	*pval += 1;
#endif
	return 0;
}

char _license[] SEC("license") = "GPL";
