// SPDX-License-Identifier: GPL-2.0
/*
 * The member of libarchive.a that nothing needs: none of its map, program,
 * variable or function is in a link
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} lib2_map SEC(".maps");

int lib2_val;

int lib2_func(int x)
{
	int key = 0, *val = bpf_map_lookup_elem(&lib2_map, &key);

	if (val)
		*val += x;
	lib2_val += x;
	return x;
}

SEC("syscall")
int lib2_prog(void *ctx)
{
	return lib2_func(1);
}
