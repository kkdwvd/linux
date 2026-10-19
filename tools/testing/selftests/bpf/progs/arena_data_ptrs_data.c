// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

/* a pointer in arena to data that is not in arena */
int x = 1;
int *px SEC(".addr_space.1") = &x;

SEC("syscall")
int ptr_to_data(void *ctx)
{
	return x;
}

char _license[] SEC("license") = "GPL";
