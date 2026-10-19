// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf_arena_common.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE | BPF_F_NO_USER_CONV);
	__uint(max_entries, 1);
} arena SEC(".maps");

volatile u32 __arena value;

SEC("struct_ops/open")
int BPF_PROG(forbidden_helper, struct bpf_net_driver *drv)
{
	value = bpf_get_prandom_u32();
	return 0;
}

SEC("struct_ops/open")
int BPF_PROG(backward_branch, struct bpf_net_driver *drv)
{
#pragma clang loop unroll(disable)
	for (int i = 0; i < 8; i++)
		value++;
	return 0;
}

SEC(".struct_ops.link")
struct bpf_net_driver_ops forbidden = {
	.open = (void *)forbidden_helper,
};

SEC(".struct_ops.link")
struct bpf_net_driver_ops backward = {
	.open = (void *)backward_branch,
};

char LICENSE[] SEC("license") = "GPL";
