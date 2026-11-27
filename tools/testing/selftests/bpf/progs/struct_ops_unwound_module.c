// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

/* A struct_ops of a module that has no ->unwound(). User space keeps this prog when the map goes. */
SEC("struct_ops")
int BPF_PROG(test_1)
{
	return 0;
}

/* Goes with the map, and so tells user space when the map has let go of the module */
SEC("struct_ops")
void BPF_PROG(test_2, int a, int b)
{
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_ops = {
	.test_1 = (void *)test_1,
	.test_2 = (void *)test_2,
};
