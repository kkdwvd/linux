// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* global data of the object is in arena */
char data_in_arena SEC(".arena.data");

/* per-CPU data is a map of its own, not a part of arena */
int x SEC(".percpu") = 42;
int *px = &x;

SEC("syscall")
int ptr_to_map(void *ctx)
{
	return *px;
}

char _license[] SEC("license") = "GPL";
