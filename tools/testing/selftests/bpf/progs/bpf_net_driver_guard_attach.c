// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("fentry")
int BPF_PROG(guard_fentry, unsigned long long *st_ops_ctx)
{
	return 0;
}

SEC("fexit")
int BPF_PROG(guard_fexit, unsigned long long *st_ops_ctx, int ret)
{
	return 0;
}

SEC("fmod_ret")
int BPF_PROG(guard_fmod_ret, unsigned long long *st_ops_ctx, int ret)
{
	return 0;
}

SEC("freplace")
int guard_freplace(unsigned long long *st_ops_ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
