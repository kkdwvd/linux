// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Tracing and extension programs aimed at subprogs of
 * progs/exceptions_cleanup.c. The attach target is set at load time.
 */
SEC("?fexit")
int BPF_PROG(fexit_unwinding_subprog)
{
	return 0;
}

int fentry_hits;

SEC("?fentry")
int BPF_PROG(fentry_unwinding_subprog)
{
	fentry_hits++;
	return 0;
}

__u64 never;

/*
 * An extension that can unwind, aimed at plain_global(), which cannot: it
 * would return straight into a caller that planted no branch for it.
 */
SEC("?freplace")
__u64 unwinding_extension(__u64 x)
{
	if (never)
		bpf_unwind();
	return x;
}

char _license[] SEC("license") = "GPL";
