// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * The target is global_throws_13() in verifier_noreturn_call.c, which never
 * returns: it throws on every path. Its callers have nothing to continue
 * with after the call, so an extension that returns can't replace it.
 */

int fentry_cnt;

SEC("?fentry/global_throws_13")
int BPF_PROG(fentry_noreturn)
{
	fentry_cnt++;
	return 0;
}

SEC("?fexit/global_throws_13")
int BPF_PROG(fexit_noreturn)
{
	return 0;
}

SEC("?freplace/global_throws_13")
int freplace_returns(void)
{
	return 1;
}

char _license[] SEC("license") = "GPL";
