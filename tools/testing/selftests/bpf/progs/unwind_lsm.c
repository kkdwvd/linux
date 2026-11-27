// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"

int pid;

/* It denies with -EACCES. The kernel ends the recursion before it gets there: 0 would allow. */
static __noinline long is_ended(long n)
{
	long ret = n ? is_ended(n - 1) : -EACCES;

	barrier_var(ret); /* keeps the compiler from making a loop of it */
	return ret;
}

__noinline int wants_eperm(u64 cookie)
{
	return cookie == -EPERM ? -E2BIG : 0;
}

/* The callback is not called a second time: the prog ends as if it had none */
__noinline int is_ended_itself(u64 cookie)
{
	return is_ended(1 << 20);
}

SEC("lsm/task_setnice")
int BPF_PROG(no_cb)
{
	return bpf_get_current_pid_tgid() >> 32 == pid ? is_ended(1 << 20) : 0;
}

SEC("lsm/task_setnice")
__exception_cb(wants_eperm)
int BPF_PROG(with_cb)
{
	return bpf_get_current_pid_tgid() >> 32 == pid ? is_ended(1 << 20) : 0;
}

SEC("lsm/task_setnice")
__exception_cb(is_ended_itself)
int BPF_PROG(in_cb)
{
	if (bpf_get_current_pid_tgid() >> 32 == pid)
		bpf_throw(-EACCES);
	return 0;
}

char _license[] SEC("license") = "GPL";
