// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

static __noinline int spins(void)
{
	__u64 t0 = bpf_ktime_get_ns();

	while (can_loop)
		;
	return bpf_ktime_get_ns() - t0 > 100 * 1000 * 1000;
}

/*
 * Each call of an extension prog is an invocation, with its own time. When that is up the
 * extension is unwound, to its own exit: the function that it replaces returns the value of an
 * unwound prog of the type that it extends, and the caller goes on.
 */
static __noinline int counts_to_1000(void)
{
	int i, cnt = 0;

	for (i = 0; i < 1000 && can_loop; i++)
		cnt++;
	return cnt;
}

/* The calls that had the time for a short loop before they used it up */
int calls, counted_to_1000;

SEC("freplace")
int replacement(int i)
{
	calls++;
	counted_to_1000 += counts_to_1000() == 1000;
	return 10 + spins() + spins() + i;
}
