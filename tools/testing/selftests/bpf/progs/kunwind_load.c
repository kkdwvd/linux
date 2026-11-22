// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/*
 * bpf_prog_load() gives a prog its id before the load is over, and from then on the prog can be
 * taken by that id and run. Hold the load of 'below_throw' in the first function that it enters
 * with the id, until the test has run the prog or a second has passed.
 */
int pid;
__u32 id;
bool done;

static int spin(__u32 i, __u64 *t0)
{
	return done || bpf_ktime_get_ns() - *t0 > 1000000000;
}

static int hold(struct bpf_prog *prog)
{
	char name[16];
	__u64 t0;

	if (id || !prog->aux->id || (bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;
	bpf_probe_read_kernel_str(name, sizeof(name), prog->aux->name);
	if (bpf_strncmp(name, sizeof(name), "below_throw"))
		return 0;
	id = prog->aux->id;
	t0 = bpf_ktime_get_ns();
	bpf_loop(1 << 23, spin, &t0, 0);
	return 0;
}

SEC("fentry/bpf_prog_kallsyms_add")
int BPF_PROG(kallsyms_add, struct bpf_prog *prog)
{
	return hold(prog);
}

SEC("fentry/perf_event_bpf_event")
int BPF_PROG(perf_event, struct bpf_prog *prog, enum perf_bpf_event_type type)
{
	return type == PERF_BPF_EVENT_PROG_LOAD ? hold(prog) : 0;
}
