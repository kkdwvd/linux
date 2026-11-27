// SPDX-License-Identifier: GPL-2.0
/*
 * The packets that a program gave up. As the last one to hold them: they are back in their
 * memory when the call returns, or sent. Or in the invocation that took them, in which the
 * driver still hands the buffer over, and has it back then. See prog_tests/coro_frame_xdp.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

__u64 returned, early;

/* the count shares its storage with a pointer, which a direct load of half of it is refused for */

SEC("fentry/bpf_xdp_frame_release")
int BPF_PROG(frame_released, struct xdp_frame *frame)
{
	int refs = BPF_CORE_READ(frame, bpf_refs.refs.counter);

	if (refs == 1)
		__sync_fetch_and_add(&returned, 1);
	else if (refs == 2)
		__sync_fetch_and_add(&early, 1);
	return 0;
}

SEC("fentry/bpf_xdp_frame_xmit")
int BPF_PROG(frame_sent, struct xdp_frame *frame)
{
	if (BPF_CORE_READ(frame, bpf_refs.refs.counter) == 1)
		__sync_fetch_and_add(&returned, 1);
	return 0;
}

char _license[] SEC("license") = "GPL";
