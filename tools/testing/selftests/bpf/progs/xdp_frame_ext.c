// SPDX-License-Identifier: GPL-2.0
/*
 * An extension that would take the frame of the program it extends, whose
 * caller keeps its copies of the context.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("freplace")
int steal_in_extension(struct xdp_md *ctx)
{
	struct xdp_frame *f = bpf_xdp_frame_steal(ctx);

	if (!f)
		return XDP_PASS;
	bpf_xdp_frame_release(f);
	return XDP_CONSUME;
}
