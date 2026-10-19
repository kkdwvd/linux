// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("struct_ops/open")
int BPF_PROG(guard_open, struct bpf_net_driver *drv)
{
	return 0;
}

SEC("struct_ops/poll")
int BPF_PROG(guard_poll, struct bpf_net_driver *drv, int budget)
{
	return 0;
}

SEC("struct_ops/xmit")
int BPF_PROG(guard_xmit, struct bpf_net_driver *drv, u64 id)
{
	return 0;
}

SEC("struct_ops/close")
void BPF_PROG(guard_close, struct bpf_net_driver *drv)
{
}

/* Load the callbacks and map without registering a device. */
SEC(".struct_ops.link")
struct bpf_net_driver_ops guard_ops = {
	.open = (void *)guard_open,
	.poll = (void *)guard_poll,
	.xmit = (void *)guard_xmit,
	.close = (void *)guard_close,
	.ifindex = 1,
};

char _license[] SEC("license") = "GPL";
