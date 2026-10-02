// SPDX-License-Identifier: GPL-2.0
/*
 * Transmitting bytes from arena memory as an XDP frame.
 *
 * An XDP program that hands the rest of a request to a thread, as a parked
 * coroutine frame say, has given its packet back to the driver by the time
 * the thread answers: the buffer was the driver's for the duration of the
 * poll, and the verdict XDP_TX was for that buffer. The thread builds the
 * reply in arena memory instead and sends it with bpf_xdp_xmit(), which
 * copies it into a frame of its own and queues that on the device through
 * ndo_xdp_xmit(), the path XDP_TX and XDP_REDIRECT take, from any context
 * that runs programs. A reply queued without a flush waits for the next
 * flushed one or for bpf_xdp_xmit_flush(), so a thread answering several
 * requests rings the doorbell once.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/sizes.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <net/net_namespace.h>
#include <net/xdp.h>

/* Headroom before the frame data, enough for any driver's own header. */
#define BPF_XDP_XMIT_HEADROOM	XDP_PACKET_HEADROOM
/* A frame is a single buffer: one MTU-sized packet. */
#define BPF_XDP_XMIT_MAX	(ETH_HLEN + ETH_DATA_LEN)

enum {
	/* Queue the frame but leave the doorbell to a later call. */
	BPF_XDP_XMIT_F_NO_FLUSH = 1,
};

__bpf_kfunc_start_defs();

/**
 * bpf_xdp_xmit - transmit bytes from arena memory as an XDP frame
 * @ifindex: the device, in the initial network namespace
 * @buf__arena: the frame, from its Ethernet header on, in arena memory
 * @len: its length in bytes, at most BPF_XDP_XMIT_MAX
 * @flags: BPF_XDP_XMIT_F_NO_FLUSH to queue without ringing the doorbell
 * @aux: the calling program (implicit)
 *
 * Returns 0 once the frame is queued on the device, -ENOSPC when the
 * device's queue is full, or another -errno.
 */
__bpf_kfunc int bpf_xdp_xmit(u32 ifindex, void *buf__arena, u32 len, u64 flags,
			     struct bpf_prog_aux *aux)
{
	u64 start = bpf_arena_get_kern_vm_start(aux->arena), addr = (u64)(long)buf__arena;
	unsigned int size = SKB_DATA_ALIGN(sizeof(struct xdp_frame) + BPF_XDP_XMIT_HEADROOM + len) +
			    SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	struct net_device *dev;
	struct xdp_frame *xdpf;
	void *p, *data;
	int ret;

	if (flags & ~BPF_XDP_XMIT_F_NO_FLUSH)
		return -EINVAL;
	if (len < ETH_HLEN || len > BPF_XDP_XMIT_MAX)
		return -EINVAL;
	if (!aux->arena || addr < start || addr + len > start + SZ_4G)
		return -EFAULT;
	for (p = buf__arena; p < buf__arena + len; p += PAGE_SIZE - offset_in_page(p))
		if (!vmalloc_to_page(p))
			return -EFAULT;

	local_bh_disable();
	rcu_read_lock();
	dev = dev_get_by_index_rcu(&init_net, ifindex);
	if (!dev || !dev->netdev_ops->ndo_xdp_xmit) {
		ret = -ENODEV;
		goto out;
	}
	xdpf = netdev_alloc_frag(size);
	if (!xdpf) {
		ret = -ENOMEM;
		goto out;
	}
	memset(xdpf, 0, sizeof(*xdpf));
	data = (void *)xdpf + sizeof(*xdpf) + BPF_XDP_XMIT_HEADROOM;
	memcpy(data, buf__arena, len);
	xdpf->data = data;
	xdpf->len = len;
	xdpf->headroom = BPF_XDP_XMIT_HEADROOM;
	xdpf->frame_sz = size;
	xdpf->mem_type = MEM_TYPE_PAGE_SHARED;
	ret = dev->netdev_ops->ndo_xdp_xmit(dev, 1, &xdpf,
					    flags & BPF_XDP_XMIT_F_NO_FLUSH ? 0 : XDP_XMIT_FLUSH);
	if (ret == 1) {
		ret = 0;
	} else {
		xdp_return_frame(xdpf);
		if (ret >= 0)
			ret = -ENOSPC;
	}
out:
	rcu_read_unlock();
	local_bh_enable();
	return ret;
}

/**
 * bpf_xdp_xmit_flush - ring the doorbell for frames queued without a flush
 * @ifindex: the device, in the initial network namespace
 */
__bpf_kfunc int bpf_xdp_xmit_flush(u32 ifindex)
{
	struct net_device *dev;
	int ret;

	local_bh_disable();
	rcu_read_lock();
	dev = dev_get_by_index_rcu(&init_net, ifindex);
	if (!dev || !dev->netdev_ops->ndo_xdp_xmit) {
		ret = -ENODEV;
		goto out;
	}
	ret = dev->netdev_ops->ndo_xdp_xmit(dev, 0, NULL, XDP_XMIT_FLUSH);
	if (ret > 0)
		ret = 0;
out:
	rcu_read_unlock();
	local_bh_enable();
	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_xdp_xmit_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xdp_xmit, KF_IMPLICIT_ARGS)
BTF_ID_FLAGS(func, bpf_xdp_xmit_flush)
BTF_KFUNCS_END(bpf_xdp_xmit_kfunc_ids)

static const struct btf_kfunc_id_set bpf_xdp_xmit_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_xdp_xmit_kfunc_ids,
};

static int __init bpf_xdp_xmit_kfunc_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_xdp_xmit_kfunc_set);
	return ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_xdp_xmit_kfunc_set);
}
late_initcall(bpf_xdp_xmit_kfunc_init);
