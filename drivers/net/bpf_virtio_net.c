// SPDX-License-Identifier: GPL-2.0-only
/*
 * Virtio transport for the experimental BPF network-driver interface.
 * Virtqueue owns DMA descriptors; the attached program owns packet policy.
 */
#include <linux/bpf_net_driver.h>
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_net.h>

#define BVNET_HDR_LEN sizeof(struct virtio_net_hdr_mrg_rxbuf)
#define BVNET_RX_DEPTH 32
#define BVNET_POLL_MAX 64

struct bvnet {
	struct virtio_device *vdev;
	struct virtqueue *vq[2];
	struct bpf_net_driver *drv;
	u32 rx_posted;
	bool stopping;
};

static void bvnet_irq(struct virtqueue *vq)
{
	struct bvnet *vi = READ_ONCE(vq->vdev->priv);
	struct bpf_net_driver *drv;

	if (!vi || READ_ONCE(vi->stopping))
		return;
	drv = READ_ONCE(vi->drv);
	if (drv)
		bpf_net_driver_schedule(drv);
}

static int bvnet_start(struct bpf_net_driver *drv)
{
	struct bvnet *vi = bpf_net_driver_private(drv);
	struct virtqueue_info info[] = {
		{ .name = "bpf-rx", .callback = bvnet_irq },
		{ .name = "bpf-tx", .callback = bvnet_irq },
	};
	struct virtio_device *vdev = vi->vdev;
	struct virtqueue *vqs[2];
	int err;

	/* A previous stop reset both the queues and feature negotiation. */
	virtio_reset_device(vdev);
	virtio_add_status(vdev, VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER);
	err = vdev->config->finalize_features(vdev);
	if (err)
		return err;
	virtio_add_status(vdev, VIRTIO_CONFIG_S_FEATURES_OK);
	if (!(vdev->config->get_status(vdev) & VIRTIO_CONFIG_S_FEATURES_OK))
		return -ENODEV;
	err = virtio_find_vqs(vdev, ARRAY_SIZE(info), vqs, info, NULL);
	if (err)
		return err;
	/* find_vqs frees partial allocations on error without clearing vqs. */
	memcpy(vi->vq, vqs, sizeof(vqs));
	virtqueue_disable_cb(vi->vq[BPF_NET_DRIVER_RX]);
	virtqueue_disable_cb(vi->vq[BPF_NET_DRIVER_TX]);
	WRITE_ONCE(vi->stopping, false);
	virtio_device_ready(vdev);
	return 0;
}

static int bvnet_stop(struct bpf_net_driver *drv)
{
	struct bvnet *vi = bpf_net_driver_private(drv);
	int i;

	/*
	 * Disable the callback entry independently of successful DMA reset.
	 * Failed reset quarantines the rings, but must not retain callbacks into
	 * a removed driver. synchronize_cbs also drains a callback already entered.
	 */
	WRITE_ONCE(vi->stopping, true);
	for (i = 0; i < ARRAY_SIZE(vi->vq); i++) {
		if (!vi->vq[i])
			continue;
		virtqueue_disable_cb(vi->vq[i]);
		WRITE_ONCE(vi->vq[i]->callback, NULL);
	}
	virtio_reset_device(vi->vdev);
	virtio_synchronize_cbs(vi->vdev);
	if (vi->vdev->config->get_status(vi->vdev))
		return -EIO;
	for (i = 0; i < ARRAY_SIZE(vi->vq); i++) {
		if (!vi->vq[i])
			continue;
		while (virtqueue_detach_unused_buf(vi->vq[i]))
			;
	}
	if (vi->vq[0])
		vi->vdev->config->del_vqs(vi->vdev);
	memset(vi->vq, 0, sizeof(vi->vq));
	return 0;
}

static int bvnet_submit(struct bpf_net_driver *drv, unsigned int queue,
			struct bpf_net_driver_buffer *buf)
{
	struct bvnet *vi = bpf_net_driver_private(drv);
	struct scatterlist sg[2];

	if (queue > BPF_NET_DRIVER_TX || !vi->vq[queue])
		return -ENODEV;
	if (queue == BPF_NET_DRIVER_RX) {
		if (buf->offset || buf->submitted != BPF_NET_DRIVER_RX_SIZE)
			return -EINVAL;
		sg_init_one(sg, buf->skb->data, buf->submitted);
		return virtqueue_add_inbuf(vi->vq[queue], sg, 1, buf, GFP_ATOMIC);
	}
	if (buf->offset != BVNET_HDR_LEN || buf->submitted != buf->skb->len)
		return -EINVAL;
	if (memchr_inv(buf->prefix, 0, BVNET_HDR_LEN))
		return -EINVAL;
	sg_init_table(sg, ARRAY_SIZE(sg));
	sg_set_buf(&sg[0], buf->prefix, buf->offset);
	sg_set_buf(&sg[1], buf->skb->data, buf->submitted);
	return virtqueue_add_outbuf(vi->vq[queue], sg, ARRAY_SIZE(sg), buf, GFP_ATOMIC);
}

static struct bpf_net_driver_buffer *bvnet_complete(struct bpf_net_driver *drv,
						    unsigned int queue, u32 *length)
{
	struct bvnet *vi = bpf_net_driver_private(drv);

	if (queue > BPF_NET_DRIVER_TX || !vi->vq[queue])
		return NULL;
	return virtqueue_get_buf(vi->vq[queue], length);
}

static void bvnet_kick(struct bpf_net_driver *drv, unsigned int queue)
{
	struct bvnet *vi = bpf_net_driver_private(drv);

	if (queue <= BPF_NET_DRIVER_TX && vi->vq[queue])
		virtqueue_kick(vi->vq[queue]);
}

static void bvnet_mask(struct bpf_net_driver *drv)
{
	struct bvnet *vi = bpf_net_driver_private(drv);
	int i;

	for (i = 0; i < ARRAY_SIZE(vi->vq); i++)
		if (vi->vq[i])
			virtqueue_disable_cb(vi->vq[i]);
}

static bool bvnet_rearm(struct bpf_net_driver *drv)
{
	struct bvnet *vi = bpf_net_driver_private(drv);
	unsigned int cookie[2];
	bool pending = false;
	int i;

	for (i = 0; i < ARRAY_SIZE(vi->vq); i++)
		cookie[i] = virtqueue_enable_cb_prepare(vi->vq[i]);
	for (i = 0; i < ARRAY_SIZE(vi->vq); i++)
		pending |= virtqueue_poll(vi->vq[i], cookie[i]);
	if (pending)
		bvnet_mask(drv);
	return pending;
}

/*
 * Reference policy for recovery and matched native/BPF comparisons. These
 * callbacks use the same capabilities as the BPF program, including checks.
 */
static void bvnet_refill(struct bpf_net_driver *drv)
{
	struct bvnet *vi = bpf_net_driver_private(drv);
	u64 id;
	int i;

	for (i = 0; i < BVNET_RX_DEPTH && vi->rx_posted < BVNET_RX_DEPTH; i++) {
		id = bpf_net_buffer_alloc(drv);
		if (!id)
			break;
		if (bpf_net_queue_submit(drv, id, BPF_NET_DRIVER_RX, 0,
					 BPF_NET_DRIVER_RX_SIZE)) {
			bpf_net_buffer_release(drv, id);
			break;
		}
		vi->rx_posted++;
	}
	bpf_net_queue_kick(drv, BPF_NET_DRIVER_RX);
}

static int bvnet_native_open(struct bpf_net_driver *drv)
{
	struct bvnet *vi = bpf_net_driver_private(drv);

	vi->rx_posted = 0;
	bvnet_refill(drv);
	return 0;
}

static int bvnet_native_poll(struct bpf_net_driver *drv, int budget)
{
	struct bvnet *vi = bpf_net_driver_private(drv);
	u32 len;
	u64 id;
	int tx, rx;

	for (tx = 0; tx < BVNET_POLL_MAX; tx++) {
		id = bpf_net_queue_complete(drv, BPF_NET_DRIVER_TX);
		if (!id)
			break;
		bpf_net_buffer_release(drv, id);
	}
	if (!budget)
		return 0;
	for (rx = 0; rx < budget; rx++) {
		id = bpf_net_queue_complete(drv, BPF_NET_DRIVER_RX);
		if (!id)
			break;
		if (vi->rx_posted)
			vi->rx_posted--;
		len = bpf_net_buffer_length(drv, id);
		if (len < BVNET_HDR_LEN + ETH_HLEN || bpf_net_buffer_load(drv, id, 0, 2)) {
			bpf_net_buffer_release(drv, id);
			continue;
		}
		bpf_net_receive(drv, id, BVNET_HDR_LEN, len - BVNET_HDR_LEN);
	}
	bvnet_refill(drv);
	return tx == BVNET_POLL_MAX ? budget : rx;
}

static int bvnet_native_xmit(struct bpf_net_driver *drv, u64 id)
{
	int err;

	bpf_net_buffer_store(drv, id, 0, 8, 0);
	bpf_net_buffer_store(drv, id, 8, 4, 0);
	err = bpf_net_queue_submit(drv, id, BPF_NET_DRIVER_TX, BVNET_HDR_LEN,
				   bpf_net_buffer_length(drv, id));
	if (err)
		bpf_net_buffer_release(drv, id);
	else
		bpf_net_queue_kick(drv, BPF_NET_DRIVER_TX);
	return 0;
}

static void bvnet_native_close(struct bpf_net_driver *drv)
{
	struct bvnet *vi = bpf_net_driver_private(drv);

	vi->rx_posted = 0;
}

static const struct bpf_net_driver_ops bvnet_native_ops = {
	.open = bvnet_native_open,
	.poll = bvnet_native_poll,
	.xmit = bvnet_native_xmit,
	.close = bvnet_native_close,
};

static const struct bpf_net_driver_backend bvnet_backend = {
	.start = bvnet_start,
	.stop = bvnet_stop,
	.submit = bvnet_submit,
	.complete = bvnet_complete,
	.kick = bvnet_kick,
	.mask = bvnet_mask,
	.rearm = bvnet_rearm,
	.native_ops = &bvnet_native_ops,
};

static int bvnet_probe(struct virtio_device *vdev)
{
	struct net_device *dev;
	struct bvnet *vi;
	u8 mac[ETH_ALEN];
	int err;

	if (!virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		return -ENODEV;
	dev = alloc_etherdev(sizeof(*vi));
	if (!dev)
		return -ENOMEM;
	vi = netdev_priv(dev);
	vi->vdev = vdev;
	vi->stopping = true;
	vdev->priv = vi;
	strscpy(dev->name, "bpfv%d", IFNAMSIZ);
	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = ETH_DATA_LEN;
	SET_NETDEV_DEV(dev, &vdev->dev);
	if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC)) {
		virtio_cread_bytes(vdev, offsetof(struct virtio_net_config, mac), mac, ETH_ALEN);
		eth_hw_addr_set(dev, mac);
	} else {
		eth_hw_addr_random(dev);
	}
	vi->drv = bpf_net_driver_create(dev, &bvnet_backend, vi);
	if (IS_ERR(vi->drv)) {
		err = PTR_ERR(vi->drv);
		free_netdev(dev);
		vdev->priv = NULL;
		return err;
	}
	err = bpf_net_driver_register(vi->drv);
	if (err) {
		bpf_net_driver_destroy(vi->drv);
		vdev->priv = NULL;
	}
	return err;
}

static void bvnet_remove(struct virtio_device *vdev)
{
	struct bvnet *vi = vdev->priv;

	bpf_net_driver_destroy(vi->drv);
	WRITE_ONCE(vdev->priv, NULL);
}

static const struct virtio_device_id bvnet_ids[] = {
	{ VIRTIO_ID_NET, VIRTIO_DEV_ANY_ID },
	{ },
};

static unsigned int bvnet_features[] = { VIRTIO_NET_F_MAC };

static struct virtio_driver bvnet_driver = {
	.driver.name = "bpf_virtio_net",
	.id_table = bvnet_ids,
	.feature_table = bvnet_features,
	.feature_table_size = ARRAY_SIZE(bvnet_features),
	.probe = bvnet_probe,
	.remove = bvnet_remove,
};
module_virtio_driver(bvnet_driver);
MODULE_DEVICE_TABLE(virtio, bvnet_ids);
MODULE_DESCRIPTION("Virtio transport for bounded BPF network drivers");
MODULE_LICENSE("GPL");
