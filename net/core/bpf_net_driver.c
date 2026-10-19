// SPDX-License-Identifier: GPL-2.0
/*
 * Revocable network driver algorithms. Hardware authority and packet lifetime
 * remain native even when all queue policy runs in an arena-backed BPF program.
 */
#include <linux/bpf.h>
#include <linux/bpf_net_driver.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/etherdevice.h>
#include <linux/filter.h>
#include <linux/kref.h>
#include <linux/if_vlan.h>
#include <linux/nsproxy.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <net/net_namespace.h>

#define BPF_NET_DRIVER_TIMEOUT (5 * HZ)
#define BPF_NET_DRIVER_NO_PROGRESS 1024

enum bpf_net_phase { BPF_NET_OPEN, BPF_NET_POLL, BPF_NET_XMIT, BPF_NET_CLOSE };

struct bpf_net_driver {
	struct net_device *dev;
	struct napi_struct napi;
	const struct bpf_net_driver_backend *backend;
	void *backend_private;
	struct bpf_net_driver_ops *attached;
	struct kref ref;
	/* Serializes callbacks, buffer ownership and transport queue access. */
	spinlock_t lock;
	struct work_struct recovery;
	struct delayed_work watchdog;
	struct bpf_net_driver_buffer buffers[BPF_NET_DRIVER_BUFFERS];
	u64 completions;
	unsigned long last_progress;
	u32 pending_tx;
	u32 idle_polls;
	atomic_t external_fault;
	atomic_t active_polls;
	wait_queue_head_t poll_wait;
	struct sk_buff_head received;
	u64 calls;
	u64 recoveries;
	u32 phase;
	int last_fault;
	int fault;
	bool alive;
	bool running;
	bool revoked;
	bool quarantined;
	bool fallback_requested;
};

/*
 * Every invocation holds the device lock with BH disabled. Kconfig excludes
 * PREEMPT_RT, so callbacks cannot interleave on a CPU while this identity is
 * installed. A kfunc checks it before dereferencing its argument. Tokens alone
 * never grant access to another device, an old allocation, or a device-owned
 * packet. Supporting RT requires task-local invocation state instead.
 */
static DEFINE_PER_CPU(struct bpf_net_driver *, bpf_net_current);
static atomic64_t bpf_net_generation = ATOMIC64_INIT(0);
static struct bpf_struct_ops bpf_bpf_net_driver_ops;

static void bpf_net_fault(struct bpf_net_driver *drv, int error)
{
	if (!drv->fault) {
		drv->fallback_requested = drv->attached && !drv->revoked;
		drv->fault = error ?: -EPROTO;
		drv->last_fault = drv->fault;
		drv->revoked = true;
		schedule_work(&drv->recovery);
	}
}

static struct bpf_net_driver *bpf_net_context(struct bpf_net_driver *arg)
{
	struct bpf_net_driver *drv = this_cpu_read(bpf_net_current);

	if (unlikely(!drv || drv != arg)) {
		if (drv)
			bpf_net_fault(drv, -EXDEV);
		return NULL;
	}
	if (unlikely(drv->fault || !drv->running))
		return NULL;
	return drv;
}

static struct bpf_net_driver_buffer *bpf_net_buffer(struct bpf_net_driver *drv, u64 id)
{
	struct bpf_net_driver_buffer *buf = &drv->buffers[id & (BPF_NET_DRIVER_BUFFERS - 1)];

	if (!id || buf->id != id || buf->state != BPF_NET_BUFFER_CPU) {
		bpf_net_fault(drv, -ESTALE);
		return NULL;
	}
	return buf;
}

static struct bpf_net_driver_buffer *bpf_net_new_buffer(struct bpf_net_driver *drv,
							struct sk_buff *skb, u32 queue)
{
	unsigned int i, first = queue == BPF_NET_DRIVER_RX ? 0 : BPF_NET_DRIVER_BUFFERS / 2;
	struct bpf_net_driver_buffer *buf;
	u64 generation;

	for (i = first; i < first + BPF_NET_DRIVER_BUFFERS / 2; i++) {
		buf = &drv->buffers[i];
		if (buf->state != BPF_NET_BUFFER_FREE)
			continue;
		generation = atomic64_inc_return(&bpf_net_generation);
		if (unlikely(generation >= BIT_ULL(56)))
			return NULL;
		memset(buf, 0, sizeof(*buf));
		buf->skb = skb;
		buf->id = generation << 8 | i;
		buf->queue = queue;
		buf->state = BPF_NET_BUFFER_CPU;
		buf->length = skb->len;
		buf->capacity = queue == BPF_NET_DRIVER_RX ? BPF_NET_DRIVER_RX_SIZE : skb->len;
		return buf;
	}
	return NULL;
}

static void bpf_net_free_buffer(struct bpf_net_driver_buffer *buf)
{
	dev_kfree_skb_any(buf->skb);
	buf->skb = NULL;
	buf->state = BPF_NET_BUFFER_FREE;
	buf->id = 0;
}

__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_net_buffer_alloc(struct bpf_net_driver *arg)
{
	struct bpf_net_driver *drv = bpf_net_context(arg);
	struct bpf_net_driver_buffer *buf;
	struct sk_buff *skb;

	if (!drv)
		return 0;
	skb = __netdev_alloc_skb(drv->dev, BPF_NET_DRIVER_RX_SIZE, GFP_ATOMIC);
	if (!skb)
		return 0;
	buf = bpf_net_new_buffer(drv, skb, BPF_NET_DRIVER_RX);
	if (!buf) {
		dev_kfree_skb_any(skb);
		return 0;
	}
	return buf->id;
}
EXPORT_SYMBOL_GPL(bpf_net_buffer_alloc);

__bpf_kfunc u32 bpf_net_buffer_length(struct bpf_net_driver *arg, u64 id)
{
	struct bpf_net_driver *drv = bpf_net_context(arg);
	struct bpf_net_driver_buffer *buf;

	if (!drv)
		return 0;
	buf = bpf_net_buffer(drv, id);
	return buf ? buf->length : 0;
}
EXPORT_SYMBOL_GPL(bpf_net_buffer_length);

__bpf_kfunc u64 bpf_net_buffer_load(struct bpf_net_driver *arg, u64 id, u32 offset, u32 size)
{
	struct bpf_net_driver *drv = bpf_net_context(arg);
	struct bpf_net_driver_buffer *buf;
	u64 value = 0;
	unsigned int i;

	if (!drv)
		return 0;
	buf = bpf_net_buffer(drv, id);
	if (!buf)
		return 0;
	if (!size || size > sizeof(value) || offset > buf->length || size > buf->length - offset) {
		bpf_net_fault(drv, -ERANGE);
		return 0;
	}
	for (i = 0; i < size; i++)
		value |= (u64)buf->skb->data[offset + i] << (8 * i);
	return value;
}
EXPORT_SYMBOL_GPL(bpf_net_buffer_load);

__bpf_kfunc int bpf_net_buffer_store(struct bpf_net_driver *arg, u64 id, u32 offset,
				     u32 size, u64 value)
{
	struct bpf_net_driver *drv = bpf_net_context(arg);
	struct bpf_net_driver_buffer *buf;
	u8 *dest;
	u32 capacity;
	unsigned int i;

	if (!drv)
		return -ENODEV;
	buf = bpf_net_buffer(drv, id);
	if (!buf)
		return -ESTALE;
	dest = buf->queue == BPF_NET_DRIVER_TX ? buf->prefix : buf->skb->data;
	capacity = buf->queue == BPF_NET_DRIVER_TX ? sizeof(buf->prefix) : buf->capacity;
	if (!size || size > sizeof(value) || offset > capacity || size > capacity - offset) {
		bpf_net_fault(drv, -ERANGE);
		return -ERANGE;
	}
	for (i = 0; i < size; i++)
		dest[offset + i] = value >> (8 * i);
	return 0;
}
EXPORT_SYMBOL_GPL(bpf_net_buffer_store);

__bpf_kfunc int bpf_net_buffer_release(struct bpf_net_driver *arg, u64 id)
{
	struct bpf_net_driver *drv = bpf_net_context(arg);
	struct bpf_net_driver_buffer *buf;

	if (!drv)
		return -ENODEV;
	buf = bpf_net_buffer(drv, id);
	if (!buf)
		return -ESTALE;
	if (buf->queue == BPF_NET_DRIVER_TX) {
		if (buf->completed) {
			drv->dev->stats.tx_packets++;
			drv->dev->stats.tx_bytes += buf->length;
		} else {
			drv->dev->stats.tx_dropped++;
		}
	}
	bpf_net_free_buffer(buf);
	return 0;
}
EXPORT_SYMBOL_GPL(bpf_net_buffer_release);

__bpf_kfunc int bpf_net_queue_submit(struct bpf_net_driver *arg, u64 id, u32 queue,
				     u32 offset, u32 length)
{
	struct bpf_net_driver *drv = bpf_net_context(arg);
	struct bpf_net_driver_buffer *buf;
	int err;

	if (!drv)
		return -ENODEV;
	buf = bpf_net_buffer(drv, id);
	if (!buf)
		return -ESTALE;
	if (queue != buf->queue || queue > BPF_NET_DRIVER_TX || !length ||
	    (queue == BPF_NET_DRIVER_RX && (offset || length > buf->capacity)) ||
	    (queue == BPF_NET_DRIVER_TX &&
	     (offset > sizeof(buf->prefix) || length != buf->skb->len || buf->completed))) {
		bpf_net_fault(drv, -EINVAL);
		return -EINVAL;
	}
	buf->offset = offset;
	buf->submitted = length;
	err = drv->backend->submit(drv, queue, buf);
	if (err)
		return err;
	buf->state = BPF_NET_BUFFER_DEVICE;
	buf->submitted_at = jiffies;
	if (queue == BPF_NET_DRIVER_TX) {
		if (!drv->pending_tx)
			drv->last_progress = jiffies;
		drv->pending_tx++;
		netdev_sent_queue(drv->dev, length);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(bpf_net_queue_submit);

__bpf_kfunc u64 bpf_net_queue_complete(struct bpf_net_driver *arg, u32 queue)
{
	struct bpf_net_driver *drv = bpf_net_context(arg);
	struct bpf_net_driver_buffer *buf;
	u32 length;

	if (!drv)
		return 0;
	if (queue > BPF_NET_DRIVER_TX) {
		bpf_net_fault(drv, -EINVAL);
		return 0;
	}
	buf = drv->backend->complete(drv, queue, &length);
	if (IS_ERR(buf)) {
		bpf_net_fault(drv, PTR_ERR(buf));
		return 0;
	}
	if (!buf)
		return 0;
	/* Backend cookies are native, but check the ledger before using them. */
	if ((unsigned long)buf < (unsigned long)drv->buffers ||
	    (unsigned long)buf >= (unsigned long)(drv->buffers + BPF_NET_DRIVER_BUFFERS) ||
	    ((unsigned long)buf - (unsigned long)drv->buffers) % sizeof(*buf) ||
	    buf->state != BPF_NET_BUFFER_DEVICE || buf->queue != queue ||
	    (queue == BPF_NET_DRIVER_RX && length > buf->submitted)) {
		bpf_net_fault(drv, -EPROTO);
		return 0;
	}
	buf->state = BPF_NET_BUFFER_CPU;
	buf->completed = true;
	if (queue == BPF_NET_DRIVER_RX) {
		buf->length = length;
	} else {
		drv->pending_tx--;
		netdev_completed_queue(drv->dev, 1, buf->length);
	}
	drv->last_progress = jiffies;
	drv->completions++;
	return buf->id;
}
EXPORT_SYMBOL_GPL(bpf_net_queue_complete);

__bpf_kfunc int bpf_net_queue_kick(struct bpf_net_driver *arg, u32 queue)
{
	struct bpf_net_driver *drv = bpf_net_context(arg);

	if (!drv)
		return -ENODEV;
	if (queue > BPF_NET_DRIVER_TX) {
		bpf_net_fault(drv, -EINVAL);
		return -EINVAL;
	}
	drv->backend->kick(drv, queue);
	return 0;
}
EXPORT_SYMBOL_GPL(bpf_net_queue_kick);

__bpf_kfunc int bpf_net_receive(struct bpf_net_driver *arg, u64 id, u32 offset, u32 length)
{
	struct bpf_net_driver *drv = bpf_net_context(arg);
	struct bpf_net_driver_buffer *buf;
	struct sk_buff *skb;

	if (!drv)
		return -ENODEV;
	buf = bpf_net_buffer(drv, id);
	if (!buf)
		return -ESTALE;
	if (drv->phase != BPF_NET_POLL || buf->queue != BPF_NET_DRIVER_RX ||
	    !buf->completed || offset > buf->length ||
	    length > buf->length - offset) {
		bpf_net_fault(drv, -ERANGE);
		return -ERANGE;
	}
	/* A malformed wire packet is a drop, not a driver ownership violation. */
	if (length < ETH_HLEN || length > drv->dev->mtu + ETH_HLEN + VLAN_HLEN) {
		drv->dev->stats.rx_dropped++;
		bpf_net_free_buffer(buf);
		return -EMSGSIZE;
	}
	skb = buf->skb;
	buf->skb = NULL;
	buf->id = 0;
	buf->state = BPF_NET_BUFFER_FREE;
	skb_put(skb, offset + length);
	skb_pull(skb, offset);
	skb->protocol = eth_type_trans(skb, drv->dev);
	skb->ip_summed = CHECKSUM_NONE;
	drv->dev->stats.rx_packets++;
	drv->dev->stats.rx_bytes += length;
	__skb_queue_tail(&drv->received, skb);
	return 0;
}
EXPORT_SYMBOL_GPL(bpf_net_receive);

__bpf_kfunc_end_defs();

static const struct bpf_net_driver_ops *bpf_net_ops(struct bpf_net_driver *drv)
{
	return drv->attached && !drv->revoked ? drv->attached : drv->backend->native_ops;
}

static int bpf_net_poll(struct napi_struct *napi, int budget)
{
	struct bpf_net_driver *drv = container_of(napi, struct bpf_net_driver, napi);
	struct bpf_net_driver *previous;
	struct sk_buff_head received;
	struct sk_buff *skb;
	bool progress = false, completed;
	u64 before;
	int work;

	/* No RX/page-pool operations are allowed in a zero-budget TX-only poll. */
	if (!budget)
		return 0;
	atomic_inc(&drv->active_polls);
	__skb_queue_head_init(&received);
	spin_lock(&drv->lock);
	work = atomic_xchg(&drv->external_fault, 0);
	if (unlikely(work))
		bpf_net_fault(drv, work);
	if (unlikely(!drv->running || drv->fault)) {
		work = 0;
		goto deliver;
	}
	drv->backend->mask(drv);
	previous = this_cpu_read(bpf_net_current);
	this_cpu_write(bpf_net_current, drv);
	before = drv->completions;
	drv->phase = BPF_NET_POLL;
	if (drv->attached && !drv->revoked)
		drv->calls++;
	work = bpf_net_ops(drv)->poll(drv, budget);
	this_cpu_write(bpf_net_current, previous);
	if (work < 0 || work > budget) {
		bpf_net_fault(drv, -EPROTO);
		work = 0;
	}
	progress = before != drv->completions;
	if (progress)
		drv->idle_polls = 0;
	else if (work == budget && ++drv->idle_polls > BPF_NET_DRIVER_NO_PROGRESS)
		bpf_net_fault(drv, -ETIMEDOUT);
	if (drv->fault)
		work = 0;
	skb_queue_splice_tail_init(&drv->received, &received);
deliver:
	spin_unlock(&drv->lock);
	while ((skb = __skb_dequeue(&received)))
		napi_gro_receive(napi, skb);
	/* Completion also flushes GRO and may synchronously re-enter ndo_start_xmit. */
	completed = work < budget && napi_complete_done(napi, work);
	spin_lock(&drv->lock);
	if (completed && drv->running && !drv->fault) {
		if (drv->backend->rearm(drv)) {
			if (!progress && ++drv->idle_polls > BPF_NET_DRIVER_NO_PROGRESS)
				bpf_net_fault(drv, -ETIMEDOUT);
			else
				napi_schedule(napi);
		} else {
			drv->idle_polls = 0;
		}
	}
	/*
	 * napi_disable() alone may return after napi_complete_done(). Stop also
	 * waits for this count and then acquires the lock, which drains the wakeup
	 * and all post-completion accesses before backend or netdevice destruction.
	 */
	if (atomic_dec_and_test(&drv->active_polls))
		wake_up_all(&drv->poll_wait);
	spin_unlock(&drv->lock);
	return work;
}

static netdev_tx_t bpf_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct bpf_net_driver *drv = dev->ml_priv;
	struct bpf_net_driver_buffer *buf;
	struct bpf_net_driver *previous;
	int err;

	if (unlikely(skb_is_nonlinear(skb) && skb_linearize(skb)))
		goto drop;
	spin_lock_bh(&drv->lock);
	if (unlikely(drv->fault || !drv->running))
		goto unlock_drop;
	buf = bpf_net_new_buffer(drv, skb, BPF_NET_DRIVER_TX);
	if (!buf)
		goto unlock_drop;
	previous = this_cpu_read(bpf_net_current);
	this_cpu_write(bpf_net_current, drv);
	drv->phase = BPF_NET_XMIT;
	if (drv->attached && !drv->revoked)
		drv->calls++;
	err = bpf_net_ops(drv)->xmit(drv, buf->id);
	this_cpu_write(bpf_net_current, previous);
	if (err)
		bpf_net_fault(drv, err);
	/* A callback may submit or drop, but may not silently retain TX ownership. */
	if (buf->state == BPF_NET_BUFFER_CPU) {
		bpf_net_fault(drv, -EPROTO);
		bpf_net_free_buffer(buf);
		dev->stats.tx_dropped++;
	}
	spin_unlock_bh(&drv->lock);
	return NETDEV_TX_OK;
unlock_drop:
	spin_unlock_bh(&drv->lock);
drop:
	dev->stats.tx_dropped++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static void bpf_net_reclaim(struct bpf_net_driver *drv)
{
	int i;

	for (i = 0; i < BPF_NET_DRIVER_BUFFERS; i++)
		if (drv->buffers[i].state != BPF_NET_BUFFER_FREE)
			bpf_net_free_buffer(&drv->buffers[i]);
	drv->pending_tx = 0;
	netdev_reset_queue(drv->dev);
}

static int bpf_net_open(struct net_device *dev)
{
	struct bpf_net_driver *drv = dev->ml_priv;
	struct bpf_net_driver *previous;
	int err;

	if (!drv->alive || drv->quarantined)
		return -ENODEV;
	drv->fault = 0;
	drv->fallback_requested = false;
	atomic_set(&drv->external_fault, 0);
	drv->idle_polls = 0;
	err = drv->backend->start(drv);
	if (err) {
		/* Failure may mean a partially accepted DMA-bearing command. */
		if (drv->backend->stop(drv))
			drv->quarantined = true;
		else
			bpf_net_reclaim(drv);
		return err;
	}
	napi_enable(&drv->napi);
	spin_lock_bh(&drv->lock);
	drv->running = true;
	previous = this_cpu_read(bpf_net_current);
	this_cpu_write(bpf_net_current, drv);
	drv->phase = BPF_NET_OPEN;
	if (drv->attached && !drv->revoked)
		drv->calls++;
	err = bpf_net_ops(drv)->open(drv);
	this_cpu_write(bpf_net_current, previous);
	if (err || drv->fault) {
		err = err ?: drv->fault;
		drv->running = false;
	} else {
		netif_carrier_on(dev);
		netif_start_queue(dev);
		napi_schedule(&drv->napi);
	}
	spin_unlock_bh(&drv->lock);
	if (err) {
		napi_disable(&drv->napi);
		wait_event(drv->poll_wait, !atomic_read(&drv->active_polls));
		spin_lock_bh(&drv->lock);
		spin_unlock_bh(&drv->lock);
		if (drv->backend->stop(drv))
			drv->quarantined = true;
		else
			bpf_net_reclaim(drv);
		return err;
	}
	schedule_delayed_work(&drv->watchdog, HZ);
	return 0;
}

static int bpf_net_stop(struct net_device *dev)
{
	struct bpf_net_driver *drv = dev->ml_priv;
	struct bpf_net_driver *previous;

	netif_tx_disable(dev);
	netif_carrier_off(dev);
	cancel_delayed_work_sync(&drv->watchdog);
	spin_lock_bh(&drv->lock);
	drv->backend->mask(drv);
	spin_unlock_bh(&drv->lock);
	napi_disable(&drv->napi);
	wait_event(drv->poll_wait, !atomic_read(&drv->active_polls));
	spin_lock_bh(&drv->lock);
	if (!drv->fault) {
		previous = this_cpu_read(bpf_net_current);
		this_cpu_write(bpf_net_current, drv);
		drv->phase = BPF_NET_CLOSE;
		if (drv->attached && !drv->revoked)
			drv->calls++;
		bpf_net_ops(drv)->close(drv);
		this_cpu_write(bpf_net_current, previous);
	}
	drv->running = false;
	spin_unlock_bh(&drv->lock);
	if (drv->backend->stop(drv)) {
		drv->quarantined = true;
		netdev_err(dev, "DMA quiescence failed; retaining packet allocations\n");
	} else {
		bpf_net_reclaim(drv);
	}
	return 0;
}

static const struct net_device_ops bpf_netdev_ops = {
	.ndo_open = bpf_net_open,
	.ndo_stop = bpf_net_stop,
	.ndo_start_xmit = bpf_net_xmit,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr = eth_validate_addr,
};

static void bpf_net_watchdog(struct work_struct *work)
{
	struct bpf_net_driver *drv = container_of(to_delayed_work(work),
						 struct bpf_net_driver, watchdog);

	unsigned int i;

	spin_lock_bh(&drv->lock);
	for (i = BPF_NET_DRIVER_BUFFERS / 2; drv->running && i < BPF_NET_DRIVER_BUFFERS; i++) {
		struct bpf_net_driver_buffer *buf = &drv->buffers[i];

		if (buf->state != BPF_NET_BUFFER_FREE &&
		    time_after(jiffies, buf->submitted_at + BPF_NET_DRIVER_TIMEOUT)) {
			bpf_net_fault(drv, -ETIMEDOUT);
			break;
		}
	}
	if (drv->running && !drv->fault)
		schedule_delayed_work(&drv->watchdog, HZ);
	spin_unlock_bh(&drv->lock);
}

static void bpf_net_recovery(struct work_struct *work)
{
	struct bpf_net_driver *drv = container_of(work, struct bpf_net_driver, recovery);
	bool reopen, fallback;

	rtnl_lock();
	if (!drv->alive || !drv->fault)
		goto out;
	netdev_warn(drv->dev, "revoking BPF driver after error %d\n", drv->fault);
	reopen = netif_running(drv->dev);
	fallback = drv->fallback_requested;
	drv->fallback_requested = false;
	if (reopen)
		dev_close(drv->dev);
	drv->revoked = true;
	if (reopen && fallback && !drv->quarantined) {
		int err = dev_open(drv->dev, NULL);

		drv->recoveries++;

		if (err)
			netdev_err(drv->dev, "native recovery failed: %d\n", err);
	}
out:
	rtnl_unlock();
}

static void bpf_net_release(struct kref *ref)
{
	struct bpf_net_driver *drv = container_of(ref, struct bpf_net_driver, ref);

	/* A failed hardware reset intentionally retains the DMA resource ledger. */
	if (drv->quarantined)
		return;
	netif_napi_del(&drv->napi);
	free_netdev(drv->dev);
	kfree(drv);
}

static ssize_t state_show(struct device *device, struct device_attribute *attr, char *buf)
{
	struct bpf_net_driver *drv = to_net_dev(device)->ml_priv;
	const char *state;

	spin_lock_bh(&drv->lock);
	if (drv->quarantined)
		state = "quarantined";
	else if (drv->fault)
		state = "recovering";
	else if (drv->revoked)
		state = "revoked";
	else if (drv->attached)
		state = "bpf";
	else
		state = "native";
	spin_unlock_bh(&drv->lock);
	return sysfs_emit(buf, "%s\n", state);
}
static DEVICE_ATTR_RO(state);

static ssize_t fault_show(struct device *device, struct device_attribute *attr, char *buf)
{
	struct bpf_net_driver *drv = to_net_dev(device)->ml_priv;

	return sysfs_emit(buf, "%d\n", READ_ONCE(drv->last_fault));
}
static DEVICE_ATTR_RO(fault);

static ssize_t calls_show(struct device *device, struct device_attribute *attr, char *buf)
{
	struct bpf_net_driver *drv = to_net_dev(device)->ml_priv;

	return sysfs_emit(buf, "%llu\n", READ_ONCE(drv->calls));
}
static DEVICE_ATTR_RO(calls);

static ssize_t recoveries_show(struct device *device, struct device_attribute *attr, char *buf)
{
	struct bpf_net_driver *drv = to_net_dev(device)->ml_priv;

	return sysfs_emit(buf, "%llu\n", READ_ONCE(drv->recoveries));
}
static DEVICE_ATTR_RO(recoveries);

static struct attribute *bpf_net_attrs[] = {
	&dev_attr_state.attr,
	&dev_attr_fault.attr,
	&dev_attr_calls.attr,
	&dev_attr_recoveries.attr,
	NULL,
};

static const struct attribute_group bpf_net_attribute_group = {
	.name = "bpf_driver",
	.attrs = bpf_net_attrs,
};

struct bpf_net_driver *bpf_net_driver_create(struct net_device *dev,
					     const struct bpf_net_driver_backend *backend,
					     void *backend_private)
{
	struct bpf_net_driver *drv;

	if (!backend || !backend->native_ops)
		return ERR_PTR(-EINVAL);
	drv = kzalloc_obj(*drv);
	if (!drv)
		return ERR_PTR(-ENOMEM);
	drv->dev = dev;
	drv->backend = backend;
	drv->backend_private = backend_private;
	drv->alive = true;
	kref_init(&drv->ref);
	spin_lock_init(&drv->lock);
	init_waitqueue_head(&drv->poll_wait);
	__skb_queue_head_init(&drv->received);
	INIT_WORK(&drv->recovery, bpf_net_recovery);
	INIT_DELAYED_WORK(&drv->watchdog, bpf_net_watchdog);
	dev->ml_priv = drv;
	dev->netdev_ops = &bpf_netdev_ops;
	/* Netpoll may enter xmit from a hard IRQ that interrupted our lock holder. */
	dev->priv_flags |= IFF_DISABLE_NETPOLL;
	dev->features = 0;
	dev->hw_features = 0;
	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = ETH_DATA_LEN;
	dev->sysfs_groups[0] = &bpf_net_attribute_group;
	netif_napi_add(dev, &drv->napi, bpf_net_poll);
	return drv;
}
EXPORT_SYMBOL_GPL(bpf_net_driver_create);

int bpf_net_driver_register(struct bpf_net_driver *drv)
{
	return register_netdev(drv->dev);
}
EXPORT_SYMBOL_GPL(bpf_net_driver_register);

void bpf_net_driver_destroy(struct bpf_net_driver *drv)
{
	rtnl_lock();
	drv->alive = false;
	if (drv->dev->reg_state == NETREG_REGISTERED)
		unregister_netdevice(drv->dev);
	rtnl_unlock();
	cancel_work_sync(&drv->recovery);
	cancel_delayed_work_sync(&drv->watchdog);
	kref_put(&drv->ref, bpf_net_release);
}
EXPORT_SYMBOL_GPL(bpf_net_driver_destroy);

void *bpf_net_driver_private(struct bpf_net_driver *drv)
{
	return drv->backend_private;
}
EXPORT_SYMBOL_GPL(bpf_net_driver_private);

struct net_device *bpf_net_driver_netdev(struct bpf_net_driver *drv)
{
	return drv->dev;
}
EXPORT_SYMBOL_GPL(bpf_net_driver_netdev);

void bpf_net_driver_schedule(struct bpf_net_driver *drv)
{
	if (READ_ONCE(drv->running))
		napi_schedule(&drv->napi);
}
EXPORT_SYMBOL_GPL(bpf_net_driver_schedule);

/* IRQ-side error reporting never waits on the callback lock. */
void bpf_net_driver_error(struct bpf_net_driver *drv, int error)
{
	atomic_cmpxchg(&drv->external_fault, 0, error ?: -EIO);
	bpf_net_driver_schedule(drv);
}
EXPORT_SYMBOL_GPL(bpf_net_driver_error);

BTF_KFUNCS_START(bpf_net_driver_kfunc_ids)
BTF_ID_FLAGS(func, bpf_net_buffer_alloc)
BTF_ID_FLAGS(func, bpf_net_buffer_length)
BTF_ID_FLAGS(func, bpf_net_buffer_load)
BTF_ID_FLAGS(func, bpf_net_buffer_store)
BTF_ID_FLAGS(func, bpf_net_buffer_release)
BTF_ID_FLAGS(func, bpf_net_queue_submit)
BTF_ID_FLAGS(func, bpf_net_queue_complete)
BTF_ID_FLAGS(func, bpf_net_queue_kick)
BTF_ID_FLAGS(func, bpf_net_receive)
BTF_KFUNCS_END(bpf_net_driver_kfunc_ids)

bool bpf_net_driver_kfunc_allowed(u32 id)
{
	return btf_id_set8_contains(&bpf_net_driver_kfunc_ids, id);
}

static int bpf_net_kfunc_filter(const struct bpf_prog *prog, u32 id)
{
	if (!bpf_net_driver_kfunc_allowed(id))
		return 0;
	return prog->aux->st_ops == &bpf_bpf_net_driver_ops ? 0 : -EACCES;
}

static const struct btf_kfunc_id_set bpf_net_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_net_driver_kfunc_ids,
	.filter = bpf_net_kfunc_filter,
};

static int bpf_net_init_member(const struct btf_type *t, const struct btf_member *member,
			       void *kdata, const void *udata)
{
	struct bpf_net_driver_ops *ops = kdata;
	const struct bpf_net_driver_ops *uops = udata;
	u32 off = __btf_member_bit_offset(t, member) / 8;

	if (off == offsetof(struct bpf_net_driver_ops, ifindex)) {
		ops->ifindex = uops->ifindex;
		return ops->ifindex ? 1 : -EINVAL;
	}
	if (off == offsetof(struct bpf_net_driver_ops, priv))
		return uops->priv ? -EINVAL : 1;
	return 0;
}

static int bpf_net_validate(void *kdata)
{
	struct bpf_net_driver_ops *ops = kdata;

	return ops->open && ops->close && ops->poll && ops->xmit ? 0 : -EINVAL;
}

static int bpf_net_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_net_driver_ops *ops = kdata;
	struct net_device *dev;
	struct bpf_net_driver *drv;
	int err = 0;

	/* Device ownership is intentionally restricted to the initial netns. */
	if (!net_eq(current->nsproxy->net_ns, &init_net))
		return -EOPNOTSUPP;
	rtnl_lock();
	dev = __dev_get_by_index(&init_net, ops->ifindex);
	if (!dev || dev->netdev_ops != &bpf_netdev_ops) {
		err = -ENODEV;
		goto out;
	}
	drv = dev->ml_priv;
	if (!drv->alive || drv->attached || netif_running(dev) || drv->quarantined) {
		err = -EBUSY;
		goto out;
	}
	kref_get(&drv->ref);
	drv->attached = ops;
	drv->revoked = false;
	drv->fault = 0;
	drv->fallback_requested = false;
	ops->priv = drv;
out:
	rtnl_unlock();
	return err;
}

static void bpf_net_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_net_driver_ops *ops = kdata;
	struct bpf_net_driver *drv = ops->priv;
	bool reopen;

	if (!drv)
		return;
	rtnl_lock();
	reopen = drv->alive && netif_running(drv->dev);
	if (reopen)
		dev_close(drv->dev);
	drv->attached = NULL;
	drv->revoked = false;
	drv->fallback_requested = false;
	ops->priv = NULL;
	if (reopen && !drv->quarantined)
		dev_open(drv->dev, NULL);
	rtnl_unlock();
	/* RTNL and napi_disable have drained every possible callback. */
	kref_put(&drv->ref, bpf_net_release);
}

static int bpf_net_stub_open(struct bpf_net_driver *drv)
{
	return 0;
}

static int bpf_net_stub_poll(struct bpf_net_driver *drv, int budget)
{
	return 0;
}

static int bpf_net_stub_xmit(struct bpf_net_driver *drv, u64 buffer)
{
	return 0;
}

static void bpf_net_stub_close(struct bpf_net_driver *drv)
{
}

static struct bpf_net_driver_ops bpf_net_cfi_stubs = {
	.open = bpf_net_stub_open,
	.poll = bpf_net_stub_poll,
	.xmit = bpf_net_stub_xmit,
	.close = bpf_net_stub_close,
};

static const struct bpf_verifier_ops bpf_net_verifier_ops = {
	.is_valid_access = bpf_tracing_btf_ctx_access,
};

static int bpf_net_btf_init(struct btf *btf)
{
	return 0;
}

static struct bpf_struct_ops bpf_bpf_net_driver_ops = {
	.verifier_ops = &bpf_net_verifier_ops,
	.init = bpf_net_btf_init,
	.check_member = bpf_net_driver_check_member,
	.init_member = bpf_net_init_member,
	.validate = bpf_net_validate,
	.reg = bpf_net_reg,
	.unreg = bpf_net_unreg,
	.cfi_stubs = &bpf_net_cfi_stubs,
	.name = "bpf_net_driver_ops",
	.owner = THIS_MODULE,
	.no_prog_composition = true,
};

static int __init bpf_net_driver_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_net_kfunc_set);
	return err ?: register_bpf_struct_ops(&bpf_bpf_net_driver_ops, bpf_net_driver_ops);
}
late_initcall(bpf_net_driver_init);
