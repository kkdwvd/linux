/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_NET_DRIVER_H
#define _LINUX_BPF_NET_DRIVER_H

#include <linux/netdevice.h>
#include <linux/types.h>

#define BPF_NET_DRIVER_RX 0
#define BPF_NET_DRIVER_TX 1
#define BPF_NET_DRIVER_BUFFERS 256
#define BPF_NET_DRIVER_RX_SIZE 2048
#define BPF_NET_DRIVER_PREFIX 16

struct bpf_net_driver;

/*
 * Callbacks execute serially for a device, with BH disabled. They must use
 * acyclic control flow and the bounded driver kfuncs. poll returns work
 * in [0, budget]. An error revokes the attachment and requests native recovery.
 * priv is initialized by the core and must be zero in the userspace image.
 */
struct bpf_net_driver_ops {
	int (*open)(struct bpf_net_driver *drv);
	int (*poll)(struct bpf_net_driver *drv, int budget);
	int (*xmit)(struct bpf_net_driver *drv, u64 buffer);
	void (*close)(struct bpf_net_driver *drv);
	u32 ifindex;
	struct bpf_net_driver *priv;
};

enum bpf_net_driver_buffer_state {
	BPF_NET_BUFFER_FREE,
	BPF_NET_BUFFER_CPU,
	BPF_NET_BUFFER_DEVICE,
};

/* Native-owned state: the kfunc API exposes checked IDs, not these records. */
struct bpf_net_driver_buffer {
	struct sk_buff *skb;
	u64 id;
	u32 capacity;
	u32 length;
	u32 offset;
	u32 submitted;
	unsigned long submitted_at;
	u8 state;
	u8 queue;
	bool completed;
	u8 prefix[BPF_NET_DRIVER_PREFIX];
};

/*
 * The backend owns the DMA mappings and physical descriptor rings. stop must
 * synchronously prove DMA quiescence before returning success. On failure the
 * core keeps all buffers quarantined. complete only returns submitted cookies,
 * NULL for an empty queue, or ERR_PTR for a fatal hardware error. rearm returns
 * true if completion raced with enabling interrupts and service is needed.
 * These methods run under the device callback lock, except start and stop.
 */
struct bpf_net_driver_backend {
	int (*start)(struct bpf_net_driver *drv);
	int (*stop)(struct bpf_net_driver *drv);
	int (*submit)(struct bpf_net_driver *drv, unsigned int queue,
		      struct bpf_net_driver_buffer *buffer);
	struct bpf_net_driver_buffer *(*complete)(struct bpf_net_driver *drv,
						unsigned int queue, u32 *length);
	void (*kick)(struct bpf_net_driver *drv, unsigned int queue);
	void (*mask)(struct bpf_net_driver *drv);
	bool (*rearm)(struct bpf_net_driver *drv);
	const struct bpf_net_driver_ops *native_ops;
};

struct bpf_net_driver *bpf_net_driver_create(struct net_device *dev,
				 const struct bpf_net_driver_backend *backend,
				 void *backend_private);
int bpf_net_driver_register(struct bpf_net_driver *drv);
void bpf_net_driver_destroy(struct bpf_net_driver *drv);
void *bpf_net_driver_private(struct bpf_net_driver *drv);
struct net_device *bpf_net_driver_netdev(struct bpf_net_driver *drv);
void bpf_net_driver_schedule(struct bpf_net_driver *drv);
void bpf_net_driver_error(struct bpf_net_driver *drv, int error);

/*
 * Buffer IDs are device-owned, generation-tagged capabilities. CPU access is
 * rejected while a buffer belongs to hardware or the networking stack.
 * TX stores address the private transport prefix; RX loads address DMA data.
 */
u64 bpf_net_buffer_alloc(struct bpf_net_driver *drv);
u32 bpf_net_buffer_length(struct bpf_net_driver *drv, u64 id);
u64 bpf_net_buffer_load(struct bpf_net_driver *drv, u64 id, u32 offset, u32 size);
int bpf_net_buffer_store(struct bpf_net_driver *drv, u64 id, u32 offset, u32 size, u64 value);
int bpf_net_buffer_release(struct bpf_net_driver *drv, u64 id);
int bpf_net_queue_submit(struct bpf_net_driver *drv, u64 id, u32 queue, u32 offset, u32 length);
u64 bpf_net_queue_complete(struct bpf_net_driver *drv, u32 queue);
int bpf_net_queue_kick(struct bpf_net_driver *drv, u32 queue);
int bpf_net_receive(struct bpf_net_driver *drv, u64 id, u32 offset, u32 length);

/* Internal to the built-in core and its verifier policy. */
struct bpf_prog;
struct bpf_func_proto;
struct btf_type;
struct btf_member;
bool bpf_net_driver_kfunc_allowed(u32 id);
int bpf_net_driver_check_member(const struct btf_type *t, const struct btf_member *member,
			      const struct bpf_prog *prog);

#endif
