/* SPDX-License-Identifier: GPL-2.0 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf_arena_common.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE | BPF_F_NO_USER_CONV);
	__uint(max_entries, 1);
} arena SEC(".maps");

u32 __arena rx_posted;

#ifdef BPF_NET_DRIVER_RUN
#define fault_mode 0
#define count_stat(...) do { } while (0)
#else
u64 __arena opens;
u64 __arena polls;
u64 __arena transmitted;
u64 __arena received;
u64 __arena completed;
u64 __arena closes;
volatile u32 __arena fault_mode;
#define count_stat(name) ((name)++)
#endif

u64 bpf_net_buffer_alloc(struct bpf_net_driver *drv) __ksym;
u32 bpf_net_buffer_length(struct bpf_net_driver *drv, u64 id) __ksym;
u64 bpf_net_buffer_load(struct bpf_net_driver *drv, u64 id, u32 offset, u32 size) __ksym;
int bpf_net_buffer_store(struct bpf_net_driver *drv, u64 id, u32 offset, u32 size,
			 u64 value) __ksym;
int bpf_net_buffer_release(struct bpf_net_driver *drv, u64 id) __ksym;
int bpf_net_queue_submit(struct bpf_net_driver *drv, u64 id, u32 queue, u32 offset,
			 u32 length) __ksym;
u64 bpf_net_queue_complete(struct bpf_net_driver *drv, u32 queue) __ksym;
int bpf_net_queue_kick(struct bpf_net_driver *drv, u32 queue) __ksym;
int bpf_net_receive(struct bpf_net_driver *drv, u64 id, u32 offset, u32 length) __ksym;

#define RX 0
#define TX 1
#define RX_SIZE 2048
#define RX_DEPTH 32
#ifdef BPF_NET_MLX5
#define HDR_SIZE 0
#else
#define HDR_SIZE 12
#endif
#define POLL_MAX 64

/*
 * Spell out the callback's finite work bound. Compiler-directed loop unrolling
 * is not reliable when an iteration contains several external kfunc calls.
 */
#define REPEAT_2(statement) do { statement; statement; } while (0)
#define REPEAT_4(statement) do { REPEAT_2(statement); REPEAT_2(statement); } while (0)
#define REPEAT_8(statement) do { REPEAT_4(statement); REPEAT_4(statement); } while (0)
#define REPEAT_16(statement) do { REPEAT_8(statement); REPEAT_8(statement); } while (0)
#define REPEAT_32(statement) do { REPEAT_16(statement); REPEAT_16(statement); } while (0)
#define REPEAT_64(statement) do { REPEAT_32(statement); REPEAT_32(statement); } while (0)

static __always_inline bool refill_one(struct bpf_net_driver *drv)
{
	u64 id;

	if (rx_posted >= RX_DEPTH)
		return false;
	id = bpf_net_buffer_alloc(drv);
	if (!id)
		return false;
	if (bpf_net_queue_submit(drv, id, RX, 0, RX_SIZE)) {
		bpf_net_buffer_release(drv, id);
		return false;
	}
	rx_posted++;
	return true;
}

static __always_inline void refill(struct bpf_net_driver *drv)
{
	REPEAT_32({
		if (!refill_one(drv))
			goto done;
	});
done:
	bpf_net_queue_kick(drv, RX);
}

static __always_inline bool complete_tx(struct bpf_net_driver *drv)
{
	u64 id = bpf_net_queue_complete(drv, TX);

	if (!id)
		return false;
	if (fault_mode != 7)
		bpf_net_buffer_release(drv, id);
	count_stat(completed);
	return true;
}

static __always_inline bool complete_rx(struct bpf_net_driver *drv)
{
	u64 id = bpf_net_queue_complete(drv, RX);
	u32 len;

	if (!id)
		return false;
	if (rx_posted)
		rx_posted--;
	len = bpf_net_buffer_length(drv, id);
	if (len < HDR_SIZE + 14)
		goto drop;
#ifndef BPF_NET_MLX5
	if (bpf_net_buffer_load(drv, id, 0, 2))
		goto drop;
#endif
	if (!bpf_net_receive(drv, id, HDR_SIZE, len - HDR_SIZE))
		count_stat(received);
	return true;
drop:
	bpf_net_buffer_release(drv, id);
	return true;
}

SEC("struct_ops/open")
int BPF_PROG(bvnet_open, struct bpf_net_driver *drv)
{
	count_stat(opens);
	rx_posted = 0;
	refill(drv);
	return 0;
}

SEC("struct_ops/poll")
int BPF_PROG(bvnet_poll, struct bpf_net_driver *drv, int budget)
{
	int tx = 0, rx = 0;

	count_stat(polls);
	if (fault_mode == 5)
		return budget + 1;
	if (fault_mode == 6)
		return 0;
	REPEAT_64({
		if (!complete_tx(drv))
			goto tx_done;
		tx++;
	});
tx_done:
	if (!budget)
		return 0;
	REPEAT_64({
		if (rx >= budget || !complete_rx(drv))
			goto rx_done;
		rx++;
	});
rx_done:
	refill(drv);
	return tx == POLL_MAX ? budget : rx;
}

SEC("struct_ops/xmit")
int BPF_PROG(bvnet_xmit, struct bpf_net_driver *drv, u64 id)
{
	u32 len = bpf_net_buffer_length(drv, id);
	int err;

	count_stat(transmitted);
	if (fault_mode == 1) {
		bpf_net_buffer_release(drv, id ^ (1ULL << 32));
		bpf_net_buffer_release(drv, id);
		return 0;
	}
	if (fault_mode == 2) {
		bpf_net_buffer_store(drv, id, 16, 8, 0);
		bpf_net_buffer_release(drv, id);
		return 0;
	}
	if (fault_mode == 4)
		return 0;
#ifdef BPF_NET_MLX5
	/*
	 * SEND opcode and completion request in a mlx5 control segment template.
	 * The backend validates it and supplies the protected WQE index, queue
	 * number and DMA segments. Stores emit least-significant byte first;
	 * these bytes are not part of the packet.
	 */
	bpf_net_buffer_store(drv, id, 0, 8, 0x0a000000ULL);
	bpf_net_buffer_store(drv, id, 8, 8, 0x08000000ULL);
#else
	bpf_net_buffer_store(drv, id, 0, 8, 0);
	bpf_net_buffer_store(drv, id, 8, 4, 0);
#endif
	err = bpf_net_queue_submit(drv, id, TX, HDR_SIZE, len);
	if (err) {
		bpf_net_buffer_release(drv, id);
	} else {
		if (fault_mode == 3)
			bpf_net_queue_submit(drv, id, TX, HDR_SIZE, len);
		bpf_net_queue_kick(drv, TX);
	}
	return 0;
}

SEC("struct_ops/close")
void BPF_PROG(bvnet_close, struct bpf_net_driver *drv)
{
	count_stat(closes);
	rx_posted = 0;
}

SEC(".struct_ops.link")
struct bpf_net_driver_ops bvnet = {
	.open = (void *)bvnet_open,
	.poll = (void *)bvnet_poll,
	.xmit = (void *)bvnet_xmit,
	.close = (void *)bvnet_close,
};

char LICENSE[] SEC("license") = "GPL";
