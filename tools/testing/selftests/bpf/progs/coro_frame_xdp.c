// SPDX-License-Identifier: GPL-2.0
/*
 * Coroutine frames in the headroom of a packet. An XDP program gets its frame from
 * bpf_coro_frame_alloc_xdp(), keeps the packet with bpf_xdp_frame_steal() and parks the frame
 * with the packet in it. Whoever resumes or destroys the frame gives the packet up, and there
 * is no frame behind that. See prog_tests/coro_frame_xdp.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "coro_frame_xdp.h"

extern void *bpf_coro_frame_alloc_xdp(__u64 size, struct xdp_md *ctx) __ksym;

struct slot {
	struct bpf_coro_xdp __kptr *xdp;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_SLOTS);
	__type(key, __u32);
	__type(value, struct slot);
} slots SEC(".maps");

struct coro_obj {
	int data;
};

/* What the program does in this run, and with what */
int op;
int by[2];
__u32 slot;
/* what OP_PLACE returns: a buffer that is dropped is the next packet's at once */
int verdict = XDP_PASS;

/* frames in a packet, and second ones in the same packet */
__u64 got, got_again;
/* how far the packet begins behind its frame, and a frame behind the packet that is kept */
__s64 data_off, frame_off;
/* what moving the packet or its metadata returned */
__s64 moved[2];
/* the frame and the packet next to it are as they were written */
__u64 intact;
__u64 sum, parked, steal_failed, resumed, destroyed, sent;
int send_err;

#define PATTERN		0x1122334455667788ULL

/* What a compiler emits for a coroutine handle: the function is in the frame. */
static __always_inline void coro_call(void *coro, int slot)
{
	((void (*)(void *))((void **)coro)[slot])(coro);
}

#define coro_resume(coro)	coro_call(coro, 0)
#define coro_destroy(coro)	coro_call(coro, 1)

static __always_inline int place(struct xdp_md *ctx)
{
	__u64 *f, *g;

	f = bpf_coro_frame_alloc_xdp(FRAME_SIZE, ctx);
	if (!f)
		return XDP_DROP;
	got++;
	data_off = (long)(void *)(long)ctx->data - (long)f;
	f[0] = 1;
	f[7] = 2;
	/* the buffer lends once */
	g = bpf_coro_frame_alloc_xdp(FRAME_SIZE, ctx);
	if (g) {
		got_again++;
		g[0] = 100;
	}
	sum += f[0] + f[7];
	return verdict;
}

/* The headroom that the program has taken for the packet is no room for a frame */
static __always_inline int taken(struct xdp_md *ctx)
{
	__u64 *f;

	if (by[0])
		moved[0] = bpf_xdp_adjust_head(ctx, by[0]);
	if (by[1])
		moved[1] = bpf_xdp_adjust_meta(ctx, by[1]);
	f = bpf_coro_frame_alloc_xdp(FRAME_SIZE, ctx);
	if (!f)
		return XDP_PASS;
	got++;
	data_off = (long)(void *)(long)ctx->data - (long)f;
	f[7] = PATTERN;
	sum += f[7] == PATTERN;
	return XDP_PASS;
}

/* And what the frame has is no headroom for the packet, nor for its metadata */
static __always_inline int limit(struct xdp_md *ctx, bool meta)
{
	__u64 *f, *data, *data_end;

	f = bpf_coro_frame_alloc_xdp(FRAME_SIZE, ctx);
	if (!f)
		return XDP_DROP;
	got++;
	f[7] = PATTERN;
	if (meta) {
		moved[0] = bpf_xdp_adjust_meta(ctx, by[0]);
		moved[1] = bpf_xdp_adjust_meta(ctx, by[1]);
		data = (void *)(long)ctx->data_meta;
		data_end = (void *)(long)ctx->data;
	} else {
		moved[0] = bpf_xdp_adjust_head(ctx, by[0]);
		moved[1] = bpf_xdp_adjust_head(ctx, by[1]);
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
	}
	if (data + 1 > data_end)
		return XDP_DROP;
	data_off = (long)data - (long)f;
	/* the two are neighbours now, and neither writes into the other */
	*data = ~PATTERN;
	intact = f[7] == PATTERN;
	f[7] = PATTERN + 1;
	intact += *data == ~PATTERN;
	return XDP_PASS;
}

/*
 * The frame holds its packet and an object across the suspension. Each function drops the
 * object and gives the packet up last, and has no frame then: nothing is freed.
 */
static __noinline __used void destroy_fn(void *frame)
{
	__u64 *f = frame;

	destroyed += f[2];
	bpf_obj_drop((struct coro_obj *)f[4]);
	bpf_xdp_frame_release((struct xdp_frame *)f[3]);
}

static __noinline __used void resume_fn(void *frame)
{
	struct xdp_frame *p;
	__u64 *f = frame;

	resumed += f[2];
	p = (struct xdp_frame *)f[3];
	frame_off = (long)f - (long)p;
	bpf_obj_drop((struct coro_obj *)f[4]);
	bpf_xdp_frame_release(p);
}

/* The reply goes out of the buffer that the frame is in, as the last thing */
static __noinline __used void resume_sends(void *frame)
{
	__u64 *f = frame;

	bpf_obj_drop((struct coro_obj *)f[4]);
	sent += f[2];
	send_err = bpf_xdp_frame_xmit((struct xdp_frame *)f[3], 0);
}

/* The frames of a recursion that began */
unsigned long frames;

/* It calls itself until the stack has no room, which has the kernel unwind the program */
__naked __noinline __used
static unsigned long dives(void)
{
	asm volatile (
		"r1 = %[frames] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"*(u64 *)(r10 - 128) = r2;"
		"call dives;"
		"exit;"
		:
		: __imm_addr(frames)
		: __clobber_all
	);
}

/* The landing pad of the continuation has the object and the packet through the frame */
static __noinline __used void resume_dives(void *frame)
{
	__u64 *f = frame;

	dives();
	resumed += f[2];
	bpf_obj_drop((struct coro_obj *)f[4]);
	bpf_xdp_frame_release((struct xdp_frame *)f[3]);
}

static __always_inline int keep(struct bpf_coro_xdp *coro, __u32 idx)
{
	struct slot *s = bpf_map_lookup_elem(&slots, &idx);

	if (!s) {
		bpf_coro_drop_xdp(coro);
		return -1;
	}
	coro = bpf_kptr_xchg(&s->xdp, coro);
	if (coro)
		bpf_coro_drop_xdp(coro);
	return 0;
}

/* A frame in the packet, with the packet and an object in it. NULL: the packet is not kept. */
static __always_inline __u64 *new_frame(struct xdp_md *ctx, void *resume, int *ret)
{
	struct coro_obj *obj;
	struct xdp_frame *p;
	__u64 *f;

	*ret = XDP_DROP;
	f = bpf_coro_frame_alloc_xdp(FRAME_SIZE, ctx);
	if (!f)
		return NULL;
	got++;
	obj = bpf_obj_new(typeof(*obj));
	if (!obj)
		return NULL;
	p = bpf_xdp_frame_steal(ctx);
	if (!p) {
		steal_failed++;
		bpf_obj_drop(obj);
		*ret = XDP_PASS;
		return NULL;
	}
	f[0] = (__u64)resume;
	f[1] = (__u64)destroy_fn;
	f[2] = 1;
	f[3] = (__u64)p;
	f[4] = (__u64)obj;
	*ret = XDP_CONSUME;
	return f;
}

static __always_inline int park(struct xdp_md *ctx, void *resume)
{
	__u64 *f;
	int ret;

	f = new_frame(ctx, resume, &ret);
	if (!f)
		return ret;
	if (keep(bpf_coro_park_xdp(f), parked++ % NR_SLOTS))
		return XDP_ABORTED;
	return XDP_CONSUME;
}

/* The program is unwound with the frame: its landing pad gives the packet up */
static __always_inline int dive(struct xdp_md *ctx)
{
	__u64 *f;
	int ret;

	f = new_frame(ctx, resume_fn, &ret);
	if (!f)
		return ret;
	dives();
	bpf_obj_drop((struct coro_obj *)f[4]);
	bpf_xdp_frame_release((struct xdp_frame *)f[3]);
	return XDP_CONSUME;
}

static __always_inline int take(int what)
{
	struct bpf_coro_xdp *coro;
	__u32 idx = slot;
	struct slot *s;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return XDP_ABORTED;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return XDP_DROP;
	if (what == OP_RESUME)
		coro_resume(coro);
	else if (what == OP_DESTROY)
		coro_destroy(coro);
	else
		bpf_coro_drop_xdp(coro);
	return XDP_PASS;
}

SEC("xdp")
int handle(struct xdp_md *ctx)
{
	switch (op) {
	case OP_PLACE:
		return place(ctx);
	case OP_TAKEN:
		return taken(ctx);
	case OP_LIMIT_HEAD:
		return limit(ctx, false);
	case OP_LIMIT_META:
		return limit(ctx, true);
	case OP_PARK:
		return park(ctx, resume_fn);
	case OP_PARK_SENDS:
		return park(ctx, resume_sends);
	case OP_PARK_DIVES:
		return park(ctx, resume_dives);
	case OP_RESUME:
		return take(OP_RESUME);
	case OP_DESTROY:
		return take(OP_DESTROY);
	case OP_DROP:
		return take(OP_DROP);
	case OP_DIVE:
		return dive(ctx);
	}
	return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
