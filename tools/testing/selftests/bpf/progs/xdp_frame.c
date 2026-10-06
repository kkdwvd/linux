// SPDX-License-Identifier: GPL-2.0
/*
 * Frames a program keeps. The XDP program stamps a sequence number into each
 * frame it is given, takes the frame and files it in an rbtree node that holds
 * the frame as a kptr and the number as its key. A syscall program drains the
 * tree in order, reads and writes the payload through a dynptr, and gives the
 * frames back; what it leaves in the tree is returned by the frame's
 * destructor when the tree goes.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_misc.h"

#define NR_FRAMES	16
#define REC_DATA	64
#define SEQ_OFF		14	/* the stamp goes right after the Ethernet header */
#define MARK_OFF	(REC_DATA - 4)

struct frame_rec {
	__u32 seq;
	__u32 len;
	int read_err;
	int bad_read_err;
	int write_err;
	__u8 data[REC_DATA];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_FRAMES);
	__type(key, __u32);
	__type(value, struct frame_rec);
} recs SEC(".maps");

struct frame_node {
	struct bpf_rb_node node;
	struct xdp_frame __kptr *frame;
	__u32 seq;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock lock;
private(A) struct bpf_rb_root held __contains(frame_node, node);

__u32 stamped;
__u64 stolen, steal_failed, drained, released;
__u32 drain_max;	/* 0: everything; otherwise leave the rest to the destructor */

static bool seq_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct frame_node *na = container_of(a, struct frame_node, node);
	struct frame_node *nb = container_of(b, struct frame_node, node);

	return na->seq < nb->seq;
}

SEC("xdp")
int xdp_frame_steal(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *data_end = (void *)(long)ctx->data_end;
	struct frame_node *n;
	struct xdp_frame *f;
	__u32 *p, i, seq;

	/* Frames arrive in a scrambled order and come out of the tree sorted. */
	p = data + SEQ_OFF;
	if (p + 1 > data_end)
		return XDP_DROP;
	i = stamped++;
	seq = (i * 7) % NR_FRAMES;
	*p = seq;

	f = bpf_xdp_frame_steal(ctx);
	if (!f) {
		steal_failed++;
		return XDP_PASS;
	}
	stolen++;
	n = bpf_obj_new(typeof(*n));
	if (!n) {
		bpf_xdp_frame_release(f);
		return XDP_CONSUME;
	}
	n->seq = seq;
	f = bpf_kptr_xchg(&n->frame, f);
	if (f)
		bpf_xdp_frame_release(f);
	bpf_spin_lock(&lock);
	bpf_rbtree_add(&held, &n->node, seq_less);
	bpf_spin_unlock(&lock);
	return XDP_CONSUME;
}

SEC("syscall")
int xdp_frame_drain(void *ctx)
{
	__u32 i;

	bpf_for(i, 0, NR_FRAMES) {
		struct frame_rec *rec;
		struct bpf_rb_node *rb;
		struct frame_node *n;
		struct bpf_dynptr ptr;
		struct xdp_frame *f;
		__u32 seq = 0, len;

		if (drain_max && i >= drain_max)
			break;
		bpf_spin_lock(&lock);
		rb = bpf_rbtree_first(&held);
		if (rb)
			rb = bpf_rbtree_remove(&held, rb);
		bpf_spin_unlock(&lock);
		if (!rb)
			break;
		n = container_of(rb, struct frame_node, node);
		f = bpf_kptr_xchg(&n->frame, NULL);
		bpf_obj_drop(n);
		if (!f)
			break;
		drained++;
		if (bpf_dynptr_from_xdp_frame(f, 0, &ptr)) {
			bpf_xdp_frame_release(f);
			continue;
		}
		len = bpf_dynptr_size(&ptr);
		bpf_dynptr_read(&seq, sizeof(seq), &ptr, SEQ_OFF, 0);
		rec = bpf_map_lookup_elem(&recs, &i);
		if (rec) {
			rec->seq = seq;
			rec->len = len;
			/* The frame is the program's: it may write to it. */
			rec->write_err = bpf_dynptr_write(&ptr, MARK_OFF, &seq, sizeof(seq), 0);
			rec->read_err = bpf_dynptr_read(rec->data, REC_DATA, &ptr, 0, 0);
			/* One byte past the end is not within the frame. */
			rec->bad_read_err = bpf_dynptr_read(rec->data, 1, &ptr, len, 0);
		}
		bpf_xdp_frame_release(f);
		released++;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
