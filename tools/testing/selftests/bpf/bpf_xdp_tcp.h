/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_XDP_TCP_H
#define __BPF_XDP_TCP_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <linux/errno.h>
#include "bpf_experimental.h"
#include "bpf_kfuncs.h"

/*
 * A thin socket interface over the TCP kfuncs, for XDP programs that serve
 * established connections. Documentation/bpf/xdp_tcp.rst says what it
 * bypasses and what it keeps.
 *
 * The in-order path is one kfunc call: bpf_xdp_tcp_sock_recv() finds the
 * connection and takes the segment under one socket lock section. Nothing
 * else runs unless a segment is out of order or the socket is busy, in which
 * case the program decides whether to hold the frame in connection state it
 * owns, a struct bpf_xdp_tcp_conn placed wherever it likes, or to pass the
 * segment to the stack.
 *
 * Nothing here locks on the program's behalf. The kernel keeps TCP state
 * consistent whatever the program does and delivers the bytes of a connection
 * in order and once; calls on one connection's state, and what the program
 * does with the payload, it serializes itself, by steering a flow to one CPU
 * or with a lock of its own.
 */

/* A transient handle: on the stack, zeroed, released on every path. */
struct bpf_xdp_tcp_sock {
	struct sock *__sk;
	struct bpf_xdp_tcp_info __info;
	struct xdp_frame *__frame;	/* the held frame bpf_xdp_tcp_sock_next() delivered */
	struct bpf_xdp_tcp_conn *__conn;	/* the reference came from here and goes back */
	bool __ack;			/* held frames were consumed: an ACK is due */
};

/*
 * Receive the segment. True with a live handle for a data segment of an
 * established connection; false, with no handle, for anything else. The
 * status, from enum bpf_xdp_tcp_status, says what became of the segment. On
 * BPF_XDP_TCP_RECEIVED the new bytes are the program's, through @payload for
 * as long as the packet lives, and the frame is the program's to drop,
 * redirect or send from. On
 * BPF_XDP_TCP_OUT_OF_ORDER and BPF_XDP_TCP_BUSY nothing was done: hold the
 * frame or pass it. A duplicate was acknowledged: drop it. BPF_XDP_TCP_PASS is
 * the stack's.
 */
static __always_inline bool bpf_xdp_tcp_sock_recv(struct xdp_md *ctx,
						  struct bpf_xdp_tcp_sock *sock,
						  struct bpf_dynptr *payload)
{
	struct bpf_xdp_tcp_info *info = &sock->__info;

	sock->__sk = bpf_xdp_tcp_recv(ctx, info);
	if (!sock->__sk)
		return false;
	/* Set up on every path, so that the verifier sees it initialized wherever it is used. */
	if (!bpf_dynptr_from_xdp(ctx, 0, payload))
		bpf_dynptr_adjust(payload, info->payload_off, info->payload_off + info->payload_len);
	return true;
}

static __always_inline __u32 bpf_xdp_tcp_sock_status(const struct bpf_xdp_tcp_sock *sock)
{
	return sock->__info.status;
}

static __always_inline __u32 bpf_xdp_tcp_sock_len(const struct bpf_xdp_tcp_sock *sock)
{
	return sock->__info.payload_len;
}

/* The sequence number of the payload's first byte. */
static __always_inline __u32 bpf_xdp_tcp_sock_seq(const struct bpf_xdp_tcp_sock *sock)
{
	return sock->__info.seq;
}

/* The bytes last received, if any, were the last of the peer's stream. */
static __always_inline bool bpf_xdp_tcp_sock_eof(const struct bpf_xdp_tcp_sock *sock)
{
	return sock->__info.flags & BPF_XDP_TCP_FIN;
}

/* The connection has SACKed data beyond the cursor: frames held for it may be due. */
static __always_inline bool bpf_xdp_tcp_sock_sacked(const struct bpf_xdp_tcp_sock *sock)
{
	return sock->__info.flags & BPF_XDP_TCP_SACKED;
}

/* A key for per-connection state, stable for the life of the socket. */
static __always_inline __u64 bpf_xdp_tcp_sock_cookie(const struct bpf_xdp_tcp_sock *sock)
{
	return sock->__info.cookie;
}

static __always_inline bool bpf_xdp_tcp_sock_closed(const struct bpf_xdp_tcp_sock *sock)
{
	return sock->__sk->__sk_common.skc_state == TCP_CLOSE || !sock->__sk->sk_socket;
}

/*
 * Copy an arena buffer to the TCP send queue. Returns len on success, or a
 * negative errno. In particular, -EAGAIN requires retaining the response and
 * retrying later; receiving does not reserve send-buffer space.
 */
static __always_inline int bpf_xdp_tcp_sock_send(struct bpf_xdp_tcp_sock *sock,
						 void __attribute__((address_space(1))) *buf,
						 __u32 len)
{
	return bpf_xdp_tcp_send(sock->__sk, buf, len);
}

/* Where the payload sits in the packet, for a reply written over it. */
static __always_inline __u32 bpf_xdp_tcp_sock_offset(const struct bpf_xdp_tcp_sock *sock)
{
	return sock->__info.payload_off;
}

/* Why the last frame send gave the frame back, or 0. */
static __always_inline int bpf_xdp_tcp_sock_error(const struct bpf_xdp_tcp_sock *sock)
{
	return sock->__info.error;
}

/*
 * Send the reply the program wrote into the packet, @len bytes at @off, from
 * the packet's own buffer: the frame is taken out of XDP and the segment is
 * built around it, with no copy. Grow the packet with bpf_xdp_adjust_tail()
 * first when the reply is longer than what arrived. The context is gone after
 * this call whatever the outcome. Return XDP_CONSUME, except after a NULL
 * return with -EOPNOTSUPP, when nothing was taken: return XDP_DROP then,
 * since XDP_CONSUME without a taken frame aborts. Returns NULL once the
 * reply is queued, or the frame when it could not be sent, with
 * bpf_xdp_tcp_sock_error() saying why: on -EAGAIN keep the frame, with a
 * reference from bpf_xdp_tcp_sock_acquire(), and retry it with
 * bpf_xdp_tcp_sock_resend(); otherwise release it. A NULL return with
 * -EOPNOTSUPP means the buffer was not a driver's and could not be taken:
 * generic XDP, whose replies go through bpf_xdp_tcp_sock_send().
 */
static __always_inline struct xdp_frame *
bpf_xdp_tcp_sock_send_frame(struct xdp_md *ctx, struct bpf_xdp_tcp_sock *sock, __u32 off,
			    __u32 len)
{
	struct xdp_frame *frame = bpf_xdp_frame_steal(ctx);

	if (!frame) {
		sock->__info.error = -EOPNOTSUPP;
		return NULL;
	}
	return bpf_xdp_tcp_send_frame(frame, sock->__sk, off, len, &sock->__info);
}

/* Try a kept reply again, on a handle for the same connection. Returns as above. */
static __always_inline struct xdp_frame *
bpf_xdp_tcp_sock_resend(struct bpf_xdp_tcp_sock *sock, struct xdp_frame *frame, __u32 off,
			__u32 len)
{
	return bpf_xdp_tcp_send_frame(frame, sock->__sk, off, len, &sock->__info);
}

/* A reference to the connection to keep in a kptr, for work outside this invocation. */
static __always_inline struct sock *bpf_xdp_tcp_sock_acquire(struct bpf_xdp_tcp_sock *sock)
{
	return bpf_xdp_tcp_acquire(sock->__sk);
}

/*
 * The in-order path in two steps, for a program that inspects a segment before
 * accepting it: lookup finds the connection of a segment the fast path would
 * take, payload exposes the bytes without consuming them, consume commits.
 * A failed consume leaves the segment to XDP_PASS; a successful one requires
 * XDP_DROP. Call consume at most once per packet.
 */
static __always_inline bool bpf_xdp_tcp_sock_lookup(struct xdp_md *ctx,
						    struct bpf_xdp_tcp_sock *sock)
{
	sock->__sk = bpf_xdp_tcp_lookup(ctx, &sock->__info);
	return sock->__sk != NULL;
}

static __always_inline int bpf_xdp_tcp_sock_payload(struct bpf_xdp_tcp_sock *sock,
						    struct xdp_md *ctx, struct bpf_dynptr *ptr)
{
	int err;

	err = bpf_dynptr_from_xdp(ctx, 0, ptr);
	if (err)
		return err;
	return bpf_dynptr_adjust(ptr, sock->__info.payload_off,
				 sock->__info.payload_off + sock->__info.payload_len);
}

static __always_inline int bpf_xdp_tcp_sock_consume(struct bpf_xdp_tcp_sock *sock,
						    struct xdp_md *ctx)
{
	return bpf_xdp_tcp_consume(sock->__sk, ctx, &sock->__info);
}

/*
 * Connection state for frames held across a hole or a busy socket. The program
 * owns it: a global for a single connection, a map value keyed by the cookie
 * for many, one per map value since the tree's lock has to be alone in it. A
 * bpf_timer next to it can drive retries, see bpf_xdp_tcp_sock_resume(). The
 * frames count against BPF_XDP_TCP_HOLD_MAX, not against the socket.
 */
#ifndef BPF_XDP_TCP_HOLD_MAX
#define BPF_XDP_TCP_HOLD_MAX 64
#endif

struct bpf_xdp_tcp_node {
	struct bpf_rb_node node;
	struct xdp_frame __kptr *frame;
	__u32 seq;
	__u32 end_seq;
};

struct bpf_xdp_tcp_conn {
	struct bpf_spin_lock lock;	/* the tree's, which the verifier requires */
	struct bpf_rb_root held __contains(bpf_xdp_tcp_node, node);
	struct sock __kptr *sk;		/* the connection, for retries from outside XDP */
	__u32 nr_held;
};

static __always_inline bool __bpf_xdp_tcp_before(__u32 a, __u32 b)
{
	return (__s32)(a - b) < 0;
}

/* By sequence number, the longer segment first among equals. */
static bool __bpf_xdp_tcp_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct bpf_xdp_tcp_node *na = container_of(a, struct bpf_xdp_tcp_node, node);
	struct bpf_xdp_tcp_node *nb = container_of(b, struct bpf_xdp_tcp_node, node);

	if (na->seq == nb->seq)
		return __bpf_xdp_tcp_before(nb->end_seq, na->end_seq);
	return __bpf_xdp_tcp_before(na->seq, nb->seq);
}

/* File a node, unless a held segment already covers it; D-SACK any overlap. */
static __always_inline void __bpf_xdp_tcp_file(struct bpf_xdp_tcp_sock *sock,
					       struct bpf_xdp_tcp_conn *conn,
					       struct bpf_xdp_tcp_node *n)
{
	__u32 dup_seq = 0, dup_end = 0;
	bool covered = false, overlap = false;
	struct bpf_rb_node *rb;
	int depth;

	bpf_spin_lock(&conn->lock);
	rb = bpf_rbtree_root(&conn->held);
	bpf_for(depth, 0, 64) {
		struct bpf_xdp_tcp_node *o;

		if (!rb)
			break;
		o = container_of(rb, struct bpf_xdp_tcp_node, node);
		if (__bpf_xdp_tcp_before(n->seq, o->end_seq) &&
		    __bpf_xdp_tcp_before(o->seq, n->end_seq)) {
			dup_seq = __bpf_xdp_tcp_before(n->seq, o->seq) ? o->seq : n->seq;
			dup_end = __bpf_xdp_tcp_before(n->end_seq, o->end_seq) ? n->end_seq : o->end_seq;
			overlap = true;
			if (!__bpf_xdp_tcp_before(n->seq, o->seq) &&
			    !__bpf_xdp_tcp_before(o->end_seq, n->end_seq)) {
				covered = true;
				break;
			}
		}
		if (__bpf_xdp_tcp_before(n->seq, o->seq) ||
		    (n->seq == o->seq && __bpf_xdp_tcp_before(o->end_seq, n->end_seq)))
			rb = bpf_rbtree_left(&conn->held, rb);
		else
			rb = bpf_rbtree_right(&conn->held, rb);
	}
	if (!covered) {
		bpf_rbtree_add(&conn->held, &n->node, __bpf_xdp_tcp_less);
		conn->nr_held++;
	}
	bpf_spin_unlock(&conn->lock);
	if (overlap)
		bpf_xdp_tcp_dup(sock->__sk, dup_seq, dup_end);
	if (covered)
		bpf_obj_drop(n);
}

/*
 * Take the frame of a segment recv() reported out of order or the socket busy
 * for, and hold it in @conn. Returns the XDP action to return once the handle
 * is released: XDP_CONSUME when the frame was taken, which includes a frame
 * dropped as a duplicate, over budget or outside the window, where the peer's
 * retransmission recovers; XDP_PASS when it could not be taken and stays the
 * stack's. The context is gone after this call. The first hold keeps a
 * reference to the connection in @conn, for retries from a timer.
 */
static __always_inline int bpf_xdp_tcp_sock_hold(struct xdp_md *ctx, struct bpf_xdp_tcp_sock *sock,
						 struct bpf_xdp_tcp_conn *conn)
{
	struct bpf_xdp_tcp_node *n;
	struct xdp_frame *frame;
	struct sock *ref;
	int err;

	frame = bpf_xdp_frame_steal(ctx);
	if (!frame)
		return XDP_PASS;
	if (conn->nr_held >= BPF_XDP_TCP_HOLD_MAX)
		goto drop;
	/* The node first: a frame dropped unadmitted is one the peer still has to send. */
	n = bpf_obj_new(typeof(*n));
	if (!n)
		goto drop;
	/* Busy now: admitted on the next attempt, see bpf_xdp_tcp_sock_next(). */
	err = bpf_xdp_tcp_hold(sock->__sk, frame);
	if (err && err != -EAGAIN) {
		bpf_obj_drop(n);
		goto drop;
	}
	n->seq = sock->__info.seq;
	n->end_seq = sock->__info.end_seq;
	frame = bpf_kptr_xchg(&n->frame, frame);
	if (frame)
		bpf_xdp_frame_release(frame);
	__bpf_xdp_tcp_file(sock, conn, n);
	if (!conn->sk) {
		ref = bpf_xdp_tcp_acquire(sock->__sk);
		if (ref) {
			ref = bpf_kptr_xchg(&conn->sk, ref);
			if (ref)
				bpf_xdp_tcp_release(ref);
		}
	}
	return XDP_CONSUME;
drop:
	bpf_xdp_frame_release(frame);
	return XDP_CONSUME;
}

/*
 * Deliver the next held segment whose turn has come, one per call. Returns
 * the number of new bytes, with @payload over them for as long as the handle
 * holds the frame, that is until the next call or the release; 0 when nothing
 * is due now, because no frame is held, a hole remains before the first, or
 * the socket is busy; or a negative error. A FIN delivered this way sets
 * bpf_xdp_tcp_sock_eof(). Call after a receive while frames are held, and
 * from a retry when the socket was busy.
 */
static __always_inline int bpf_xdp_tcp_sock_next(struct bpf_xdp_tcp_sock *sock,
						 struct bpf_xdp_tcp_conn *conn,
						 struct bpf_dynptr *payload)
{
	int i;

	if (sock->__frame) {
		bpf_xdp_frame_release(sock->__frame);
		sock->__frame = NULL;
	}
	bpf_for(i, 0, BPF_XDP_TCP_HOLD_MAX) {
		struct bpf_xdp_tcp_node *n;
		struct bpf_rb_node *rb;
		struct xdp_frame *frame;
		int err;

		bpf_spin_lock(&conn->lock);
		rb = bpf_rbtree_first(&conn->held);
		if (rb) {
			rb = bpf_rbtree_remove(&conn->held, rb);
			conn->nr_held--;
		}
		bpf_spin_unlock(&conn->lock);
		if (!rb)
			return 0;
		n = container_of(rb, struct bpf_xdp_tcp_node, node);
		frame = bpf_kptr_xchg(&n->frame, NULL);
		if (!frame) {
			bpf_obj_drop(n);
			continue;
		}
		err = bpf_xdp_tcp_hold(sock->__sk, frame);
		if (!err)
			err = bpf_xdp_tcp_consume_frame(sock->__sk, frame, &sock->__info);
		if (err == -EAGAIN || err == -ENODATA) {
			/* Not yet: back it goes, under the same keys. */
			frame = bpf_kptr_xchg(&n->frame, frame);
			if (frame)
				bpf_xdp_frame_release(frame);
			bpf_spin_lock(&conn->lock);
			bpf_rbtree_add(&conn->held, &n->node, __bpf_xdp_tcp_less);
			conn->nr_held++;
			bpf_spin_unlock(&conn->lock);
			return 0;
		}
		bpf_obj_drop(n);
		if (err) {
			bpf_xdp_frame_release(frame);
			if (err == -EALREADY)
				continue;
			/* Known negative, so that a caller's check on the count can trust it. */
			return err < 0 ? err : -EINVAL;
		}
		sock->__frame = frame;
		sock->__ack = true;
		if (bpf_dynptr_from_xdp_frame(frame, 0, payload) ||
		    bpf_dynptr_adjust(payload, sock->__info.payload_off,
				      sock->__info.payload_off + sock->__info.payload_len))
			return -EFAULT;
		return sock->__info.payload_len;
	}
	return 0;
}

/* Give every held frame back and forget the SACK state that advertised them. */
static __always_inline int bpf_xdp_tcp_sock_purge(struct bpf_xdp_tcp_sock *sock,
						  struct bpf_xdp_tcp_conn *conn)
{
	int i, err;

	err = bpf_xdp_tcp_ooo_reset(sock->__sk);
	if (err)
		return err;
	bpf_for(i, 0, BPF_XDP_TCP_HOLD_MAX) {
		struct bpf_rb_node *rb;

		bpf_spin_lock(&conn->lock);
		rb = bpf_rbtree_first(&conn->held);
		if (rb) {
			rb = bpf_rbtree_remove(&conn->held, rb);
			conn->nr_held--;
		}
		bpf_spin_unlock(&conn->lock);
		if (!rb)
			break;
		bpf_obj_drop(container_of(rb, struct bpf_xdp_tcp_node, node));
	}
	return 0;
}

/*
 * A handle on the connection whose frames @conn holds, outside XDP: from a
 * timer, to retry held frames once the socket is free, or to find out that
 * the connection is closed. False when @conn has no connection. Release the
 * handle as any other; the reference goes back into @conn.
 */
static __always_inline bool bpf_xdp_tcp_sock_resume(struct bpf_xdp_tcp_conn *conn,
						    struct bpf_xdp_tcp_sock *sock)
{
	struct sock *sk = bpf_kptr_xchg(&conn->sk, NULL);

	if (!sk)
		return false;
	sock->__sk = sk;
	sock->__conn = conn;
	return true;
}

/* Let the connection go and give its frames back: for a closed connection. */
static __always_inline void bpf_xdp_tcp_conn_destroy(struct bpf_xdp_tcp_conn *conn)
{
	struct sock *sk = bpf_kptr_xchg(&conn->sk, NULL);
	int i;

	if (sk)
		bpf_xdp_tcp_release(sk);
	bpf_for(i, 0, BPF_XDP_TCP_HOLD_MAX) {
		struct bpf_rb_node *rb;

		bpf_spin_lock(&conn->lock);
		rb = bpf_rbtree_first(&conn->held);
		if (rb) {
			rb = bpf_rbtree_remove(&conn->held, rb);
			conn->nr_held--;
		}
		bpf_spin_unlock(&conn->lock);
		if (!rb)
			break;
		bpf_obj_drop(container_of(rb, struct bpf_xdp_tcp_node, node));
	}
}

/*
 * Release the handle on every path after a successful receive, lookup or
 * resume. Releasing does not close the connection: it gives back a frame
 * still delivered, sends the ACK a batch of held frames calls for, and drops
 * or returns the connection reference.
 */
static __always_inline void bpf_xdp_tcp_sock_release(struct bpf_xdp_tcp_sock *sock)
{
	struct sock *old;

	if (sock->__frame) {
		bpf_xdp_frame_release(sock->__frame);
		sock->__frame = NULL;
	}
	if (!sock->__sk)
		return;
	if (sock->__ack)
		bpf_xdp_tcp_ack_pending(sock->__sk);
	if (sock->__conn) {
		old = bpf_kptr_xchg(&sock->__conn->sk, sock->__sk);
		if (old)
			bpf_xdp_tcp_release(old);
	} else {
		bpf_xdp_tcp_release(sock->__sk);
	}
	sock->__sk = NULL;
}

#endif /* __BPF_XDP_TCP_H */
