/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __XDP_TCP_XSK_H
#define __XDP_TCP_XSK_H

/*
 * What the XDP TCP test program puts in front of each payload it hands to an
 * AF_XDP socket: the connection and the position in its stream. The consumer
 * finds it at the descriptor's address minus its size, and the payload at the
 * descriptor's address plus off: bpf_xdp_adjust_head() leaves at least an
 * Ethernet header's worth of bytes in a frame, so a payload shorter than that
 * keeps a tail of the headers in front of it.
 */
struct xdp_tcp_xsk_meta {
	__u64 cookie;	/* the socket's cookie */
	__u32 seq;	/* sequence number of the first byte */
	__u32 len;	/* bytes of payload */
	__u32 fin;	/* the peer's stream ends with them */
	__u32 off;	/* where the payload starts */
};

#endif
