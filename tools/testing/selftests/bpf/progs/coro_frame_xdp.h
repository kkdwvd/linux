/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CORO_FRAME_XDP_H
#define __CORO_FRAME_XDP_H

/* The size of the frames, and how many parked ones the program has room for */
#define FRAME_SIZE	64
#define NR_SLOTS	8

/* What the program does in a run, see progs/coro_frame_xdp.c */
enum coro_frame_xdp_op {
	OP_PLACE,	/* a frame in the packet, and a second one, which there is none of */
	OP_TAKEN,	/* move the packet and its metadata by by[0] and by[1], then a frame */
	OP_LIMIT_HEAD,	/* a frame, then move the packet by by[0], and by by[1] */
	OP_LIMIT_META,	/* a frame, then move the metadata by by[0], and by by[1] */
	OP_PARK,	/* park a frame with its packet, in the next slot */
	OP_PARK_SENDS,	/* one whose continuation sends the packet */
	OP_PARK_DIVES,	/* one whose continuation the kernel unwinds */
	OP_RESUME,	/* resume the frame of slot 'slot' */
	OP_DESTROY,	/* destroy it */
	OP_DROP,	/* have the kernel destroy it */
	OP_DIVE,	/* a frame with its packet, and then the kernel unwinds the program */
};

#endif
