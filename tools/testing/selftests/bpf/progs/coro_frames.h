/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CORO_FRAMES_H
#define __CORO_FRAMES_H

/*
 * How many frames of a size class a CPU keeps at first, and how many more wait beside those
 * before the kernel looks: BPF_CORO_CACHE_MIN and BPF_CORO_CACHE_BATCH of kernel/bpf/coro.c.
 */
#define CACHE_FRAMES	64
/* frames for both, the one that is too many, and some more */
#define NR_SLOTS	(2 * CACHE_FRAMES + 8)
#define NR_MANY		8192
/* the size of the frames of OP_FILL, which are in the size class of that many bytes */
#define MANY_SIZE	488
#define MANY_CLASS	512

/* What the program does in a run, see progs/coro_frames.c */
enum coro_frames_op {
	OP_PARK,	/* frames of 48 bytes in slots[from, to), their addresses in addr[] */
	OP_DESTROY,	/* destroy the frames in slots[from, to) */
	OP_PAIR_48,	/* allocate a frame of 48 bytes, note where it is in last, and free it */
	OP_PAIR_64,	/* one of 64 bytes, which is of the same size class */
	OP_PAIR_200,	/* one of 200 bytes, which is of another one */
	OP_PAIR_ANY,	/* 48 and 200 bytes, in last and other, by one call for both */
	OP_PARK_ALLOCS,	/* in slots[from], a frame whose destroy function allocates one */
	OP_FILL,	/* frames of MANY_SIZE bytes in many[from, to) */
};

/* The contexts that progs/coro_frames_count.c tells apart */
enum coro_frames_where {
	CTX_TASK,
	CTX_SOFTIRQ,
	CTX_HARDIRQ,
	CTX_NMI,
	NR_CTX,
};

#endif
