/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CORO_PARK_H
#define __CORO_PARK_H

/* What the program that parks the frames does in a run, see progs/coro_park.c */
enum coro_park_op {
	OP_PARK,	/* a frame for an XDP program in slot 0, one for a syscall program in slot 1 */
	OP_PARK_AGAIN,	/* one whose continuation parks it again, in slot 0 */
	OP_PARK_NODES,	/* three in the nodes of the tree, three in those of the list */
	OP_PARK_DIVES,	/* as OP_PARK, with continuations that the kernel unwinds */
	OP_RESUME,	/* resume its own frame of slot 0 */
	OP_PARK_HASH,	/* two in the hash map, one of them in an element that is deleted */
	OP_PARK_CARRIERS, /* two that carry another frame each, in slots 2 and 3 */
};

/* What the syscall program that parks does in a run, see progs/coro_park_sys.c */
enum coro_park_sys_op {
	SYS_PARK,	/* a frame for an XDP program */
	SYS_PARK_SYS,	/* a frame for a syscall program */
	SYS_RESUME_SYS,	/* resume it */
	SYS_WQ,		/* start a bpf_wq whose callback holds the frame of SYS_PARK for a while */
};

#endif
