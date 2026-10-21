/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARENA_DATA_PTRS_H
#define __ARENA_DATA_PTRS_H

struct ptr_node {
	long v;
	struct ptr_node __arena *next;
	long __arena *pv;
};

typedef int (*ptr_fn_t)(int);

/* like a vtable in arena: pointers to functions next to pointers to data */
struct ptr_ops {
	ptr_fn_t fn;
	struct ptr_node __arena *node;
	ptr_fn_t global_fn;
};

#endif
