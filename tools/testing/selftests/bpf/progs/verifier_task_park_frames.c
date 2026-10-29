// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "bpf_experimental.h"
#include <errno.h>
#include "bpf_misc.h"

/* Where a bpf_task_park() may sit in the call graph, and what its callers lose. */
char _license[] SEC("license") = "GPL";

struct park_elem {
	__u32 state;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct park_elem);
} park_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct park_elem);
} hash_map SEC(".maps");

struct wq_elem {
	struct bpf_wq wq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

struct tw_elem {
	struct bpf_task_work tw;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tw_elem);
} tw_map SEC(".maps");

static __always_inline struct park_elem *lookup_hash_elem(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&hash_map, &key);
}

/* A static function is verified in its caller's state: the park sees every frame. */
static __noinline int park_static(void)
{
	return bpf_task_park(0, 0);
}

/* A global function is verified alone: its callers rely on the might_park mark. */
__noinline int park_global(void)
{
	return bpf_task_park(0, 0);
}

/* The mark reaches callers through further static and global functions. */
static __noinline int park_via_static(void)
{
	return park_global();
}

__noinline int park_via_global(void)
{
	return park_global();
}

/* A park in a function called directly from the main program is allowed. */
SEC("syscall")
__success __retval(0)
int park_in_static_subprog(void *ctx)
{
	return park_static() != -ETIMEDOUT;
}

SEC("syscall")
__success __retval(0)
int park_in_global_subprog(void *ctx)
{
	return park_global() != -ETIMEDOUT;
}

/* The caller's hash map value does not survive a park in its callee, static or global. */
SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int hash_value_after_static_subprog_park(void *ctx)
{
	struct park_elem *elem = lookup_hash_elem();

	if (!elem)
		return 0;
	park_static();
	return elem->state;
}

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int hash_value_after_global_subprog_park(void *ctx)
{
	struct park_elem *elem = lookup_hash_elem();

	if (!elem)
		return 0;
	park_global();
	return elem->state;
}

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int hash_value_after_nested_subprog_park(void *ctx)
{
	struct park_elem *elem = lookup_hash_elem();

	if (!elem)
		return 0;
	park_via_static();
	return elem->state;
}

/* A dynptr held by the caller is as live across a global call that parks as across the park. */
char dynptr_buf[8];

SEC("syscall")
__failure __msg("bpf_task_park() with a live dynptr at frame 0")
int dynptr_across_global_subprog_park(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &ptr);
	park_global();
	return 0;
}

SEC("syscall")
__failure __msg("bpf_task_park() with a live bits iterator at frame 0")
int bits_iterator_across_global_subprog_park(void *ctx)
{
	struct bpf_iter_bits it;
	__u64 word = 1;

	bpf_iter_bits_new(&it, &word, 1);
	park_global();
	bpf_iter_bits_destroy(&it);
	return 0;
}

/* No callback may park: not directly, not through a static or a global function. */
static int park_cb(__u32 index, void *data)
{
	bpf_task_park(0, 0);
	return 1;
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int park_in_loop_callback(void *ctx)
{
	bpf_loop(1, park_cb, NULL, 0);
	return 0;
}

static int park_static_cb(__u32 index, void *data)
{
	park_static();
	return 1;
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int static_subprog_park_in_callback(void *ctx)
{
	bpf_loop(1, park_static_cb, NULL, 0);
	return 0;
}

static int park_global_cb(__u32 index, void *data)
{
	park_global();
	return 1;
}

SEC("syscall")
__failure __msg("global function park_global() may call bpf_task_park(), "
		"which is not allowed in a callback")
int global_subprog_park_in_callback(void *ctx)
{
	bpf_loop(1, park_global_cb, NULL, 0);
	return 0;
}

static int park_via_global_cb(__u32 index, void *data)
{
	park_via_global();
	return 1;
}

SEC("syscall")
__failure __msg("global function park_via_global() may call bpf_task_park(), "
		"which is not allowed in a callback")
int nested_global_subprog_park_in_callback(void *ctx)
{
	bpf_loop(1, park_via_global_cb, NULL, 0);
	return 0;
}

static int park_for_each_cb(struct bpf_map *map, __u32 *key, struct park_elem *val, void *data)
{
	bpf_task_park(0, 0);
	return 1;
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int park_in_for_each_callback(void *ctx)
{
	bpf_for_each_map_elem(&park_map, park_for_each_cb, NULL, 0);
	return 0;
}

/* An asynchronous callback is verified as its own state, with the callback as frame 0. */
static int park_wq_cb(void *map, int *key, void *value)
{
	bpf_task_park(0, 0);
	return 0;
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int park_in_wq_callback(void *ctx)
{
	struct wq_elem *elem;
	__u32 key = 0;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return 0;
	if (bpf_wq_init(&elem->wq, &wq_map, 0))
		return 0;
	if (bpf_wq_set_callback(&elem->wq, park_wq_cb, 0))
		return 0;
	return bpf_wq_start(&elem->wq, 0);
}

static int park_task_work_cb(struct bpf_map *map, void *key, void *value)
{
	bpf_task_park(0, 0);
	return 0;
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int park_in_task_work_callback(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct tw_elem *elem;
	__u32 key = 0;

	elem = bpf_map_lookup_elem(&tw_map, &key);
	if (!elem)
		return 0;
	return bpf_task_work_schedule_signal(task, &elem->tw, &tw_map, park_task_work_cb);
}

/* The exception callback unwinds the program after bpf_throw(): no park there either. */
__noinline int park_exception_cb(u64 cookie)
{
	bpf_task_park(0, 0);
	return 0;
}

SEC("syscall")
__exception_cb(park_exception_cb)
__failure __msg("bpf_task_park() is not allowed in a callback")
int park_in_exception_callback(void *ctx)
{
	bpf_throw(0);
	return 0;
}
