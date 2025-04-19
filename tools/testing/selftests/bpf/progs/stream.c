// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 100); /* number of pages */
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32); /* start of mmap() region */
#else
	__ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
#endif
} arena SEC(".maps");

struct arr_elem {
	struct bpf_res_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct arr_elem);
} arrmap SEC(".maps");

/*
#define _STR "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

#define STREAM_STR (u64)(_STR _STR _STR _STR)

static __noinline int stream_exercise(int id, int N)
{
	struct bpf_stream_elem *elem, *earr[56] = {};
	struct bpf_stream *stream;
	int ret;
	u32 i;

	if (N > 56)
		return 56;

	stream = bpf_stream_get(id, NULL);
	if (!stream)
		return 1;
	for (i = 0; i < N; i++)
		if ((ret = bpf_stream_vprintk(stream, "%llu%s", &(u64[]){i, STREAM_STR}, 16)) < 0) {
			bpf_printk("bpf_stream_vprintk ret=%d", ret);
			return 2;
		}
	ret = 0;
	for (i = 0; i < N; i++) {
		elem = bpf_stream_next_elem(stream);
		if (!elem) {
			ret = 4;
			break;
		}
		earr[i] = elem;
	}
	elem = bpf_stream_next_elem(stream);
	if (elem) {
		bpf_stream_free_elem(elem);
		ret = 5;
	}
	for (i = 0; i < N; i++)
		if (earr[i])
			bpf_stream_free_elem(earr[i]);
	return ret;
}

static __noinline int stream_exercise_nums(int id)
{
	int ret = 0;

	ret = ret ?: stream_exercise(id, 56);
	ret = ret ?: stream_exercise(id, 42);
	ret = ret ?: stream_exercise(id, 28);
	ret = ret ?: stream_exercise(id, 10);
	ret = ret ?: stream_exercise(id, 1);

	return ret;
}

SEC("syscall")
__success __retval(0)
int stream_test(void *ctx)
{
	unsigned long flags;
	int ret;

	bpf_local_irq_save(&flags);
	bpf_repeat(50) {
		ret = stream_exercise_nums(BPF_STDOUT);
		if (ret)
			break;
	}
	if (ret) {
		bpf_local_irq_restore(&flags);
		return ret;
	}
	bpf_repeat(100) {
		ret = stream_exercise_nums(BPF_STDERR);
		if (ret)
			break;
	}
	bpf_local_irq_restore(&flags);

	if (ret)
		return ret;

	ret = stream_exercise_nums(BPF_STDOUT);
	if (ret)
		return ret;
	return stream_exercise_nums(BPF_STDERR);
}

SEC("syscall")
__success __retval(0)
int stream_test_output(void *ctx)
{
	for (int i = 0; i < 1000; i++)
		bpf_stream_printk(BPF_STDOUT, "num=%d\n", i);
	return 0;
}

SEC("syscall")
__success __retval(0)
int stream_test_limit(void *ctx)
{
	struct bpf_stream *stream;
	bool failed = false;

	stream = bpf_stream_get(BPF_STDOUT, NULL);
	if (!stream)
		return 2;

	bpf_repeat(BPF_MAX_LOOPS) {
		failed = bpf_stream_vprintk(stream, "%s%s%s", &(u64[]){STREAM_STR, STREAM_STR}, 16) != 0;
		if (failed)
			break;
	}

	if (failed)
		return 0;
	return 1;
}
*/

SEC("syscall")
__success __retval(0)
int stream_cond_break(void *ctx)
{
	while (can_loop)
		;
	return 0;
}

SEC("syscall")
__success __retval(0)
int stream_deadlock(void *ctx)
{
	struct bpf_res_spin_lock *lock, *nlock;

	lock = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!lock)
		return 0;
	nlock = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!nlock)
		return 0;
	if (bpf_res_spin_lock(lock))
		return 0;
	if (bpf_res_spin_lock(nlock)) {
		bpf_res_spin_unlock(lock);
		return 0;
	}
	bpf_res_spin_unlock(nlock);
	bpf_res_spin_unlock(lock);
	return 0;
}

#define __arena __attribute__((address_space(1)))
u64 __arena *ptr = (u64 __arena*)0xdeadbeef;

SEC("syscall")
__success __retval(0)
int stream_arena_read(void *ctx)
{
	/* Silence addr_space_cast insn only usable in program with arena error. */
	if (ctx)
		return (long)&arena;
	return *ptr;
}

SEC("syscall")
__success __retval(0)
int stream_arena_write(void *ctx)
{
	/* Silence addr_space_cast insn only usable in program with arena error. */
	if (ctx)
		return (long)&arena;
	*ptr = 0xfaceb00c;
	return 0;
}

SEC("syscall")
__success __retval(0)
int stream_syscall(void *ctx)
{
	bpf_stream_printk(BPF_STDOUT, "foo");
	return 0;
}

char _license[] SEC("license") = "GPL";
