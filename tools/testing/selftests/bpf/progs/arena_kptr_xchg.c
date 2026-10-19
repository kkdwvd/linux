// SPDX-License-Identifier: GPL-2.0

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include <bpf_arena_common.h>

struct task_struct *bpf_task_acquire(struct task_struct *task) __ksym;
void bpf_task_release(struct task_struct *task) __ksym;

#ifdef __TARGET_ARCH_arm64
#define ARENA_START ((1ull << 32) + 0x100000)
#else
#define ARENA_START ((1ull << 44) + 0x100000)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE | BPF_F_NO_USER_CONV);
	__uint(max_entries, 4);
	__ulong(map_extra, ARENA_START);
} arena SEC(".maps");

struct task_slot {
	struct task_struct __kptr *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct task_slot);
} native_slots SEC(".maps");

#define __arena_kptr(type) __attribute__((btf_decl_tag("bpf_arena_kptr:" #type)))

/* Force a scalar reload instead of propagating the arena pointer's type. */
volatile u64 scalar_slot;

SEC("syscall")
__arch_x86_64 __arch_arm64 __load_if_JITed() __arena_kptr(task_struct)
__description("arena kptr: replace, take, and take an empty slot")
__success __retval(0)
int arena_kptr_roundtrip(void *ctx)
{
	struct task_slot __arena *slot;
	struct task_struct *task, *old;
	int pid, ret = 0;

	slot = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!slot)
		return 1;
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task) {
		ret = 2;
		goto out;
	}
	pid = task->pid;
	old = bpf_kptr_xchg((void *)&slot->task, task);
	if (old) {
		bpf_task_release(old);
		ret = 3;
		goto drain;
	}
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task) {
		ret = 4;
		goto drain;
	}
	old = bpf_kptr_xchg((void *)&slot->task, task);
	if (!old) {
		ret = 5;
		goto drain;
	}
	if (old->pid != pid)
		ret = 6;
	bpf_task_release(old);
drain:
	old = bpf_kptr_xchg((void *)&slot->task, NULL);
	if (old) {
		if (old->pid != pid)
			ret = 7;
		bpf_task_release(old);
	} else if (!ret) {
		ret = 8;
	}
	old = bpf_kptr_xchg((void *)&slot->task, NULL);
	if (old) {
		bpf_task_release(old);
		ret = 9;
	}
out:
	bpf_arena_free_pages(&arena, slot, 1);
	return ret;
}

SEC("syscall")
__arch_x86_64 __arch_arm64 __load_if_JITed() __arena_kptr(task_struct)
__flag(BPF_F_ARENA_SCALAR)
__description("arena kptr: scalar destination with no user conversion")
__success __retval(0)
int arena_kptr_scalar(void *ctx)
{
	struct task_slot __arena *slot;
	struct task_struct *task, *old;
	int ret = 0;

	slot = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!slot)
		return 1;
	scalar_slot = (u64)slot;
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task) {
		ret = 2;
		goto out;
	}
	old = bpf_kptr_xchg((void *)scalar_slot, task);
	if (old) {
		bpf_task_release(old);
		ret = 3;
	}
	old = bpf_kptr_xchg((void *)scalar_slot, NULL);
	if (old)
		bpf_task_release(old);
	else
		ret = 4;
out:
	bpf_arena_free_pages(&arena, slot, 1);
	return ret;
}

static __always_inline int invalid_destination(void __arena *dst)
{
	struct task_struct *task, *old;
	int pid, ret;

	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return 1;
	pid = task->pid;
	old = bpf_kptr_xchg((void *)dst, task);
	if (!old)
		return 2;
	ret = old->pid != pid;
	bpf_task_release(old);
	return ret;
}

SEC("syscall")
__arch_x86_64 __arch_arm64 __load_if_JITed() __arena_kptr(task_struct)
__description("arena kptr: invalid destinations return incoming ownership")
__success __retval(0)
int arena_kptr_invalid_destination(void *ctx)
{
	char __arena *page;
	int ret;

	page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!page)
		return 1;
	ret = invalid_destination(page + 1);
	if (ret)
		goto out;
	ret = invalid_destination(page + PAGE_SIZE);
	if (ret)
		goto out;
	ret = invalid_destination(page + 4 * PAGE_SIZE);
out:
	bpf_arena_free_pages(&arena, page, 1);
	if (ret)
		return ret;
	return invalid_destination(page);
}

SEC("syscall")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__description("arena kptr: require explicit WIP pointee metadata")
__failure __msg("arena kptr exchange requires one bpf_arena_kptr:TYPE tag")
int arena_kptr_missing_type(void *ctx)
{
	void __arena *slot;
	struct task_struct *old;

	slot = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	old = bpf_kptr_xchg((void *)slot, NULL);
	if (old)
		bpf_task_release(old);
	return 0;
}

SEC("syscall")
__arch_x86_64 __arch_arm64 __load_if_JITed() __arena_kptr(sk_buff)
__description("arena kptr: reject a source with a different pointee type")
__failure __msg("invalid kptr access")
int arena_kptr_wrong_type(void *ctx)
{
	struct task_struct *task, *old;
	void __arena *slot;

	slot = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return 0;
	old = bpf_kptr_xchg((void *)slot, task);
	if (old)
		bpf_task_release(old);
	return 0;
}

SEC("syscall")
__arch_x86_64 __arch_arm64 __load_if_JITed() __arena_kptr(task_struct)
__description("arena kptr: require source ownership")
__failure __msg("release function bpf_kptr_xchg expects referenced PTR_TO_BTF_ID passed to R2")
int arena_kptr_unowned(void *ctx)
{
	struct task_struct *old;
	void __arena *slot;

	slot = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	old = bpf_kptr_xchg((void *)slot, bpf_get_current_task_btf());
	if (old)
		bpf_task_release(old);
	return 0;
}

SEC("syscall")
__arch_x86_64 __arch_arm64 __load_if_JITed() __arena_kptr(task_struct)
__description("arena kptr: scalar destination still requires arena scalar mode")
__failure __msg("R1 type=scalar")
int arena_kptr_scalar_without_flag(void *ctx)
{
	struct task_struct *old;
	void __arena *slot;

	slot = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	scalar_slot = (u64)slot;
	old = bpf_kptr_xchg((void *)scalar_slot, NULL);
	if (old)
		bpf_task_release(old);
	return 0;
}

SEC("syscall")
__arch_x86_64 __arch_arm64 __load_if_JITed() __arena_kptr(task_struct)
__description("arena kptr: reject mixed arena and native helper destinations")
__failure __msg("kptr exchange mixes arena and native destinations")
int arena_kptr_mixed_destination(void *ctx)
{
	struct task_slot *native;
	struct task_struct *old;
	void __arena *slot;
	void *dst;
	int key = 0;

	slot = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	native = bpf_map_lookup_elem(&native_slots, &key);
	if (!native)
		return 0;
	if (bpf_get_prandom_u32() & 1)
		dst = (void *)slot;
	else
		dst = &native->task;
	old = bpf_kptr_xchg(dst, NULL);
	if (old)
		bpf_task_release(old);
	return 0;
}

char _license[] SEC("license") = "GPL";
