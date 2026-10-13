// SPDX-License-Identifier: GPL-2.0

#include "bpf_experimental.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern struct task_struct *bpf_task_acquire(struct task_struct *task) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;

struct waitq_elem {
	struct bpf_spin_lock lock;
	struct bpf_waitq waitq;
	__u32 state;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct waitq_elem);
} waitq_map SEC(".maps");

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int map_value_after_wait(void *ctx)
{
	__u32 key = 0;
	struct waitq_elem *elem;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem)
		return 0;
	bpf_waitq_wait(&elem->waitq, &elem->state, 0, 0, 0);
	return elem->state;
}

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
__naked int spilled_map_value_after_wait(void)
{
	asm volatile ("\
	r1 = 0;\
	*(u32 *)(r10 - 4) = r1;\
	r2 = r10;\
	r2 += -4;\
	r1 = %[waitq_map] ll;\
	call %[bpf_map_lookup_elem];\
	if r0 == 0 goto l0_%=;\
	*(u64 *)(r10 - 16) = r0;\
	r1 = r0;\
	r1 += 8;\
	r2 = r0;\
	r2 += 24;\
	r3 = 0;\
	r4 = 0;\
	r5 = 0;\
	call bpf_waitq_wait;\
	r6 = *(u64 *)(r10 - 16);\
	r0 = *(u32 *)(r6 + 24);\
l0_%=: exit;\
" :
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(waitq_map)
	: __clobber_all);
}

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int task_pointer_after_wait(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u32 key = 0;
	struct waitq_elem *elem;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem)
		return 0;
	bpf_waitq_wait(&elem->waitq, &elem->state, 0, 0, 0);
	return task->pid;
}

SEC("syscall")
__success __retval(0)
int referenced_task_survives_wait(void *ctx)
{
	struct task_struct *task, *referenced;
	__u32 key = 0;
	struct waitq_elem *elem;

	task = bpf_get_current_task_btf();
	referenced = bpf_task_acquire(task);
	if (!referenced)
		return 0;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem) {
		bpf_task_release(referenced);
		return 0;
	}
	bpf_waitq_wait(&elem->waitq, &elem->state, 0, 0, 0);
	bpf_task_release(referenced);
	return 0;
}

SEC("syscall")
__success __retval(0)
int stack_pointer_survives_wait(void *ctx)
{
	__u32 key = 0, word = 0;
	struct waitq_elem *elem;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem)
		return 0;
	bpf_waitq_wait(&elem->waitq, &word, 0, 0, 0);
	return word;
}

SEC("syscall")
__failure __msg("function calls are not allowed while holding a lock")
int wait_while_locked(void *ctx)
{
	__u32 key = 0;
	struct waitq_elem *elem;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem)
		return 0;
	bpf_spin_lock(&elem->lock);
	bpf_waitq_wait(&elem->waitq, &elem->state, 0, 0, 0);
	bpf_spin_unlock(&elem->lock);
	return 0;
}

struct plain_waitq_elem {
	struct bpf_waitq waitq;
	__u32 state;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct plain_waitq_elem);
} plain_waitq_map SEC(".maps");

SEC("tp/syscalls/sys_enter_nanosleep")
__failure __msg("calling kernel function bpf_waitq_wait is not allowed")
int wait_from_non_syscall(void *ctx)
{
	__u32 key = 0;
	struct plain_waitq_elem *elem;

	elem = bpf_map_lookup_elem(&plain_waitq_map, &key);
	if (!elem)
		return 0;
	return bpf_waitq_wait(&elem->waitq, &elem->state, 0, 0, 0);
}
