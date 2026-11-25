// SPDX-License-Identifier: GPL-2.0
/* An extension of the program that parks coroutine frames, see progs/coro_park.c */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct slot {
	struct bpf_coro_xdp __kptr *xdp;
	struct bpf_coro_syscall __kptr *sys;
};

/* that of the other program, see prog_tests/coro_park.c */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct slot);
} slots SEC(".maps");

/*
 * It replaces a function that a continuation of the other program may call, or a callback that
 * has no network context: it calls no parked frame, bound or not.
 */
SEC("freplace/owner_hook")
int ext_resumes(int op)
{
	struct bpf_coro_xdp *coro;
	struct slot *s;
	__u32 idx = 0;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return op;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (coro)
		((void (*)(void *))((void **)coro)[0])(coro);
	return op;
}

char _license[] SEC("license") = "GPL";
