// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_res_spin_lock rlock;

/*
 * A socket cast to its struct by a helper carries the reference of the
 * socket a lookup acquired: the socket is in the slot the lookup filled at
 * the throw, and the release through the cast pointer clears that slot.
 */
SEC("tc")
__description("frame_desc: a throw with a socket cast to tcp_sock live")
__success
int sock_cast_at_throw(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	struct tcp_sock *tp;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		bpf_sk_release(sk);
		return 0;
	}
	if (skb->len > 100)
		bpf_throw(0);
	bpf_sk_release((struct bpf_sock *)tp);
	return 1;
}

/* Nothing reads the socket after the lookup: it is in the slot of the frame at the throw. */
SEC("tc")
__description("frame_desc: a socket read by nothing but the throw")
__success
int sock_dead_at_throw(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	bpf_throw(0);
	return 1;
}

static __noinline int throw_unconditionally(void)
{
	bpf_throw(0);
	return 0;
}

/*
 * The callee's throw is unconditional, so the caller never reads the socket
 * again after the call: the socket is in the hidden slot of the caller's
 * frame, which the lookup filled, and the statistics line reports the slots.
 */
SEC("tc")
__description("frame_desc: a socket nothing reads in the caller of a throw")
__success __log_level(5)
__msg("frame descriptors: slots 1 insns 3 classes 1")
int sock_dead_in_caller(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	return throw_unconditionally();
}

static __noinline struct bpf_sock *lookup_in_subprog(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};

	return bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
}

/*
 * The socket was acquired by a subprog that has returned: the subprog handed
 * its slot over to the caller's frame when it returned, which holds the
 * socket at the throw, and the statistics line reports the slots.
 */
SEC("tc")
__description("frame_desc: a socket a returned subprog acquired, held at a throw")
__success __log_level(5)
__msg("frame descriptors: slots 2 insns 6 classes 1")
int sock_dead_from_subprog(struct __sk_buff *skb)
{
	struct bpf_sock *sk;

	sk = lookup_in_subprog(skb);
	if (!sk)
		return 0;
	return throw_unconditionally();
}

/*
 * The throw is reached holding the lock, or without it when the lock failed:
 * the address of the lock goes into a slot of the frame after the call only
 * when the call returned 0, and the unlock clears the slot. The statistics
 * line reports the slots.
 */
SEC("tc")
__description("frame_desc: a resilient lock that fails takes no slot")
__success __log_level(5)
__msg("frame descriptors: slots 3 insns 11 classes 1")
int res_lock_fails_takes_no_slot(struct __sk_buff *skb)
{
	int ret;

	ret = bpf_res_spin_lock(&rlock);
	if (skb->len > 100)
		bpf_throw(0);
	if (!ret)
		bpf_res_spin_unlock(&rlock);
	return ret;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

/* Discards the record in R1. */
__naked __noinline __used
static long discard_record(void)
{
	asm volatile (
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ringbuf_discard)
	: __clobber_all);
}

/*
 * A loop the verifier walks reserves a record at one insn on each of two
 * iterations, the first kept in R7 and the second spilled, and a callee
 * discards the first when the test says so: the throw is reached with the
 * second record alone on the one path and with both on the other. The frame
 * has a slot for each record, as it holds two at once, and the discard in
 * the callee clears the slot that holds the record it was passed.
 */
SEC("tc")
__description("frame_desc: a callee discards one of two records reserved at one insn")
__success
__naked int release_one_of_several(void)
{
	asm volatile (
	"r7 = 0;"
	"r6 = 0;"
	"1: r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 5f;"
	"if r7 != 0 goto 2f;"
	"r7 = r0;"
	"goto 3f;"
	"2: *(u64 *)(r10 - 8) = r0;"
	"3: r6 += 1;"
	"if r6 < 2 goto 1b;"
	"call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 4f;"
	"r1 = r7;"
	"call discard_record;"
	"4: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"5: if r7 == 0 goto 6f;"
	"r1 = r7;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"6: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_get_prandom_u32),
	  __imm(bpf_throw)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
