// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void bpf_local_irq_save(unsigned long *) __ksym;
extern void bpf_local_irq_restore(unsigned long *) __ksym;

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_res_spin_lock rlock;

/* Saves IRQ flags around a cancellation point, the timed may_goto of the loop. */
static __noinline int spin_with_irqs_off(int n)
{
	unsigned long flags;
	int i = 0;

	bpf_local_irq_save(&flags);
	while (i < n && can_loop)
		i++;
	bpf_local_irq_restore(&flags);
	return i;
}

/*
 * The subprog saves its flags under a caller's saved flags on one path and
 * under none on the other. What the subprog's frame holds at the may_goto is
 * the same either way: its own flags, in its own slot.
 */
SEC("tc")
__description("frame_desc: a subprog saving irq flags under a caller's flags and without")
__success __retval(3)
int irq_flags_rank_differs_by_caller(struct __sk_buff *skb)
{
	unsigned long flags;
	int r;

	if (skb->len > 100) {
		bpf_local_irq_save(&flags);
		r = spin_with_irqs_off(3);
		bpf_local_irq_restore(&flags);
	} else {
		r = spin_with_irqs_off(3);
	}
	return r;
}

/*
 * A socket cast to its struct by a helper carries the reference of the
 * socket a lookup acquired: a site reached with the cast pointer live
 * releases the socket from it.
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

/* A throw reads every register and stack slot: the socket is live at it. */
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
 * again and no live location of its frame holds it at the call: the socket
 * is listed from its mirror, a hidden slot the acquisition fills, which the
 * statistics count.
 */
SEC("tc")
__description("frame_desc: a socket held in no live location of the caller of a throw")
__success __log_level(5)
__msg("frame descriptors:{{.*}} mirrors 1 mirror_insns")
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
 * The socket was acquired by a subprog that has returned: the caller owns it
 * since the return, so its mirror is a slot of the caller's frame, filled
 * from R0 after the call that returned it.
 */
SEC("tc")
__description("frame_desc: a socket of a returned subprog held in no live location at a throw")
__success __log_level(5)
__msg("frame descriptors:{{.*}} mirrors 1 mirror_insns")
int sock_dead_from_subprog(struct __sk_buff *skb)
{
	struct bpf_sock *sk;

	sk = lookup_in_subprog(skb);
	if (!sk)
		return 0;
	return throw_unconditionally();
}

/*
 * The throw is reached holding the lock, or without it when the lock failed,
 * so the lock is mirrored: the mirror is stored from R1 in front of the
 * call, and the call that failed clears it after, in two insns, since the
 * verifier forks the failing path in front of the call; the unlock clears it
 * in one.
 */
SEC("tc")
__description("frame_desc: a resilient lock that fails clears its mirror")
__success __log_level(5)
__msg("frame descriptors:{{.*}} mirrors 1 mirror_insns 4 section")
int res_lock_fails_clears_mirror(struct __sk_buff *skb)
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
 * second record alone on the one path and with both on the other, so the
 * records are released from the mirror of the reserving insn, a slot each.
 * The frame holds a record of that insn after the call either way, and
 * nothing after the call tells which: the call cannot keep the mirror right.
 */
SEC("tc")
__description("frame_desc: a callee discards one of two records reserved at one insn")
__failure __msg("may release one of the references obtained at insn")
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
