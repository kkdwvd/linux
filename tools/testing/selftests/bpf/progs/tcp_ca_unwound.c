// SPDX-License-Identifier: GPL-2.0

#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

/*
 * Reno, whose operators the kernel unwinds when user space says so. An unwound operator returns
 * what tcp_congestion_ops says for it, see bpf_tcp_ca_unwound_retval(). 0 is no window and no
 * slow start threshold that TCP can take: with 0 from ->undo_cwnd() or ->ssthresh()
 * tcp_snd_cwnd_set() warns, and after 0 from ->ssthresh() tcp_reno_cong_avoid() divides by a
 * window of 0.
 */

/* set by user space: the kernel unwinds each call of the operator */
bool unwind_ssthresh, unwind_undo_cwnd, unwind_tso_segs, unwind_sndbuf_expand;
/* how many calls of each operator got to the recursion, and how many got behind it */
int ssthresh_went_down, ssthresh_went_on;
int undo_cwnd_went_down, undo_cwnd_went_on;
int tso_segs_went_down, tso_segs_went_on;
int sndbuf_expand_went_down, sndbuf_expand_went_on;

/* snd_ssthresh where TCP enters the recovery, which is what ->ssthresh() returned */
__u32 ssthresh_in_recovery;
/* snd_cwnd where the recovery is over: TCP has set it to snd_ssthresh */
__u32 cwnd_after_recovery;
int recoveries;
/*
 * A retransmission timeout fell into the recovery: snd_ssthresh where TCP enters the loss state,
 * which is still what ->ssthresh() returned
 */
__u32 ssthresh_in_loss;
int losses;
/* the recovery, or the loss state that took its place, is over: TCP is back in the open state */
int recovered;
bool in_recovery;
/*
 * snd_cwnd where TCP goes back to the open state after an undo, which is what ->undo_cwnd()
 * returned
 */
__u32 cwnd_after_undo;
int undos;
bool in_undo;

/* What the tcx prog drops, once: nothing, an ACK of the server without data, data of the client */
enum {
	DROP_NONE,
	DROP_ACK,
	DROP_DATA,
};

int drop;
int dropped;
/* in network byte order */
__u16 srv_port, cli_port;

/* A recursion without an end: the kernel unwinds it when the stack has no room for another frame */
__naked __noinline __used
static unsigned long goes_down(void)
{
	asm volatile (
		"r1 = 0;"
		"call goes_down;"
		"exit;"
		::: __clobber_all);
}

SEC("struct_ops")
__u32 BPF_PROG(unwound_ssthresh, struct sock *sk)
{
	if (unwind_ssthresh) {
		ssthresh_went_down++;
		goes_down();
		ssthresh_went_on++;
	}
	return tcp_reno_ssthresh(sk);
}

SEC("struct_ops")
__u32 BPF_PROG(unwound_undo_cwnd, struct sock *sk)
{
	in_undo = true;
	if (unwind_undo_cwnd) {
		undo_cwnd_went_down++;
		goes_down();
		undo_cwnd_went_on++;
	}
	return tcp_reno_undo_cwnd(sk);
}

/* One segment in a packet, so that the tcx prog can drop one segment of a write */
SEC("struct_ops")
__u32 BPF_PROG(unwound_tso_segs, struct sock *sk, __u32 mss_now)
{
	if (unwind_tso_segs) {
		tso_segs_went_down++;
		goes_down();
		tso_segs_went_on++;
	}
	return 1;
}

SEC("struct_ops")
__u32 BPF_PROG(unwound_sndbuf_expand, struct sock *sk)
{
	if (unwind_sndbuf_expand) {
		sndbuf_expand_went_down++;
		goes_down();
		sndbuf_expand_went_on++;
	}
	return 2;
}

SEC("struct_ops")
void BPF_PROG(unwound_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
	tcp_reno_cong_avoid(sk, ack, acked);
}

SEC("struct_ops")
void BPF_PROG(unwound_set_state, struct sock *sk, __u8 new_state)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if (new_state == TCP_CA_Recovery) {
		ssthresh_in_recovery = tp->snd_ssthresh;
		in_recovery = true;
	} else if (new_state == TCP_CA_Loss && in_recovery) {
		ssthresh_in_loss = tp->snd_ssthresh;
		losses++;
	} else if (new_state == TCP_CA_Open && in_recovery) {
		in_recovery = false;
		recovered++;
	} else if (new_state == TCP_CA_Open && in_undo) {
		in_undo = false;
		cwnd_after_undo = tp->snd_cwnd;
		undos++;
	}
}

SEC("struct_ops")
void BPF_PROG(unwound_cwnd_event, struct sock *sk, enum tcp_ca_event ev)
{
	if (ev == CA_EVENT_COMPLETE_CWR) {
		cwnd_after_recovery = tcp_sk(sk)->snd_cwnd;
		recoveries++;
	}
}

SEC(".struct_ops.link")
struct tcp_congestion_ops unwound = {
	.ssthresh	= (void *)unwound_ssthresh,
	.undo_cwnd	= (void *)unwound_undo_cwnd,
	.tso_segs	= (void *)unwound_tso_segs,
	.sndbuf_expand	= (void *)unwound_sndbuf_expand,
	.cong_avoid	= (void *)unwound_cong_avoid,
	.set_state	= (void *)unwound_set_state,
	.cwnd_event	= (void *)unwound_cwnd_event,
	.name		= "bpf_unwound",
};

/* On the way in: the sender is not told, as it is when its own device drops the packet */
SEC("tcx/ingress")
int drops_one(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = (void *)(long)skb->data;
	struct iphdr *iph = (void *)(eth + 1);
	struct tcphdr *th = (void *)(iph + 1);
	__u32 len;

	if (drop == DROP_NONE)
		return TCX_NEXT;
	if ((void *)(th + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP) ||
	    iph->ihl != 5 || iph->protocol != IPPROTO_TCP)
		return TCX_NEXT;

	len = bpf_ntohs(iph->tot_len) - sizeof(*iph) - th->doff * 4;
	if (drop == DROP_ACK) {
		if (th->source != srv_port || th->dest != cli_port || len ||
		    th->syn || th->fin || th->rst)
			return TCX_NEXT;
	} else {
		if (th->source != cli_port || th->dest != srv_port || !len)
			return TCX_NEXT;
	}

	drop = DROP_NONE;
	dropped++;
	return TCX_DROP;
}
