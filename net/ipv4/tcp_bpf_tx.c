// SPDX-License-Identifier: GPL-2.0
/*
 * TCP pushes handed to BPF worker threads.
 *
 * A sender's work on its CPU has two parts: the copy into the socket buffer,
 * which is the application's own, and the push that follows it, the
 * segmentation, congestion control, IP, qdisc and driver work of
 * __tcp_push_pending_frames(), which the application neither sees nor
 * controls. NetChannel (Cai et al., SIGCOMM 2022) put the second part on
 * cores of its own so that it neither competes with the application nor
 * with a latency-sensitive neighbour on the same core. Here the push is the
 * continuation: a socket bound to a worker leaves tcp_push() and the TSQ
 * deferred write to the worker, a BPF kthread that takes the socket off its
 * list, locks it and pushes, on whichever CPU the policy put the worker.
 *
 * One worker per CPU, named by the CPU; bpf_tcp_tx_bind() gives it a wait
 * queue to signal, which the kthread sleeps on, and bpf_tcp_tx_poll() does
 * the work. A socket is bound from a sockops program with
 * bpf_tcp_tx_sock_bind(), the policy choosing the worker, or from a syscall
 * program by descriptor. A socket is on at most one list at a time: the
 * queued bit in sk_tsq_flags is set when it is put on and cleared before it
 * is pushed, so a push that arrives meanwhile queues it again. The socket
 * holds a reference while queued; a worker that is unbound pushes what is on
 * its list before it goes.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/file.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/tcp.h>

struct tcp_bpf_tx_worker {
	spinlock_t lock;
	struct list_head sockets;
	struct bpf_waitq_kern __rcu *waitq;
	struct task_struct *polling;	/* the thread inside bpf_tcp_tx_poll() */
	u64 pushes;
};

static DEFINE_PER_CPU(struct tcp_bpf_tx_worker, tcp_bpf_tx_workers);

static struct tcp_bpf_tx_worker *tcp_bpf_tx_worker_of(struct sock *sk)
{
	u16 cpu1 = READ_ONCE(tcp_sk(sk)->bpf_tx_cpu1);

	if (!cpu1 || cpu1 - 1 >= nr_cpu_ids)
		return NULL;
	return per_cpu_ptr(&tcp_bpf_tx_workers, cpu1 - 1);
}

/*
 * Hand @sk's push to its worker, if it has one: true when the worker will
 * push, false when the caller has to. Called with the socket locked by its
 * owner. The worker's own release of the socket pushes inline, since a
 * write it deferred while it held the lock would otherwise wait a round.
 */
bool tcp_bpf_tx_defer(struct sock *sk, int nonagle)
{
	struct tcp_bpf_tx_worker *w = tcp_bpf_tx_worker_of(sk);
	struct bpf_waitq_kern *waitq;
	bool queued = false;

	if (!w || READ_ONCE(w->polling) == current)
		return false;
	rcu_read_lock();
	waitq = rcu_dereference(w->waitq);
	if (!waitq)
		goto out;
	tcp_sk(sk)->bpf_tx_nonagle = nonagle;
	if (!test_and_set_bit(TCP_BPF_TX_QUEUED, &sk->sk_tsq_flags)) {
		sock_hold(sk);
		spin_lock_bh(&w->lock);
		list_add_tail(&tcp_sk(sk)->bpf_tx_node, &w->sockets);
		spin_unlock_bh(&w->lock);
		bpf_waitq_signal(waitq, 1);
	}
	queued = true;
out:
	rcu_read_unlock();
	return queued;
}

/* Take the first queued socket off @w's list, or NULL. */
static struct sock *tcp_bpf_tx_dequeue(struct tcp_bpf_tx_worker *w)
{
	struct tcp_sock *tp;

	spin_lock_bh(&w->lock);
	tp = list_first_entry_or_null(&w->sockets, struct tcp_sock, bpf_tx_node);
	if (tp)
		list_del_init(&tp->bpf_tx_node);
	spin_unlock_bh(&w->lock);
	return tp ? (struct sock *)tp : NULL;
}

/* Push @sk's pending frames as its owner would have, and drop the queue's reference. */
static void tcp_bpf_tx_push(struct sock *sk)
{
	/* Cleared first: a push arriving from here on queues the socket again. */
	clear_bit(TCP_BPF_TX_QUEUED, &sk->sk_tsq_flags);
	smp_mb__after_atomic();
	lock_sock(sk);
	if (sk->sk_state != TCP_CLOSE)
		__tcp_push_pending_frames(sk, tcp_current_mss(sk), tcp_sk(sk)->bpf_tx_nonagle);
	release_sock(sk);
	sock_put(sk);
}

__bpf_kfunc_start_defs();

/**
 * bpf_tcp_tx_bind - make a BPF thread the TX worker of a CPU
 * @cpu: the CPU whose worker it is; sockets are bound to CPUs
 * @waitq: the queue to signal when a socket is put on the worker's list
 * @flags: must be 0
 *
 * Binding a CPU that has a worker replaces it; sockets queued for the
 * previous worker are signalled to the new one.
 */
__bpf_kfunc int bpf_tcp_tx_bind(u32 cpu, struct bpf_waitq *waitq, u64 flags)
{
	struct tcp_bpf_tx_worker *w;
	struct bpf_waitq_kern *kern, *old;

	if (flags || cpu >= nr_cpu_ids)
		return -EINVAL;
	kern = bpf_waitq_get(waitq);
	if (!kern)
		return -EINVAL;
	w = per_cpu_ptr(&tcp_bpf_tx_workers, cpu);
	old = rcu_replace_pointer(w->waitq, kern, true);
	if (old) {
		synchronize_rcu();
		bpf_waitq_put(old);
	}
	spin_lock_bh(&w->lock);
	if (!list_empty(&w->sockets))
		bpf_waitq_signal(kern, 1);
	spin_unlock_bh(&w->lock);
	return 0;
}

/**
 * bpf_tcp_tx_unbind - take a CPU's TX worker away
 * @cpu: the CPU
 *
 * Pushes the sockets still queued for the worker here, in the caller's
 * context. Bound sockets push inline from then on.
 */
__bpf_kfunc int bpf_tcp_tx_unbind(u32 cpu)
{
	struct tcp_bpf_tx_worker *w;
	struct bpf_waitq_kern *old;
	struct sock *sk;

	if (cpu >= nr_cpu_ids)
		return -EINVAL;
	w = per_cpu_ptr(&tcp_bpf_tx_workers, cpu);
	old = rcu_replace_pointer(w->waitq, NULL, true);
	if (old) {
		synchronize_rcu();
		bpf_waitq_put(old);
	}
	while ((sk = tcp_bpf_tx_dequeue(w)))
		tcp_bpf_tx_push(sk);
	return 0;
}

/**
 * bpf_tcp_tx_poll - push the sockets queued for a CPU's worker
 * @cpu: the CPU whose worker the caller is
 * @budget: at most this many sockets
 *
 * Each socket is locked and its pending frames pushed as its owner would
 * have pushed them, from the calling thread. Returns the number pushed; the
 * caller sleeps on the worker's wait queue when that is 0.
 */
__bpf_kfunc int bpf_tcp_tx_poll(u32 cpu, u32 budget)
{
	struct tcp_bpf_tx_worker *w;
	struct sock *sk;
	u32 n = 0;

	if (cpu >= nr_cpu_ids)
		return -EINVAL;
	w = per_cpu_ptr(&tcp_bpf_tx_workers, cpu);
	WRITE_ONCE(w->polling, current);
	while (n < budget && (sk = tcp_bpf_tx_dequeue(w))) {
		tcp_bpf_tx_push(sk);
		n++;
	}
	WRITE_ONCE(w->polling, NULL);
	w->pushes += n;
	return n;
}

/**
 * bpf_tcp_tx_pushes - how many pushes a CPU's worker has done
 * @cpu: the CPU
 */
__bpf_kfunc u64 bpf_tcp_tx_pushes(u32 cpu)
{
	if (cpu >= nr_cpu_ids)
		return 0;
	return per_cpu_ptr(&tcp_bpf_tx_workers, cpu)->pushes;
}

static int tcp_bpf_tx_sock_set(struct sock *sk, s32 cpu)
{
	if (!sk || sk->sk_protocol != IPPROTO_TCP)
		return -EINVAL;
	if (cpu >= (s32)nr_cpu_ids)
		return -EINVAL;
	WRITE_ONCE(tcp_sk(sk)->bpf_tx_cpu1, cpu < 0 ? 0 : cpu + 1);
	return 0;
}

/**
 * bpf_tcp_tx_sock_bind - send a socket's pushes to a CPU's TX worker
 * @skops: the sockops context, whose socket it is
 * @cpu: the CPU, or -1 to push inline again
 *
 * Takes effect at the socket's next push. A CPU without a worker pushes
 * inline until one is bound.
 */
__bpf_kfunc int bpf_tcp_tx_sock_bind(struct bpf_sock_ops *skops, s32 cpu)
{
	struct bpf_sock_ops_kern *kern = (struct bpf_sock_ops_kern *)skops;

	return tcp_bpf_tx_sock_set(kern->sk, cpu);
}

/**
 * bpf_tcp_tx_sock_bind_fd - send a socket's pushes to a CPU's TX worker
 * @fd: a TCP socket of the calling process
 * @cpu: the CPU, or -1 to push inline again
 */
__bpf_kfunc int bpf_tcp_tx_sock_bind_fd(int fd, s32 cpu)
{
	struct socket *sock;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return err;
	err = tcp_bpf_tx_sock_set(sock->sk, cpu);
	sockfd_put(sock);
	return err;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(tcp_bpf_tx_syscall_ids)
BTF_ID_FLAGS(func, bpf_tcp_tx_bind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_tcp_tx_unbind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_tcp_tx_poll, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_tcp_tx_pushes)
BTF_ID_FLAGS(func, bpf_tcp_tx_sock_bind_fd, KF_SLEEPABLE)
BTF_KFUNCS_END(tcp_bpf_tx_syscall_ids)

static const struct btf_kfunc_id_set tcp_bpf_tx_syscall_set = {
	.owner = THIS_MODULE,
	.set = &tcp_bpf_tx_syscall_ids,
};

BTF_KFUNCS_START(tcp_bpf_tx_sockops_ids)
BTF_ID_FLAGS(func, bpf_tcp_tx_sock_bind)
BTF_KFUNCS_END(tcp_bpf_tx_sockops_ids)

static const struct btf_kfunc_id_set tcp_bpf_tx_sockops_set = {
	.owner = THIS_MODULE,
	.set = &tcp_bpf_tx_sockops_ids,
};

static int __init tcp_bpf_tx_init(void)
{
	int cpu, ret;

	for_each_possible_cpu(cpu) {
		struct tcp_bpf_tx_worker *w = per_cpu_ptr(&tcp_bpf_tx_workers, cpu);

		spin_lock_init(&w->lock);
		INIT_LIST_HEAD(&w->sockets);
	}
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &tcp_bpf_tx_syscall_set);
	return ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SOCK_OPS, &tcp_bpf_tx_sockops_set);
}
late_initcall(tcp_bpf_tx_init);
