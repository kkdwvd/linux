// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <net/tcp.h>

/* TCP xmit work done by BPF kthreads.
 *
 * A sender's work has two parts. The copy into the socket's write queue is
 * the application's own. The xmit work that follows, tcp_write_xmit() with
 * the IP output, the qdisc and the driver's transmit below it, runs on the
 * application's CPU as well but is the network stack's work. A program that
 * runs the stack's receive side on CPUs of its own can take the xmit work
 * there too.
 *
 * There is a fixed number of xmit queues, known by their index. A BPF kthread
 * is bound to a queue as the thread that serves it, and a socket is assigned
 * to a queue. When such a socket is about to transmit, from sendmsg() or from
 * the write a TSQ wakeup asks for, it is put on its queue instead and the
 * queue's thread is woken. The thread takes sockets off the queue and
 * transmits for each as its owner would have. What the indexes stand for, a
 * CPU, a NAPI or a group of connections, is the program's business.
 *
 * A socket is on its queue at most once: TCP_BPF_TX_QUEUED is set when it is
 * put on, with a reference held, and cleared before the thread transmits, so
 * xmit work that arrives while the thread is at it queues the socket again.
 * Xmit work that already runs on the queue's thread is done on the spot. That
 * covers the thread's own, and what an ACK or a TX completion asks for when
 * the thread is the one processing it, in its poll of a NAPI.
 *
 * The thread does not sleep on a socket. If the owner holds the socket's lock
 * the xmit work is left to tcp_release_cb(), like a TSQ wakeup that finds the
 * socket owned, and the owner's release sends it back to the queue.
 */

#define TCP_BPF_TX_QUEUES	256

struct tcp_bpf_tx_queue {
	spinlock_t lock;		/* socks */
	struct list_head socks;		/* through tcp_sock.bpf_tx_node */
	struct task_struct __rcu *thread;
} ____cacheline_aligned_in_smp;

static struct tcp_bpf_tx_queue tcp_bpf_tx_queues[TCP_BPF_TX_QUEUES];

/* Serializes the binding of threads to queues. */
static DEFINE_MUTEX(tcp_bpf_tx_mutex);

/* Leave the xmit work of @sk to the thread of its queue. Called with the
 * socket locked, by its owner or from softirq, where the work would start.
 * Returns false when the caller has to transmit itself: the queue has no
 * thread, or the caller is that thread.
 */
bool __tcp_bpf_tx_defer(struct sock *sk, int nonagle)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u16 id = READ_ONCE(tp->bpf_tx_queue);
	struct tcp_bpf_tx_queue *q;
	struct task_struct *thread;
	bool deferred = false;

	if (!id || id > TCP_BPF_TX_QUEUES)
		return false;
	q = &tcp_bpf_tx_queues[id - 1];

	/* An unbind waits for this section before it empties the queue. */
	rcu_read_lock();
	thread = rcu_dereference(q->thread);
	if (!thread || thread == current)
		goto out;

	/* The socket lock orders this against the thread's read of it. */
	tp->bpf_tx_nonagle = nonagle;
	if (!test_and_set_bit(TCP_BPF_TX_QUEUED, &sk->sk_tsq_flags)) {
		sock_hold(sk);
		spin_lock_bh(&q->lock);
		list_add_tail(&tp->bpf_tx_node, &q->socks);
		spin_unlock_bh(&q->lock);
		bpf_task_wake_direct(thread);
	}
	deferred = true;
out:
	rcu_read_unlock();
	return deferred;
}

static struct sock *tcp_bpf_tx_dequeue(struct tcp_bpf_tx_queue *q)
{
	struct tcp_sock *tp;

	spin_lock_bh(&q->lock);
	tp = list_first_entry_or_null(&q->socks, struct tcp_sock, bpf_tx_node);
	if (tp)
		list_del(&tp->bpf_tx_node);
	spin_unlock_bh(&q->lock);
	return (struct sock *)tp;
}

/* Transmit what @sk has pending and drop the queue's reference. */
static void tcp_bpf_tx_xmit(struct sock *sk)
{
	/* Cleared before the write queue is looked at. A sender that finds
	 * the bit set has left data the look below still sees, and one that
	 * comes later queues the socket again.
	 */
	clear_bit(TCP_BPF_TX_QUEUED, &sk->sk_tsq_flags);
	smp_mb__after_atomic();

	local_bh_disable();
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		tcp_push_pending_frames_now(sk, tcp_current_mss(sk), tcp_sk(sk)->bpf_tx_nonagle);
	} else if (!test_and_set_bit(TCP_TSQ_DEFERRED, &sk->sk_tsq_flags)) {
		/* The owner writes when it releases the socket, see
		 * tcp_release_cb(), which also drops this reference.
		 */
		sock_hold(sk);
	}
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}

/**
 * tcp_bpf_tx_bind() - make a BPF kthread the thread that serves an xmit queue
 * @queue: index of the queue
 * @task: the BPF kthread
 *
 * Replaces the queue's thread if it has one. May sleep.
 *
 * Return: 0 on success, -EINVAL for an index out of range, -ESRCH if @task is
 * gone.
 */
int tcp_bpf_tx_bind(u32 queue, struct task_struct *task)
{
	struct tcp_bpf_tx_queue *q;
	struct task_struct *old;

	if (queue >= TCP_BPF_TX_QUEUES)
		return -EINVAL;
	q = &tcp_bpf_tx_queues[queue];
	if (!refcount_inc_not_zero(&task->rcu_users))
		return -ESRCH;

	mutex_lock(&tcp_bpf_tx_mutex);
	old = rcu_replace_pointer(q->thread, task, lockdep_is_held(&tcp_bpf_tx_mutex));
	/* A sender that read the old thread woke the old thread. Once all of
	 * them are through, wake the new one for what is on the queue.
	 */
	synchronize_rcu();
	if (!list_empty_careful(&q->socks))
		bpf_task_wake_direct(task);
	mutex_unlock(&tcp_bpf_tx_mutex);

	if (old)
		put_task_struct_rcu_user(old);
	return 0;
}

/**
 * tcp_bpf_tx_unbind() - leave the xmit work of a queue's sockets to the sockets
 * @queue: index of the queue
 *
 * The sockets that are on the queue are served here, in the caller's context.
 * May sleep.
 */
void tcp_bpf_tx_unbind(u32 queue)
{
	struct tcp_bpf_tx_queue *q;
	struct task_struct *old;
	struct sock *sk;

	if (queue >= TCP_BPF_TX_QUEUES)
		return;
	q = &tcp_bpf_tx_queues[queue];

	mutex_lock(&tcp_bpf_tx_mutex);
	old = rcu_replace_pointer(q->thread, NULL, lockdep_is_held(&tcp_bpf_tx_mutex));
	if (old) {
		/* No sender queues a socket for the old thread after this. */
		synchronize_rcu();
		while ((sk = tcp_bpf_tx_dequeue(q)))
			tcp_bpf_tx_xmit(sk);
		put_task_struct_rcu_user(old);
	}
	mutex_unlock(&tcp_bpf_tx_mutex);
}

/**
 * tcp_bpf_tx_poll() - do the xmit work of the sockets on a queue
 * @queue: index of a queue the calling thread serves
 * @budget: serve at most this many sockets
 *
 * Return: the number of sockets served, -EINVAL for an index out of range,
 * -EPERM if the caller is not the queue's thread, whose xmit work would be put
 * back on the queue.
 */
int tcp_bpf_tx_poll(u32 queue, u32 budget)
{
	struct tcp_bpf_tx_queue *q;
	struct sock *sk;
	u32 n = 0;

	if (queue >= TCP_BPF_TX_QUEUES)
		return -EINVAL;
	q = &tcp_bpf_tx_queues[queue];
	if (rcu_access_pointer(q->thread) != current)
		return -EPERM;

	while (n < budget && (sk = tcp_bpf_tx_dequeue(q))) {
		tcp_bpf_tx_xmit(sk);
		n++;
	}
	return n;
}

/**
 * tcp_bpf_tx_sock_bind() - assign a socket to an xmit queue
 * @sk: a TCP socket
 * @queue: index of the queue, or a negative value for none
 *
 * Takes effect the next time the socket has xmit work. A queue without a
 * thread leaves it to the socket.
 *
 * Return: 0 on success, -EINVAL for an index out of range or a socket that is
 * not a full TCP socket.
 */
int tcp_bpf_tx_sock_bind(struct sock *sk, s32 queue)
{
	if (!sk || !sk_fullsock(sk) || !sk_is_tcp(sk) || queue >= TCP_BPF_TX_QUEUES)
		return -EINVAL;
	WRITE_ONCE(tcp_sk(sk)->bpf_tx_queue, queue < 0 ? 0 : queue + 1);
	return 0;
}

static int __init tcp_bpf_tx_init(void)
{
	int i;

	for (i = 0; i < TCP_BPF_TX_QUEUES; i++) {
		spin_lock_init(&tcp_bpf_tx_queues[i].lock);
		INIT_LIST_HEAD(&tcp_bpf_tx_queues[i].socks);
	}
	return 0;
}
core_initcall(tcp_bpf_tx_init);
