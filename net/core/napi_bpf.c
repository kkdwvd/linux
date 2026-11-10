// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/capability.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <net/net_namespace.h>

#include "dev.h"

/* kfuncs for polling NAPIs from BPF kthreads. The mechanism, and what keeps
 * the device in control of a NAPI that a program polls, is described above
 * napi_bpf_bind_locked().
 *
 * A NAPI is named by its ID, the one netlink reports for the NAPI and for its
 * queues, and is looked up on every call. A program holds no NAPI pointer, so
 * a device that reconfigures its queues or goes away needs nothing from the
 * program, which sees an error for the ID and can bind again when the NAPI is
 * back.
 */

__bpf_kfunc_start_defs();

/**
 * bpf_napi_bind - Make a BPF kthread the poller of a NAPI
 * @napi_id: ID of a NAPI
 * @task: a thread created by bpf_kthread_create()
 * @flags: must be 0
 *
 * From now on a schedule of the NAPI, by its interrupt or otherwise, wakes
 * @task with the wake bpf_task_wake() issues instead of raising softirq, and
 * the NAPI waits for bpf_napi_poll(). Several NAPIs may be bound to one
 * thread. Binding a NAPI that is bound moves it to @task, and binding one
 * whose polls return -ECANCELED puts it back in service.
 *
 * The binding ends with bpf_napi_unbind(), when the thread's callback returns,
 * and whenever the device disables the NAPI or its threaded setting is
 * written; the NAPI is then polled by softirq again.
 *
 * Return: 0 on success, -EINVAL if @flags is not 0, -ENOENT if no NAPI has
 * this ID, -ESRCH if @task is not a BPF kthread, or one whose callback has
 * returned or that is being stopped, -EBUSY if the NAPI is in the kernel's
 * threaded mode, -EOPNOTSUPP if it cannot be polled by a thread.
 */
__bpf_kfunc int bpf_napi_bind(u32 napi_id, struct task_struct *task, u64 flags)
{
	struct napi_struct *napi;
	int ret;

	if (flags)
		return -EINVAL;

	napi = napi_bpf_by_id_lock(napi_id);
	if (!napi)
		return -ENOENT;
	ret = napi_bpf_bind_locked(napi, task);
	netdev_unlock(napi->dev);
	return ret;
}

/**
 * bpf_napi_unbind - Return a NAPI to softirq
 * @napi_id: ID of a NAPI
 *
 * Waits for a poll of the NAPI that is in progress. Work that was pending for
 * the thread is done by softirq.
 *
 * Return: 0 on success, also when the NAPI was not bound, -ENOENT if no NAPI
 * has this ID.
 */
__bpf_kfunc int bpf_napi_unbind(u32 napi_id)
{
	struct napi_struct *napi;

	napi = napi_bpf_by_id_lock(napi_id);
	if (!napi)
		return -ENOENT;
	napi_bpf_unbind_locked(napi);
	netdev_unlock(napi->dev);
	return 0;
}

/**
 * bpf_napi_poll - One round of service of a bound NAPI
 * @napi_id: ID of a NAPI bound with bpf_napi_bind()
 * @flags: BPF_NAPI_POLL_F_BUSY or 0
 *
 * Calls the driver's poll once, with the NAPI's budget, if the NAPI is
 * scheduled for its thread. The thread's loop polls each of its NAPIs until
 * none reports BPF_NAPI_POLL_MORE and then sleeps in bpf_task_park(); a
 * schedule that arrives in between leaves a wake pending, so the park returns
 * at once.
 *
 * With BPF_NAPI_POLL_F_BUSY the poll leaves the NAPI scheduled and its
 * interrupt masked, and also takes a NAPI that was not scheduled. The thread
 * then polls again when it sees fit, right away or after a timed park, and
 * no interrupt comes until a poll without the flag has completed the NAPI. A
 * NAPI left scheduled and unpolled for about a second is taken away from the
 * thread, whether a busy poll or an interrupt scheduled it.
 *
 * Any program may poll any bound NAPI: a poll is service, and two callers
 * exclude each other. The call is a rescheduling point.
 *
 * Return: the number of packets processed, at most BPF_NAPI_POLL_WORK_MASK,
 * ORed with BPF_NAPI_POLL_MORE if the NAPI is still scheduled for its thread.
 * -EAGAIN if the NAPI is not scheduled for its thread, -EBUSY if another
 * caller is polling it, -ENOENT if no NAPI with this ID is bound, -ECANCELED
 * if the NAPI is suspended, or was taken away from its thread for not being
 * polled, until bpf_napi_resume() or a new bind, -EINVAL for unknown @flags.
 */
__bpf_kfunc int bpf_napi_poll(u32 napi_id, u64 flags)
{
	int ret;

	ret = napi_bpf_poll(napi_id, flags);
	/* What napi_threaded_poll_loop() does between the rounds of a NAPI
	 * thread, for a thread that polls in a loop without ever parking.
	 */
	cond_resched();
	return ret;
}

/**
 * bpf_napi_suspend - Leave a bound NAPI to softirq for the time being
 * @napi_id: ID of a NAPI bound with bpf_napi_bind()
 * @wake_after: wake the NAPI's thread after softirq has processed about this
 *	many packets, 0 to never wake it
 *
 * The NAPI stays bound to its thread, but softirq polls it, as if it were not:
 * a packet costs no wakeup of the thread. A NAPI the thread held with a busy
 * poll is completed by softirq and its interrupt unmasked. Polls of a
 * suspended NAPI return -ECANCELED. The wake lets the thread measure the
 * traffic it no longer sees: the time @wake_after packets took tells it the
 * rate, and whether to take the NAPI back with bpf_napi_resume() or to
 * suspend it again.
 *
 * Costs one atomic operation and takes no lock, unlike unbinding and binding.
 *
 * Return: 0 on success, -ENOENT if no NAPI with this ID is bound.
 */
__bpf_kfunc int bpf_napi_suspend(u32 napi_id, u32 wake_after)
{
	return napi_bpf_suspend(napi_id, wake_after);
}

/**
 * bpf_napi_resume - Take the scheduling of a bound NAPI back from softirq
 * @napi_id: ID of a NAPI bound with bpf_napi_bind()
 *
 * From the NAPI's next schedule on, its thread is woken and polls it again.
 * Also puts a NAPI back in service that was taken away for not being polled,
 * as a new bpf_napi_bind() does. A busy poll after this call takes the NAPI
 * as soon as softirq is done with it.
 *
 * Return: 0 on success, -ENOENT if no NAPI with this ID is bound.
 */
__bpf_kfunc int bpf_napi_resume(u32 napi_id)
{
	return napi_bpf_resume(napi_id);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_napi_kfunc_ids)
BTF_ID_FLAGS(func, bpf_napi_bind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_napi_unbind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_napi_poll, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_napi_suspend)
BTF_ID_FLAGS(func, bpf_napi_resume)
BTF_KFUNCS_END(bpf_napi_kfunc_ids)

/* NAPI IDs are global, and a BPF kthread runs with the kernel's credentials
 * whoever created it, so there is nothing to check when a kfunc is called.
 * The program is checked instead, when it is loaded: it may call these kfuncs
 * only if its loader has CAP_NET_ADMIN in the initial user namespace. A BPF
 * token, which delegates within a user namespace, does not grant that.
 */
static int bpf_napi_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&bpf_napi_kfunc_ids, kfunc_id))
		return 0;
	return capable(CAP_NET_ADMIN) ? 0 : -EPERM;
}

static const struct btf_kfunc_id_set bpf_napi_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_napi_kfunc_ids,
	.filter = bpf_napi_kfunc_filter,
};

/* Syscall programs create BPF kthreads, and a thread's callback is part of
 * the syscall program that created it.
 */
static int __init bpf_napi_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_napi_kfunc_set);
}
late_initcall(bpf_napi_kfunc_init);
