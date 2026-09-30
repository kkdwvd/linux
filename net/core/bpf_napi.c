// SPDX-License-Identifier: GPL-2.0-only
/*
 * kfuncs that hand NAPI instances to BPF pollers.
 *
 * A NAPI is named by its ID, as reported by netlink and SO_INCOMING_NAPI_ID,
 * and resolved under RCU on every call, so a poller keeps no kernel pointer
 * across its sleeps. See napi_bpf_bind_locked() for the scheduling model.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/netdevice.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <net/netdev_lock.h>

#include "dev.h"

__bpf_kfunc_start_defs();

/**
 * bpf_napi_bind - route a NAPI's scheduling to a BPF poller
 * @napi_id: NAPI to bind, in the caller's network namespace
 * @waitq: wait queue to signal whenever the NAPI is scheduled
 * @flags: must be 0
 *
 * Binding a NAPI that is already bound moves it to @waitq; work pending for
 * the previous poller is signalled to the new one.
 *
 * Return: 0 on success. -EINVAL for bad flags or an uninitialized wait
 * queue, -ENOENT when no such NAPI exists, -EBUSY when the NAPI runs in
 * native threaded mode, -EOPNOTSUPP on PREEMPT_RT.
 */
__bpf_kfunc int bpf_napi_bind(u32 napi_id, struct bpf_waitq *waitq, u64 flags)
{
	struct bpf_waitq_kern *kern;
	struct napi_struct *napi;
	int err;

	if (flags)
		return -EINVAL;

	kern = bpf_waitq_get(waitq);
	if (!kern)
		return -EINVAL;

	napi = netdev_napi_by_id_lock(current->nsproxy->net_ns, napi_id);
	if (!napi) {
		bpf_waitq_put(kern);
		return -ENOENT;
	}
	err = napi_bpf_bind_locked(napi, kern);
	netdev_unlock(napi->dev);
	if (err)
		bpf_waitq_put(kern);
	return err;
}

/**
 * bpf_napi_unbind - return a NAPI to native scheduling
 * @napi_id: NAPI to unbind, in the caller's network namespace
 *
 * Work pending for the poller is serviced natively. Unbinding a NAPI that
 * is not bound succeeds.
 *
 * Return: 0 on success, -ENOENT when no such NAPI exists.
 */
__bpf_kfunc int bpf_napi_unbind(u32 napi_id)
{
	struct napi_struct *napi;

	napi = netdev_napi_by_id_lock(current->nsproxy->net_ns, napi_id);
	if (!napi)
		return -ENOENT;
	napi_bpf_unbind_locked(napi);
	netdev_unlock(napi->dev);
	return 0;
}

/**
 * bpf_napi_poll - service a bound NAPI once
 * @napi_id: NAPI bound with bpf_napi_bind()
 * @flags: BPF_NAPI_POLL_F_BUSY or 0
 *
 * Runs the driver's poll once if the NAPI is pending for its poller. The
 * driver re-arms its interrupt when it completes; the poller must call
 * again while BPF_NAPI_POLL_MORE is set in the result.
 *
 * With BPF_NAPI_POLL_F_BUSY the NAPI stays scheduled with its interrupt
 * masked, so the result always carries BPF_NAPI_POLL_MORE and the poller
 * sees new packets only by polling again; a busy poll also takes an idle
 * NAPI instead of returning -EAGAIN. A later poll without the flag lets
 * the driver complete and re-arm.
 *
 * Return: the work done ORed with BPF_NAPI_POLL_MORE when the NAPI is
 * still scheduled. -EAGAIN when nothing is pending, -ENOENT when no NAPI
 * with this ID is bound, -EINVAL for bad flags.
 */
__bpf_kfunc int bpf_napi_poll(u32 napi_id, u64 flags)
{
	int ret;

	if (flags & ~(u64)BPF_NAPI_POLL_F_BUSY)
		return -EINVAL;

	ret = napi_bpf_poll(napi_id, flags & BPF_NAPI_POLL_F_BUSY);
	/* A poller that spins on a busy NAPI must still yield on voluntary-preemption kernels. */
	cond_resched();
	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_napi_kfunc_ids)
BTF_ID_FLAGS(func, bpf_napi_bind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_napi_unbind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_napi_poll, KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_napi_kfunc_ids)

static const struct btf_kfunc_id_set bpf_napi_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_napi_kfunc_ids,
};

static int __init bpf_napi_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_napi_kfunc_set);
}
late_initcall(bpf_napi_kfunc_init);
