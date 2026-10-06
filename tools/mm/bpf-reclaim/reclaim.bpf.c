// SPDX-License-Identifier: GPL-2.0
/*
 * Proactive reclaim in BPF: a pool of kernel threads keeps a buffer of free
 * memory by reclaiming from the children of one cgroup.
 *
 * A controller thread ticks every cfg.interval_ns. It walks the children of
 * the root cgroup, reads the free page count and each child's usage, and
 * turns the gap below the buffer into a demand in bytes. The demand is split
 * among the children in proportion to what each has above the floor, which
 * is the kernel's own rule for distributing reclaim pressure. Worker threads
 * sleep on one wait queue, and the controller wakes as many as the demand
 * has chunks. A worker claims a chunk of a cgroup's quota with a
 * compare-and-swap and calls bpf_proactive_reclaim() until the chunk is done
 * or the cgroup has nothing left to give this tick. Any worker serves any
 * cgroup.
 *
 * Per-cgroup state lives in cgroup storage, so it is freed with the cgroup,
 * and a child that appears or disappears needs no help from user space: the
 * controller publishes the IDs it found at the last tick, and the workers
 * look each one up again, skipping any that has gone.
 *
 * The threads are created by a syscall program because that is the one
 * program type allowed to call bpf_proactive_reclaim(): other sleepable
 * programs may run with filesystem locks held that the shrinkers it runs can
 * deadlock against.
 */
#include "vmlinux.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_helpers.h>
#include "reclaim.h"
#include "reclaim_compat.bpf.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct bpf_reclaim_cgroup);
} cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BPF_RECLAIM_MAX_THREADS);
	__type(key, __u32);
	__type(value, struct bpf_reclaim_thread);
} threads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bpf_reclaim_control);
} control SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bpf_reclaim_pool);
} pool SEC(".maps");

/* Set by the loader before the setup program runs. */
struct bpf_reclaim_cfg cfg;

/*
 * Snapshot the IDs of the root's children. The walk needs RCU, which rules
 * out the sleepable kfuncs, so the rest of the tick works from the IDs.
 */
static int discover(struct bpf_reclaim_control *c)
{
	struct cgroup_subsys_state *pos;
	struct cgroup *root;
	__u32 n = 0;

	root = bpf_cgroup_from_id(cfg.root_cgroup_id);
	if (!root) {
		c->nr_cgroups = 0;
		return -ENOENT;
	}
	bpf_rcu_read_lock();
	bpf_for_each(css, pos, &root->self, BPF_CGROUP_ITER_CHILDREN) {
		if (n >= BPF_RECLAIM_MAX_CGROUPS)
			break;
		/*
		 * The mask bounds every store on its own; without it the
		 * compiler walks a pointer in step with n and the verifier
		 * cannot relate the two across the iterator's loop. The
		 * barrier keeps the compiler from proving the mask redundant
		 * from the check above and dropping it again.
		 */
		barrier_var(n);
		c->ids[n & (BPF_RECLAIM_MAX_CGROUPS - 1)] = pos->cgroup->kn->id;
		n++;
	}
	bpf_rcu_read_unlock();
	bpf_cgroup_release(root);
	c->nr_cgroups = n;
	return 0;
}

/* Sample a cgroup at a tick and decide how much of it is on offer. */
static __always_inline int sample_cgroup(__u64 id, __u64 *offered)
{
	struct bpf_reclaim_cgroup *cg;
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;
	__u64 usage, headroom = 0;

	cgrp = bpf_cgroup_from_id(id);
	if (!cgrp)
		return -ENOENT;
	cg = bpf_cgrp_storage_get(&cgroups, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cg) {
		bpf_cgroup_release(cgrp);
		return -ENOMEM;
	}
	memcg = bpf_get_mem_cgroup(&cgrp->self);
	if (!memcg) {
		bpf_cgroup_release(cgrp);
		return -ENOENT;
	}
	usage = bpf_mem_cgroup_usage(memcg);
	bpf_put_mem_cgroup(memcg);

	/*
	 * On offer is the usage above the floor, unless a worker found the
	 * cgroup empty since the last tick: then it sits this tick out rather
	 * than drawing quota it cannot serve. Less than a chunk is not worth
	 * a share of the demand.
	 */
	if (usage > cfg.floor && !cg->exhausted)
		headroom = usage - cfg.floor;
	if (headroom < cfg.chunk)
		headroom = 0;
	cg->usage = usage;
	cg->headroom = headroom;
	cg->exhausted = 0;
	cg->quota = 0;
	bpf_cgroup_release(cgrp);
	*offered = headroom;
	return 0;
}

/* Give a cgroup its share of the demand, in proportion to its headroom. */
static __always_inline __u64 set_quota(__u64 id, __u64 demand, __u64 total)
{
	struct bpf_reclaim_cgroup *cg;
	struct cgroup *cgrp;
	__u64 quota = 0, headroom;

	cgrp = bpf_cgroup_from_id(id);
	if (!cgrp)
		return 0;
	cg = bpf_cgrp_storage_get(&cgroups, cgrp, 0, 0);
	if (cg && cg->headroom) {
		headroom = cg->headroom;
		/*
		 * headroom * demand / total without a 128-bit product: the
		 * ratio is scaled to 20 bits, which is exact to a millionth
		 * and keeps the product within 64 bits below 16 TiB.
		 */
		if (demand >= total)
			quota = headroom;
		else
			quota = (headroom * ((demand << 20) / total)) >> 20;
		quota &= ~(BPF_RECLAIM_PAGE_SIZE - 1);
		cg->quota = quota;
		cg->quota_given += quota;
	}
	bpf_cgroup_release(cgrp);
	return quota;
}

/*
 * The controller's tick: find the cgroups, turn the free-memory deficit into
 * demand, split it into per-cgroup quotas, wake enough workers, sleep.
 */
static int control_cb(void *map, int *key, void *value)
{
	struct bpf_reclaim_control *c = value;
	struct bpf_reclaim_pool *p;
	__u64 free, demand, offered, total = 0, quota = 0;
	__u32 zero = 0, seq, k, n;
	int i;

	p = bpf_map_lookup_elem(&pool, &zero);
	if (!p)
		return 1;
	seq = bpf_waitq_sequence(&c->tick);
	c->ticks++;

	discover(c);
	free = bpf_global_zone_page_state(NR_FREE_PAGES);
	c->free = free;
	if (free < c->free_min)
		c->free_min = free;
	demand = free < cfg.buffer ? cfg.buffer - free : 0;
	if (demand)
		c->deficit_ticks++;
	c->demand = demand;

	n = c->nr_cgroups;
	bpf_for(i, 0, n) {
		if (i >= BPF_RECLAIM_MAX_CGROUPS)
			break;
		if (!sample_cgroup(c->ids[i], &offered))
			total += offered;
	}
	if (demand && total) {
		bpf_for(i, 0, n) {
			if (i >= BPF_RECLAIM_MAX_CGROUPS)
				break;
			quota += set_quota(c->ids[i], demand, total);
		}
	}

	c->awake = 0;
	if (quota) {
		k = (quota + cfg.chunk - 1) / cfg.chunk;
		if (k > cfg.pool)
			k = cfg.pool;
		c->awake = k;
		c->wakeups += k;
		bpf_waitq_wake(&p->work, k, 0);
	}

	c->last_ns = bpf_ktime_get_ns();
	bpf_waitq_wait_event(&c->tick, seq, cfg.interval_ns);
	return 0;
}

/* Take up to a chunk of a cgroup's quota, racing the other workers. */
static __always_inline __u64 claim(struct bpf_reclaim_cgroup *cg)
{
	__u64 old = cg->quota, seen, take;

	while (old && can_loop) {
		take = old < cfg.chunk ? old : cfg.chunk;
		seen = __sync_val_compare_and_swap(&cg->quota, old, old - take);
		if (seen == old)
			return take;
		old = seen;
	}
	return 0;
}

/* Serve one cgroup: claim a chunk and reclaim it. True if there was work. */
static __always_inline bool serve(struct bpf_reclaim_thread *t, __u64 id)
{
	struct bpf_reclaim_cgroup *cg;
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;
	__u64 take, done = 0, busy;
	long ret;

	cgrp = bpf_cgroup_from_id(id);
	if (!cgrp)
		return false;
	cg = bpf_cgrp_storage_get(&cgroups, cgrp, 0, 0);
	if (!cg) {
		bpf_cgroup_release(cgrp);
		return false;
	}
	take = claim(cg);
	if (!take) {
		bpf_cgroup_release(cgrp);
		return false;
	}
	t->claims++;
	memcg = bpf_get_mem_cgroup(&cgrp->self);
	if (!memcg) {
		cg->quota = 0;
		bpf_cgroup_release(cgrp);
		return true;
	}

	busy = bpf_ktime_get_ns();
	while (done < take && can_loop) {
		ret = bpf_proactive_reclaim(memcg, take - done, cfg.swappiness);
		__sync_fetch_and_add(&cg->calls, 1);
		if (ret <= 0) {
			/* Nothing left this tick: drop the rest of the quota. */
			__sync_fetch_and_add(&cg->empty, 1);
			cg->exhausted = 1;
			cg->quota = 0;
			break;
		}
		done += ret;
	}
	busy = bpf_ktime_get_ns() - busy;
	bpf_put_mem_cgroup(memcg);

	t->busy_ns += busy;
	t->reclaimed += done;
	__sync_fetch_and_add(&cg->busy_ns, busy);
	__sync_fetch_and_add(&cg->reclaimed, done);
	bpf_cgroup_release(cgrp);
	return true;
}

/*
 * A worker's iteration: serve every cgroup with quota, then sleep on the
 * pool's wait queue. The sequence sampled first makes a wakeup that lands
 * during the scan return from the wait at once.
 */
static int worker_cb(void *map, int *key, void *value)
{
	struct bpf_reclaim_thread *t = value;
	struct bpf_reclaim_control *c;
	struct bpf_reclaim_pool *p;
	__u32 zero = 0, seq, n;
	bool found = false;
	int i;

	p = bpf_map_lookup_elem(&pool, &zero);
	c = bpf_map_lookup_elem(&control, &zero);
	if (!p || !c)
		return 1;
	seq = bpf_waitq_sequence(&p->work);
	t->rounds++;

	n = c->nr_cgroups;
	bpf_for(i, 0, n) {
		if (i >= BPF_RECLAIM_MAX_CGROUPS)
			break;
		if (serve(t, c->ids[i]))
			found = true;
	}
	if (!found) {
		t->sleeps++;
		bpf_waitq_wait_event(&p->work, seq, ~0ULL);
	}
	return 0;
}

SEC("syscall")
int reclaim_setup(void *ctx)
{
	struct bpf_reclaim_control *c;
	struct bpf_reclaim_pool *p;
	struct bpf_reclaim_thread *t;
	__u32 zero = 0;
	int ret, i;

	c = bpf_map_lookup_elem(&control, &zero);
	p = bpf_map_lookup_elem(&pool, &zero);
	if (!c || !p)
		return -E2BIG;
	ret = bpf_waitq_init(&c->tick, &control, 0);
	if (ret)
		return ret;
	ret = bpf_waitq_init(&p->work, &pool, 0);
	if (ret)
		return ret;
	c->last_ns = bpf_ktime_get_ns();
	c->free = bpf_global_zone_page_state(NR_FREE_PAGES);
	c->free_min = c->free;

	bpf_for(i, 0, cfg.pool) {
		t = bpf_map_lookup_elem(&threads, &i);
		if (!t)
			return -E2BIG;
		t->index = i;
		ret = bpf_kthread_create(&t->kthread, &threads, 0, worker_cb);
		if (ret)
			return ret;
	}
	ret = bpf_kthread_create(&c->kthread, &control, 0, control_cb);
	if (ret)
		return ret;

	bpf_for(i, 0, cfg.pool) {
		t = bpf_map_lookup_elem(&threads, &i);
		if (!t)
			return -E2BIG;
		ret = bpf_kthread_start(&t->kthread, 0);
		if (ret)
			return ret;
	}
	return bpf_kthread_start(&c->kthread, 0);
}

SEC("syscall")
int reclaim_teardown(void *ctx)
{
	struct bpf_reclaim_control *c;
	struct bpf_reclaim_thread *t;
	__u32 zero = 0;
	int i;

	/* The controller first, so it wakes no more workers. */
	c = bpf_map_lookup_elem(&control, &zero);
	if (c)
		bpf_kthread_stop(&c->kthread, 0);
	bpf_for(i, 0, cfg.pool) {
		t = bpf_map_lookup_elem(&threads, &i);
		if (!t)
			break;
		bpf_kthread_stop(&t->kthread, 0);
	}
	return 0;
}
