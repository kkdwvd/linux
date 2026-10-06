// SPDX-License-Identifier: GPL-2.0
/*
 * Proactive reclaim in BPF: a pool of kernel threads keeps a buffer of free
 * memory by reclaiming from the children of one cgroup, each only as far as
 * its working set allows.
 *
 * A controller thread ticks every cfg.interval_ns. It walks the children of
 * the root cgroup, reads the free page count, and for every child its usage,
 * its memory pressure (the PSI "some" stall time from bpf_psi_total()) and
 * its refaults. The tick's demand is the gap below the buffer plus, once
 * the rate at which free memory drains would reach the buffer within
 * cfg.lead_ns, a tick's worth of that drain: the buffer absorbs the lag of
 * the reaction, the lead keeps the lag short. The demand is split
 * among the children by a weight each earns from its response to the last
 * reclaim: a coldness estimate that grows while memory leaves without
 * refaults and halves when refaults take back a good part of what was
 * reclaimed, or when pressure exceeds the child's target with refaults
 * behind it, which also gates the child out for the tick. Refaults mean the
 * reclaim has reached the working set, which is what the gate protects, the
 * way Senpai and TMO gate theirs; pressure alone does not gate, since a
 * child whose tasks stall in the kernel's own direct reclaim shows pressure
 * without any working set being touched, and holds exactly the cold memory
 * the pool should take. A child gives at most a slice of itself per tick
 * that grows with its coldness, and the coldness grows by an eighth per
 * tick of reclaim without complaint, so that the first probes take little
 * before a refault has had time to arrive.
 *
 * Refaults undercount when a child has been squeezed small: the kernel
 * only counts a refault whose eviction is recent relative to the child's
 * current size. Memory the pool took that is back by the next tick is
 * therefore also measured, as "undone" reclaim, whether it came back as a
 * refault or as a fresh allocation; it is reported, not yet acted on.
 *
 * Bytes do not bound what reclaim costs. A call into a child whose memory
 * is all in use makes the kernel scan the LRU at rising priority to find a
 * few evictable pages, and costs a hundred times the CPU of a call into a
 * cold child. So each child has a CPU budget per tick, which a worker
 * checks before every call, and a child whose reclaim yields less than
 * cfg.min_efficiency bytes per CPU-second, while its scans keep finding
 * pages in use, on three judged ticks in a row is gated as expensive, the
 * same way as one that refaults. Slowness alone is not hotness: a cold page
 * takes two scans to evict, the first clears its referenced bit and rotates
 * it, the second reclaims it, so the first pass over a set nobody has
 * reclaimed from before yields almost nothing for a minute of one CPU per
 * hundred gigabytes. What tells that pass from a hot set is what the scans
 * do to the pages: a hot set's pages are found referenced again and
 * activated, an un-aged cold set's are merely rotated. So a slow tick
 * counts against a child only when its scans activated at least half of
 * what they looked at. The probe pays the aging pass ahead of any burst,
 * which is a reason to leave it on at a small rate. A gated child rests for
 * a time that
 * doubles with every consecutive gate, up to a few seconds, and halves with
 * every tick it serves well, so a child that keeps proving hot is probed
 * ever more rarely.
 *
 * Worker threads sleep on one wait queue, and the controller wakes as many
 * as the demand needs given the measured reclaim throughput of one busy
 * worker, so the pool's active size follows the demand. A worker claims a
 * chunk of a child's quota with
 * a compare-and-swap and calls bpf_proactive_reclaim() until the chunk is
 * done or the child has nothing left to give this tick, in which case the
 * child sits the next tick out. Any worker serves any child.
 *
 * Besides the demand, cfg.probe_ppm asks every child that is under its
 * pressure target for a small fraction of its headroom every second, the
 * fraction shrinking to nothing as pressure approaches the target. This is
 * Senpai's probe: with no deficit at all it trims idle memory away over
 * minutes, each child settling where its pressure meets its target, and the
 * settled usage is the child's working set. The gate and the rest apply to
 * the probe as to everything else, so a child that answers with refaults is
 * left alone and probed more rarely.
 *
 * When free memory has stayed below the buffer for cfg.throttle_ticks
 * ticks, an allocator is outrunning the pool, and cfg.throttle lets the
 * controller set memory.high of the fastest growing child, growth divided
 * by weight, to its usage. Its own tasks then reclaim from its own
 * hierarchy on their way back to user space and are delayed in proportion
 * to the overage, outside any lock, which is the kernel's own answer to a
 * task that allocates faster than memory can be found for it. The limit is
 * lifted once the buffer is back, and on teardown.
 *
 * cfg.per_child gives every child workers of its own instead of, or as
 * well as, the shared pool. The controller creates them inside the child's
 * cgroup the first time it gives the child quota, so that their CPU is
 * charged to the child by membership, and wakes them whenever the child has
 * quota; they serve only their child and exit when it is gone, and the
 * controller sweeps their entries. A child that cannot hold tasks, because
 * it has children of its own with controllers enabled, gets its workers in
 * the pool's cgroup instead, and the fact is counted. The two placements
 * are the two sides of the accounting debate: a thread per child charges
 * by membership and costs a thread per child; a shared pool costs nothing
 * per child and charges nobody.
 *
 * The threads live in the root cgroup unless cfg.pool_cgroup_id names
 * another, in which case cpu.max and cpu.weight there bound what the whole
 * pool may cost, and each worker may be bound to a CPU, to keep reclaim off
 * the CPUs a latency-sensitive workload runs on or to place it on the node
 * whose memory it frees. Nothing charges the pool's time to the children
 * it reclaims for; that is the subject of the remote charging RFC.
 *
 * Children are equal unless the loader says otherwise: a per-child map of
 * overrides, keyed by cgroup ID, carries a floor, a weight that multiplies
 * into the split, a pressure target, a CPU budget, an efficiency floor and
 * a swappiness, or excludes the child. A child's memory.low and memory.min
 * are honoured as a floor of their own: the kernel ignores a cgroup's own
 * protection when that cgroup is the root of a reclaim, as it is here, so
 * the policy has to.
 *
 * Per-child state lives in cgroup storage, so it is freed with the cgroup,
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
#include <bpf/bpf_core_read.h>
#include "reclaim.h"
#include "reclaim_compat.bpf.h"

char _license[] SEC("license") = "GPL";

#define PAGE_SHIFT BPF_RECLAIM_PAGE_SHIFT
#define EWMA_SHIFT 3	/* an eighth of each sample: about a second of history at 100 ms ticks */
#define COLD_MIN 4	/* a gated child keeps a token weight, so it is probed again */
#define COLD_INIT 1024
#define COLD_MAX BPF_RECLAIM_COLD_MAX
#define REFAULT_MIN (256ULL << 10)	/* refaults below this rate are noise, not thrashing */
#define BUSY_MIN 1000000	/* less CPU than this in a tick says nothing about efficiency */
#define REST_MAX_NS 6400000000ULL	/* the longest a child is rested after a gate */
#define NO_LIMIT (~0UL)		/* memory.high "max" */
#define PF_KTHREAD 0x00200000	/* task_struct::flags, not in BTF */
#define CSS_TASK_ITER_PROCS 1	/* css task iterator flag, not in BTF */

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct bpf_reclaim_cgroup);
} cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BPF_RECLAIM_MAX_CGROUPS);
	__type(key, __u64);
	__type(value, struct bpf_reclaim_child_cfg);
} children SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BPF_RECLAIM_MAX_THREADS);
	__type(key, __u32);
	__type(value, struct bpf_reclaim_thread);
} threads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BPF_RECLAIM_MAX_CHILD_THREADS);
	__type(key, struct bpf_reclaim_child_key);
	__type(value, struct bpf_reclaim_child_thread);
} child_threads SEC(".maps");

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

static __always_inline __u64 ewma(__u64 old, __u64 sample)
{
	return old - (old >> EWMA_SHIFT) + (sample >> EWMA_SHIFT);
}

static __always_inline __s64 ewma_s(__s64 old, __s64 sample)
{
	return old - (old >> EWMA_SHIFT) + (sample >> EWMA_SHIFT);
}

/* Bytes over a tick to bytes per second; the tick is in milliseconds. */
static __always_inline __u64 per_second(__u64 bytes, __u64 dt_ms)
{
	return bytes * 1000 / dt_ms;
}

static __always_inline __s64 per_second_s(__s64 bytes, __u64 dt_ms)
{
	if (bytes < 0)
		return -(__s64)per_second(-bytes, dt_ms);
	return per_second(bytes, dt_ms);
}

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

/* The effective configuration of a child: the defaults, overridden per child. */
struct child_cfg {
	__u64 floor;
	__u64 weight;
	__u64 target_ppm;
	__u64 cpu_budget_ppm;
	__u64 min_efficiency;
	__s32 swappiness;
	bool excluded;
};

static __always_inline void child_config(__u64 id, struct child_cfg *out)
{
	struct bpf_reclaim_child_cfg *o;

	out->floor = cfg.floor;
	out->weight = 1;
	out->target_ppm = cfg.target_ppm;
	out->cpu_budget_ppm = cfg.cpu_budget_ppm;
	out->min_efficiency = cfg.min_efficiency;
	out->swappiness = cfg.swappiness;
	out->excluded = false;
	o = bpf_map_lookup_elem(&children, &id);
	if (!o)
		return;
	if (o->flags & BPF_RECLAIM_CHILD_FLOOR)
		out->floor = o->floor;
	if (o->flags & BPF_RECLAIM_CHILD_WEIGHT)
		out->weight = o->weight;
	if (o->flags & BPF_RECLAIM_CHILD_TARGET)
		out->target_ppm = o->target_ppm;
	if (o->flags & BPF_RECLAIM_CHILD_BUDGET)
		out->cpu_budget_ppm = o->cpu_budget_ppm;
	if (o->flags & BPF_RECLAIM_CHILD_EFFICIENCY)
		out->min_efficiency = o->min_efficiency;
	if (o->flags & BPF_RECLAIM_CHILD_SWAPPINESS)
		out->swappiness = o->swappiness;
	if (o->flags & BPF_RECLAIM_CHILD_EXCLUDE)
		out->excluded = true;
	if (!out->weight)
		out->weight = 1;
	if (out->weight > BPF_RECLAIM_WEIGHT_MAX)
		out->weight = BPF_RECLAIM_WEIGHT_MAX;
}

/*
 * One sample of a child: its stall time, usage, protection and refaults.
 * The stall total is U64_MAX when PSI is off, in which case pressure reads
 * as zero and the gate runs on refaults alone.
 */
static __always_inline void read_cgroup(struct cgroup *cgrp, struct mem_cgroup *memcg,
					__u64 *stall, __u64 *usage, __u64 *protected,
					__u64 *refaults, __u64 *scanned, __u64 *stolen,
					__u64 *activated)
{
	unsigned long low, min;

	*stall = bpf_psi_total(cgrp, PSI_MEM_SOME);
	*usage = bpf_mem_cgroup_usage(memcg);
	/* The configured protection, which is at least the effective one. */
	low = memcg->memory.low;
	min = memcg->memory.min;
	*protected = (low > min ? low : min) << PAGE_SHIFT;
	bpf_mem_cgroup_flush_stats(memcg);
	*refaults = bpf_mem_cgroup_page_state(memcg, WORKINGSET_REFAULT_ANON) +
		    bpf_mem_cgroup_page_state(memcg, WORKINGSET_REFAULT_FILE);
	/*
	 * The kernel's own count of what proactive reclaim scanned and freed
	 * in the child, in pages; kernels before the counters read zero.
	 */
	*scanned = *stolen = 0;
	if (bpf_core_enum_value_exists(enum node_stat_item, PGSCAN_PROACTIVE)) {
		*scanned = bpf_mem_cgroup_page_state(memcg, PGSCAN_PROACTIVE);
		*stolen = bpf_mem_cgroup_page_state(memcg, PGSTEAL_PROACTIVE);
	}
	/* Pages a scan found referenced again and moved to the active list. */
	*activated = bpf_mem_cgroup_vm_events(memcg, PGACTIVATE);
}

/*
 * Sample a child at a tick, judge its response to the last reclaim, and
 * decide how much of it is on offer and with what weight. The weight
 * returned is coldness times the headroom in megabytes, kept small enough
 * for the split's arithmetic.
 */
/*
 * Engage or lift memory.high on a child while its memcg is held: @throttle
 * names it as the runaway with the pool behind, @free says whether the
 * buffer is back.
 */
static __always_inline void throttle_cgroup(struct bpf_reclaim_cgroup *cg, struct mem_cgroup *memcg,
					    __u64 usage, __u64 protected, bool throttle, __u64 free)
{
	if (!cfg.throttle || cg->excluded)
		return;
	if (!cg->throttled && throttle && usage > protected) {
		if (!bpf_mem_cgroup_set_high(memcg, usage)) {
			cg->throttled = 1;
			cg->throttles++;
		}
	} else if (cg->throttled && free >= cfg.buffer) {
		bpf_mem_cgroup_set_high(memcg, NO_LIMIT);
		cg->throttled = 0;
	}
	if (cg->throttled)
		cg->throttle_ticks++;
}

static __always_inline int sample_cgroup(__u64 id, __u64 dt_ms, __u64 *weight,
					 __u64 *reclaimed_out, bool throttle, __u64 free,
					 __u64 can_serve)
{
	struct bpf_reclaim_cgroup *cg;
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;
	__u64 stall, usage, protected, refaults, refaulted = 0, reclaimed, undone, pressure = 0;
	__u64 headroom = 0, asked, busy, scanned, stolen, activated, rest_max;
	__u64 scan_delta = 0, act_delta = 0;
	struct child_cfg conf;
	__s64 growth;
	bool thrashing, expensive, in_use;

	*weight = 0;
	*reclaimed_out = 0;
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
	read_cgroup(cgrp, memcg, &stall, &usage, &protected, &refaults, &scanned, &stolen,
		    &activated);

	child_config(id, &conf);
	if (conf.floor > protected)
		protected = conf.floor;
	cg->protected = protected;
	cg->weight = conf.weight;
	cg->target_ppm = conf.target_ppm;
	cg->min_efficiency = conf.min_efficiency;
	cg->swappiness = conf.swappiness;
	cg->excluded = conf.excluded;
	throttle_cgroup(cg, memcg, usage, protected, throttle, free);
	bpf_put_mem_cgroup(memcg);
	bpf_cgroup_release(cgrp);
	cg->budget_ns = cfg.interval_ns / 1000000 * conf.cpu_budget_ppm;
	/* A child seen for the first time gives baselines, not a sample. */
	if (!cg->coldness) {
		cg->coldness = COLD_INIT;
		cg->backoff = 1;
		cg->stall_ns = stall;
		cg->usage = usage;
		cg->refaults = refaults;
		cg->scanned = scanned;
		cg->stolen = stolen;
		cg->activated = activated;
		cg->quota = 0;
		return 0;
	}

	/* Stall nanoseconds over a millisecond tick is the fraction in ppm. */
	if (stall != ~0ULL && stall >= cg->stall_ns)
		pressure = (stall - cg->stall_ns) / dt_ms;
	cg->pressure_ppm = ewma(cg->pressure_ppm, pressure);

	if (refaults >= cg->refaults)
		refaulted = (refaults - cg->refaults) << PAGE_SHIFT;
	cg->refaults_total += refaulted >> PAGE_SHIFT;
	cg->refault_rate = ewma(cg->refault_rate, per_second(refaulted, dt_ms));

	reclaimed = __sync_lock_test_and_set(&cg->tick_reclaimed, 0);
	*reclaimed_out = reclaimed;
	asked = cg->asked;
	cg->asked = 0;
	cg->reclaim_rate = ewma(cg->reclaim_rate, per_second(reclaimed, dt_ms));
	/* Growth is what the child allocated: refaults only take back memory. */
	growth = (__s64)(usage + reclaimed) - (__s64)cg->usage - (__s64)refaulted;
	cg->growth = ewma_s(cg->growth, per_second_s(growth, dt_ms));
	/* Undone is the part of what the pool took that is already back. */
	undone = 0;
	if (reclaimed && usage + reclaimed > cg->usage) {
		undone = usage + reclaimed - cg->usage;
		if (undone > reclaimed)
			undone = reclaimed;
	}
	cg->undone_total += undone;
	cg->undone_rate = ewma(cg->undone_rate, per_second(undone, dt_ms));

	/*
	 * What the tick cost: CPU as a share of one CPU, and bytes per
	 * CPU-second, judged only from a tick that spent enough to tell.
	 */
	busy = __sync_lock_test_and_set(&cg->tick_busy_ns, 0);
	cg->busy_ppm = ewma(cg->busy_ppm, busy / dt_ms);
	if (scanned >= cg->scanned)
		scan_delta = scanned - cg->scanned;
	if (activated >= cg->activated)
		act_delta = activated - cg->activated;
	cg->scanned_total += scan_delta;
	cg->activated_total += act_delta;
	if (stolen >= cg->stolen)
		cg->stolen_total += stolen - cg->stolen;
	/* Scans that activate what they look at have reached memory in use. */
	in_use = scan_delta && act_delta * 2 > scan_delta;
	if (busy >= BUSY_MIN) {
		__u64 sample = reclaimed * 1000 / (busy / 1000000);

		/*
		 * The average is for reporting; the gate judges each tick on
		 * its own, and a slow tick counts only if the scans found the
		 * memory in use, so that an aging pass is paid, not punished.
		 */
		cg->efficiency = cg->efficiency ? ewma(cg->efficiency, sample) : sample;
		if (sample >= conf.min_efficiency)
			cg->costly = 0;
		else if (in_use)
			cg->costly++;
	}
	/* Only a tick that spent CPU on the child is evidence either way. */
	expensive = busy >= BUSY_MIN && cg->costly >= 3;

	cg->usage = usage;
	cg->stall_ns = stall;
	cg->refaults = refaults;
	cg->scanned = scanned;
	cg->stolen = stolen;
	cg->activated = activated;

	/*
	 * The gate: refaults taking back half of what the pool reclaims, or
	 * pressure over the target with refaults behind it, halve the
	 * coldness every tick and keep the child out. Serving at least half
	 * of what was asked, or half of what one worker could serve in the
	 * tick when the ask was more than that, with refaults taking back
	 * less than a quarter of it, grows it by an eighth; a child that was
	 * asked and gave almost nothing is not shown to be cold by that.
	 * Pressure without refaults is the child's own tasks stalling in the
	 * kernel's reclaim, a reason to take more.
	 */
	thrashing = cg->refault_rate > REFAULT_MIN &&
		    (cg->refault_rate * 2 > cg->reclaim_rate ||
		     cg->pressure_ppm > conf.target_ppm);
	cg->gated = thrashing || expensive;
	if (cg->gated) {
		cg->gated_ticks++;
		if (expensive)
			cg->expensive_ticks++;
		cg->coldness = cg->coldness > 2 * COLD_MIN ? cg->coldness / 2 : COLD_MIN;
		/* Rest it, for twice as long as after the last gate, in ticks of this length. */
		rest_max = REST_MAX_NS / cfg.interval_ns;
		if (!rest_max)
			rest_max = 1;
		cg->rest = cg->backoff;
		cg->backoff = cg->backoff < rest_max ? cg->backoff * 2 : rest_max;
	} else if (cg->rest) {
		cg->rest--;
	} else {
		if (asked && (reclaimed >= asked / 2 || reclaimed >= can_serve / 2) &&
		    cg->refault_rate * 4 < cg->reclaim_rate) {
			if (cg->coldness < COLD_MAX)
				cg->coldness += cg->coldness / 8 + 1;
			if (cg->backoff > 1)
				cg->backoff /= 2;
		}
		if (cg->coldness > COLD_MAX)
			cg->coldness = COLD_MAX;
		/*
		 * On offer is the usage above the protected part, unless a
		 * worker found the child empty since the last tick: then it
		 * sits this tick out rather than drawing quota it cannot
		 * serve. Less than a chunk is not worth a share of the demand.
		 */
		if (usage > protected && !cg->exhausted && !conf.excluded)
			headroom = usage - protected;
		/*
		 * A child that has been gated and has not since proved itself
		 * gets no second call while one is still running, longer than
		 * the tick; a hot set is probed one call at a time. A child
		 * never gated may have several, so that the aging pass over a
		 * large cold set is shared by the workers rather than made by
		 * one; and a proven child is served on regardless, since a
		 * worker on cold memory is always mid-call when the tick comes.
		 */
		if (cg->inflight && cg->coldness <= COLD_INIT && cg->gated_ticks)
			headroom = 0;
		if (headroom < cfg.chunk)
			headroom = 0;
	}
	cg->exhausted = 0;
	cg->headroom = headroom;
	cg->share = conf.weight * cg->coldness * (headroom >> 20);
	cg->quota = 0;
	*weight = cg->share;
	return 0;
}

static void child_workers_wake(__u64 id);
static long sweep_cb(struct bpf_map *map, const void *key, void *value, void *ctx);

/*
 * The probe: the fraction of a child's headroom to ask for over a tick
 * beyond the demand, scaled by how far its pressure sits below its target.
 */
static __always_inline __u64 probe_quota(struct bpf_reclaim_cgroup *cg, __u64 dt_ms)
{
	__u64 per_tick, room;

	if (!cfg.probe_ppm || !cg->headroom || cg->pressure_ppm >= cg->target_ppm)
		return 0;
	per_tick = cg->headroom / 1000000 * cfg.probe_ppm * dt_ms / 1000;
	room = cg->target_ppm - cg->pressure_ppm;
	return per_tick * room / cg->target_ppm;
}

/*
 * Give a child its share of the demand, in proportion to its weight and up
 * to a slice of its headroom: a quarter of it for a fully cold child, less
 * in proportion to a smaller coldness. The probe's ask comes on top.
 */
static __always_inline __u64 set_quota(__u64 id, __u64 demand, __u64 total, __u32 shift,
				       __u64 dt_ms)
{
	struct bpf_reclaim_cgroup *cg;
	struct cgroup *cgrp;
	__u64 quota = 0, slice, probe;

	cgrp = bpf_cgroup_from_id(id);
	if (!cgrp)
		return 0;
	cg = bpf_cgrp_storage_get(&cgroups, cgrp, 0, 0);
	if (cg && cg->share) {
		/*
		 * demand * share / total without a 128-bit product: the shares
		 * are brought below 32 bits by the caller's shift, the ratio is
		 * scaled to 20 bits, which is exact to a millionth, and the
		 * product stays within 64 bits for a demand below 16 TiB.
		 */
		if (!demand)
			quota = 0;
		else if (cg->share >= total)
			quota = demand;
		else
			quota = (demand * (((cg->share >> shift) << 20) / (total >> shift))) >> 20;
		slice = (cg->headroom >> 2) / COLD_MAX * cg->coldness;
		if (quota > slice)
			quota = slice;
		probe = probe_quota(cg, dt_ms);
		quota += probe;
		quota &= ~(BPF_RECLAIM_PAGE_SIZE - 1);
		cg->quota = quota;
		cg->asked = quota;
		cg->quota_given += quota;
		cg->probed += probe;
	}
	bpf_cgroup_release(cgrp);
	if (quota && cfg.per_child)
		child_workers_wake(id);
	return quota;
}

/* A child's smoothed growth divided by its weight: the runaway ranking. */
static __always_inline __s64 growth_per_weight(__u64 id)
{
	struct bpf_reclaim_cgroup *cg;
	struct cgroup *cgrp;
	__s64 growth = 0;

	cgrp = bpf_cgroup_from_id(id);
	if (!cgrp)
		return 0;
	cg = bpf_cgrp_storage_get(&cgroups, cgrp, 0, 0);
	/* Only growth ranks, and BPF has no signed division before cpu v4. */
	if (cg && !cg->excluded && cg->weight && cg->growth > 0)
		growth = (__u64)cg->growth / cg->weight;
	bpf_cgroup_release(cgrp);
	return growth;
}

/* The pool's throughput per busy worker, from the workers' own tallies. */
static __always_inline void measure_capacity(struct bpf_reclaim_control *c)
{
	struct bpf_reclaim_thread *t;
	__u64 busy = 0, reclaimed = 0;
	int i;

	bpf_for(i, 0, cfg.pool) {
		t = bpf_map_lookup_elem(&threads, &i);
		if (!t)
			break;
		busy += t->busy_ns;
		reclaimed += t->reclaimed;
	}
	if (busy > c->pool_busy && reclaimed > c->pool_reclaimed)
		c->capacity = ewma(c->capacity, per_second(reclaimed - c->pool_reclaimed,
							   (busy - c->pool_busy) / 1000000 + 1));
	c->pool_busy = busy;
	c->pool_reclaimed = reclaimed;
}

/*
 * The controller's tick: find the children, sample them, turn the
 * free-memory deficit and the forecast drain into demand, split it into
 * quotas, wake enough workers, sleep.
 */
static int control_cb(void *map, int *key, void *value)
{
	struct bpf_reclaim_control *c = value;
	struct bpf_reclaim_pool *p;
	__u64 now, dt_ms, free, demand, weight, reclaimed, lose, pred, cap, per_worker;
	__u64 total = 0, quota = 0, tick_reclaimed = 0, runaway = 0;
	__s64 drain, max_growth = 0, growth;
	__u32 zero = 0, seq, k, n, shift = 0;
	bool behind;
	int i;

	p = bpf_map_lookup_elem(&pool, &zero);
	if (!p)
		return 1;
	seq = bpf_waitq_sequence(&c->tick);
	now = bpf_ktime_get_ns();
	dt_ms = (now - c->last_ns) / 1000000;
	if (!dt_ms)
		dt_ms = 1;
	c->last_ns = now;
	c->ticks++;

	discover(c);
	free = bpf_global_zone_page_state(NR_FREE_PAGES);
	if (free < c->free_min)
		c->free_min = free;
	/* The pool is behind once the buffer has been breached for a while. */
	behind = cfg.throttle && cfg.throttle_ticks && c->deficit_run >= cfg.throttle_ticks;
	if (behind)
		c->behind_ticks++;

	n = c->nr_cgroups;
	bpf_for(i, 0, n) {
		if (i >= BPF_RECLAIM_MAX_CGROUPS)
			break;
		if (!sample_cgroup(c->ids[i], dt_ms, &weight, &reclaimed,
				   behind && c->ids[i] == c->runaway, free,
				   c->capacity * dt_ms / 1000)) {
			total += weight;
			tick_reclaimed += reclaimed;
			/* The one to throttle next tick if the pool stays behind. */
			growth = growth_per_weight(c->ids[i]);
			if (growth > max_growth) {
				max_growth = growth;
				runaway = c->ids[i];
			}
		}
	}
	measure_capacity(c);
	/*
	 * A runaway grows by a good part of what the whole pool can reclaim
	 * in a second, so that no pool size would keep up with it for long.
	 */
	cap = (cfg.pool ? cfg.pool : cfg.per_child) * c->capacity;
	if (cfg.max_rate && cfg.max_rate < cap)
		cap = cfg.max_rate;
	cap /= 4;
	if (cap < (4ULL << 20))
		cap = 4ULL << 20;
	c->runaway = max_growth > (__s64)cap ? runaway : 0;

	/* Free memory lost over the tick, net of what the pool put back. */
	drain = (__s64)(c->free + tick_reclaimed) - (__s64)free;
	c->drain_rate = ewma_s(c->drain_rate, per_second_s(drain, dt_ms));
	c->free = free;
	c->reclaimed += tick_reclaimed;

	/*
	 * The demand closes the gap below the buffer, and matches the drain
	 * as soon as the drain would reach the buffer within the lead.
	 */
	demand = free < cfg.buffer ? cfg.buffer - free : 0;
	if (demand) {
		c->deficit_ticks++;
		c->deficit_run++;
	} else {
		c->deficit_run = 0;
	}
	if (c->drain_rate > 0) {
		lose = (__u64)c->drain_rate * (cfg.lead_ns / 1000000) / 1000;
		pred = lose < free ? free - lose : 0;
		if (pred < cfg.buffer) {
			if (!demand)
				c->lead_ticks++;
			demand += (__u64)c->drain_rate * dt_ms / 1000;
		}
	}
	if (cfg.max_rate) {
		cap = cfg.max_rate * dt_ms / 1000;
		if (demand > cap)
			demand = cap;
	}
	c->demand = demand;

	if ((demand || cfg.probe_ppm) && total) {
		/* Bring the shares below 32 bits for the split's arithmetic. */
		bpf_repeat(64) {
			if ((total >> shift) < (1ULL << 32))
				break;
			shift++;
		}
		bpf_for(i, 0, n) {
			if (i >= BPF_RECLAIM_MAX_CGROUPS)
				break;
			quota += set_quota(c->ids[i], demand, total, shift, dt_ms);
		}
	}

	/* Wake as many workers as the quota needs at the measured throughput. */
	c->awake = 0;
	if (quota) {
		k = 1;
		per_worker = c->capacity * dt_ms / 1000;
		if (per_worker)
			k = (quota + per_worker - 1) / per_worker;
		if (k > cfg.pool)
			k = cfg.pool;
		if (!k)
			k = 1;
		c->awake = k;
		c->wakeups += k;
		bpf_waitq_wake(&p->work, k, 0);
	}
	k = c->awake < BPF_RECLAIM_AWAKE_BUCKETS ? c->awake : BPF_RECLAIM_AWAKE_BUCKETS - 1;
	c->awake_ticks[k]++;

	if (cfg.per_child) {
		int all = 0;

		bpf_for_each_map_elem(&child_threads, sweep_cb, &all, 0);
	}

	bpf_waitq_wait_event(&c->tick, seq, cfg.interval_ns);
	return 0;
}

/* Take up to a chunk of a child's quota, racing the other workers. */
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

/* Serve one child: claim a chunk and reclaim it. True if there was work. */
static __always_inline bool serve(struct bpf_reclaim_thread *t, __u64 id)
{
	struct bpf_reclaim_cgroup *cg;
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;
	__u64 take, done = 0, busy, start;
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

	busy = 0;
	__sync_fetch_and_add(&cg->inflight, 1);
	while (done < take && can_loop) {
		/* Over the child's CPU budget for the tick: leave it be. */
		if (cg->tick_busy_ns >= cg->budget_ns) {
			__sync_fetch_and_add(&cg->budget_hits, 1);
			cg->quota = 0;
			break;
		}
		start = bpf_ktime_get_ns();
		ret = bpf_proactive_reclaim(memcg, take - done, cg->swappiness);
		start = bpf_ktime_get_ns() - start;
		busy += start;
		__sync_fetch_and_add(&cg->tick_busy_ns, start);
		__sync_fetch_and_add(&cg->calls, 1);
		if (ret <= 0) {
			/* Nothing left this tick: drop the rest of the quota. */
			__sync_fetch_and_add(&cg->empty, 1);
			cg->exhausted = 1;
			cg->quota = 0;
			break;
		}
		done += ret;
		/*
		 * A call that took long for little says the child's memory is
		 * in use: end the chunk here rather than repeat it, and let
		 * the tick's judgement rest the child.
		 */
		if (start >= BUSY_MIN && (__u64)ret * 1000 / (start / 1000000) < cg->min_efficiency) {
			__sync_fetch_and_add(&cg->slow_calls, 1);
			cg->quota = 0;
			break;
		}
	}
	__sync_fetch_and_sub(&cg->inflight, 1);
	bpf_put_mem_cgroup(memcg);

	t->busy_ns += busy;
	t->reclaimed += done;
	__sync_fetch_and_add(&cg->busy_ns, busy);
	__sync_fetch_and_add(&cg->reclaimed, done);
	__sync_fetch_and_add(&cg->tick_reclaimed, done);
	bpf_cgroup_release(cgrp);
	return true;
}

/*
 * A worker's iteration: serve every child with quota, then sleep on the
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

/*
 * True when nothing but kernel threads is left in a child. A worker that
 * stayed would keep the cgroup populated and block its removal, which is
 * the objection to threads per cgroup; so a worker leaves when its child's
 * processes have.
 */
static __always_inline bool child_is_empty(struct cgroup *cgrp)
{
	struct task_struct *task;
	bool empty = true;

	bpf_for_each(css_task, task, &cgrp->self, CSS_TASK_ITER_PROCS) {
		if (!(task->flags & PF_KTHREAD)) {
			empty = false;
			break;
		}
	}
	return empty;
}

/*
 * A per-child worker's iteration: serve its child, sleep on its own wait
 * queue; exit once the child is gone or empty, so that it can be removed.
 */
static int child_worker_cb(void *map, int *key, void *value)
{
	struct bpf_reclaim_child_thread *v = value;
	struct cgroup *cgrp;
	bool empty;
	__u32 seq;

	seq = bpf_waitq_sequence(&v->wake);
	v->t.rounds++;
	if (serve(&v->t, v->cgroup_id))
		return 0;
	cgrp = bpf_cgroup_from_id(v->cgroup_id);
	if (!cgrp)
		return 1;
	empty = child_is_empty(cgrp);
	bpf_cgroup_release(cgrp);
	if (empty)
		return 1;
	v->t.sleeps++;
	bpf_waitq_wait_event(&v->wake, seq, ~0ULL);
	return 0;
}

/* Create a child's worker, inside the child if it will have it. */
static __always_inline void child_worker_create(struct bpf_reclaim_control *c,
						struct bpf_reclaim_child_key *key)
{
	struct bpf_reclaim_child_thread init = {}, *v;
	int ret;

	init.cgroup_id = key->cgroup_id;
	init.t.index = key->index;
	init.t.cpu = -1;
	if (bpf_map_update_elem(&child_threads, key, &init, BPF_NOEXIST))
		return;
	v = bpf_map_lookup_elem(&child_threads, key);
	if (!v)
		return;
	ret = bpf_waitq_init(&v->wake, &child_threads, 0);
	if (!ret) {
		ret = bpf_kthread_create(&v->t.kthread, &child_threads, key->cgroup_id,
					 child_worker_cb);
		if (!ret) {
			v->placed = 1;
		} else {
			ret = bpf_kthread_create(&v->t.kthread, &child_threads,
						 cfg.pool_cgroup_id, child_worker_cb);
			if (!ret)
				c->child_misplaced++;
		}
	}
	if (!ret)
		ret = bpf_kthread_start(&v->t.kthread, 0);
	if (ret) {
		bpf_map_delete_elem(&child_threads, key);
		return;
	}
	c->child_threads++;
}

/* Wake a child's workers, creating them the first time. */
static void child_workers_wake(__u64 id)
{
	struct bpf_reclaim_child_key key = { .cgroup_id = id };
	struct bpf_reclaim_child_thread *v;
	struct bpf_reclaim_control *c;
	__u32 zero = 0;
	int i;

	c = bpf_map_lookup_elem(&control, &zero);
	if (!c)
		return;
	bpf_for(i, 0, cfg.per_child) {
		key.index = i;
		v = bpf_map_lookup_elem(&child_threads, &key);
		if (v)
			bpf_waitq_wake(&v->wake, 1, 0);
		else
			child_worker_create(c, &key);
	}
}

/*
 * Remove the workers of children that are gone; with @ctx pointing at a
 * nonzero flag, all of them. The flag lives on the caller's stack, which is
 * the only kind of context the iteration helper accepts.
 */
static long sweep_cb(struct bpf_map *map, const void *key, void *value, void *ctx)
{
	const struct bpf_reclaim_child_key *k = key;
	struct bpf_reclaim_control *c;
	struct cgroup *cgrp;
	__u32 zero = 0;
	int *all = ctx;

	if (!all)
		return 1;
	if (!*all) {
		cgrp = bpf_cgroup_from_id(k->cgroup_id);
		if (cgrp) {
			bpf_cgroup_release(cgrp);
			return 0;
		}
		c = bpf_map_lookup_elem(&control, &zero);
		if (c)
			c->child_swept++;
	}
	bpf_map_delete_elem(&child_threads, k);
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
	c->capacity = 64ULL << 20;	/* a starting guess; measured from the first work */

	bpf_for(i, 0, cfg.pool) {
		t = bpf_map_lookup_elem(&threads, &i);
		if (!t)
			return -E2BIG;
		t->index = i;
		ret = bpf_kthread_create(&t->kthread, &threads, cfg.pool_cgroup_id, worker_cb);
		if (ret)
			return ret;
		if (t->cpu >= 0) {
			ret = bpf_kthread_bind(&t->kthread, t->cpu);
			if (ret)
				return ret;
		}
	}
	ret = bpf_kthread_create(&c->kthread, &control, cfg.pool_cgroup_id, control_cb);
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

/* Lift a memory.high the policy set on a child. */
static __always_inline void unthrottle_cgroup(__u64 id)
{
	struct bpf_reclaim_cgroup *cg;
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(id);
	if (!cgrp)
		return;
	cg = bpf_cgrp_storage_get(&cgroups, cgrp, 0, 0);
	if (cg && cg->throttled) {
		memcg = bpf_get_mem_cgroup(&cgrp->self);
		if (memcg) {
			bpf_mem_cgroup_set_high(memcg, NO_LIMIT);
			bpf_put_mem_cgroup(memcg);
		}
		cg->throttled = 0;
	}
	bpf_cgroup_release(cgrp);
}

SEC("syscall")
int reclaim_teardown(void *ctx)
{
	struct bpf_reclaim_control *c;
	struct bpf_reclaim_thread *t;
	__u32 zero = 0, n;
	int i;

	/* The controller first, so it neither wakes workers nor throttles anew. */
	c = bpf_map_lookup_elem(&control, &zero);
	if (c)
		bpf_kthread_stop(&c->kthread, 0);
	bpf_for(i, 0, cfg.pool) {
		t = bpf_map_lookup_elem(&threads, &i);
		if (!t)
			break;
		bpf_kthread_stop(&t->kthread, 0);
	}
	/* The per-child workers stop as their entries go. */
	if (cfg.per_child) {
		int all = 1;

		bpf_for_each_map_elem(&child_threads, sweep_cb, &all, 0);
	}
	/* Lift any memory.high the policy set. */
	if (c && cfg.throttle) {
		n = c->nr_cgroups;
		bpf_for(i, 0, n) {
			if (i >= BPF_RECLAIM_MAX_CGROUPS)
				break;
			unthrottle_cgroup(c->ids[i]);
		}
	}
	return 0;
}
