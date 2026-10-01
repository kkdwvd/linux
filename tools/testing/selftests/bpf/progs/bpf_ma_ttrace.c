// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_kfuncs.h"

/* Frees elements with bpf_mem_cache_free() */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 4096);
	__type(key, int);
	__type(value, long);
} htab SEC(".maps");

/* Frees elements with bpf_mem_cache_free_rcu() */
struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 4096);
	__type(key, int);
	__type(value, long);
} rhtab SEC(".maps");

extern const void __per_cpu_offset __ksym;

int nr_cpus;
int nr_caches;
int in_progress;
int not_freed;
int rcu_in_progress;
int not_sent;

/* Look at bpf_mem_cache of every cpu that a map allocates its elements from */
static __always_inline int check_caches(unsigned long cache)
{
	const unsigned long *offsets = &__per_cpu_offset;
	struct bpf_mem_cache *c;
	unsigned long off;
	int cpu;

	nr_caches = 0;
	in_progress = 0;
	not_freed = 0;
	rcu_in_progress = 0;
	not_sent = 0;
	bpf_for(cpu, 0, nr_cpus) {
		if (bpf_probe_read_kernel(&off, sizeof(off), offsets + cpu))
			return -1;
		c = bpf_core_cast((void *)(cache + off), struct bpf_mem_cache);
		if (c->unit_size)
			nr_caches++;
		/* RCU tasks trace GP in flight, objects waiting for it */
		if (c->call_rcu_ttrace_in_progress.counter)
			in_progress++;
		if (c->free_by_rcu_ttrace.first || c->waiting_for_gp_ttrace.first)
			not_freed++;
		/* RCU GP in flight, objects waiting for it */
		if (c->call_rcu_in_progress.counter)
			rcu_in_progress++;
		if (c->free_by_rcu.first || c->free_llist_extra_rcu.first ||
		    c->waiting_for_gp.first)
			not_sent++;
	}
	return 0;
}

SEC("syscall")
int check_ttrace(void *ctx)
{
	struct bpf_htab *h = bpf_core_cast(&htab, struct bpf_htab);

	return check_caches((unsigned long)BPF_CORE_READ(h, ma.cache));
}

SEC("syscall")
int check_rcu(void *ctx)
{
	struct bpf_rhtab *h = bpf_core_cast(&rhtab, struct bpf_rhtab);

	return check_caches((unsigned long)BPF_CORE_READ(h, ma.cache));
}

char _license[] SEC("license") = "GPL";
