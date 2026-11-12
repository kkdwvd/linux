// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/*
 * network-stack: run a device's NAPI processing on a pool of BPF kthreads
 * whose size follows the load.
 *
 * The pool is kept per last-level cache. The NAPIs whose interrupts arrive in
 * one LLC are served by threads on CPUs of that LLC and never leave it, so a
 * packet is processed next to the application threads that will read it. The
 * LLC's pool CPUs are ranked, both hyperthreads of a core before the next
 * core, and the active threads are always the first ones of that order: the
 * pool grows by taking the next CPU and shrinks by giving the last one back,
 * and whole cores change hands.
 *
 * A CPU with an active thread is taken out of the cpusets named with
 * --cpuset, so the application does not run where the network stack polls,
 * and is put back when its thread has no NAPIs left. Every NAPI's interrupt
 * is steered to the CPU of the thread that polls it. Both are restored on
 * exit, and the NAPIs go back to softirq, in an order that matters under
 * load, see cleanup().
 *
 * The threads (network_stack.bpf.c) only poll and count. This file decides
 * the placement. Every tick it takes each NAPI's cost, the share of a CPU its
 * polls used, and each thread's load, the sum over its NAPIs plus the share of
 * the CPU the thread spent sending with --tx. A thread above
 * the high mark, or one whose queues wait too long between polls, hands its
 * cheapest NAPI to the least loaded active thread that stays under the target
 * with it, or to the next CPU of the order when there is none. When the last
 * active thread's NAPIs would fit on the others under the low mark for a
 * number of ticks in a row, they move there and its CPU is given back. One
 * step per LLC per tick, except for a thread near saturation, which sheds
 * NAPIs until it is under the target.
 *
 * With --tx CGROUP the pool also sends for the TCP connections of that cgroup
 * that arrive through the device: sendmsg() copies and returns, and the xmit
 * work is done by a pool thread. Every thread has an xmit queue. A queue whose
 * thread is not active is served by the first thread of its LLC, so the
 * connections that were assigned to it keep being served from the pool.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <linux/genetlink.h>
#include <linux/netdev.h>
#include <linux/netlink.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "network_stack.h"
#include "network_stack.bpf.skel.h"

#define MAX_CPUS	1024
#define MAX_LLCS	64
#define MAX_CPUSETS	8
#define CGROOT		"/sys/fs/cgroup"
#define BITS_PER_WORD	(8 * sizeof(unsigned long))

struct cpumask {
	unsigned long bits[MAX_CPUS / BITS_PER_WORD];
};

struct napi {
	__u32 id;
	int irq;
	int llc;			/* index in llcs[] */
	int thread;			/* slot of the thread that polls it, -1 before the first bind */
	char irq_affinity[256];		/* smp_affinity_list at start */
	double cost;			/* share of a CPU its polls used over the last tick */
	double full;			/* share of its polls that used the whole budget */
	__u64 gap_ns;			/* longest wait between polls over the last tick */
	struct ns_napi prev;		/* counters at the last tick */
};

struct thread {
	int cpu;
	int llc;
	double load;			/* sum of its NAPIs' costs, and its xmit work */
	double xmit;			/* share of a CPU its xmit work used over the last tick */
	__u64 prev_xmit_ns;		/* that counter at the last tick */
};

struct llc {
	int first_cpu;			/* names the LLC */
	int threads[MAX_CPUS];		/* thread slots in rank order */
	int nr_threads;
	int active;			/* the first so many threads have NAPIs */
	int nr_napis;
	int quiet;			/* ticks in a row the last thread could be let go */
};

struct cpuset {
	char path[PATH_MAX + 16];	/* its cpuset.cpus file */
	char orig[4096];		/* content at start */
	struct cpumask base;		/* effective CPUs at start */
};

static struct {
	const char *dev;
	const char *cpus;
	const char *thread_cgroup;
	const char *tx;
	__u64 hold_us, spin_us, nap_us, rest_us;
	__u64 softirq_pps;
	__u64 tx_wait_us;
	__u64 tick_ms, interval_ms, duration_s;
	__u64 gap_us;
	int hi, target, lo, panic;
	int shrink_ticks;
	int napis_per_thread;
	int min_threads;
	bool fixed;
	bool verbose;
} opt = {
	.hold_us = 2000,
	.nap_us = 50,
	.rest_us = 4000,
	.tx_wait_us = 100,
	.tick_ms = 100,
	.interval_ms = 1000,
	.gap_us = 5000,
	.hi = 80,
	.target = 65,
	.lo = 55,
	.panic = 92,
	.shrink_ticks = 10,
	.min_threads = 1,
};

static struct network_stack_bpf *skel;
static struct napi napis[NS_MAX_NAPIS];
static struct thread threads[NS_MAX_THREADS];
static struct llc llcs[MAX_LLCS];
static struct cpuset cpusets[MAX_CPUSETS];
static int nr_napis, nr_threads, nr_llcs, nr_cpusets;
static int cpu_llc[MAX_CPUS];		/* first CPU of the CPU's LLC, -1 if offline */
static int cpu_core[MAX_CPUS];		/* first CPU of the CPU's core */
static struct cpumask online;
static int txq_owner[NS_MAX_THREADS];	/* slot of the thread serving each xmit queue, -1 for none */
static struct bpf_link *tx_link;
static __u64 moves, grows, shrinks, rebinds;
static bool started;			/* cleanup() has something to undo */
static volatile sig_atomic_t stop;

static void cleanup(void);

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "network-stack: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	cleanup();
	exit(1);
}

static void warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "network-stack: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static __u64 now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* CPU masks and the kernel's list format, "0-3,8,10-11". */

static void cpu_set(struct cpumask *m, int cpu)
{
	m->bits[cpu / BITS_PER_WORD] |= 1UL << (cpu % BITS_PER_WORD);
}

static void cpu_clear(struct cpumask *m, int cpu)
{
	m->bits[cpu / BITS_PER_WORD] &= ~(1UL << (cpu % BITS_PER_WORD));
}

static bool cpu_test(const struct cpumask *m, int cpu)
{
	return m->bits[cpu / BITS_PER_WORD] & (1UL << (cpu % BITS_PER_WORD));
}

static int cpu_first(const struct cpumask *m)
{
	int cpu;

	for (cpu = 0; cpu < MAX_CPUS; cpu++)
		if (cpu_test(m, cpu))
			return cpu;
	return -1;
}

static int parse_cpulist(const char *s, struct cpumask *m)
{
	memset(m, 0, sizeof(*m));
	while (*s && *s != '\n') {
		char *end;
		long a, b;

		a = b = strtol(s, &end, 10);
		if (end == s)
			return -EINVAL;
		if (*end == '-') {
			s = end + 1;
			b = strtol(s, &end, 10);
			if (end == s)
				return -EINVAL;
		}
		if (a < 0 || b < a || b >= MAX_CPUS)
			return -EINVAL;
		for (; a <= b; a++)
			cpu_set(m, a);
		s = *end == ',' ? end + 1 : end;
		if (*end && *end != ',' && *end != '\n')
			return -EINVAL;
	}
	return 0;
}

static void format_cpulist(const struct cpumask *m, char *buf, size_t size)
{
	size_t len = 0;
	int cpu, end;

	buf[0] = '\0';
	for (cpu = 0; cpu < MAX_CPUS && len < size; cpu = end + 1) {
		end = cpu;
		if (!cpu_test(m, cpu))
			continue;
		while (end + 1 < MAX_CPUS && cpu_test(m, end + 1))
			end++;
		len += snprintf(buf + len, size - len, end > cpu ? "%s%d-%d" : "%s%d",
				len ? "," : "", cpu, end);
	}
}

/* Small files under /sys and /proc. */

static int read_file(const char *path, char *buf, size_t size)
{
	FILE *f = fopen(path, "r");
	size_t n;

	if (!f)
		return -errno;
	n = fread(buf, 1, size - 1, f);
	fclose(f);
	buf[n] = '\0';
	while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
		buf[--n] = '\0';
	return 0;
}

static int write_file(const char *path, const char *val)
{
	FILE *f = fopen(path, "w");
	int ret = 0;

	if (!f)
		return -errno;
	if (fprintf(f, "%s\n", val) < 0 || fflush(f))
		ret = -errno;
	if (fclose(f) && !ret)
		ret = -errno;
	return ret;
}

static int read_cpulist(struct cpumask *m, const char *fmt, ...)
{
	char path[PATH_MAX], buf[4096];
	va_list ap;
	int ret;

	va_start(ap, fmt);
	vsnprintf(path, sizeof(path), fmt, ap);
	va_end(ap);
	ret = read_file(path, buf, sizeof(buf));
	return ret ?: parse_cpulist(buf, m);
}

/*
 * Each online CPU's core and LLC, named by their first CPU. A machine that
 * exposes no third-level cache is one LLC per package.
 */
static void read_topology(void)
{
	struct cpumask m;
	int cpu;

	if (read_cpulist(&online, "/sys/devices/system/cpu/online"))
		die("cannot read the online CPUs");
	for (cpu = 0; cpu < MAX_CPUS; cpu++) {
		cpu_llc[cpu] = cpu_core[cpu] = -1;
		if (!cpu_test(&online, cpu))
			continue;
		if (read_cpulist(&m, "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu))
			die("cannot read the SMT siblings of CPU %d", cpu);
		cpu_core[cpu] = cpu_first(&m);
		if (read_cpulist(&m, "/sys/devices/system/cpu/cpu%d/cache/index3/shared_cpu_list", cpu) &&
		    read_cpulist(&m, "/sys/devices/system/cpu/cpu%d/topology/package_cpus_list", cpu))
			die("cannot read the LLC of CPU %d", cpu);
		cpu_llc[cpu] = cpu_first(&m);
	}
}

/*
 * The device's NAPIs and their interrupts, from the netdev netlink family: a
 * napi-get dump for the ifindex. A dozen lines of generic netlink by hand
 * keep the tool free of a generated netlink library.
 */

struct nl_req {
	struct nlmsghdr nlh;
	struct genlmsghdr genl;
	char attrs[64];
};

static void nl_put(struct nl_req *req, __u16 type, const void *data, __u16 len)
{
	struct nlattr *nla = (void *)req + NLMSG_ALIGN(req->nlh.nlmsg_len);

	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	req->nlh.nlmsg_len = NLMSG_ALIGN(req->nlh.nlmsg_len) + NLA_ALIGN(nla->nla_len);
}

/* Send @req and call @cb with the attributes of every reply message. */
static int nl_talk(int fd, struct nl_req *req, void (*cb)(struct nlattr *nla, int len))
{
	static char buf[1 << 16];
	bool dump = req->nlh.nlmsg_flags & NLM_F_DUMP;
	struct nlmsghdr *nlh;
	int len;

	if (send(fd, req, req->nlh.nlmsg_len, 0) < 0)
		return -errno;
	for (;;) {
		len = recv(fd, buf, sizeof(buf), 0);
		if (len < 0)
			return -errno;
		for (nlh = (void *)buf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = NLMSG_DATA(nlh);

				return err->error;
			}
			cb(NLMSG_DATA(nlh) + GENL_HDRLEN, NLMSG_PAYLOAD(nlh, GENL_HDRLEN));
			if (!dump)
				return 0;
		}
	}
}

static __u16 nl_family;

static void family_cb(struct nlattr *nla, int len)
{
	for (; len >= NLA_HDRLEN && nla->nla_len >= NLA_HDRLEN && nla->nla_len <= len;
	     len -= NLA_ALIGN(nla->nla_len), nla = (void *)nla + NLA_ALIGN(nla->nla_len))
		if (nla->nla_type == CTRL_ATTR_FAMILY_ID)
			nl_family = *(__u16 *)((char *)nla + NLA_HDRLEN);
}

static void napi_cb(struct nlattr *nla, int len)
{
	struct napi *n = &napis[nr_napis];
	bool threaded = false;

	if (nr_napis == NS_MAX_NAPIS)
		die("more than %d NAPIs", NS_MAX_NAPIS);
	n->id = 0;
	n->irq = -1;
	for (; len >= NLA_HDRLEN && nla->nla_len >= NLA_HDRLEN && nla->nla_len <= len;
	     len -= NLA_ALIGN(nla->nla_len), nla = (void *)nla + NLA_ALIGN(nla->nla_len)) {
		__u32 val = *(__u32 *)((char *)nla + NLA_HDRLEN);

		if (nla->nla_type == NETDEV_A_NAPI_ID)
			n->id = val;
		else if (nla->nla_type == NETDEV_A_NAPI_IRQ)
			n->irq = val;
		else if (nla->nla_type == NETDEV_A_NAPI_THREADED)
			threaded = val != NETDEV_NAPI_THREADED_DISABLED;
	}
	if (threaded)
		die("NAPI %u is in threaded mode; switch the device's threaded mode off first", n->id);
	/* A NAPI without an interrupt of its own cannot be steered to a pool CPU. */
	if (!n->id || n->irq < 0)
		return;
	nr_napis++;
}

static void read_napis(void)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	struct nl_req req;
	__u32 ifindex;
	int fd, ret;

	ifindex = if_nametoindex(opt.dev);
	if (!ifindex)
		die("no device %s", opt.dev);
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0 || bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
		die("netlink socket: %s", strerror(errno));

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = GENL_ID_CTRL;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.genl.cmd = CTRL_CMD_GETFAMILY;
	req.genl.version = 1;
	nl_put(&req, CTRL_ATTR_FAMILY_NAME, NETDEV_FAMILY_NAME, sizeof(NETDEV_FAMILY_NAME));
	ret = nl_talk(fd, &req, family_cb);
	if (ret || !nl_family)
		die("no netdev netlink family: %s", strerror(-ret));

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = nl_family;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.genl.cmd = NETDEV_CMD_NAPI_GET;
	req.genl.version = 1;
	nl_put(&req, NETDEV_A_NAPI_IFINDEX, &ifindex, sizeof(ifindex));
	ret = nl_talk(fd, &req, napi_cb);
	if (ret)
		die("NAPI dump of %s: %s", opt.dev, strerror(-ret));
	close(fd);
	if (!nr_napis)
		die("%s has no NAPI with an interrupt", opt.dev);
}

/* Where each NAPI's interrupt arrives now, which names the NAPI's LLC. */
static int napi_irq_cpu(struct napi *n)
{
	char path[PATH_MAX];
	struct cpumask m;
	int cpu;

	snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity_list", n->irq);
	if (read_file(path, n->irq_affinity, sizeof(n->irq_affinity)))
		die("cannot read the affinity of IRQ %d", n->irq);
	if (read_cpulist(&m, "/proc/irq/%d/effective_affinity_list", n->irq) || cpu_first(&m) < 0)
		parse_cpulist(n->irq_affinity, &m);
	cpu = cpu_first(&m);
	if (cpu < 0 || cpu_llc[cpu] < 0)
		die("IRQ %d has no online CPU", n->irq);
	return cpu;
}

static int find_llc(int first_cpu)
{
	int i;

	for (i = 0; i < nr_llcs; i++)
		if (llcs[i].first_cpu == first_cpu)
			return i;
	if (nr_llcs == MAX_LLCS)
		die("more than %d LLCs", MAX_LLCS);
	llcs[nr_llcs].first_cpu = first_cpu;
	return nr_llcs++;
}

/*
 * Group the NAPIs by LLC and rank each LLC's pool CPUs. The pool is the CPUs
 * given with --cpus, or else the cores the device's interrupts are on now,
 * with their SMT siblings. Going through the CPUs in order of their core
 * ranks both hyperthreads of a core before the next core.
 */
static void build_layout(void)
{
	struct cpumask pool = {}, irq_cores = {};
	int i, cpu, core;

	for (i = 0; i < nr_napis; i++) {
		cpu = napi_irq_cpu(&napis[i]);
		napis[i].llc = find_llc(cpu_llc[cpu]);
		napis[i].thread = -1;
		llcs[napis[i].llc].nr_napis++;
		cpu_set(&irq_cores, cpu_core[cpu]);
	}

	if (opt.cpus) {
		if (parse_cpulist(opt.cpus, &pool))
			die("bad CPU list %s", opt.cpus);
	} else {
		for (cpu = 0; cpu < MAX_CPUS; cpu++)
			if (cpu_core[cpu] >= 0 && cpu_test(&irq_cores, cpu_core[cpu]))
				cpu_set(&pool, cpu);
	}

	for (core = 0; core < MAX_CPUS; core++) {
		for (cpu = core; cpu < MAX_CPUS; cpu++) {
			struct llc *l;

			if (cpu_core[cpu] != core || !cpu_test(&pool, cpu))
				continue;
			for (i = 0; i < nr_llcs; i++)
				if (llcs[i].first_cpu == cpu_llc[cpu])
					break;
			/* A pool CPU in an LLC where no interrupt arrives is not used. */
			if (i == nr_llcs)
				continue;
			if (nr_threads == NS_MAX_THREADS)
				die("more than %d pool CPUs", NS_MAX_THREADS);
			l = &llcs[i];
			threads[nr_threads].cpu = cpu;
			threads[nr_threads].llc = i;
			l->threads[l->nr_threads++] = nr_threads;
			nr_threads++;
		}
	}

	for (i = 0; i < nr_llcs; i++) {
		struct llc *l = &llcs[i];

		if (!l->nr_threads)
			die("no pool CPU in the LLC of CPU %d, where %d NAPIs' interrupts arrive",
			    l->first_cpu, l->nr_napis);
		if (l->nr_napis > l->nr_threads * NS_THREAD_NAPIS)
			die("too few pool CPUs in the LLC of CPU %d for %d NAPIs",
			    l->first_cpu, l->nr_napis);
	}
}

/* The cpusets that must stay off the active pool CPUs. */

static void add_cpuset(const char *arg)
{
	struct cpuset *cs = &cpusets[nr_cpusets];
	char path[PATH_MAX];

	if (nr_cpusets == MAX_CPUSETS)
		die("more than %d cpusets", MAX_CPUSETS);
	if (arg[0] == '/' && strncmp(arg, CGROOT, strlen(CGROOT)))
		snprintf(path, sizeof(path), "%s%s", CGROOT, arg);
	else
		snprintf(path, sizeof(path), "%s", arg);
	snprintf(cs->path, sizeof(cs->path), "%s/cpuset.cpus", path);
	if (read_file(cs->path, cs->orig, sizeof(cs->orig)))
		die("cannot read %s: is the cpuset controller enabled for it?", cs->path);
	if (read_cpulist(&cs->base, "%s/cpuset.cpus.effective", path))
		die("cannot read the effective CPUs of %s", path);
	nr_cpusets++;
}

/* Keep the cpusets off exactly the CPUs whose threads are active. */
static void apply_cpusets(void)
{
	struct cpumask m;
	char buf[4096];
	int i, j, ret;

	for (i = 0; i < nr_cpusets; i++) {
		m = cpusets[i].base;
		for (j = 0; j < nr_llcs; j++) {
			int k;

			for (k = 0; k < llcs[j].active; k++)
				cpu_clear(&m, threads[llcs[j].threads[k]].cpu);
		}
		format_cpulist(&m, buf, sizeof(buf));
		ret = write_file(cpusets[i].path, buf);
		if (ret)
			warn("cannot write %s: %s", cpusets[i].path, strerror(-ret));
	}
}

static __u64 cgroup_id(const char *arg)
{
	char path[PATH_MAX];
	struct stat st;

	if (arg[0] == '/' && strncmp(arg, CGROOT, strlen(CGROOT)))
		snprintf(path, sizeof(path), "%s%s", CGROOT, arg);
	else
		snprintf(path, sizeof(path), "%s", arg);
	if (stat(path, &st))
		die("no cgroup %s", path);
	return st.st_ino;
}

/* Run a syscall program and return what it returned. */
static int run_prog(struct bpf_program *prog, struct ns_args *args)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = args,
		.ctx_size_in = sizeof(*args),
	);
	int ret;

	ret = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	return ret ?: (int)opts.retval;
}

/* The list a thread polls, changed in the order network_stack.h describes. */

static void thread_add_napi(int thread, int slot)
{
	struct ns_thread *t = &skel->bss->threads[thread];

	if (t->nr_napis == NS_THREAD_NAPIS)
		die("thread on CPU %d has no room for another NAPI", threads[thread].cpu);
	t->napi[t->nr_napis] = slot;
	__atomic_store_n(&t->nr_napis, t->nr_napis + 1, __ATOMIC_RELEASE);
}

static void thread_del_napi(int thread, int slot)
{
	struct ns_thread *t = &skel->bss->threads[thread];
	__u32 k;

	for (k = 0; k < t->nr_napis; k++) {
		if (t->napi[k] != slot)
			continue;
		t->napi[k] = t->napi[t->nr_napis - 1];
		__atomic_store_n(&t->nr_napis, t->nr_napis - 1, __ATOMIC_RELEASE);
		return;
	}
}

static int thread_nr_napis(int thread)
{
	return skel->bss->threads[thread].nr_napis;
}

static void steer_irq(struct napi *n, int cpu)
{
	char path[PATH_MAX], buf[16];
	int ret;

	snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity_list", n->irq);
	snprintf(buf, sizeof(buf), "%d", cpu);
	ret = write_file(path, buf);
	if (ret)
		warn("cannot steer IRQ %d to CPU %d: %s", n->irq, cpu, strerror(-ret));
}

/*
 * With --tx: give every xmit queue to its own thread while that is active and
 * to the first thread of its LLC otherwise. Like a NAPI, a queue is in the
 * new thread's list before the bind and in the old one's until after it.
 */
static void assign_txqs(void)
{
	int i, k, q, want, ret;

	if (!opt.tx)
		return;
	for (i = 0; i < nr_llcs; i++) {
		struct llc *l = &llcs[i];

		for (k = 0; k < l->nr_threads; k++) {
			struct ns_args args = {};
			struct ns_thread *t;

			q = l->threads[k];
			want = k < l->active ? q : l->threads[0];
			if (txq_owner[q] == want)
				continue;
			t = &skel->bss->threads[want];
			if (t->nr_txqs == NS_THREAD_TXQS) {
				warn("thread on CPU %d has no room for another xmit queue",
				     threads[want].cpu);
				continue;
			}
			t->txq[t->nr_txqs] = q;
			__atomic_store_n(&t->nr_txqs, t->nr_txqs + 1, __ATOMIC_RELEASE);

			args.thread = want;
			args.txq = q;
			ret = run_prog(skel->progs.ns_txq_bind, &args);
			if (ret)
				die("cannot bind xmit queue %d: %s", q, strerror(-ret));

			if (txq_owner[q] >= 0) {
				__u32 j;

				t = &skel->bss->threads[txq_owner[q]];
				for (j = 0; j < t->nr_txqs; j++) {
					if (t->txq[j] != q)
						continue;
					t->txq[j] = t->txq[t->nr_txqs - 1];
					__atomic_store_n(&t->nr_txqs, t->nr_txqs - 1,
							 __ATOMIC_RELEASE);
					break;
				}
			}
			txq_owner[q] = want;
		}
	}
}

/* The set of active threads changed: move the cpusets and the xmit queues. */
static void active_changed(void)
{
	apply_cpusets();
	assign_txqs();
}

/*
 * Run ns_mark_socks() over every TCP socket: mark the --tx cgroup's existing
 * connections for assignment, or with tx_unmark take the marks back.
 */
static void run_mark_iter(void)
{
	struct bpf_link *link;
	char buf[64];
	int fd;

	link = bpf_program__attach_iter(skel->progs.ns_mark_socks, NULL);
	if (!link) {
		warn("cannot run the TCP socket iterator: %s", strerror(errno));
		return;
	}
	fd = bpf_iter_create(bpf_link__fd(link));
	if (fd < 0) {
		warn("cannot run the TCP socket iterator: %s", strerror(errno));
	} else {
		while (read(fd, buf, sizeof(buf)) > 0)
			;
		close(fd);
	}
	bpf_link__destroy(link);
}

/*
 * Bind the xmit queues and start assigning the connections of the --tx cgroup
 * to them.
 */
static void start_tx(void)
{
	char path[PATH_MAX];
	int i, fd;

	if (!opt.tx)
		return;
	for (i = 0; i < nr_threads; i++) {
		txq_owner[i] = -1;
		skel->bss->cpu_txq[threads[i].cpu] = i + 1;
	}
	assign_txqs();

	if (opt.tx[0] == '/' && strncmp(opt.tx, CGROOT, strlen(CGROOT)))
		snprintf(path, sizeof(path), "%s%s", CGROOT, opt.tx);
	else
		snprintf(path, sizeof(path), "%s", opt.tx);
	fd = open(path, O_RDONLY | O_DIRECTORY);
	if (fd < 0)
		die("no cgroup %s", path);
	tx_link = bpf_program__attach_cgroup(skel->progs.ns_sock_assign, fd);
	close(fd);
	if (!tx_link)
		die("cannot attach to cgroup %s: %s", path, strerror(errno));
	/* Now that marked connections find ns_sock_assign() attached. */
	skel->bss->tx_cgroup_id = cgroup_id(opt.tx);
	run_mark_iter();
	printf("tx: %llu existing connections marked for assignment\n",
	       (unsigned long long)skel->bss->tx_marked);
}

/*
 * Give NAPI @slot to @thread. The thread has the NAPI in its list before the
 * bind wakes it for a NAPI that is scheduled, and the thread it leaves keeps
 * it in its list until then, so somebody polls it throughout.
 */
static int move_napi(int slot, int thread)
{
	struct ns_args args = { .thread = thread, .napi_id = napis[slot].id };
	struct napi *n = &napis[slot];
	int from = n->thread, ret;

	if (from == thread)
		return 0;
	thread_add_napi(thread, slot);
	ret = run_prog(skel->progs.ns_napi_bind, &args);
	if (ret) {
		thread_del_napi(thread, slot);
		return ret;
	}
	if (from >= 0)
		thread_del_napi(from, slot);
	n->thread = thread;
	steer_irq(n, threads[thread].cpu);
	/* For a thread that was parked with nothing to poll. */
	run_prog(skel->progs.ns_thread_wake, &args);
	moves++;
	return 0;
}

static void start_threads(void)
{
	struct ns_args args = {};
	int i, ret;

	if (opt.thread_cgroup)
		args.cgroup_id = cgroup_id(opt.thread_cgroup);
	for (i = 0; i < nr_threads; i++) {
		args.thread = i;
		args.cpu = threads[i].cpu;
		ret = run_prog(skel->progs.ns_thread_create, &args);
		if (ret)
			die("cannot start the thread for CPU %d: %s", threads[i].cpu, strerror(-ret));
	}
}

/*
 * The first placement: --napis-per-thread NAPIs on each thread, in rank
 * order. Without it, a static placement puts two on each thread, two queues
 * per hyperthread on whole cores, and a dynamic one gives every pool CPU a
 * thread and spreads the NAPIs over all of them. The controller has no
 * measurement until its first tick, and under load a thread that starts with
 * more than it can poll drops packets before then (7,696 in the first second
 * of a run with --hi 95), so the dynamic pool starts at its largest and folds
 * down to what the load needs.
 */
static void place_napis(void)
{
	int fill[MAX_LLCS] = {};
	int i, ret;

	for (i = 0; i < nr_llcs; i++) {
		struct llc *l = &llcs[i];
		int per = opt.napis_per_thread;

		if (!per)
			per = opt.fixed ? 2 : 1;
		l->active = (l->nr_napis + per - 1) / per;
		if (l->active > l->nr_threads)
			l->active = l->nr_threads;
		if (l->active < opt.min_threads)
			l->active = opt.min_threads < l->nr_threads ? opt.min_threads : l->nr_threads;
	}
	apply_cpusets();

	for (i = 0; i < nr_napis; i++) {
		struct llc *l = &llcs[napis[i].llc];
		int rank = fill[napis[i].llc]++ * l->active / l->nr_napis;

		skel->bss->napis[i].id = napis[i].id;
		ret = move_napi(i, l->threads[rank]);
		if (ret)
			die("cannot bind NAPI %u: %s", napis[i].id, strerror(-ret));
	}
}

/*
 * Interrupts of @irq so far on the CPUs of @m, from /proc/interrupts, whose
 * columns are the online CPUs in the order of its header. Returns -1 if the
 * line is not found.
 */
static long long irq_count_on(int irq, const struct cpumask *m)
{
	static int col_cpu[MAX_CPUS];
	long long sum = -1;
	size_t size = 0;
	char *line = NULL, *p, *end;
	int ncols = 0, col;
	FILE *f;

	f = fopen("/proc/interrupts", "r");
	if (!f)
		return -1;
	if (getline(&line, &size, f) > 0)
		for (p = line; (p = strstr(p, "CPU")) && ncols < MAX_CPUS; p += 3)
			col_cpu[ncols++] = atoi(p + 3);
	while (getline(&line, &size, f) > 0) {
		if (strtol(line, &end, 10) != irq || *end != ':')
			continue;
		sum = 0;
		p = end + 1;
		for (col = 0; col < ncols; col++) {
			long long v = strtoll(p, &end, 10);

			if (end == p)
				break;
			p = end;
			if (cpu_test(m, col_cpu[col]))
				sum += v;
		}
		break;
	}
	free(line);
	fclose(f);
	return sum;
}

/*
 * Wait until every NAPI's interrupt has come on one of the CPUs it had at
 * start. Only a NAPI that completed and was unmasked can interrupt there, so
 * once it has, nothing of it is scheduled on a pool CPU any more, see
 * cleanup(). The wait is long: until it ends the pool CPUs stay out of the
 * cpusets, which costs the application a few CPUs, while giving them back too
 * early can strand a NAPI that softirq cannot keep up with.
 */
static void wait_irqs_home(void)
{
	static long long base[NS_MAX_NAPIS];
	static struct cpumask home[NS_MAX_NAPIS];
	__u64 deadline = now_ns() + 20000000000ULL;
	int i, left;

	for (i = 0; i < nr_napis; i++) {
		parse_cpulist(napis[i].irq_affinity, &home[i]);
		base[i] = irq_count_on(napis[i].irq, &home[i]);
	}
	do {
		usleep(50000);
		left = 0;
		for (i = 0; i < nr_napis; i++)
			if (base[i] >= 0 && irq_count_on(napis[i].irq, &home[i]) == base[i])
				left++;
	} while (left && now_ns() < deadline);
	if (left)
		warn("%d NAPIs had no interrupt on their old CPUs within 20 s", left);
}

/*
 * Give NAPI @i back to softirq on its home CPU, the first CPU of the affinity
 * its interrupt had at start, in a way that leaves nothing of it anywhere
 * else. One NAPI at a time; cleanup() explains why.
 *
 * Where a bound NAPI goes when it is unbound depends on its state at that
 * moment (napi_bpf_revoke() and napi_bpf_release() in net/core/dev.c):
 *  - not scheduled: nowhere; its next interrupt is softirq's, on whatever CPU
 *    the affinity names then;
 *  - scheduled for its thread, no poll running: to the softirq of the CPU that
 *    unbinds it (__napi_schedule() runs there);
 *  - being polled by its thread: to the softirq of the thread's CPU, once that
 *    poll ends and finds the NAPI still scheduled.
 * So the NAPI first leaves its thread's list: the thread finishes the pass it
 * is in and never polls it again, which rules out the third case and halves
 * the thread's load. Its interrupt is steered home, and after a pause that is
 * many polls long (one poll is at most NS_POLL_BUDGET packets, ~0.3 ms) the
 * loader moves to the home CPU and unbinds from there: whatever is scheduled
 * lands in the home CPU's softirq, and an idle NAPI's next interrupt goes home
 * anyway. Either way the NAPI is back where it was before the tool started,
 * the one stock state that is known to keep up. While the NAPI waits for the
 * unbind, scheduled and polled by nobody, its ring fills: at ~100K packets/s
 * a 2047-entry ring holds ~20 ms, ten times the pause.
 *
 * The loader moves to the home CPU before the NAPI leaves its thread, so that
 * the time the NAPI is polled by nobody is the pause and the unbind, and not
 * also the wait to get onto a home CPU the application keeps busy: cleanup()
 * runs the loader as SCHED_FIFO for that reason. Moving after the pause
 * instead dropped ~4.9K packets in an exit at 77% thread load.
 * Returns how long the NAPI was polled by nobody, in ns.
 */
static __u64 hand_back(int i)
{
	struct ns_args args = { .napi_id = napis[i].id };
	struct napi *n = &napis[i];
	char path[PATH_MAX];
	struct cpumask home;
	cpu_set_t one;
	__u64 t0;

	snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity_list", n->irq);
	if (n->thread < 0) {
		write_file(path, n->irq_affinity);
		return 0;
	}
	CPU_ZERO(&one);
	if (!parse_cpulist(n->irq_affinity, &home))
		CPU_SET(cpu_first(&home), &one);
	if (!CPU_COUNT(&one) || sched_setaffinity(0, sizeof(one), &one))
		warn("cannot move to the home CPU of NAPI %u (%s) to unbind it",
		     n->id, n->irq_affinity);
	t0 = now_ns();
	thread_del_napi(n->thread, i);
	write_file(path, n->irq_affinity);
	usleep(2000);
	run_prog(skel->progs.ns_napi_unbind, &args);
	n->thread = -1;
	return now_ns() - t0;
}

/* Unbind, and put the interrupts and the cpusets back as they were found. */
static void cleanup(void)
{
	struct sched_param rt = { .sched_priority = 1 }, other = {};
	struct ns_args args = {};
	__u64 t0, gap_max = 0;
	bool pinned, fifo;
	cpu_set_t own;
	int i;

	if (!started)
		return;
	started = false;
	/*
	 * Stop assigning connections, give the ones still marked their flags
	 * back, then let the assigned ones transmit for themselves.
	 */
	bpf_link__destroy(tx_link);
	if (opt.tx) {
		skel->bss->tx_unmark = true;
		run_mark_iter();
	}
	for (i = 0; opt.tx && i < nr_threads; i++) {
		if (txq_owner[i] >= 0) {
			args.txq = i;
			run_prog(skel->progs.ns_txq_unbind, &args);
		}
	}
	/*
	 * Give the NAPIs back to softirq on their home CPUs, one at a time, see
	 * hand_back(), and give the pool CPUs back to the cpusets only after
	 * every interrupt has come home.
	 *
	 * The order is what makes an exit under load safe. The obvious ways
	 * all failed on a loaded host, with the threads at 80-99% load
	 * and two NAPIs on each: unbinding every NAPI from the loader's CPU
	 * piled the scheduled ones onto that CPU's softirq; unbinding each
	 * thread's NAPIs from the thread's CPU left two loaded NAPIs to the
	 * softirq of each pool CPU; and leaving each NAPI to softirq right
	 * after a poll completed it needed completions that a saturated thread
	 * hardly has, while steering all 64 interrupts home at once seemed to
	 * cost the threads the little headroom they had. Each time, a NAPI
	 * that softirq could not keep up with stayed polled with its interrupt
	 * masked; a NAPI moves only when it completes, so its restored
	 * affinity never took effect, and the NIC dropped packets until it was
	 * reset. hand_back() puts every NAPI straight into the stock state on
	 * its home CPU, never two loaded NAPIs on one CPU, and the pool CPUs
	 * keep no application threads until nothing is left on them.
	 */
	pinned = !sched_getaffinity(0, sizeof(own), &own);
	/*
	 * Real-time for the handover only, so that the loader gets each home
	 * CPU at once, see hand_back(); it preempts an application thread
	 * there for about 2 ms per NAPI, about the cost of the softirq the
	 * NAPI brings back.
	 */
	fifo = !sched_setscheduler(0, SCHED_FIFO, &rt);
	t0 = now_ns();
	for (i = 0; i < nr_napis; i++) {
		__u64 gap = hand_back(i);

		if (gap > gap_max)
			gap_max = gap;
	}
	fprintf(stderr, "network-stack: handed back %d NAPIs in %llu ms, longest unpolled %llu us%s\n",
		nr_napis, (unsigned long long)(now_ns() - t0) / 1000000,
		(unsigned long long)gap_max / 1000, fifo ? "" : " (not SCHED_FIFO)");
	if (fifo)
		sched_setscheduler(0, SCHED_OTHER, &other);
	if (pinned)
		sched_setaffinity(0, sizeof(own), &own);
	wait_irqs_home();
	for (i = 0; i < nr_cpusets; i++)
		write_file(cpusets[i].path, cpusets[i].orig);
	/* Releasing the program stops its threads. */
	network_stack_bpf__destroy(skel);
}

/* What each NAPI cost and how each thread is loaded over the last tick. */
static void sample(__u64 dt_ns)
{
	struct ns_args args = {};
	int i, ret;

	/*
	 * A thread's load starts with its xmit work, which no NAPI
	 * accounts for and which stays with the thread when a NAPI leaves.
	 */
	for (i = 0; i < nr_threads; i++) {
		__u64 xmit_ns = skel->bss->threads[i].xmit_ns;

		threads[i].xmit = (double)(xmit_ns - threads[i].prev_xmit_ns) / dt_ns;
		threads[i].prev_xmit_ns = xmit_ns;
		threads[i].load = threads[i].xmit;
	}

	for (i = 0; i < nr_napis; i++) {
		struct ns_napi cur = skel->bss->napis[i];
		struct napi *n = &napis[i];
		__u64 polls = cur.polls - n->prev.polls;

		n->cost = (double)(cur.busy_ns - n->prev.busy_ns) / dt_ns;
		n->full = polls ? (double)(cur.full - n->prev.full) / polls : 0;
		n->gap_ns = cur.gap_max_ns;
		skel->bss->napis[i].gap_max_ns = 0;
		threads[n->thread].load += n->cost;

		/*
		 * The kernel took the NAPI away from a thread that did not
		 * poll it for a second, or something unbound it: a write of
		 * the threaded setting, or the device going down and up. Bind
		 * again; a NAPI whose ID is gone means the device has new
		 * queues, and the placement with them.
		 */
		if (cur.cancelled != n->prev.cancelled || cur.missing != n->prev.missing) {
			args.thread = n->thread;
			args.napi_id = n->id;
			ret = run_prog(skel->progs.ns_napi_bind, &args);
			if (ret)
				die("NAPI %u cannot be bound again (%s): was %s reconfigured?",
				    n->id, strerror(-ret), opt.dev);
			warn("NAPI %u was taken from the thread on CPU %d (%s), bound again",
			     n->id, threads[n->thread].cpu,
			     cur.cancelled != n->prev.cancelled ? "not polled" : "unbound");
			rebinds++;
		}
		n->prev = cur;
	}
}

static bool thread_hot(int thread)
{
	int i;

	if (threads[thread].load * 100 > opt.hi)
		return true;
	for (i = 0; i < nr_napis; i++) {
		if (napis[i].thread != thread)
			continue;
		if (napis[i].gap_ns > opt.gap_us * 1000 || napis[i].full > 0.5)
			return true;
	}
	return false;
}

static bool thread_panics(int thread)
{
	int i;

	if (threads[thread].load * 100 > opt.panic)
		return true;
	for (i = 0; i < nr_napis; i++)
		if (napis[i].thread == thread && napis[i].full > 0.5)
			return true;
	return false;
}

/* The cheapest NAPI of @thread, or -1. */
static int cheapest_napi(int thread)
{
	int i, best = -1;

	for (i = 0; i < nr_napis; i++)
		if (napis[i].thread == thread && (best < 0 || napis[i].cost < napis[best].cost))
			best = i;
	return best;
}

/* The least loaded active thread of @l other than @except, by @load. */
static int coolest_thread(struct llc *l, int except, const double *load)
{
	int k, best = -1;

	for (k = 0; k < l->active; k++) {
		int t = l->threads[k];

		if (t != except && (best < 0 || load[t] < load[best]))
			best = t;
	}
	return best;
}

static void relieve(struct llc *l, int hot)
{
	bool panic = thread_panics(hot);
	double load[NS_MAX_THREADS];
	int i, slot, dest;

	for (i = 0; i < nr_threads; i++)
		load[i] = threads[i].load;

	do {
		if (thread_nr_napis(hot) <= 1)
			return;
		slot = cheapest_napi(hot);
		dest = coolest_thread(l, hot, load);
		if (dest < 0 || (load[dest] + napis[slot].cost) * 100 > opt.target ||
		    thread_nr_napis(dest) == NS_THREAD_NAPIS) {
			if (l->active == l->nr_threads)
				return;
			dest = l->threads[l->active++];
			grows++;
			/* The CPU leaves the cpusets before its thread polls. */
			active_changed();
		}
		if (move_napi(slot, dest))
			return;
		load[hot] -= napis[slot].cost;
		load[dest] += napis[slot].cost;
		threads[hot].load = load[hot];
		threads[dest].load = load[dest];
	} while (panic && load[hot] * 100 > opt.target);
}

/*
 * Whether the NAPIs of the last active thread fit on the others under the low
 * mark, dearest first onto the least loaded. With @commit, move them.
 */
static bool fold_last(struct llc *l, bool commit)
{
	int last = l->threads[l->active - 1];
	double load[NS_MAX_THREADS];
	bool placed[NS_MAX_NAPIS] = {};
	int nr[NS_MAX_THREADS];
	int i, slot, dest;

	for (i = 0; i < nr_threads; i++) {
		load[i] = threads[i].load;
		nr[i] = thread_nr_napis(i);
	}
	/* The xmit queue of a thread that is let go moves to the LLC's first thread. */
	if (last != l->threads[0]) {
		load[l->threads[0]] += threads[last].xmit;
		if (load[l->threads[0]] * 100 > opt.lo)
			return false;
	}

	for (;;) {
		slot = -1;
		for (i = 0; i < nr_napis; i++)
			if (napis[i].thread == last && !placed[i] &&
			    (slot < 0 || napis[i].cost > napis[slot].cost))
				slot = i;
		if (slot < 0)
			return true;
		placed[slot] = true;
		dest = coolest_thread(l, last, load);
		if (dest < 0 || (load[dest] + napis[slot].cost) * 100 > opt.lo ||
		    nr[dest] == NS_THREAD_NAPIS)
			return false;
		load[dest] += napis[slot].cost;
		nr[dest]++;
		if (commit && move_napi(slot, dest))
			return false;
	}
}

static void control(struct llc *l)
{
	int k, hot = -1;

	for (k = 0; k < l->active; k++) {
		int t = l->threads[k];

		if (thread_hot(t) && (hot < 0 || threads[t].load > threads[hot].load))
			hot = t;
	}
	if (hot >= 0) {
		l->quiet = 0;
		relieve(l, hot);
		return;
	}

	if (l->active <= opt.min_threads || !fold_last(l, false)) {
		l->quiet = 0;
		return;
	}
	if (++l->quiet < opt.shrink_ticks)
		return;
	l->quiet = 0;
	if (!fold_last(l, true))
		return;
	l->active--;
	shrinks++;
	/* The CPU goes back to the cpusets now that its thread polls nothing. */
	active_changed();
}

static void report(__u64 dt_ns)
{
	static __u64 prev_pkts, prev_naps, prev_parks, prev_xmits, prev_quiets;
	__u64 pkts = 0, naps = 0, parks = 0, gap = 0, xmits = 0, quiets = 0;
	int active = 0, suspended = 0, i, k;
	double max_load = 0, sum_load = 0;

	for (i = 0; i < nr_napis; i++) {
		pkts += skel->bss->napis[i].pkts;
		if (napis[i].gap_ns > gap)
			gap = napis[i].gap_ns;
	}
	for (i = 0; i < nr_threads; i++) {
		naps += skel->bss->threads[i].naps;
		parks += skel->bss->threads[i].parks;
		xmits += skel->bss->threads[i].xmits;
		quiets += skel->bss->threads[i].tx_quiets;
		suspended += skel->bss->threads[i].suspended && skel->bss->threads[i].nr_napis;
	}
	for (i = 0; i < nr_llcs; i++) {
		active += llcs[i].active;
		for (k = 0; k < llcs[i].active; k++) {
			double load = threads[llcs[i].threads[k]].load;

			sum_load += load;
			if (load > max_load)
				max_load = load;
		}
	}
	printf("threads %d/%d  pkts/s %.0f  load avg %.0f%% max %.0f%%  gap %llu us  naps/s %.0f  parks/s %.0f  moves %llu (+%llu -%llu)  rebinds %llu\n",
	       active, nr_threads, (pkts - prev_pkts) * 1e9 / dt_ns,
	       active ? sum_load * 100 / active : 0, max_load * 100,
	       (unsigned long long)gap / 1000,
	       (naps - prev_naps) * 1e9 / dt_ns, (parks - prev_parks) * 1e9 / dt_ns,
	       (unsigned long long)moves, (unsigned long long)grows,
	       (unsigned long long)shrinks, (unsigned long long)rebinds);
	if (opt.softirq_pps)
		printf("  softirq: %d of %d active threads have left their NAPIs to softirq\n",
		       suspended, active);
	if (opt.tx)
		printf("  tx: xmits/s %.0f  connections assigned %llu  quiet parks/s %.0f\n",
		       (xmits - prev_xmits) * 1e9 / dt_ns,
		       (unsigned long long)skel->bss->tx_socks,
		       (quiets - prev_quiets) * 1e9 / dt_ns);
	if (opt.verbose) {
		for (i = 0; i < nr_llcs; i++) {
			printf("  llc %d: %d/%d threads:", llcs[i].first_cpu, llcs[i].active,
			       llcs[i].nr_threads);
			for (k = 0; k < llcs[i].active; k++) {
				int t = llcs[i].threads[k];

				printf(" cpu%d %.0f%%/%d", threads[t].cpu, threads[t].load * 100,
				       thread_nr_napis(t));
			}
			printf("\n");
		}
	}
	fflush(stdout);
	prev_pkts = pkts;
	prev_naps = naps;
	prev_parks = parks;
	prev_xmits = xmits;
	prev_quiets = quiets;
}

static void on_signal(int sig)
{
	stop = 1;
}

static void usage(void)
{
	fprintf(stderr,
"Usage: network-stack --dev IFNAME [options]\n"
"\n"
"Poll IFNAME's NAPIs from a pool of BPF kthreads sized to the load.\n"
"\n"
"Placement:\n"
"  --cpus LIST            pool CPUs (default: the cores IFNAME's IRQs are on, with SMT siblings)\n"
"  --cpuset PATH          cgroup to keep off the active pool CPUs; may be repeated\n"
"  --thread-cgroup PATH   cgroup to run the threads in\n"
"  --napis-per-thread N   NAPIs per thread at start (default: 2 with --static, else\n"
"                         one thread on every pool CPU, folding down with the load)\n"
"  --min-threads N        threads kept active per LLC (default 1)\n"
"  --static               keep the placement of the start\n"
"  --tx CGROUP            also do the TCP xmit work of CGROUP's connections in the pool\n"
"                         while a thread polls with interrupts masked, or with --irq\n"
"                         while its interrupts keep coming\n"
"                         (off by default; needs a kernel with TCP xmit queues)\n"
"  --tx-wait-us N         with --irq: the longest park with sockets queued, after which\n"
"                         senders transmit for themselves until packets return\n"
"                         (default 100, 0 to have them always transmit with --irq)\n"
"\n"
"Controller:\n"
"  --tick-ms N            period (default 100)\n"
"  --hi PCT               a thread above this load hands off a NAPI (default 80)\n"
"  --target PCT           load a thread may reach by taking a NAPI (default 65)\n"
"  --lo PCT               load the others may reach when a thread is let go (default 55)\n"
"  --gap-us N             a NAPI that waits longer between polls counts as overload (default 5000)\n"
"  --shrink-ticks N       ticks a thread must be dispensable before it is let go (default 10)\n"
"\n"
"Threads:\n"
"  --irq                  never mask interrupts: park after every completed poll\n"
"  --hold-us N            keep interrupts masked this long after the last packet (default 2000)\n"
"  --spin-us N            of that, spin this long before napping (default 0)\n"
"  --nap-us N             length of a nap with interrupts masked (default 50)\n"
"  --softirq-pps N        a parked thread leaves its NAPIs to softirq and takes one back\n"
"                         when it receives more than N packets/s (default 0: never)\n"
"\n"
"  --interval-ms N        report period (default 1000)\n"
"  --duration S           exit after S seconds\n"
"  --verbose              report every LLC\n");
	exit(2);
}

enum {
	OPT_DEV = 256, OPT_CPUS, OPT_CPUSET, OPT_THREAD_CGROUP, OPT_NAPIS_PER_THREAD,
	OPT_MIN_THREADS, OPT_STATIC, OPT_TICK_MS, OPT_HI, OPT_TARGET, OPT_LO, OPT_GAP_US,
	OPT_SHRINK_TICKS, OPT_IRQ, OPT_HOLD_US, OPT_SPIN_US, OPT_NAP_US, OPT_INTERVAL_MS,
	OPT_DURATION, OPT_VERBOSE, OPT_TX, OPT_TX_WAIT_US, OPT_SOFTIRQ_PPS,
};

static const struct option longopts[] = {
	{ "dev", required_argument, NULL, OPT_DEV },
	{ "cpus", required_argument, NULL, OPT_CPUS },
	{ "cpuset", required_argument, NULL, OPT_CPUSET },
	{ "thread-cgroup", required_argument, NULL, OPT_THREAD_CGROUP },
	{ "napis-per-thread", required_argument, NULL, OPT_NAPIS_PER_THREAD },
	{ "min-threads", required_argument, NULL, OPT_MIN_THREADS },
	{ "static", no_argument, NULL, OPT_STATIC },
	{ "tx", required_argument, NULL, OPT_TX },
	{ "tx-wait-us", required_argument, NULL, OPT_TX_WAIT_US },
	{ "tick-ms", required_argument, NULL, OPT_TICK_MS },
	{ "hi", required_argument, NULL, OPT_HI },
	{ "target", required_argument, NULL, OPT_TARGET },
	{ "lo", required_argument, NULL, OPT_LO },
	{ "gap-us", required_argument, NULL, OPT_GAP_US },
	{ "shrink-ticks", required_argument, NULL, OPT_SHRINK_TICKS },
	{ "irq", no_argument, NULL, OPT_IRQ },
	{ "hold-us", required_argument, NULL, OPT_HOLD_US },
	{ "spin-us", required_argument, NULL, OPT_SPIN_US },
	{ "nap-us", required_argument, NULL, OPT_NAP_US },
	{ "softirq-pps", required_argument, NULL, OPT_SOFTIRQ_PPS },
	{ "interval-ms", required_argument, NULL, OPT_INTERVAL_MS },
	{ "duration", required_argument, NULL, OPT_DURATION },
	{ "verbose", no_argument, NULL, OPT_VERBOSE },
	{ "help", no_argument, NULL, 'h' },
	{}
};

int main(int argc, char **argv)
{
	const char *cpuset_args[MAX_CPUSETS];
	__u64 start, last_tick, last_report, now;
	int nr_cpuset_args = 0, c, i, err;

	while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
		switch (c) {
		case OPT_DEV: opt.dev = optarg; break;
		case OPT_CPUS: opt.cpus = optarg; break;
		case OPT_CPUSET:
			if (nr_cpuset_args == MAX_CPUSETS)
				die("more than %d cpusets", MAX_CPUSETS);
			cpuset_args[nr_cpuset_args++] = optarg;
			break;
		case OPT_THREAD_CGROUP: opt.thread_cgroup = optarg; break;
		case OPT_NAPIS_PER_THREAD:
			opt.napis_per_thread = atoi(optarg);
			if (opt.napis_per_thread < 1)
				die("--napis-per-thread must be 1 to %d", NS_THREAD_NAPIS);
			break;
		case OPT_MIN_THREADS: opt.min_threads = atoi(optarg); break;
		case OPT_STATIC: opt.fixed = true; break;
		case OPT_TX: opt.tx = optarg; break;
		case OPT_TX_WAIT_US: opt.tx_wait_us = strtoull(optarg, NULL, 0); break;
		case OPT_TICK_MS: opt.tick_ms = strtoull(optarg, NULL, 0); break;
		case OPT_HI: opt.hi = atoi(optarg); break;
		case OPT_TARGET: opt.target = atoi(optarg); break;
		case OPT_LO: opt.lo = atoi(optarg); break;
		case OPT_GAP_US: opt.gap_us = strtoull(optarg, NULL, 0); break;
		case OPT_SHRINK_TICKS: opt.shrink_ticks = atoi(optarg); break;
		case OPT_IRQ: opt.hold_us = 0; break;
		case OPT_HOLD_US: opt.hold_us = strtoull(optarg, NULL, 0); break;
		case OPT_SPIN_US: opt.spin_us = strtoull(optarg, NULL, 0); break;
		case OPT_NAP_US: opt.nap_us = strtoull(optarg, NULL, 0); break;
		case OPT_SOFTIRQ_PPS: opt.softirq_pps = strtoull(optarg, NULL, 0); break;
		case OPT_INTERVAL_MS: opt.interval_ms = strtoull(optarg, NULL, 0); break;
		case OPT_DURATION: opt.duration_s = strtoull(optarg, NULL, 0); break;
		case OPT_VERBOSE: opt.verbose = true; break;
		default: usage();
		}
	}
	if (!opt.dev || optind != argc)
		usage();
	/* 0 is the default, see place_napis(). */
	if (opt.napis_per_thread < 0 || opt.napis_per_thread > NS_THREAD_NAPIS)
		die("--napis-per-thread must be 1 to %d", NS_THREAD_NAPIS);
	if (opt.min_threads < 1)
		die("--min-threads must be at least 1");
	if (!(opt.lo < opt.target && opt.target < opt.hi && opt.hi <= 100))
		die("need --lo < --target < --hi <= 100");
	if (!opt.tick_ms || !opt.interval_ms || !opt.nap_us)
		die("--tick-ms, --interval-ms and --nap-us must not be 0");

	read_topology();
	read_napis();
	build_layout();
	for (i = 0; i < nr_cpuset_args; i++)
		add_cpuset(cpuset_args[i]);

	skel = network_stack_bpf__open();
	if (!skel)
		die("cannot open the BPF object");
	skel->bss->hold_ns = opt.hold_us * 1000;
	skel->bss->spin_ns = opt.spin_us * 1000;
	skel->bss->nap_ns = opt.nap_us * 1000;
	skel->bss->rest_ns = opt.rest_us * 1000;
	/* The time NS_SOFTIRQ_WAKE packets take at the rate that is still softirq's. */
	if (opt.softirq_pps)
		skel->bss->softirq_ns = NS_SOFTIRQ_WAKE * 1000000000ULL / opt.softirq_pps;
	skel->rodata->tx_enabled = !!opt.tx;
	if (opt.tx)
		skel->bss->tx_wait_ns = opt.tx_wait_us * 1000;
	if (!opt.tx) {
		/* Their kfuncs are missing on a kernel without TCP xmit queues. */
		bpf_program__set_autoload(skel->progs.ns_txq_bind, false);
		bpf_program__set_autoload(skel->progs.ns_txq_unbind, false);
		bpf_program__set_autoload(skel->progs.ns_sock_assign, false);
		bpf_program__set_autoload(skel->progs.ns_mark_socks, false);
	}
	err = network_stack_bpf__load(skel);
	if (err)
		die("cannot load the BPF object: %s (does the kernel have the BPF NAPI kfuncs%s?)",
		    strerror(-err), opt.tx ? " and TCP xmit queues" : "");

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	started = true;
	start_threads();
	place_napis();
	start_tx();

	printf("%s: %d NAPIs, %d pool CPUs in %d LLCs, %s\n", opt.dev, nr_napis, nr_threads,
	       nr_llcs, opt.fixed ? "static placement" : "dynamic placement");

	start = last_tick = last_report = now_ns();
	for (i = 0; i < nr_napis; i++)
		napis[i].prev = skel->bss->napis[i];

	while (!stop) {
		usleep(opt.tick_ms * 1000);
		now = now_ns();
		sample(now - last_tick);
		last_tick = now;
		if (!opt.fixed)
			for (i = 0; i < nr_llcs; i++)
				control(&llcs[i]);
		if (now - last_report >= opt.interval_ms * 1000000ULL) {
			report(now - last_report);
			last_report = now;
		}
		if (opt.duration_s && now - start >= opt.duration_s * 1000000000ULL)
			break;
	}

	cleanup();
	return 0;
}
