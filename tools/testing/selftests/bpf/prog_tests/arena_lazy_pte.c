// SPDX-License-Identifier: GPL-2.0
/*
 * On-demand PTE tables for the arena's kernel mapping. The arena allocates the
 * PTE table of a 2 MB slot when a page in it is first mapped, counts the
 * tables in the map's memory usage (fdinfo memlock), keeps them until the map
 * is destroyed, and recovers kernel-side faults in a slot without a table by
 * installing a shared scratch table. Each check names the kernel path it
 * exercises.
 */
#define _GNU_SOURCE
#include <test_progs.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/user.h>
#ifndef PAGE_SIZE /* on some archs it comes in sys/user.h */
#include <unistd.h>
#define PAGE_SIZE getpagesize()
#endif

#include "arena_lazy_pte.skel.h"

/*
 * Pages that are REGION_SZ apart lie in distinct PMD slots on every
 * architecture with a slot of 32 MB or less, which includes the 2 MB slots of
 * x86-64 and arm64 with 4 KB pages, the only configurations where the slot
 * size is known to the test and the counts below are checked exactly.
 */
#define REGION_SZ	(32UL * 1024 * 1024)
#define NR_REGIONS	4
#define REGION(i)	((i) * REGION_SZ)
/* the region of the probe allocation and of the flushes, with a table from the start */
#define SPARE_REGION	REGION(NR_REGIONS + 3)

/* same reader as arena_mem_usage.c: the memlock line of the map's fdinfo */
static long map_memlock(int map_fd)
{
	char path[64], line[128];
	long memlock = -1;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", map_fd);
	f = fopen(path, "r");
	if (!ASSERT_OK_PTR(f, "open_fdinfo"))
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "memlock:\t%ld", &memlock) == 1)
			break;
	}
	fclose(f);
	ASSERT_NEQ(memlock, -1, "parse_memlock");
	return memlock;
}

static int run(struct bpf_program *prog, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);

	if (!ASSERT_OK(err, name))
		return -1;
	if (!ASSERT_OK(opts.retval, name))
		return -1;
	return 0;
}

static sigjmp_buf fault_env;
static __thread bool fault_armed;

/* Only touch_faults() expects a signal; anywhere else it keeps its default action. */
static void fault_handler(int sig)
{
	if (!fault_armed) {
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	siglongjmp(fault_env, 1);
}

/* Write a byte at @p; true if that raised SIGBUS or SIGSEGV. */
static bool touch_faults(char *p)
{
	if (sigsetjmp(fault_env, 1)) {
		fault_armed = false;
		return true;
	}
	fault_armed = true;
	WRITE_ONCE(*p, 1);
	fault_armed = false;
	return false;
}

struct ctx {
	struct arena_lazy_pte *skel;
	char *base;
	long ps;
	int fd;
	/* the slot geometry is known: counts are checked exactly */
	bool exact;
};

static int alloc_at(struct ctx *c, unsigned long off, __u64 val, bool atomic)
{
	struct arena_lazy_pte *skel = c->skel;

	skel->bss->off = off;
	skel->bss->val = val;
	if (run(atomic ? skel->progs.alloc_page_atomic : skel->progs.alloc_page, "alloc_page"))
		return -1;
	if (!ASSERT_OK_PTR(skel->bss->ptr, "alloc_page ptr"))
		return -1;
	if (!ASSERT_EQ((unsigned long)skel->bss->ptr, (unsigned long)c->base + off,
		       "alloc_page addr"))
		return -1;
	return 0;
}

static int free_at(struct ctx *c, unsigned long off)
{
	c->skel->bss->off = off;
	return run(c->skel->progs.free_page, "free_page");
}

/*
 * x86 leaves the translations a kernel-fault recovery cached in place when the
 * real table or page replaces scratch (see arena_ensure_pt() and
 * apply_range_set_cb()): kernel accesses from the CPU that took the fault may
 * keep hitting scratch until the entries are evicted. A kernel range flush
 * evicts them, and freeing pages does one; freeing more pages than x86's
 * single-page flush ceiling (33) makes it a full flush on every CPU. Do that
 * after every recovered fault, so the data checks that follow are
 * deterministic. arm64 flushes in the replacement itself and does not need it.
 */
static int evict_stale_translations(struct ctx *c)
{
	int ret;

	c->skel->bss->cnt = 128;
	ret = alloc_at(c, SPARE_REGION, 0, false) ?: free_at(c, SPARE_REGION);
	c->skel->bss->cnt = 1;
	return ret;
}

/*
 * Pages in regions that never had a table: each allocation creates the table
 * of its slot (arena_ensure_pt() on a none slot). Even regions use the
 * sleepable program, which preallocates the table outside the arena lock; odd
 * regions use the non-sleepable one, which allocates it under the lock with
 * the non-blocking allocator.
 */
static void test_lazy_alloc(struct ctx *c)
{
	long before, after, tables;
	int i;

	before = map_memlock(c->fd);
	for (i = 0; i < NR_REGIONS; i++) {
		if (alloc_at(c, REGION(i), 0x1000 + i, i & 1))
			return;
		/* the user fault maps the page BPF allocated, no new table */
		ASSERT_EQ(*(__u64 *)(c->base + REGION(i)), 0x1000 + i, "value after alloc");
	}
	after = map_memlock(c->fd);
	tables = (after - before - NR_REGIONS * c->ps) / c->ps;
	/* every table is counted; one per distinct slot, which is every region when exact */
	ASSERT_GE(tables, 1, "tables after alloc");
	ASSERT_LE(tables, NR_REGIONS, "tables after alloc");
	if (c->exact)
		ASSERT_EQ(tables, NR_REGIONS, "one table per region");

	/* tables are kept after their pages are freed: only the pages go */
	for (i = 0; i < NR_REGIONS; i++)
		if (free_at(c, REGION(i)))
			return;
	ASSERT_EQ(map_memlock(c->fd), before + tables * c->ps, "tables kept after free");

	/* the kept tables are reused: no new table for the same regions */
	for (i = 0; i < NR_REGIONS; i++) {
		if (alloc_at(c, REGION(i), 0x2000 + i, !(i & 1)))
			return;
		ASSERT_EQ(*(__u64 *)(c->base + REGION(i)), 0x2000 + i, "value after realloc");
	}
	ASSERT_EQ(map_memlock(c->fd), before + (NR_REGIONS + tables) * c->ps,
		  "tables reused after realloc");

	for (i = 0; i < NR_REGIONS; i++)
		if (free_at(c, REGION(i)))
			return;
	ASSERT_EQ(map_memlock(c->fd), before + tables * c->ps, "tables kept after second free");
}

/*
 * A user fault in a region that never had a table: arena_vm_fault() creates
 * the table (preallocated outside the lock) and then the page.
 */
static void test_lazy_user_fault(struct ctx *c)
{
	unsigned long off = REGION(NR_REGIONS);
	long before, after, delta;

	before = map_memlock(c->fd);
	ASSERT_FALSE(touch_faults(c->base + off), "user fault in new region");
	after = map_memlock(c->fd);
	delta = (after - before) / c->ps;
	/* the page, plus its table unless a coarser slot already had one */
	ASSERT_GE(delta, 1, "page after user fault");
	ASSERT_LE(delta, 2, "page and table after user fault");
	if (c->exact)
		ASSERT_EQ(delta, 2, "page and table after user fault");

	/* BPF sees the page user space faulted in */
	c->skel->bss->off = off;
	if (run(c->skel->progs.read_page, "read_page"))
		return;
	ASSERT_EQ(c->skel->bss->val, 1, "value user space wrote");

	if (free_at(c, off))
		return;
	ASSERT_EQ(map_memlock(c->fd), after - c->ps, "table kept after free");
}

#if defined(__x86_64__) || defined(__aarch64__)
/* Hand the unallocated page at @off to a kfunc and check the stream report. */
static int kfunc_touch(struct ctx *c, unsigned long off)
{
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
	int prog_fd = bpf_program__fd(c->skel->progs.kfunc_touch);
	char fault_addr[64], buf[4096];
	int ret;

	c->skel->bss->off = off;
	if (run(c->skel->progs.kfunc_touch, "kfunc_touch"))
		return -1;

	/* the report names the page, as the full user address */
	snprintf(fault_addr, sizeof(fault_addr), "unmapped address 0x%lx",
		 ((unsigned long)c->base + off) & ~(c->ps - 1));
	ret = bpf_prog_stream_read(prog_fd, BPF_STREAM_STDERR, buf, sizeof(buf) - 1, &ropts);
	if (!ASSERT_GT(ret, 0, "stream read"))
		return -1;
	buf[ret] = '\0';
	if (!ASSERT_HAS_SUBSTR(buf, fault_addr, "stream report")) {
		fprintf(stderr, "Output from stream:\n%s\n", buf);
		return -1;
	}
	return evict_stale_translations(c);
}

/*
 * Kernel-side faults, recovered with scratch. In a region without a table the
 * fault handler installs the scratch table into the PMD slot; a later
 * allocation in that region replaces it with a real table (the scratch->none->
 * table swap in arena_ensure_pt()). In a region with a real table the handler
 * installs a scratch PTE, as before.
 */
static void test_kernel_fault(struct ctx *c)
{
	unsigned long region = REGION(NR_REGIONS + 1), stray = region + 3 * c->ps;
	unsigned long region2 = REGION(NR_REGIONS + 2), stray2 = region2 + 5 * c->ps;
	long before, after;

	/* 1. a kfunc touches a never-touched region: arena_install_scratch() on a none slot */
	before = map_memlock(c->fd);
	if (kfunc_touch(c, stray))
		return;
	/* the scratch table is not counted, like the scratch page */
	ASSERT_EQ(map_memlock(c->fd), before, "scratch table not counted");

	/* 2. an allocation in that region: the swap replaces the scratch table */
	if (alloc_at(c, region, 0xabcd, false))
		return;
	/* the page is a real one, not scratch: the value round-trips both ways */
	ASSERT_EQ(*(__u64 *)(c->base + region), 0xabcd, "value through user mapping");
	*(__u64 *)(c->base + region) = 0xdcba;
	c->skel->bss->off = region;
	if (run(c->skel->progs.read_page, "read_page"))
		return;
	ASSERT_EQ(c->skel->bss->val, 0xdcba, "value through kernel mapping");
	after = map_memlock(c->fd);
	if (c->exact)
		ASSERT_EQ(after, before + 2 * c->ps, "page and table after swap");

	/*
	 * 3. the page the kfunc hit is not poisoned: the slot-level scratch
	 * entry could not record which page was hit, so a user fault there
	 * allocates it like any other page. (With a real table in place it
	 * would have stayed poisoned, see 5.)
	 */
	ASSERT_FALSE(touch_faults(c->base + stray), "user fault on the stray page");
	ASSERT_EQ(map_memlock(c->fd), after + c->ps, "stray page allocated");

	/* 4. a region with a real table: a kfunc touch scratches one PTE */
	if (alloc_at(c, region2, 0x5555, false))
		return;
	before = map_memlock(c->fd);
	if (kfunc_touch(c, stray2))
		return;
	ASSERT_EQ(map_memlock(c->fd), before, "scratch PTE not counted");

	/* 5. that page stays poisoned for user space, as before */
	ASSERT_TRUE(touch_faults(c->base + stray2), "user fault on a scratched page");
	ASSERT_EQ(map_memlock(c->fd), before, "nothing allocated by the poisoned fault");

	/* 6. an allocation replaces the scratch PTE (apply_range_set_cb()) and lifts the poison */
	if (alloc_at(c, stray2, 0x7777, false))
		return;
	ASSERT_EQ(*(__u64 *)(c->base + stray2), 0x7777, "value after replacing scratch PTE");
	ASSERT_EQ(map_memlock(c->fd), before + c->ps, "page after replacing scratch PTE");
}
#endif

void serial_test_arena_lazy_pte(void)
{
	struct sigaction sa = { .sa_handler = fault_handler }, old_bus, old_segv;
	struct ctx c = { .ps = PAGE_SIZE };
	size_t sz;

	c.skel = arena_lazy_pte__open_and_load();
	if (!ASSERT_OK_PTR(c.skel, "open_and_load"))
		return;
	c.fd = bpf_map__fd(c.skel->maps.arena);
	/* libbpf mmap()s the arena at map_extra during load */
	c.base = bpf_map__initial_value(c.skel->maps.arena, &sz);
	if (!ASSERT_OK_PTR(c.base, "arena base"))
		goto out;
#if defined(__x86_64__) || defined(__aarch64__)
	c.exact = c.ps == 4096;
#endif

	/* fresh arena: nothing counted, the scratch page and table are overhead */
	ASSERT_EQ(map_memlock(c.fd), 0, "initial");

	/* a probe allocation tells whether the compiler can build arena pointers */
	c.skel->bss->cnt = 1;
	if (alloc_at(&c, SPARE_REGION, 0, false))
		goto out;
	if (c.skel->bss->skip) {
		printf("%s:SKIP: compiler doesn't support arena_cast\n", __func__);
		test__skip();
		goto out;
	}
	if (free_at(&c, SPARE_REGION))
		goto out;
	/* the probe's table stays */
	ASSERT_EQ(map_memlock(c.fd), c.ps, "after probe");

	if (sigaction(SIGBUS, &sa, &old_bus) || sigaction(SIGSEGV, &sa, &old_segv)) {
		ASSERT_OK(1, "sigaction");
		goto out;
	}

	if (test__start_subtest("lazy_alloc"))
		test_lazy_alloc(&c);
	if (test__start_subtest("lazy_user_fault"))
		test_lazy_user_fault(&c);
#if defined(__x86_64__) || defined(__aarch64__)
	if (test__start_subtest("kernel_fault"))
		test_kernel_fault(&c);
#else
	printf("%s:SKIP: kernel-fault recovery is x86-64 and arm64 only\n", __func__);
#endif

	sigaction(SIGBUS, &old_bus, NULL);
	sigaction(SIGSEGV, &old_segv, NULL);
out:
	arena_lazy_pte__destroy(c.skel);
}
