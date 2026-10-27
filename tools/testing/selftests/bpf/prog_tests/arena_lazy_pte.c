// SPDX-License-Identifier: GPL-2.0
/*
 * On-demand PTE tables for the arena's kernel mapping. The arena allocates the
 * PTE table of a PMD slot when a page in it is first mapped, counts the tables
 * in the map's memory usage (fdinfo memlock), keeps them until the map is
 * destroyed, and recovers kernel-side faults in a slot without a table by
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
 * The test works in regions one stride apart. On x86-64 and arm64 the slot
 * geometry is known: a PTE table holds PAGE_SIZE / 8 entries, so a slot covers
 * PAGE_SIZE * PAGE_SIZE / 8 bytes (2 MB, 32 MB or 512 MB), the stride is the
 * larger of 32 MB and the slot, every region lies in a slot of its own and the
 * counts below are checked exactly. Elsewhere the stride is 32 MB, which keeps
 * the regions in distinct slots on every architecture with a slot of 32 MB or
 * less, and the counts are only bounded. The eight regions fit the arena on
 * every page size: 256 MB with 4 KB pages, 4 GB with 64 KB pages.
 */
#define MIN_STRIDE	(32UL * 1024 * 1024)
#define NR_REGIONS	4

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
static bool fault_armed;

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

/* Write a byte at @p; true if that raised SIGBUS. */
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
	/* the bytes a PMD slot covers, 0 where the test does not know */
	unsigned long slot;
	/* the distance between the regions the subtests work in */
	unsigned long stride;
	int fd;
	/* the slot geometry is known: counts are checked exactly */
	bool exact;
};

static unsigned long region(struct ctx *c, int i)
{
	return i * c->stride;
}

/* the region of the probe allocation and of the flushes, with a table from the start */
#define SPARE_REGION(c)	region(c, NR_REGIONS + 3)

/* a slot narrower than the stride: a region holds slots the subtests never touched */
static bool has_subslots(struct ctx *c)
{
	return c->exact && c->slot < c->stride;
}

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

/* The address-less variant: the kernel picks the lowest free range, expected at @off. */
static int alloc_anywhere(struct ctx *c, unsigned long off, __u64 val)
{
	struct arena_lazy_pte *skel = c->skel;
	int ret;

	skel->bss->addr_null = true;
	skel->bss->val = val;
	ret = run(skel->progs.alloc_page, "alloc_page anywhere");
	skel->bss->addr_null = false;
	if (ret)
		return -1;
	if (!ASSERT_EQ((unsigned long)skel->bss->ptr, (unsigned long)c->base + off,
		       "alloc_page anywhere addr"))
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
	ret = alloc_at(c, SPARE_REGION(c), 0, false) ?: free_at(c, SPARE_REGION(c));
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
		if (alloc_at(c, region(c, i), 0x1000 + i, i & 1))
			return;
		/* the user fault maps the page BPF allocated, no new table */
		ASSERT_EQ(*(__u64 *)(c->base + region(c, i)), 0x1000 + i, "value after alloc");
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
		if (free_at(c, region(c, i)))
			return;
	ASSERT_EQ(map_memlock(c->fd), before + tables * c->ps, "tables kept after free");

	/* the kept tables are reused: no new table for the same regions */
	for (i = 0; i < NR_REGIONS; i++) {
		if (alloc_at(c, region(c, i), 0x2000 + i, !(i & 1)))
			return;
		ASSERT_EQ(*(__u64 *)(c->base + region(c, i)), 0x2000 + i, "value after realloc");
	}
	ASSERT_EQ(map_memlock(c->fd), before + (NR_REGIONS + tables) * c->ps,
		  "tables reused after realloc");

	for (i = 0; i < NR_REGIONS; i++)
		if (free_at(c, region(c, i)))
			return;
	ASSERT_EQ(map_memlock(c->fd), before + tables * c->ps, "tables kept after second free");
}

/*
 * Allocations and frees that cross slot boundaries, in the slots of region 0
 * that test_lazy_alloc() left untouched (its page sat in the first slot, whose
 * table remains). Only where a region holds more than one slot.
 */
static void test_lazy_alloc_span(struct ctx *c)
{
	unsigned long r0 = region(c, 0), slot = c->slot, slot_pages = slot / c->ps;
	long before;

	/* two pages straddling two empty slots: two tables from one preallocation */
	before = map_memlock(c->fd);
	c->skel->bss->cnt = 2;
	if (alloc_at(c, r0 + 2 * slot - c->ps, 0x3000, false))
		return;
	ASSERT_EQ(map_memlock(c->fd), before + 4 * c->ps, "two pages and two tables");
	if (free_at(c, r0 + 2 * slot - c->ps))
		return;
	ASSERT_EQ(map_memlock(c->fd), before + 2 * c->ps, "two tables kept");

	/*
	 * A free that crosses from a slot with a table into one without: the
	 * clearing walk visits the first and skips the second (arena_walk_ptes()
	 * without tables). The range needs an allocated page, or the free has
	 * nothing to do before it reaches the walk.
	 */
	c->skel->bss->cnt = 1;
	if (alloc_at(c, r0 + 3 * slot - c->ps, 0x3001, false))
		return;
	c->skel->bss->cnt = 2;
	if (free_at(c, r0 + 3 * slot - c->ps))
		return;
	c->skel->bss->cnt = 1;
	ASSERT_EQ(map_memlock(c->fd), before + 2 * c->ps, "free across a slot without a table");

	/*
	 * An address-less allocation: the kernel peeks the range tree under the
	 * lock to size its table preallocation, then maps the lowest free range,
	 * which starts at offset 0 here and reaches the fourth slot, the only one
	 * of the four without a table.
	 */
	c->skel->bss->cnt = 3 * slot_pages + 1;
	if (alloc_anywhere(c, r0, 0x3002))
		return;
	ASSERT_EQ(*(__u64 *)(c->base + r0), 0x3002, "value after address-less alloc");
	ASSERT_EQ(map_memlock(c->fd), before + (3 + 3 * slot_pages + 1) * c->ps,
		  "pages and one table after address-less alloc");
	if (free_at(c, r0))
		return;
	c->skel->bss->cnt = 1;
	ASSERT_EQ(map_memlock(c->fd), before + 3 * c->ps, "three tables kept");
}

/*
 * A user fault in a region that never had a table: arena_vm_fault() creates
 * the table (preallocated outside the lock) and then the page.
 */
static void test_lazy_user_fault(struct ctx *c)
{
	unsigned long off = region(c, NR_REGIONS);
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
/*
 * Hand the unallocated page at @off to a kfunc and check the stream report.
 * The kfunc returns the word it read and increments it in place: with the
 * access resolved to the scratch page, the value counts the recovered faults.
 */
static int kfunc_touch(struct ctx *c, unsigned long off, __u64 expect)
{
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
	int prog_fd = bpf_program__fd(c->skel->progs.kfunc_touch);
	char fault_addr[64], buf[16384];
	int ret, len = 0;

	c->skel->bss->off = off;
	if (run(c->skel->progs.kfunc_touch, "kfunc_touch"))
		return -1;
	ASSERT_EQ(c->skel->bss->val, expect, "value read through scratch");

	/* the report names the page, as the full user address; drain the stream */
	snprintf(fault_addr, sizeof(fault_addr), "unmapped address 0x%lx",
		 ((unsigned long)c->base + off) & ~(c->ps - 1));
	while ((ret = bpf_prog_stream_read(prog_fd, BPF_STREAM_STDERR, buf + len,
					   sizeof(buf) - 1 - len, &ropts)) > 0)
		len += ret;
	buf[len] = '\0';
	if (!ASSERT_OK(ret, "stream read") || !ASSERT_GT(len, 0, "stream report length"))
		return -1;
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
	unsigned long region1 = region(c, NR_REGIONS + 1), stray = region1 + 3 * c->ps;
	unsigned long region2 = region(c, NR_REGIONS + 2), stray2 = region2 + 5 * c->ps;
	long before, after;

	/* a page right below the region, in a slot of its own or the previous region's */
	if (alloc_at(c, region1 - c->ps, 0x1111, false))
		return;

	/* 1. a kfunc touches a never-touched region: arena_install_scratch() on a none slot */
	before = map_memlock(c->fd);
	if (kfunc_touch(c, stray, 0))
		return;
	/* the scratch table is not counted, like the scratch page */
	ASSERT_EQ(map_memlock(c->fd), before, "scratch table not counted");

	/*
	 * A free that runs from the page below into the scratch slot: the
	 * clearing walk frees the page and skips the scratch table, which must
	 * never be visited (its entries serve every slot it is installed in).
	 */
	c->skel->bss->cnt = 2;
	if (free_at(c, region1 - c->ps))
		return;
	c->skel->bss->cnt = 1;
	before -= c->ps;
	ASSERT_EQ(map_memlock(c->fd), before, "free across the scratch slot");

	/* 2. an allocation in that region: the swap replaces the scratch table */
	if (alloc_at(c, region1, 0xabcd, false))
		return;
	/* the page is a real one, not scratch: the value round-trips both ways */
	ASSERT_EQ(*(__u64 *)(c->base + region1), 0xabcd, "value through user mapping");
	*(__u64 *)(c->base + region1) = 0xdcba;
	c->skel->bss->off = region1;
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
	if (kfunc_touch(c, stray2, 1))
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

	/*
	 * 7. the scratch table again, in an untouched slot of the first region:
	 * it still maps the scratch page everywhere after the free that crossed
	 * it in 1 and the swap in 2.
	 */
	if (!has_subslots(c))
		return;
	before = map_memlock(c->fd);
	if (kfunc_touch(c, region1 + c->slot + 3 * c->ps, 2))
		return;
	ASSERT_EQ(map_memlock(c->fd), before, "scratch table not counted again");
}
#endif

void serial_test_arena_lazy_pte(void)
{
	struct sigaction sa = { .sa_handler = fault_handler }, old_bus;
	struct ctx c = { .ps = PAGE_SIZE, .stride = MIN_STRIDE };
	long initial;
	size_t sz;

	c.skel = arena_lazy_pte__open();
	if (!ASSERT_OK_PTR(c.skel, "open"))
		return;
#if defined(__x86_64__) || defined(__aarch64__)
	c.slot = c.ps * (c.ps / 8);
	c.stride = c.slot > MIN_STRIDE ? c.slot : MIN_STRIDE;
	c.exact = true;
#else
	/* only the JITs that recover kernel faults take kfuncs with arena arguments */
	bpf_program__set_autoload(c.skel->progs.kfunc_touch, false);
#endif
	if (!ASSERT_OK(arena_lazy_pte__load(c.skel), "load"))
		goto out;
	c.fd = bpf_map__fd(c.skel->maps.arena);
	/* libbpf mmap()s the arena at map_extra during load */
	c.base = bpf_map__initial_value(c.skel->maps.arena, &sz);
	if (!ASSERT_OK_PTR(c.base, "arena base"))
		goto out;

	/*
	 * A fresh arena with on-demand tables counts nothing: the scratch page
	 * and the scratch table are overhead. The configurations that populate
	 * every table at creation (ARENA_LAZY_PT == 0 in kernel/bpf/arena.c)
	 * count those tables from the start and never add one, so nothing
	 * below applies to them.
	 */
	initial = map_memlock(c.fd);
	if (initial > 0) {
		printf("%s:SKIP: PTE tables are populated at map creation here\n", __func__);
		test__skip();
		goto out;
	}
	ASSERT_EQ(initial, 0, "initial");

	/* a probe allocation tells whether the compiler can build arena pointers */
	c.skel->bss->cnt = 1;
	c.skel->bss->off = SPARE_REGION(&c);
	if (run(c.skel->progs.alloc_page, "probe"))
		goto out;
	if (c.skel->bss->skip) {
		printf("%s:SKIP: compiler doesn't support arena_cast\n", __func__);
		test__skip();
		goto out;
	}
	if (!ASSERT_EQ((unsigned long)c.skel->bss->ptr, (unsigned long)c.base + SPARE_REGION(&c),
		       "probe addr"))
		goto out;
	if (free_at(&c, SPARE_REGION(&c)))
		goto out;
	/* the probe's table stays */
	ASSERT_EQ(map_memlock(c.fd), c.ps, "after probe");

	/* the map has no BPF_F_SEGV_ON_FAULT, so a poisoned page raises SIGBUS */
	if (!ASSERT_OK(sigaction(SIGBUS, &sa, &old_bus), "sigaction"))
		goto out;

	if (test__start_subtest("lazy_alloc"))
		test_lazy_alloc(&c);
	if (test__start_subtest("lazy_alloc_span")) {
		if (has_subslots(&c)) {
			test_lazy_alloc_span(&c);
		} else {
			printf("%s:SKIP: a region holds a single slot here\n", __func__);
			test__skip();
		}
	}
	if (test__start_subtest("lazy_user_fault"))
		test_lazy_user_fault(&c);
	if (test__start_subtest("kernel_fault")) {
#if defined(__x86_64__) || defined(__aarch64__)
		test_kernel_fault(&c);
#else
		printf("%s:SKIP: kernel-fault recovery is x86-64 and arm64 only\n", __func__);
		test__skip();
#endif
	}

	sigaction(SIGBUS, &old_bus, NULL);
out:
	arena_lazy_pte__destroy(c.skel);
}
