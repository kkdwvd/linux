// SPDX-License-Identifier: GPL-2.0
/* The frames that a program keeps for its next ones, see progs/coro_frames.c */
#define _GNU_SOURCE
#include <sched.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "coro_frames.skel.h"
#include "coro_frames_count.skel.h"
#include "coro_frames_ctx.skel.h"
#include "progs/coro_frames.h"

static cpu_set_t all_cpus;
/* two CPUs that the test may run on */
static int cpu_a, cpu_b;

static bool two_cpus(void)
{
	int cpu;

	cpu_a = cpu_b = -1;
	if (sched_getaffinity(0, sizeof(all_cpus), &all_cpus))
		return false;
	for (cpu = 0; cpu < CPU_SETSIZE && cpu_b < 0; cpu++) {
		if (!CPU_ISSET(cpu, &all_cpus))
			continue;
		if (cpu_a < 0)
			cpu_a = cpu;
		else
			cpu_b = cpu;
	}
	return cpu_b >= 0;
}

static void pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	ASSERT_OK(sched_setaffinity(0, sizeof(set), &set), "sched_setaffinity");
}

static void unpin(void)
{
	sched_setaffinity(0, sizeof(all_cpus), &all_cpus);
}

/* Have the program do @op on the CPU that this runs on */
static int run(struct coro_frames *skel, enum coro_frames_op op, __u32 from, __u32 to)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = data,
		    .data_size_in = sizeof(data),
		    .repeat = 1);
	int err;

	skel->bss->op = op;
	skel->bss->from = from;
	skel->bss->to = to;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.frames), &opts);
	if (!ASSERT_OK(err, "test_run") || !ASSERT_EQ(opts.retval, XDP_PASS, "retval") ||
	    !ASSERT_EQ(skel->bss->err, 0, "err"))
		return -1;
	return 0;
}

static struct coro_frames *load(void)
{
	struct coro_frames *skel = coro_frames__open_and_load();

	ASSERT_OK_PTR(skel, "coro_frames__open_and_load");
	return skel;
}

static bool wait_for(__u64 *counter, __u64 want)
{
	int i;

	for (i = 0; i < 10000 && READ_ONCE(*counter) != want; i++)
		usleep(1000);
	return ASSERT_EQ(READ_ONCE(*counter), want, "counter");
}

/* The last reference of the program with @id is gone, and its frames are destroyed */
static bool released(__u32 id)
{
	__u32 next;
	int i;

	for (i = 0; i < 10000; i++) {
		if (bpf_prog_get_next_id(id - 1, &next) || next != id)
			return true;
		usleep(1000);
	}
	return ASSERT_LT(i, 10000, "the program is released");
}

static int prog_info(struct coro_frames *skel, struct bpf_prog_info *info)
{
	__u32 len = sizeof(*info);

	memset(info, 0, sizeof(*info));
	return ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.frames), info, &len),
			 "get_info") ? 0 : -1;
}

static int cmp_u64(const void *a, const void *b)
{
	return *(const __u64 *)a < *(const __u64 *)b ? -1 : *(const __u64 *)a > *(const __u64 *)b;
}

/* Are the @nr frames at @a those at @b, in any order? */
static void same_frames(__u64 *a, __u64 *b, int nr, const char *what)
{
	qsort(a, nr, sizeof(*a), cmp_u64);
	qsort(b, nr, sizeof(*b), cmp_u64);
	ASSERT_NEQ(a[0], 0, what);
	ASSERT_OK(memcmp(a, b, nr * sizeof(*a)), what);
}

/*
 * A frame that is freed is the next one of its size class that the program allocates on the
 * CPU, whatever the size of that one.
 */
static void test_reuse(void)
{
	struct coro_frames *skel = load();
	__u64 small, large;

	if (!skel)
		return;
	pin(cpu_a);
	if (run(skel, OP_PAIR_48, 0, 0))
		goto out;
	small = skel->bss->last;
	if (run(skel, OP_PAIR_48, 0, 0))
		goto out;
	ASSERT_EQ(skel->bss->last, small, "again");
	if (run(skel, OP_PAIR_64, 0, 0))
		goto out;
	ASSERT_EQ(skel->bss->last, small, "a larger one of the class");
	if (run(skel, OP_PAIR_200, 0, 0))
		goto out;
	large = skel->bss->last;
	ASSERT_NEQ(large, small, "another class");
	if (run(skel, OP_PAIR_200, 0, 0) || run(skel, OP_PAIR_48, 0, 0))
		goto out;
	ASSERT_EQ(skel->bss->last, small, "each class has its own");
	if (run(skel, OP_PAIR_200, 0, 0))
		goto out;
	ASSERT_EQ(skel->bss->last, large, "each class has its own, the other one");
	/* and where one call allocates both, which the kernel has to tell apart */
	if (run(skel, OP_PAIR_ANY, 0, 0))
		goto out;
	ASSERT_EQ(skel->bss->last, small, "one call, the small one");
	ASSERT_EQ(skel->bss->other, large, "one call, the large one");
	/* a frame that is in use is not in the cache */
	if (run(skel, OP_PARK, 0, 1))
		goto out;
	ASSERT_EQ(skel->bss->addr[0], small, "parked");
	if (run(skel, OP_PAIR_48, 0, 0))
		goto out;
	ASSERT_NEQ(skel->bss->last, small, "in use");
out:
	unpin();
	coro_frames__destroy(skel);
}

/* A frame that another CPU frees is that CPU's next one. */
static void test_other_cpu(void)
{
	struct coro_frames *skel = load();
	__u64 frame;

	if (!skel)
		return;
	pin(cpu_a);
	if (run(skel, OP_PARK, 0, 1))
		goto out;
	frame = skel->bss->addr[0];
	pin(cpu_b);
	if (run(skel, OP_DESTROY, 0, 1) || run(skel, OP_PAIR_48, 0, 0))
		goto out;
	ASSERT_EQ(skel->bss->last, frame, "where it was freed");
	pin(cpu_a);
	if (run(skel, OP_PAIR_48, 0, 0))
		goto out;
	ASSERT_NEQ(skel->bss->last, frame, "where it was allocated");
out:
	unpin();
	coro_frames__destroy(skel);
}

/* What the cache of the program of @skel does is counted from now on */
static struct coro_frames_count *count(struct coro_frames *skel)
{
	struct coro_frames_count *counts = coro_frames_count__open_and_load();
	struct bpf_prog_info info;

	if (!ASSERT_OK_PTR(counts, "coro_frames_count__open_and_load"))
		return NULL;
	if (prog_info(skel, &info) || !ASSERT_OK(coro_frames_count__attach(counts), "attach")) {
		coro_frames_count__destroy(counts);
		return NULL;
	}
	counts->bss->load_time = info.load_time;
	return counts;
}

/* How many frames the program has taken from the allocator */
static __u64 taken(struct coro_frames_count *counts)
{
	return counts->bss->made + counts->bss->refilled;
}

/*
 * The program goes: every frame that it took from the allocator has gone back by then, or
 * goes back with its cache. Destroys both objects.
 */
static void all_freed(struct coro_frames *skel, struct coro_frames_count *counts)
{
	coro_frames__destroy(skel);
	if (counts && wait_for(&counts->bss->gone, 1))
		ASSERT_EQ(counts->bss->freed, taken(counts), "freed");
	coro_frames_count__destroy(counts);
}

/*
 * More frames end on a CPU than it keeps, in a row, and the CPU has been to the allocator for
 * them: its cache was too small. It grows, nothing goes back to the allocator, and the same
 * burst again takes no frame from there.
 */
static void test_grow(void)
{
	struct coro_frames *skel = load();
	struct coro_frames_count *counts;
	__u64 before;

	if (!skel)
		return;
	counts = count(skel);
	if (!counts)
		goto out;
	pin(cpu_a);
	if (run(skel, OP_PARK, 0, NR_SLOTS) || run(skel, OP_DESTROY, 0, NR_SLOTS))
		goto out;
	ASSERT_GE(counts->bss->made, 16, "made");
	before = taken(counts);
	if (run(skel, OP_PARK, 0, NR_SLOTS) || run(skel, OP_DESTROY, 0, NR_SLOTS))
		goto out;
	ASSERT_EQ(taken(counts), before, "taken again");
	ASSERT_EQ(counts->bss->freed, 0, "freed");
out:
	unpin();
	all_freed(skel, counts);
}

/*
 * The same number of frames end on a CPU that allocated none of them, as one that has an
 * executor and no device. It keeps the first ones in its cache and the next ones beside it;
 * when those are too many it has no use for them, and the kernel frees them, once and not each
 * frame as it comes. What the CPU has then are its next frames.
 */
static void test_one_way(void)
{
	__u64 first[NR_SLOTS], kept[NR_SLOTS];
	struct coro_frames *skel = load();
	struct coro_frames_count *counts;
	int freed, nr, i;
	__u64 before;

	if (!skel)
		return;
	counts = count(skel);
	if (!counts)
		goto out;
	pin(cpu_a);
	if (run(skel, OP_PARK, 0, NR_SLOTS))
		goto out;
	memcpy(first, skel->bss->addr, sizeof(first));
	pin(cpu_b);
	if (run(skel, OP_DESTROY, 0, NR_SLOTS))
		goto out;
	/*
	 * The cache is full, as many came as wait beside it, and one more. Where the irq_work
	 * is not there at once, some of the last ones came before it.
	 */
	for (i = 0; i < 10000 && READ_ONCE(counts->bss->freed) <= CACHE_FRAMES; i++)
		usleep(1000);
	freed = counts->bss->freed;
	if (!ASSERT_GT(freed, CACHE_FRAMES, "freed") ||
	    !ASSERT_LE(freed, NR_SLOTS - CACHE_FRAMES, "freed"))
		goto out;
	nr = NR_SLOTS - freed;
	memcpy(kept, first, CACHE_FRAMES * sizeof(*kept));
	memcpy(kept + CACHE_FRAMES, first + CACHE_FRAMES + freed,
	       (nr - CACHE_FRAMES) * sizeof(*kept));
	before = taken(counts);
	if (run(skel, OP_PARK, 0, nr))
		goto out;
	same_frames(skel->bss->addr, kept, nr, "kept");
	ASSERT_EQ(taken(counts), before, "taken");
	ASSERT_EQ(counts->bss->freed, freed, "freed once");
out:
	unpin();
	all_freed(skel, counts);
}

/*
 * The frames that a program has when it goes are freed with it: in the caches of two CPUs, of
 * two classes, and beside a cache.
 */
static void test_teardown(void)
{
	struct coro_frames_count *counts;
	struct coro_frames *skel;
	int i;

	for (i = 0; i < 3; i++) {
		skel = load();
		if (!skel)
			return;
		counts = count(skel);
		if (counts) {
			pin(cpu_a);
			run(skel, OP_PARK, 0, CACHE_FRAMES + 6);
			pin(cpu_b);
			run(skel, OP_DESTROY, 0, CACHE_FRAMES + 6);
			run(skel, OP_PAIR_200, 0, 0);
			ASSERT_EQ(counts->bss->freed, 0, "freed before");
			ASSERT_GT(taken(counts), CACHE_FRAMES + 6, "taken");
		}
		unpin();
		all_freed(skel, counts);
	}
}

/*
 * A CPU that does not run out of the frames that it keeps gives back half of them every two
 * seconds. The timer is one that does not wake a CPU, so this stays on the CPU that loaded
 * the program.
 */
static void test_age(void)
{
	struct coro_frames_count *counts;
	struct coro_frames *skel;
	int i;

	pin(cpu_a);
	skel = load();
	if (!skel)
		return;
	counts = count(skel);
	if (!counts || run(skel, OP_PARK, 0, 40) || run(skel, OP_DESTROY, 0, 40))
		goto out;
	ASSERT_EQ(counts->bss->freed, 0, "freed");
	for (i = 0; i < 100000 && READ_ONCE(counts->bss->freed) * 2 < taken(counts); i++)
		usleep(100);
	ASSERT_GE(counts->bss->freed * 2, taken(counts), "half");
	/* and has what it kept */
	if (!run(skel, OP_PAIR_48, 0, 0))
		ASSERT_GE(counts->bss->freed * 2, taken(counts), "kept");
out:
	unpin();
	all_freed(skel, counts);
}

static int perf_event(int type, int config, int cpu)
{
	struct perf_event_attr attr = {
		.size = sizeof(attr),
		.type = type,
		.config = config,
		.sample_period = 100003,
	};

	return syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
}

/*
 * An interrupt and an NMI come over the code that has taken a class of the cache: the
 * program's timer loops on allocating and freeing in softirq, and the program does the same
 * where its two perf events come. They find the class taken, the allocation goes to the
 * allocator and the free puts the frame beside the cache, and no frame is lost or handed out
 * twice: KASAN would say so, and the count at the end.
 */
static void test_contexts(void)
{
	struct coro_frames_ctx *skel = coro_frames_ctx__open_and_load();
	struct bpf_link *clock_link = NULL, *cycles_link = NULL;
	struct coro_frames_count *counts = NULL;
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	int clock = -1, cycles = -1, i;

	if (!ASSERT_OK_PTR(skel, "coro_frames_ctx__open_and_load"))
		return;
	counts = coro_frames_count__open_and_load();
	if (!ASSERT_OK_PTR(counts, "coro_frames_count__open_and_load") ||
	    !ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.event), &info, &len),
		       "get_info") ||
	    !ASSERT_OK(coro_frames_count__attach(counts), "attach"))
		goto out;
	counts->bss->load_time = info.load_time;
	clock = perf_event(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, cpu_b);
	if (!ASSERT_GE(clock, 0, "cpu-clock"))
		goto out;
	clock_link = bpf_program__attach_perf_event(skel->progs.event, clock);
	if (!ASSERT_OK_PTR(clock_link, "attach cpu-clock"))
		goto out;
	/* no such counter in every guest */
	cycles = perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, cpu_b);
	if (cycles >= 0) {
		cycles_link = bpf_program__attach_perf_event(skel->progs.event, cycles);
		if (!ASSERT_OK_PTR(cycles_link, "attach cycles"))
			goto out;
	}
	/* a round of the loop is over, and interrupts have come over it */
	for (i = 0; i < 10000; i++) {
		if (skel->bss->rounds &&
		    counts->bss->busy_alloc[CTX_HARDIRQ] && counts->bss->busy_free[CTX_HARDIRQ] &&
		    (cycles < 0 ||
		     (counts->bss->busy_alloc[CTX_NMI] && counts->bss->busy_free[CTX_NMI])))
			break;
		usleep(1000);
	}
	skel->bss->stop = 1;
	ASSERT_GT(skel->bss->rounds, 0, "rounds");
	ASSERT_GT(counts->bss->busy_alloc[CTX_HARDIRQ], 0, "allocation, hard interrupt");
	ASSERT_GT(counts->bss->busy_free[CTX_HARDIRQ], 0, "free, hard interrupt");
	if (cycles >= 0) {
		ASSERT_GT(counts->bss->busy_alloc[CTX_NMI], 0, "allocation, NMI");
		ASSERT_GT(counts->bss->busy_free[CTX_NMI], 0, "free, NMI");
	} else {
		printf("%s:SKIP:no PERF_COUNT_HW_CPU_CYCLES, nothing in NMI\n", __func__);
	}
out:
	bpf_link__destroy(cycles_link);
	bpf_link__destroy(clock_link);
	if (cycles >= 0)
		close(cycles);
	if (clock >= 0)
		close(clock);
	coro_frames_ctx__destroy(skel);
	if (counts && counts->bss->load_time && wait_for(&counts->bss->gone, 1))
		ASSERT_EQ(counts->bss->freed, taken(counts), "freed");
	coro_frames_count__destroy(counts);
}

/*
 * A program whose last reference is gone gets no frame, also where its cache has one: the
 * destroy function of a frame that it left parked allocates one when the kernel calls it.
 */
static void test_dying(void)
{
	struct coro_frames *skel = load();
	struct coro_frames__bss bss = {};
	struct bpf_prog_info info;
	int cpu, bss_fd, zero = 0;

	if (!skel)
		return;
	bss_fd = dup(bpf_map__fd(skel->maps.bss));
	if (!ASSERT_GE(bss_fd, 0, "bss_fd") || prog_info(skel, &info))
		goto out;
	/* while the program is there it gets one */
	if (run(skel, OP_PARK_ALLOCS, 0, 0) || run(skel, OP_DESTROY, 0, 1))
		goto out;
	ASSERT_EQ(skel->bss->tried, 1, "tried");
	ASSERT_EQ(skel->bss->got, 1, "got");
	if (run(skel, OP_PARK_ALLOCS, 0, 0))
		goto out;
	/* a frame in the cache of each CPU, for whichever of them destroys the parked one */
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, &all_cpus))
			continue;
		pin(cpu);
		if (run(skel, OP_PAIR_48, 0, 0))
			goto out;
	}
	coro_frames__destroy(skel);
	skel = NULL;
	if (released(info.id) && ASSERT_OK(bpf_map_lookup_elem(bss_fd, &zero, &bss), "bss")) {
		ASSERT_EQ(bss.tried, 2, "tried");
		ASSERT_EQ(bss.got, 1, "got");
	}
out:
	unpin();
	if (bss_fd >= 0)
		close(bss_fd);
	coro_frames__destroy(skel);
}

static long long cgroup_bytes(const char *cgroup)
{
	char buf[32] = {};

	if (!ASSERT_OK(read_cgroup_file(cgroup, "memory.current", buf, sizeof(buf)), cgroup))
		return -1;
	return atoll(buf);
}

/*
 * The frames of a program are charged to the memory cgroup of the task that loaded it, whoever
 * runs it, until they are freed.
 */
static void test_charge(void)
{
	const long long bytes = (long long)NR_MANY * MANY_CLASS;
	long long loader, runner, loader_full, runner_full;
	struct coro_frames *skel = NULL;
	struct bpf_prog_info info;
	int loader_fd, runner_fd = -1, i;

	loader_fd = test__join_cgroup("/coro_frames_loader");
	if (!ASSERT_GE(loader_fd, 0, "join loader"))
		return;
	skel = load();
	runner_fd = test__join_cgroup("/coro_frames_runner");
	if (!skel || !ASSERT_GE(runner_fd, 0, "join runner") || prog_info(skel, &info))
		goto out;
	loader = cgroup_bytes("/coro_frames_loader");
	runner = cgroup_bytes("/coro_frames_runner");
	for (i = 0; i < NR_MANY; i += 512)
		if (run(skel, OP_FILL, i, i + 512))
			goto out;
	loader_full = cgroup_bytes("/coro_frames_loader");
	runner_full = cgroup_bytes("/coro_frames_runner");
	if (loader < 0 || runner < 0 || loader_full < 0 || runner_full < 0)
		goto out;
	/* charges come and go in batches of pages on each CPU */
	ASSERT_GT(loader_full - loader, bytes / 2, "the loader pays");
	ASSERT_LT(runner_full - runner, bytes / 4, "who runs it does not");
	coro_frames__destroy(skel);
	skel = NULL;
	if (!released(info.id))
		goto out;
	for (i = 0; i < 10000; i++) {
		loader = cgroup_bytes("/coro_frames_loader");
		if (loader < 0 || loader < loader_full - bytes / 2)
			break;
		usleep(1000);
	}
	ASSERT_LT(loader, loader_full - bytes / 2, "until the frames are freed");
out:
	coro_frames__destroy(skel);
	close(loader_fd);
	if (runner_fd >= 0)
		close(runner_fd);
}

void test_coro_frames(void)
{
	if (test__start_subtest("charge"))
		test_charge();
	if (!two_cpus()) {
		test__skip();
		return;
	}
	if (test__start_subtest("reuse"))
		test_reuse();
	if (test__start_subtest("other_cpu"))
		test_other_cpu();
	if (test__start_subtest("grow"))
		test_grow();
	if (test__start_subtest("one_way"))
		test_one_way();
	if (test__start_subtest("teardown"))
		test_teardown();
	if (test__start_subtest("age"))
		test_age();
	if (test__start_subtest("contexts"))
		test_contexts();
	if (test__start_subtest("dying"))
		test_dying();
}
