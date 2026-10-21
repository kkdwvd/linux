// SPDX-License-Identifier: GPL-2.0
#include <sys/mman.h>
#include <test_progs.h>
#include "bpf_arena_common.h"
#include "progs/arena_data_ptrs.h"
#include "arena_data_ptrs.skel.h"
#include "arena_data_ptrs_data.skel.h"

#if defined(__aarch64__)
#define ARENA_ADDR (1ull << 32)
#else
#define ARENA_ADDR (1ull << 44)
#endif
#define ARENA_PAGES 4

static char log_buf[4096];
static size_t log_len;

static int print_cb(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_WARN && log_len < sizeof(log_buf))
		log_len += vsnprintf(log_buf + log_len, sizeof(log_buf) - log_len, fmt, args);
	return 0;
}

static libbpf_print_fn_t start_log(void)
{
	log_buf[0] = 0;
	log_len = 0;
	return libbpf_set_print(print_cb);
}

static int run_prog(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &topts), "test_run"))
		return -1;
	return topts.retval;
}

static struct arena_data_ptrs *open_skel(void)
{
	struct arena_data_ptrs *skel;

	skel = arena_data_ptrs__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return NULL;
	if (skel->data->skip_tests) {
		printf("%s:SKIP: no addr_space_cast support in the BPF compiler\n", __func__);
		test__skip();
		arena_data_ptrs__destroy(skel);
		return NULL;
	}
	return skel;
}

/* p points to size bytes of the arena data at a */
static bool in_data(const struct arena_data_ptrs__arena *a, const void *p, size_t size)
{
	return p >= (const void *)a && p + size <= (const void *)(a + 1);
}

/*
 * Check the pointers in arena data that is at a, where the programs see it:
 * the values first, then from the programs and from here through the same
 * pointers. n2 and svals are static and have no names here.
 */
static void check(struct arena_data_ptrs *skel, struct arena_data_ptrs__arena *a)
{
	struct ptr_node *n2 = a->n1.next;

	if (!ASSERT_EQ(skel->data->head, &a->n1, "head") ||
	    !ASSERT_EQ(a->n1.pv, &a->n1.v, "n1.pv") ||
	    !ASSERT_TRUE(in_data(a, n2, sizeof(*n2)), "n1.next") ||
	    !ASSERT_EQ(skel->rodata->ro_head, n2, "ro_head") ||
	    !ASSERT_EQ(n2->next, &a->n3, "n2.next") ||
	    !ASSERT_EQ(n2->pv, &a->n3.v, "n2.pv") ||
	    !ASSERT_EQ(a->pfield, &n2->v, "pfield") ||
	    !ASSERT_EQ(a->pval, &a->vals[2], "pval") ||
	    !ASSERT_NULL(a->n3.next, "n3.next") ||
	    !ASSERT_TRUE(in_data(a, a->n3.pv, sizeof(long)), "n3.pv") ||
	    !ASSERT_TRUE(in_data(a, a->psval, sizeof(long)), "psval") ||
	    !ASSERT_EQ(a->back, &a->n1, "back") ||
	    !ASSERT_EQ(a->ops.node, &a->n3, "ops.node"))
		return;
	ASSERT_NULL(a->ops.fn, "ops.fn");
	ASSERT_NULL(a->ops.global_fn, "ops.global_fn");
	ASSERT_NULL(a->ops_fn, "ops_fn");

	ASSERT_EQ(run_prog(skel->progs.check1), 0, "check1");
	ASSERT_EQ(run_prog(skel->progs.check2), 0, "check2");

	ASSERT_EQ(n2->v, 2, "n2.v");
	ASSERT_EQ(*a->n3.pv, 8, "*n3.pv");
	ASSERT_EQ(*a->psval, 6, "*psval");
	ASSERT_EQ(a->vals[2], 31, "vals[2]");
}

/* libbpf creates the arena, the first mmap() picks its address */
static void test_libbpf_arena(void)
{
	struct arena_data_ptrs *skel;

	skel = open_skel();
	if (!skel)
		return;
	if (ASSERT_OK(arena_data_ptrs__load(skel), "load"))
		check(skel, skel->arena);
	arena_data_ptrs__destroy(skel);
}

/* libbpf creates the arena at map_extra */
static void test_map_extra(void)
{
	struct arena_data_ptrs *skel;

	skel = open_skel();
	if (!skel)
		return;
	ASSERT_OK(bpf_map__set_map_extra(skel->maps.arena, ARENA_ADDR), "map_extra");
	if (!ASSERT_OK(arena_data_ptrs__load(skel), "load"))
		goto out;
	ASSERT_EQ((unsigned long)skel->arena >> 32, ARENA_ADDR >> 32, "arena");
	check(skel, skel->arena);
out:
	arena_data_ptrs__destroy(skel);
}

/*
 * The arena is created here, at map_extra. libbpf doesn't write to it, so
 * the image from bpf_map__initial_value() goes where the pointers say the
 * data is.
 */
static void test_reused(__u32 flags)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE | flags,
		    .map_extra = ARENA_ADDR);
	size_t arena_sz = ARENA_PAGES * getpagesize(), sz, off;
	void *image, *data, *base = MAP_FAILED;
	struct arena_data_ptrs *skel;
	int fd = -1;

	skel = open_skel();
	if (!skel)
		return;
	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena", 0, 0, ARENA_PAGES, &opts);
	if (!ASSERT_GE(fd, 0, "map_create"))
		goto out;
	if (!ASSERT_OK(bpf_map__reuse_fd(skel->maps.arena, fd), "reuse_fd"))
		goto out;
	if (!ASSERT_OK(arena_data_ptrs__load(skel), "load"))
		goto out;

	image = bpf_map__initial_value(skel->maps.arena, &sz);
	if (!ASSERT_OK_PTR(image, "initial_value") ||
	    !ASSERT_EQ(sz, sizeof(*skel->arena), "initial_value size"))
		goto out;
	/* head is the address of n1 in arena */
	off = (unsigned long)skel->data->head - offsetof(struct arena_data_ptrs__arena, n1) -
	      ARENA_ADDR;
	if (!ASSERT_LT(off, arena_sz, "data offset") || !ASSERT_LE(sz, arena_sz - off, "data size"))
		goto out;
	data = (void *)ARENA_ADDR + off;
	/* the image has the pointers already */
	ASSERT_EQ(((struct arena_data_ptrs__arena *)image)->n1.pv,
		  &((struct arena_data_ptrs__arena *)data)->n1.v, "image n1.pv");

	base = mmap((void *)ARENA_ADDR, arena_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ASSERT_EQ(base, (void *)ARENA_ADDR, "mmap"))
		goto out;
	memcpy(data, image, sz);
	check(skel, data);
out:
	if (base != MAP_FAILED)
		munmap(base, arena_sz);
	if (fd >= 0)
		close(fd);
	arena_data_ptrs__destroy(skel);
}

/* The address of an arena without map_extra that libbpf doesn't create is not known */
static void test_reused_no_map_extra(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE);
	libbpf_print_fn_t old_print_cb;
	struct arena_data_ptrs *skel;
	int fd, err;

	skel = open_skel();
	if (!skel)
		return;
	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena", 0, 0, ARENA_PAGES, &opts);
	if (!ASSERT_GE(fd, 0, "map_create"))
		goto out;
	if (!ASSERT_OK(bpf_map__reuse_fd(skel->maps.arena, fd), "reuse_fd"))
		goto out;
	old_print_cb = start_log();
	err = arena_data_ptrs__load(skel);
	libbpf_set_print(old_print_cb);
	ASSERT_EQ(err, -ENOTSUP, "load");
	ASSERT_HAS_SUBSTR(log_buf, "set its map_extra", "log");
out:
	if (fd >= 0)
		close(fd);
	arena_data_ptrs__destroy(skel);
}

/*
 * A pinned arena at map_extra: libbpf creates and pins it for one object
 * and reuses it from the pin for another, which sees the same data.
 */
static void test_pinned(void)
{
	const char *pin_path = "/sys/fs/bpf/arena_data_ptrs";
	struct arena_data_ptrs *skel1, *skel2 = NULL;
	struct arena_data_ptrs__arena *image;
	size_t sz;

	unlink(pin_path);
	skel1 = open_skel();
	if (!skel1)
		return;
	ASSERT_OK(bpf_map__set_map_extra(skel1->maps.arena, ARENA_ADDR), "map_extra");
	ASSERT_OK(bpf_map__set_pin_path(skel1->maps.arena, pin_path), "pin_path");
	if (!ASSERT_OK(arena_data_ptrs__load(skel1), "load"))
		goto out;
	check(skel1, skel1->arena);

	skel2 = open_skel();
	if (!skel2)
		goto out;
	ASSERT_OK(bpf_map__set_map_extra(skel2->maps.arena, ARENA_ADDR), "map_extra");
	ASSERT_OK(bpf_map__set_pin_path(skel2->maps.arena, pin_path), "pin_path");
	if (!ASSERT_OK(arena_data_ptrs__load(skel2), "load"))
		goto out;
	ASSERT_TRUE(bpf_map__is_pinned(skel2->maps.arena), "pinned");
	image = bpf_map__initial_value(skel2->maps.arena, &sz);
	if (!ASSERT_OK_PTR(image, "initial_value"))
		goto out;
	ASSERT_EQ(image->n1.next, skel1->arena->n1.next, "image n1.next");
	ASSERT_EQ(skel2->data->head, &skel1->arena->n1, "head");
	ASSERT_EQ(run_prog(skel2->progs.check2), 0, "check2");
out:
	arena_data_ptrs__destroy(skel2);
	arena_data_ptrs__destroy(skel1);
	unlink(pin_path);
}

/* So is the address of a pinned arena without map_extra */
static void test_pinned_no_map_extra(void)
{
	libbpf_print_fn_t old_print_cb;
	struct arena_data_ptrs *skel;
	int err;

	skel = open_skel();
	if (!skel)
		return;
	ASSERT_OK(bpf_map__set_pin_path(skel->maps.arena, "/sys/fs/bpf/arena_data_ptrs"),
		  "pin_path");
	old_print_cb = start_log();
	err = arena_data_ptrs__load(skel);
	libbpf_set_print(old_print_cb);
	ASSERT_EQ(err, -ENOTSUP, "load");
	ASSERT_HAS_SUBSTR(log_buf, "set its map_extra", "log");
	arena_data_ptrs__destroy(skel);
}

/* A pointer in arena to data that is not in arena fails the load */
static void test_ptr_to_data(void)
{
	libbpf_print_fn_t old_print_cb;
	struct arena_data_ptrs_data *skel;
	int err;

	skel = arena_data_ptrs_data__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	old_print_cb = start_log();
	err = arena_data_ptrs_data__load(skel);
	libbpf_set_print(old_print_cb);
	ASSERT_EQ(err, -LIBBPF_ERRNO__RELOC, "load");
	ASSERT_HAS_SUBSTR(log_buf, "pointer to 'x' at offset 0 can't be resolved", "log");
	ASSERT_HAS_SUBSTR(log_buf, "sec '.data' is not in arena", "log");
	arena_data_ptrs_data__destroy(skel);
}

void test_arena_data_ptrs(void)
{
	if (test__start_subtest("libbpf_arena"))
		test_libbpf_arena();
	if (test__start_subtest("map_extra"))
		test_map_extra();
	if (test__start_subtest("reused"))
		test_reused(0);
	if (test__start_subtest("reused_no_user_conv"))
		test_reused(BPF_F_NO_USER_CONV);
	if (test__start_subtest("reused_no_map_extra"))
		test_reused_no_map_extra();
	if (test__start_subtest("pinned"))
		test_pinned();
	if (test__start_subtest("pinned_no_map_extra"))
		test_pinned_no_map_extra();
	if (test__start_subtest("ptr_to_data"))
		test_ptr_to_data();
}
