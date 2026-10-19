// SPDX-License-Identifier: GPL-2.0

#include <sys/mman.h>
#include <test_progs.h>
#include "data_in_arena.skel.h"
#include "data_in_arena_decl.skel.h"
#include "data_in_arena_fail.skel.h"

static int run_prog(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &topts), "test_run"))
		return -1;
	return topts.retval;
}

static void run(struct data_in_arena *skel, int counter)
{
	int i;

	ASSERT_EQ(run_prog(skel->progs.use_data), counter + 7 + 1 + 2, "retval");
	ASSERT_EQ(skel->bss->sum, counter + 7 + 1 + 2, "sum");
	ASSERT_EQ(skel->data->counter, counter + 1, "counter");
	ASSERT_EQ(skel->data->pair[1], 5, "pair[1]");
	for (i = 0; i < 4; i++)
		ASSERT_EQ(skel->bss->table[i], 10 * (i + 1) + i, "table");
}

static void test_in_arena(void)
{
	struct bpf_map_info info = {};
	struct data_in_arena *skel;
	__u32 len = sizeof(info);
	struct bpf_map *arena;
	size_t sz;

	skel = data_in_arena__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	arena = bpf_object__find_map_by_name(skel->obj, "arena");
	if (!ASSERT_OK_PTR(arena, "arena"))
		goto out;
	ASSERT_EQ(bpf_map__type(arena), BPF_MAP_TYPE_ARENA, "arena type");
	ASSERT_EQ(bpf_map__max_entries(arena), 1, "arena pages");
	ASSERT_OK(bpf_map__set_max_entries(arena, 8), "arena resize");
	ASSERT_FALSE(bpf_map__autocreate(skel->maps.data), "data autocreate");
	ASSERT_FALSE(bpf_map__autocreate(skel->maps.bss), "bss autocreate");
	ASSERT_FALSE(bpf_map__autocreate(skel->maps.rodata), "rodata autocreate");
	ASSERT_FALSE(bpf_map__autocreate(skel->maps.data_rel_ro), "data_rel_ro autocreate");
	ASSERT_EQ(bpf_map__set_autocreate(skel->maps.data, true), -EOPNOTSUPP, "set_autocreate");
	ASSERT_EQ(bpf_map__set_value_size(skel->maps.bss, 4096), -EOPNOTSUPP, "set_value_size");
	ASSERT_EQ(bpf_map__initial_value(skel->maps.data, &sz), skel->data, "initial_value");
	ASSERT_EQ(sz, sizeof(*skel->data), "initial_value size");

	/* initial values are set the usual way */
	skel->data->counter = 100;

	if (!ASSERT_OK(data_in_arena__load(skel), "load"))
		goto out;
	/* there are no maps behind the sections */
	ASSERT_ERR(bpf_map_get_info_by_fd(bpf_map__fd(skel->maps.data), &info, &len), "data map");
	ASSERT_ERR(bpf_map_get_info_by_fd(bpf_map__fd(skel->maps.bss), &info, &len), "bss map");
	ASSERT_ERR(bpf_map_get_info_by_fd(bpf_map__fd(skel->maps.rodata), &info, &len),
		   "rodata map");
	ASSERT_ERR(bpf_map_get_info_by_fd(bpf_map__fd(skel->maps.data_rel_ro), &info, &len),
		   "data_rel_ro map");
	run(skel, 100);

	/* read-only data with pointers to data and to functions, which are NULL */
	ASSERT_EQ(run_prog(skel->progs.use_ops), 42 + 1 + 'e', "use_ops");
	ASSERT_EQ(skel->data->counter, 102, "counter");

	/* alignment of sections and pointers to data in data */
	ASSERT_EQ((unsigned long)&skel->bss->aligned64 % 64, 0, "alignment");
	ASSERT_EQ(run_prog(skel->progs.use_ptrs), 0, "use_ptrs");
	ASSERT_EQ(skel->data->x, 43, "x");
	ASSERT_EQ(skel->bss->aligned64.v[7], 7, "aligned64");
	ASSERT_EQ(skel->data->px, &skel->data->x, "px");

	/* format strings of bpf_printk() and BPF_SNPRINTF() */
	ASSERT_EQ(run_prog(skel->progs.use_printk), sizeof("43-7"), "use_printk");
	ASSERT_STREQ(skel->bss->out, "43-7", "out");
out:
	data_in_arena__destroy(skel);
}

/* The object has an arena map and __arena variables */
static void test_declared_arena(void)
{
	struct data_in_arena_decl *skel;
	struct bpf_map *map;
	int arenas = 0;

	skel = data_in_arena_decl__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	bpf_object__for_each_map(map, skel->obj)
		arenas += bpf_map__type(map) == BPF_MAP_TYPE_ARENA;
	ASSERT_EQ(arenas, 1, "no second arena");
	skel->data->counter = 6;
	if (!ASSERT_OK(data_in_arena_decl__load(skel), "load"))
		goto out;
	ASSERT_EQ(run_prog(skel->progs.use_data), 6 + 7 + 11, "retval");
	ASSERT_EQ(run_prog(skel->progs.use_data), 7 + 7 + 12, "retval");
	ASSERT_EQ(skel->bss->sum, 7 + 7 + 12, "sum");
	ASSERT_EQ(skel->data->counter, 8, "counter");
out:
	data_in_arena_decl__destroy(skel);
}

/*
 * A pointer in data that can't be made an address of arena fails the load:
 * one to per-CPU data, which is a map of its own
 */
static void test_ptr_to_map(void)
{
	struct data_in_arena_fail *skel;

	skel = data_in_arena_fail__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	ASSERT_EQ(data_in_arena_fail__load(skel), -LIBBPF_ERRNO__RELOC, "load");
	data_in_arena_fail__destroy(skel);
}

/* So does a pointer to a variable of the kernel. There is no skeleton: the open fails. */
static void test_ptr_to_extern(void)
{
	struct bpf_object *obj;

	obj = bpf_object__open_file("./data_in_arena_extern.bpf.o", NULL);
	if (!ASSERT_ERR_PTR(obj, "open"))
		bpf_object__close(obj);
}

/* __arena variables and no arena map. There is no skeleton: the open fails. */
static void test_arena_var_no_map(void)
{
	struct bpf_object *obj;

	obj = bpf_object__open_file("./data_in_arena_nomap.bpf.o", NULL);
	if (!ASSERT_ERR_PTR(obj, "open"))
		bpf_object__close(obj);
}

/* The address of an arena that libbpf doesn't create is not known. No pointers in data then. */
static void test_not_my_arena(bool pin)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE);
	struct data_in_arena *skel;
	struct bpf_map *arena;
	int fd = -1;

	skel = data_in_arena__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	arena = bpf_object__find_map_by_name(skel->obj, "arena");
	if (!ASSERT_OK_PTR(arena, "arena"))
		goto out;
	if (pin) {
		ASSERT_OK(bpf_map__set_pin_path(arena, "/sys/fs/bpf/data_in_arena"), "pin_path");
	} else {
		fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena", 0, 0, 1, &opts);
		if (!ASSERT_GE(fd, 0, "map_create"))
			goto out;
		ASSERT_OK(bpf_map__reuse_fd(arena, fd), "reuse_fd");
	}
	ASSERT_EQ(data_in_arena__load(skel), -ENOTSUP, "load");
out:
	if (fd >= 0)
		close(fd);
	data_in_arena__destroy(skel);
}

#if defined(__aarch64__)
#define ARENA_ADDR (1ull << 32)
#else
#define ARENA_ADDR (1ull << 44)
#endif
#define ARENA_PAGES 4

/*
 * With map_extra the address of an arena that libbpf doesn't create is known. libbpf doesn't
 * write to such arena, so the data goes there from bpf_map__initial_value().
 */
static void test_reused_arena_at(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE,
		    .map_extra = ARENA_ADDR);
	size_t page_sz = getpagesize(), arena_sz = ARENA_PAGES * page_sz, sz, off;
	struct data_in_arena__data *data;
	void *image, *base = MAP_FAILED;
	struct data_in_arena *skel;
	struct bpf_map *arena;
	int fd = -1;

	skel = data_in_arena__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	arena = bpf_object__find_map_by_name(skel->obj, "arena");
	if (!ASSERT_OK_PTR(arena, "arena"))
		goto out;
	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena", 0, 0, ARENA_PAGES, &opts);
	if (!ASSERT_GE(fd, 0, "map_create"))
		goto out;
	if (!ASSERT_OK(bpf_map__reuse_fd(arena, fd), "reuse_fd"))
		goto out;
	if (!ASSERT_OK(data_in_arena__load(skel), "load"))
		goto out;

	image = bpf_map__initial_value(arena, &sz);
	if (!ASSERT_OK_PTR(image, "initial_value"))
		goto out;
	/*
	 * skel->data points into the image, px is the address of x in arena,
	 * and the image goes where that puts x.
	 */
	off = (unsigned long)skel->data->px - ARENA_ADDR - ((void *)&skel->data->x - image);
	if (!ASSERT_LT(off, arena_sz, "data offset") ||
	    !ASSERT_LE(sz, arena_sz - off, "data size") ||
	    !ASSERT_EQ(off % page_sz, 0, "data alignment"))
		goto out;

	base = mmap((void *)ARENA_ADDR, arena_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ASSERT_EQ(base, (void *)ARENA_ADDR, "mmap"))
		goto out;
	memcpy(base + off, image, sz);

	ASSERT_EQ(run_prog(skel->progs.use_ptrs), 0, "use_ptrs");
	data = base + off + ((void *)skel->data - image);
	ASSERT_EQ(data->x, 43, "x");
	ASSERT_EQ(data->px, &data->x, "px");
	ASSERT_EQ(*data->px, 43, "*px");
	ASSERT_STREQ(data->str, "hello", "str");
out:
	if (base != MAP_FAILED)
		munmap(base, arena_sz);
	if (fd >= 0)
		close(fd);
	data_in_arena__destroy(skel);
}

/*
 * A pinned arena with map_extra is at that address, whether libbpf creates it or reuses it
 * from the pin.
 */
static void test_pinned_arena_at(void)
{
	const char *pin_path = "/sys/fs/bpf/data_in_arena_at";
	struct data_in_arena *skel1, *skel2 = NULL;
	struct bpf_map *arena;

	unlink(pin_path);
	skel1 = data_in_arena__open();
	if (!ASSERT_OK_PTR(skel1, "open"))
		return;
	arena = bpf_object__find_map_by_name(skel1->obj, "arena");
	if (!ASSERT_OK_PTR(arena, "arena"))
		goto out;
	ASSERT_OK(bpf_map__set_map_extra(arena, ARENA_ADDR), "map_extra");
	ASSERT_OK(bpf_map__set_pin_path(arena, pin_path), "pin_path");
	if (!ASSERT_OK(data_in_arena__load(skel1), "load"))
		goto out;
	ASSERT_EQ(run_prog(skel1->progs.use_ptrs), 0, "use_ptrs");
	ASSERT_EQ((unsigned long)skel1->data->px >> 32, ARENA_ADDR >> 32, "px");
	ASSERT_EQ(*skel1->data->px, 43, "*px");

	skel2 = data_in_arena__open();
	if (!ASSERT_OK_PTR(skel2, "open"))
		goto out;
	arena = bpf_object__find_map_by_name(skel2->obj, "arena");
	if (!ASSERT_OK_PTR(arena, "arena"))
		goto out;
	ASSERT_OK(bpf_map__set_map_extra(arena, ARENA_ADDR), "map_extra");
	ASSERT_OK(bpf_map__set_pin_path(arena, pin_path), "pin_path");
	if (!ASSERT_OK(data_in_arena__load(skel2), "load"))
		goto out;
	ASSERT_TRUE(bpf_map__is_pinned(arena), "pinned");
	/* the image of the second object points to the data of the first one, x is 43 there */
	ASSERT_EQ(skel2->data->px, skel1->data->px, "px");
	ASSERT_EQ(run_prog(skel2->progs.use_ptrs), 2, "use_ptrs");
out:
	data_in_arena__destroy(skel2);
	data_in_arena__destroy(skel1);
	unlink(pin_path);
}

/* The object is there if rustc and clang can build it, see Makefile.buildvars */
static void test_rust(void)
{
	const char *file = "./data_in_arena_rust.bpf.o";
	struct bpf_object *obj;

	if (access(file, R_OK)) {
		test__skip();
		return;
	}
	obj = bpf_object__open_file(file, NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		return;
	if (!ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;
	/* libbpf goes on without BTF when the kernel doesn't take it */
	ASSERT_GE(bpf_object__btf_fd(obj), 0, "btf_fd");
	ASSERT_EQ(run_prog(bpf_object__find_program_by_name(obj, "list_in_data")),
		  100 + 20 + 3, "retval");
out:
	bpf_object__close(obj);
}

void test_data_in_arena(void)
{
#if !defined(__x86_64__) && !defined(__aarch64__)
	/* other JITs don't take BPF_F_ARENA_SCALAR */
	test__skip();
	return;
#endif
	if (test__start_subtest("arena"))
		test_in_arena();
	if (test__start_subtest("declared_arena"))
		test_declared_arena();
	if (test__start_subtest("ptr_to_map"))
		test_ptr_to_map();
	if (test__start_subtest("ptr_to_extern"))
		test_ptr_to_extern();
	if (test__start_subtest("arena_var_no_map"))
		test_arena_var_no_map();
	if (test__start_subtest("pinned_arena"))
		test_not_my_arena(true);
	if (test__start_subtest("reused_arena"))
		test_not_my_arena(false);
	if (test__start_subtest("reused_arena_at"))
		test_reused_arena_at();
	if (test__start_subtest("pinned_arena_at"))
		test_pinned_arena_at();
	if (test__start_subtest("rust"))
		test_rust();
}
