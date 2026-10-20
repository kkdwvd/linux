// SPDX-License-Identifier: GPL-2.0
#include <sys/mman.h>
#include <test_progs.h>
#include <bpf/btf.h>

#define OBJ "./data_in_arena_cxx.bpf.o"

#if defined(__aarch64__)
#define ARENA_ADDR (1ull << 32)
#else
#define ARENA_ADDR (1ull << 44)
#endif
#define ARENA_PAGES 4

/* struct ctx of progs/data_in_arena_cxx.cpp */
struct cxx_ctx {
	unsigned long vptr;
	unsigned long static_vptr;
	long area;
	long sides;
};

/* type_info of the C++ ABI */
struct type_info {
	const void *vptr;
	const char *name;
	const struct type_info *base;
};

#define NODE_F "_ZNK12_GLOBAL__N_14Node1fEv"
#define ERROR_DTOR "_ZN12_GLOBAL__N_15ErrorD1Ev"

static int run(struct bpf_object *obj, const char *name, struct cxx_ctx *ctx)
{
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = ctx,
		.ctx_size_in = sizeof(*ctx),
	);

	memset(ctx, 0, sizeof(*ctx));
	if (!ASSERT_OK_PTR(prog, name) ||
	    !ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
		return -1;
	return opts.retval;
}

/* The JITed functions of a program and their func_info, in the same order */
struct funcs {
	__u64 ksyms[32];
	struct bpf_func_info finfo[32];
	__u32 cnt;
};

static bool get_funcs(struct bpf_object *obj, const char *name, struct funcs *f)
{
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	memset(f, 0, sizeof(*f));
	info.nr_jited_ksyms = ARRAY_SIZE(f->ksyms);
	info.jited_ksyms = ptr_to_u64(f->ksyms);
	info.nr_func_info = ARRAY_SIZE(f->finfo);
	info.func_info_rec_size = sizeof(f->finfo[0]);
	info.func_info = ptr_to_u64(f->finfo);
	if (!prog || bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &len) ||
	    info.nr_jited_ksyms > ARRAY_SIZE(f->ksyms) || info.nr_jited_ksyms != info.nr_func_info)
		return false;
	f->cnt = info.nr_jited_ksyms;
	return true;
}

/* The BTF type of the function of the program at the JITed address, 0 if none */
static __u32 jited_func_type(struct bpf_object *obj, const char *name, unsigned long addr)
{
	struct funcs f;
	__u32 i;

	if (!get_funcs(obj, name, &f))
		return 0;
	for (i = 0; i < f.cnt; i++)
		if (f.ksyms[i] == addr)
			return f.finfo[i].type_id;
	return 0;
}

/* The JITed functions in the first slots of the vtable are those of the program */
static void check_slots(struct bpf_object *obj, const char *name, const unsigned long *vtable,
			int cnt)
{
	int i;

	for (i = 0; i < cnt; i++)
		ASSERT_NEQ(jited_func_type(obj, name, vtable[i]), 0, "slot");
}

/*
 * The virtual functions of Shape and its derived classes: through the vptrs of
 * objects in arena, one of which the program constructs there, and through the
 * type_info objects that the vtables point to
 */
static void check_virtual_calls(struct bpf_object *obj, const char *filler)
{
	const struct type_info *ti;
	const unsigned long *vtable;
	struct cxx_ctx ctx;

	ASSERT_EQ(run(obj, "virtual_calls", &ctx), 0, "virtual_calls");
	ASSERT_EQ(ctx.area, 12 + 1025 + 0 + 1036, "area");
	ASSERT_EQ(ctx.sides, 447, "sides");
	/* the vptr that the program stored is the one that libbpf put there */
	ASSERT_EQ(ctx.vptr, ctx.static_vptr, "vptr");

	/* the vtable in arena has JITed functions of the program that filled it */
	vtable = (const unsigned long *)ctx.vptr;
	if (!ASSERT_OK_PTR(vtable, "vtable"))
		return;
	check_slots(obj, filler, vtable, 2);
	ASSERT_EQ(vtable[-2], 0, "offset to top");
	ti = (const struct type_info *)vtable[-1];
	if (!ASSERT_OK_PTR(ti, "type_info") || !ASSERT_OK_PTR(ti->base, "base"))
		return;
	ASSERT_STREQ(ti->name, "N12_GLOBAL__N_16SquareE", "name");
	ASSERT_STREQ(ti->base->name, "N12_GLOBAL__N_14RectE", "base name");
}

/*
 * The virtual destructor of Node, which that of Leaf calls directly, and
 * Node::f(), which a qualified call calls directly, through the vtables
 */
static void check_destructors(struct bpf_object *obj, const char *filler)
{
	const unsigned long *vtable;
	struct cxx_ctx ctx;

	ASSERT_EQ(run(obj, "destructors", &ctx), 0, "destructors");
	ASSERT_EQ(ctx.area, 3 + 40 + 400, "f");
	ASSERT_EQ(ctx.sides, 121, "dtors");

	/* complete and deleting destructors, f() */
	vtable = (const unsigned long *)ctx.vptr;
	if (ASSERT_OK_PTR(vtable, "Node vtable"))
		check_slots(obj, filler, vtable, 3);
	vtable = (const unsigned long *)ctx.static_vptr;
	if (ASSERT_OK_PTR(vtable, "Leaf vtable"))
		check_slots(obj, filler, vtable, 3);
}

static struct bpf_object *open_obj(const char *only)
{
	struct bpf_program *prog;
	struct bpf_object *obj;

	obj = bpf_object__open_file(OBJ, NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		return NULL;
	bpf_object__for_each_program(prog, obj)
		bpf_program__set_autoload(prog, !only || !strcmp(bpf_program__name(prog), only));
	return obj;
}

/* One program has the functions and calls them */
static void test_one_prog(void)
{
	struct bpf_object *obj = open_obj("virtual_calls");

	if (obj && ASSERT_OK(bpf_object__load(obj), "load"))
		check_virtual_calls(obj, "virtual_calls");
	bpf_object__close(obj);
}

/*
 * The first program has the functions, which the others call in its image:
 * with a direct call in another program, Node::f() has a copy there too
 */
static void test_two_progs(void)
{
	struct bpf_object *obj = open_obj(NULL);
	struct cxx_ctx ctx;

	if (!obj || !ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;
	check_virtual_calls(obj, "virtual_calls");
	ASSERT_EQ(run(obj, "virtual_calls2", &ctx), 0, "virtual_calls2");
	ASSERT_EQ(ctx.area, 12 + 1025 + 0 + 1036, "area");
	ASSERT_EQ(ctx.sides, 4, "sides");
	check_destructors(obj, "virtual_calls");
	ASSERT_EQ(run(obj, "type_names", &ctx), 0, "type_names");
out:
	bpf_object__close(obj);
}

/*
 * The program calls Node::f() directly, and so does Leaf::f(). The vtable of
 * Node has another copy of it, which nothing calls and has a BTF FUNC of its
 * own: the kernel verifies only that one for callx of a number. The copy of
 * Leaf::f() in the vtable of Leaf calls a third one, of the original type like
 * the one that the program calls, which only such copies call.
 */
static void test_destructors(void)
{
	struct bpf_object *obj = open_obj("destructors");
	struct cxx_ctx ctx;
	struct funcs funcs;
	struct btf *btf;
	int f_id, copies = 0;
	__u32 slot_id, i;

	if (!obj || !ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;
	check_destructors(obj, "destructors");

	ASSERT_EQ(run(obj, "destructors", &ctx), 0, "destructors");
	btf = bpf_object__btf(obj);
	f_id = btf__find_by_name_kind(btf, NODE_F, BTF_KIND_FUNC);
	slot_id = jited_func_type(obj, "destructors", ((const unsigned long *)ctx.vptr)[2]);
	if (!ASSERT_GT(f_id, 0, "f") || !ASSERT_NEQ(slot_id, 0, "f in vtable"))
		goto out;
	ASSERT_NEQ(slot_id, f_id, "a copy for arena data");
	ASSERT_STREQ(btf__name_by_offset(btf, btf__type_by_id(btf, slot_id)->name_off), NODE_F,
		     "copy name");
	if (!ASSERT_TRUE(get_funcs(obj, "destructors", &funcs), "funcs"))
		goto out;
	for (i = 0; i < funcs.cnt; i++)
		copies += funcs.finfo[i].type_id == f_id;
	ASSERT_EQ(copies, 2, "the copies that the code calls");
out:
	bpf_object__close(obj);
}

/*
 * The destructor of Error runs on an object on the stack, called directly, and
 * on the thrown object, through the address that the throw takes, which the
 * handler calls from arena. The address is that of a copy of the destructor
 * that nothing calls directly. The kernel verifies a function whose address
 * is taken on its own, with numbers for arguments, and the one that the code
 * calls with a pointer to the stack: one copy can't be both.
 */
static void test_throws(void)
{
	struct bpf_object *obj = NULL;
	int dtor_id, copies = 0;
	struct funcs funcs;
	struct cxx_ctx ctx;
	__u32 addr_id, i;
	struct btf *btf;

	/* the prog is there if clang lowers unwinding */
	btf = btf__parse(OBJ, NULL);
	if (!ASSERT_OK_PTR(btf, "btf"))
		return;
	if (btf__find_by_name_kind(btf, "throws", BTF_KIND_FUNC) < 0) {
		test__skip();
		goto out;
	}

	obj = open_obj("throws");
	if (!obj || !ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;
	ASSERT_EQ(run(obj, "throws", &ctx), 0, "throws");
	ASSERT_EQ(ctx.area, -1, "caught");
	ASSERT_EQ(ctx.sides, 12, "dtors");

	/* the address that the throw took is the copy, of a BTF type of its own */
	dtor_id = btf__find_by_name_kind(bpf_object__btf(obj), ERROR_DTOR, BTF_KIND_FUNC);
	addr_id = jited_func_type(obj, "throws", ctx.vptr);
	if (!ASSERT_GT(dtor_id, 0, "dtor") || !ASSERT_NEQ(addr_id, 0, "dtor address"))
		goto out;
	ASSERT_NEQ(addr_id, dtor_id, "a copy for the address");
	if (!ASSERT_TRUE(get_funcs(obj, "throws", &funcs), "funcs"))
		goto out;
	for (i = 0; i < funcs.cnt; i++)
		copies += funcs.finfo[i].type_id == dtor_id;
	ASSERT_EQ(copies, 1, "the copy that the code calls");
out:
	bpf_object__close(obj);
	btf__free(btf);
}

/* The offset of variable var in DATASEC sec */
static int var_off(const struct btf *btf, const char *sec, const char *var, __u32 *off)
{
	const struct btf_var_secinfo *vi;
	const struct btf_type *t, *v;
	int id, i;

	id = btf__find_by_name_kind(btf, sec, BTF_KIND_DATASEC);
	if (id < 0)
		return id;
	t = btf__type_by_id(btf, id);
	vi = btf_var_secinfos(t);
	for (i = 0; i < btf_vlen(t); i++, vi++) {
		v = btf__type_by_id(btf, vi->type);
		if (!strcmp(btf__name_by_offset(btf, v->name_off), var)) {
			*off = vi->offset;
			return 0;
		}
	}
	return -ENOENT;
}

/*
 * An arena that the test creates at map_extra. libbpf doesn't write to it, so
 * the image from bpf_map__initial_value(), with .rodata moved to arena and the
 * JITed functions in the vtables, goes where the pointers put the data.
 */
static void test_reused_arena(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE,
		    .map_extra = ARENA_ADDR);
	size_t arena_sz = ARENA_PAGES * getpagesize(), sz, data_sz, rodata_sz, off;
	void *image, *data, *rodata, *base = MAP_FAILED;
	struct bpf_object *obj = open_obj(NULL);
	__u32 square_off, vtable_off;
	unsigned long vptr;
	struct cxx_ctx ctx;
	struct btf *btf;
	int fd = -1;

	if (!obj)
		return;
	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena", 0, 0, ARENA_PAGES, &opts);
	if (!ASSERT_GE(fd, 0, "map_create") ||
	    !ASSERT_OK(bpf_map__reuse_fd(bpf_object__find_map_by_name(obj, "arena"), fd),
		       "reuse_fd") ||
	    !ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;

	image = bpf_map__initial_value(bpf_object__find_map_by_name(obj, "arena"), &sz);
	data = bpf_map__initial_value(bpf_object__find_map_by_name(obj, ".data"), &data_sz);
	rodata = bpf_map__initial_value(bpf_object__find_map_by_name(obj, ".rodata"), &rodata_sz);
	btf = bpf_object__btf(obj);
	if (!ASSERT_OK_PTR(image, "image") || !ASSERT_OK_PTR(data, ".data") ||
	    !ASSERT_OK_PTR(rodata, ".rodata") ||
	    !ASSERT_OK(var_off(btf, ".data", "square", &square_off), "square") ||
	    !ASSERT_OK(var_off(btf, ".rodata", "_ZTVN12_GLOBAL__N_16SquareE", &vtable_off),
		       "vtable"))
		goto out;

	/* the vptr of square in the image is the address of the vtable plus 16 */
	memcpy(&vptr, data + square_off, sizeof(vptr));
	off = vptr - 16 - (rodata - image) - vtable_off - ARENA_ADDR;
	if (!ASSERT_LT(off, arena_sz, "data offset") ||
	    !ASSERT_LE(sz, arena_sz - off, "data size") ||
	    !ASSERT_EQ(off % getpagesize(), 0, "data alignment"))
		goto out;

	base = mmap((void *)ARENA_ADDR, arena_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ASSERT_EQ(base, (void *)ARENA_ADDR, "mmap"))
		goto out;
	memcpy(base + off, image, sz);

	check_virtual_calls(obj, "virtual_calls");
	check_destructors(obj, "virtual_calls");
	ASSERT_EQ(run(obj, "type_names", &ctx), 0, "type_names");
out:
	if (base != MAP_FAILED)
		munmap(base, arena_sz);
	if (fd >= 0)
		close(fd);
	bpf_object__close(obj);
}

/* The virtual functions return string literals, which are in arena like the rest of the data */
static void test_virtual_names(void)
{
	struct bpf_object *obj = open_obj("virtual_names");
	struct cxx_ctx ctx;

	if (obj && ASSERT_OK(bpf_object__load(obj), "load"))
		ASSERT_EQ(run(obj, "virtual_names", &ctx), 0, "virtual_names");
	bpf_object__close(obj);
}

void test_data_in_arena_cxx(void)
{
#if !defined(__x86_64__) && !defined(__aarch64__)
	/* other JITs don't take BPF_F_ARENA_SCALAR */
	test__skip();
	return;
#endif
	if (test__start_subtest("one_prog"))
		test_one_prog();
	if (test__start_subtest("two_progs"))
		test_two_progs();
	if (test__start_subtest("destructors"))
		test_destructors();
	if (test__start_subtest("reused_arena"))
		test_reused_arena();
	if (test__start_subtest("throws"))
		test_throws();
	if (test__start_subtest("virtual_names"))
		test_virtual_names();
}
