// SPDX-License-Identifier: GPL-2.0
/* Parked coroutine frames, see progs/coro_park.c */
#define _GNU_SOURCE
#include <sched.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <test_progs.h>
#include <network_helpers.h>
#include <bpf/btf.h>
#include "coro_park.skel.h"
#include "coro_park_ext.skel.h"
#include "coro_park_fail.skel.h"
#include "coro_park_sys.skel.h"
#include "progs/coro_park.h"

static char log_buf[64 * 1024];

static int run_xdp(struct bpf_program *prog, int want)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = data,
		    .data_size_in = sizeof(data),
		    .repeat = 1);
	int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);

	if (!ASSERT_OK(err, "test_run xdp") || !ASSERT_EQ(opts.retval, want, "retval"))
		return -1;
	return 0;
}

/* Have the program that parks do @op */
static int run_op(struct coro_park *skel, enum coro_park_op op, int want)
{
	skel->bss->op = op;
	return run_xdp(skel->progs.owner, want);
}

static int run_syscall(struct bpf_program *prog, int want)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);

	if (!ASSERT_OK(err, "test_run syscall") || !ASSERT_EQ(opts.retval, want, "retval"))
		return -1;
	return 0;
}

static bool wait_for(__u64 *counter, __u64 want)
{
	int i;

	for (i = 0; i < 2000 && READ_ONCE(*counter) != want; i++)
		usleep(1000);
	return ASSERT_EQ(READ_ONCE(*counter), want, "counter");
}

/* The object with the program that parks loaded, and the other ones not yet */
static struct coro_park *load_owner(void)
{
	struct coro_park *skel = coro_park__open();
	struct bpf_program *prog;

	if (!ASSERT_OK_PTR(skel, "coro_park__open"))
		return NULL;
	bpf_object__for_each_program(prog, skel->obj)
		if (prog != skel->progs.owner &&
		    !ASSERT_OK(bpf_program__set_load_strategy(prog, BPF_PROG_LOAD_STRATEGY_MANUAL),
			       "set_load_strategy"))
			goto err;
	if (!ASSERT_OK(coro_park__load(skel), "coro_park__load"))
		goto err;
	return skel;
err:
	coro_park__destroy(skel);
	return NULL;
}

/* Load @prog bound to the program with @coro_prog_fd, or to none if that is 0 */
static int load_bound(struct bpf_program *prog, int coro_prog_fd)
{
	int err;

	log_buf[0] = 0;
	err = bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
	err = err ?: bpf_program__set_coro_prog_fd(prog, coro_prog_fd);
	return err ?: bpf_program__load(prog);
}

/* And with all that call its frames bound to it: every program but the one that does not load */
static struct coro_park *load(void)
{
	struct coro_park *skel = load_owner();
	struct bpf_program *prog;

	if (!skel)
		return NULL;
	bpf_object__for_each_program(prog, skel->obj) {
		if (prog == skel->progs.owner || prog == skel->progs.bound_parks)
			continue;
		if (!ASSERT_OK(load_bound(prog, bpf_program__fd(skel->progs.owner)),
			       bpf_program__name(prog))) {
			coro_park__destroy(skel);
			return NULL;
		}
	}
	return skel;
}

/* Each frame is resumed by a program of the type that it was parked for. */
static void test_resume(void)
{
	struct coro_park *skel = load();

	if (!skel)
		return;
	if (run_op(skel, OP_PARK, XDP_PASS) || run_xdp(skel->progs.resume_xdp, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->resumed, 1, "resumed, xdp");
	if (run_syscall(skel->progs.resume_syscall, 0))
		goto out;
	ASSERT_EQ(skel->bss->resumed, 101, "resumed, syscall");
	ASSERT_EQ(skel->bss->returned, 2, "returned");
	ASSERT_EQ(skel->bss->destroyed, 0, "destroyed");
	/* nothing is left to resume */
	run_xdp(skel->progs.resume_xdp, XDP_DROP);
	run_syscall(skel->progs.resume_syscall, 2);
	/* the program that parked a frame resumes it as well */
	if (run_op(skel, OP_PARK, XDP_PASS) || run_op(skel, OP_RESUME, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->resumed, 102, "resumed, own");
	ASSERT_EQ(skel->bss->returned, 3, "returned, own");
out:
	coro_park__destroy(skel);
}

/* The caller of a frame has a part of its stack in arena, and the frame's program has none. */
static void test_arena_stack(void)
{
#if defined(__x86_64__)
	struct coro_park *skel = load();

	if (!skel)
		return;
	if (!run_op(skel, OP_PARK, XDP_PASS) && !run_xdp(skel->progs.resume_xdp_arena, 7))
		ASSERT_EQ(skel->bss->resumed, 1, "resumed");
	coro_park__destroy(skel);
#else
	test__skip();
#endif
}

/* The program calls the destroy function, or has the kernel do it. */
static void test_destroy(void)
{
	struct coro_park *skel = load();

	if (!skel)
		return;
	if (run_op(skel, OP_PARK, XDP_PASS) || run_xdp(skel->progs.destroy_xdp, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->destroyed, 1, "destroyed, by the program");
	if (run_op(skel, OP_PARK, XDP_PASS) || run_syscall(skel->progs.drop_both, 0))
		goto out;
	/* the frame that the second park took out of its field, and the two that were dropped */
	wait_for(&skel->bss->destroyed, 202);
	ASSERT_EQ(skel->bss->resumed, 0, "resumed");
out:
	coro_park__destroy(skel);
}

/* A continuation parks its frame again and is resumed again, three times. */
static void test_again(void)
{
	struct coro_park *skel = load();
	int i;

	if (!skel)
		return;
	if (run_op(skel, OP_PARK_AGAIN, XDP_PASS))
		goto out;
	for (i = 0; i < 3; i++)
		if (run_xdp(skel->progs.resume_xdp, XDP_PASS))
			goto out;
	ASSERT_EQ(skel->bss->resumed, 3, "resumed");
	ASSERT_EQ(skel->bss->yields, 2, "yields");
	run_xdp(skel->progs.resume_xdp, XDP_DROP);
out:
	coro_park__destroy(skel);
}

/* Frames in the nodes of an rbtree and of a list. */
static void test_nodes(void)
{
	struct coro_park *skel = load();

	if (!skel)
		return;
	if (run_op(skel, OP_PARK_NODES, XDP_PASS) || run_xdp(skel->progs.resume_nodes, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->order[0], 10, "order[0]");
	ASSERT_EQ(skel->bss->order[1], 20, "order[1]");
	ASSERT_EQ(skel->bss->order[2], 30, "order[2]");
	ASSERT_EQ(skel->bss->resumed, 3060, "resumed");
out:
	coro_park__destroy(skel);
}

/* The kernel unwinds a continuation that a program called: the program is unwound too. */
static void test_unwound(void)
{
	struct coro_park *skel = load();

	if (!skel)
		return;
	if (run_op(skel, OP_PARK_DIVES, XDP_PASS) ||
	    run_xdp(skel->progs.resume_xdp, XDP_ABORTED) ||
	    run_syscall(skel->progs.resume_syscall, -ECANCELED))
		goto out;
	ASSERT_GT(skel->bss->frames, 0, "frames");
	ASSERT_EQ(skel->bss->resumed, 0, "resumed");
	ASSERT_EQ(skel->bss->returned, 0, "returned");
	/* through a function of the program, which the kernel unwinds on the way */
	if (run_op(skel, OP_PARK_DIVES, XDP_PASS) ||
	    run_xdp(skel->progs.resume_xdp_func, XDP_ABORTED))
		goto out;
	ASSERT_EQ(skel->bss->returned, 0, "returned, func");
	/* the program that parked it is unwound like any other */
	if (run_op(skel, OP_PARK_DIVES, XDP_PASS) || run_op(skel, OP_RESUME, XDP_ABORTED))
		goto out;
	ASSERT_EQ(skel->bss->returned, 0, "returned, own");
	/* and so is the callback of a helper, the helper and the program that called it */
	if (run_op(skel, OP_PARK_DIVES, XDP_PASS) ||
	    run_xdp(skel->progs.resume_xdp_cb, XDP_ABORTED))
		goto out;
	ASSERT_EQ(skel->bss->returned, 0, "returned, callback");
	/* and when the continuation returns, the function and the program go on */
	if (run_op(skel, OP_PARK, XDP_PASS) || run_xdp(skel->progs.resume_xdp_func, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->returned, 2, "returned, func");
	if (run_op(skel, OP_PARK, XDP_PASS) || run_xdp(skel->progs.resume_xdp_cb, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->returned, 4, "returned, callback");
out:
	coro_park__destroy(skel);
}

/*
 * The last reference of the program with @id is gone. Its release destroys the frames that it
 * left, and only then is its id taken off the list of programs: wait for that. Every destroy
 * function has run by then, and has counted in the globals of the object, which the caller
 * kept.
 */
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

static void destroyed_after(__u32 id, int bss_fd, __u64 want)
{
	struct coro_park__bss bss = {};
	int zero = 0;

	if (released(id) && ASSERT_OK(bpf_map_lookup_elem(bss_fd, &zero, &bss), "bss"))
		ASSERT_EQ(bss.destroyed, want, "destroyed");
}

static __u32 prog_id(struct bpf_program *prog)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	if (!ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &len), "get_info"))
		return 0;
	return info.id;
}

/*
 * A map that can hold parked frames is that of the program that parks them and of the programs
 * that are bound to it.
 */
static void test_bound(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct coro_park *skel = load_owner(), *other = NULL;
	int owner, fd;

	if (!skel)
		return;
	owner = bpf_program__fd(skel->progs.owner);
	/* a program that is bound to none */
	ASSERT_ERR(load_bound(skel->progs.resume_xdp, 0), "not bound");
	ASSERT_HAS_SUBSTR(log_buf, "holds the parked coro_frames of another program", "not bound");
	/* that one loads once it is bound */
	if (!ASSERT_OK(load_bound(skel->progs.resume_xdp, owner), "bound"))
		goto out;
	/* a program is bound to one that is bound to none */
	ASSERT_EQ(load_bound(skel->progs.resume_syscall, bpf_program__fd(skel->progs.resume_xdp)),
		  -EINVAL, "bound to a bound program");
	/* and parks no frame */
	ASSERT_ERR(load_bound(skel->progs.bound_parks, owner), "bound, parks");
	ASSERT_HAS_SUBSTR(log_buf, "cannot park a coro_frame", "bound, parks");
	/* the map is that of the program which the others are bound to */
	other = load_owner();
	if (!other)
		goto out;
	ASSERT_ERR(load_bound(skel->progs.resume_syscall, bpf_program__fd(other->progs.owner)),
		   "bound to another program");
	ASSERT_HAS_SUBSTR(log_buf, "is not a map of the program that this one is bound to",
			  "bound to another program");
	ASSERT_OK(load_bound(skel->progs.resume_syscall, owner), "bound, syscall");
	/* what is loaded works */
	if (!run_op(skel, OP_PARK, XDP_PASS) && !run_xdp(skel->progs.resume_xdp, XDP_PASS) &&
	    !run_syscall(skel->progs.resume_syscall, 0))
		ASSERT_EQ(skel->bss->resumed, 101, "resumed");

	/* Such a map is no inner map, whose users no load sees */
	opts.inner_map_fd = bpf_map__fd(skel->maps.slots);
	fd = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "outer", sizeof(__u32), sizeof(__u32), 1,
			    &opts);
	if (!ASSERT_EQ(fd, -EOPNOTSUPP, "inner map"))
		close(fd);
out:
	coro_park__destroy(other);
	coro_park__destroy(skel);
}

/*
 * The map types whose every value the release of a program finds: an array map and a hash map
 * that is preallocated.
 */
static void test_map_types(void)
{
	static const struct {
		enum bpf_map_type type;
		__u32 flags;
		bool ok;
	} cases[] = {
		{ BPF_MAP_TYPE_ARRAY, 0, true },
		{ BPF_MAP_TYPE_HASH, 0, true },
		{ BPF_MAP_TYPE_HASH, BPF_F_NO_PREALLOC, false },
		{ BPF_MAP_TYPE_LRU_HASH, 0, false },
		{ BPF_MAP_TYPE_PERCPU_ARRAY, 0, false },
	};
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct coro_park *skel = load_owner();
	const struct btf *btf;
	int i, fd;

	if (!skel)
		return;
	btf = bpf_object__btf(skel->obj);
	opts.btf_fd = bpf_object__btf_fd(skel->obj);
	opts.btf_key_type_id = btf__find_by_name_kind(btf, "__u32", BTF_KIND_TYPEDEF);
	opts.btf_value_type_id = btf__find_by_name_kind(btf, "slot", BTF_KIND_STRUCT);
	if (!ASSERT_GT(opts.btf_key_type_id, 0, "key type") ||
	    !ASSERT_GT(opts.btf_value_type_id, 0, "value type"))
		goto out;
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		opts.map_flags = cases[i].flags;
		fd = bpf_map_create(cases[i].type, "frames", sizeof(__u32),
				    btf__resolve_size(btf, opts.btf_value_type_id), 4, &opts);
		if (cases[i].ok)
			ASSERT_GE(fd, 0, "map with frames");
		else
			ASSERT_EQ(fd, -EOPNOTSUPP, "map with frames");
		if (fd >= 0)
			close(fd);
	}
out:
	coro_park__destroy(skel);
}

/* An extension replaces a function of the program that parks, and calls no parked frame. */
static void test_ext(void)
{
	struct coro_park *skel = load_owner();
	struct coro_park_ext *ext = NULL;
	int owner;

	if (!skel)
		return;
	owner = bpf_program__fd(skel->progs.owner);
	ext = coro_park_ext__open();
	if (!ASSERT_OK_PTR(ext, "coro_park_ext__open"))
		goto out;
	log_buf[0] = 0;
	if (!ASSERT_OK(bpf_map__reuse_fd(ext->maps.slots, bpf_map__fd(skel->maps.slots)),
		       "reuse_fd") ||
	    !ASSERT_OK(bpf_program__set_attach_target(ext->progs.ext_resumes, owner, "owner_hook"),
		       "set_attach_target") ||
	    !ASSERT_OK(bpf_program__set_coro_prog_fd(ext->progs.ext_resumes, owner),
		       "set_coro_prog_fd") ||
	    !ASSERT_OK(bpf_program__set_log_buf(ext->progs.ext_resumes, log_buf, sizeof(log_buf)),
		       "set_log_buf"))
		goto out;
	ASSERT_ERR(coro_park_ext__load(ext), "coro_park_ext__load");
	ASSERT_HAS_SUBSTR(log_buf, "an extension program cannot call a parked coro_frame", "ext");
out:
	coro_park_ext__destroy(ext);
	coro_park__destroy(skel);
}

/*
 * A program that is bound to the one whose frames it calls holds it: with every file descriptor
 * of that program closed it is still there, and so are its continuations.
 */
static void test_held(void)
{
	struct coro_park *skel = load();
	int fd, bss_fd;
	__u32 id;

	if (!skel)
		return;
	bss_fd = dup(bpf_map__fd(skel->maps.bss));
	id = prog_id(skel->progs.owner);
	if (!ASSERT_GE(bss_fd, 0, "bss_fd") || !id || run_op(skel, OP_PARK, XDP_PASS)) {
		coro_park__destroy(skel);
		goto out;
	}
	/* libbpf closes the number once more: nothing else gets it in between */
	close(bpf_program__fd(skel->progs.owner));
	fd = bpf_prog_get_fd_by_id(id);
	if (ASSERT_GE(fd, 0, "held"))
		close(fd);
	if (!run_xdp(skel->progs.resume_xdp, XDP_PASS))
		ASSERT_EQ(skel->bss->resumed, 1, "resumed");
	coro_park__destroy(skel);
	/* It goes with the last program that holds it, and the frame that is left before it */
	destroyed_after(id, bss_fd, 100);
out:
	if (bss_fd >= 0)
		close(bss_fd);
}

/*
 * No frame keeps its program. When the last reference of a program goes with frames parked, in
 * the fields of an array map and of a hash map, one of them in an element that was deleted, in
 * the nodes of a tree and of a list, and on their way to the kernel, the kernel destroys them
 * all before the program is freed. Two of the frames carry another one each: the destroy
 * function of one puts it into a value that the kernel has looked at, that of the other drops
 * it.
 */
static void test_teardown(void)
{
	struct coro_park *skel = load();
	int bss_fd;
	__u32 id;

	if (!skel)
		return;
	bss_fd = dup(bpf_map__fd(skel->maps.bss));
	id = prog_id(skel->progs.owner);
	if (!ASSERT_GE(bss_fd, 0, "bss_fd") || !id ||
	    run_op(skel, OP_PARK, XDP_PASS) || run_op(skel, OP_PARK_NODES, XDP_PASS) ||
	    run_syscall(skel->progs.drop_both, 0) || run_op(skel, OP_PARK, XDP_PASS) ||
	    run_op(skel, OP_PARK_HASH, XDP_PASS) || run_op(skel, OP_PARK_CARRIERS, XDP_PASS)) {
		coro_park__destroy(skel);
		goto out;
	}
	coro_park__destroy(skel);
	/*
	 * two frames dropped, two in fields, three in the tree, three in the list, two in the
	 * hash map, and two with the two that they carry
	 */
	destroyed_after(id, bss_fd, 101 + 101 + 60 + 3000 + 6000000 + 1130000);
out:
	if (bss_fd >= 0)
		close(bss_fd);
}

/* A page that is missing until uffd_fill(): whoever reads it sleeps, and @uffd says so. */
static void *uffd_page(int *uffd)
{
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg = { .mode = UFFDIO_REGISTER_MODE_MISSING };
	void *page;

	*uffd = syscall(__NR_userfaultfd, O_CLOEXEC);
	if (*uffd < 0 || ioctl(*uffd, UFFDIO_API, &api))
		return NULL;
	page = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
		    0);
	if (page == MAP_FAILED)
		return NULL;
	reg.range.start = (unsigned long)page;
	reg.range.len = getpagesize();
	return ioctl(*uffd, UFFDIO_REGISTER, &reg) ? NULL : page;
}

static int uffd_fill(int uffd, void *page)
{
	static char zeroes[65536];
	struct uffdio_copy copy = {
		.dst = (unsigned long)page,
		.src = (unsigned long)zeroes,
		.len = getpagesize(),
	};

	return ioctl(uffd, UFFDIO_COPY, &copy);
}

struct sleeper {
	int prog_fd;
	__u64 uaddr;
};

static void *sleeper_thread(void *arg)
{
	struct sleeper *sleeper = arg;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .ctx_in = &sleeper->uaddr,
		    .ctx_size_in = sizeof(sleeper->uaddr));

	bpf_prog_test_run_opts(sleeper->prog_fd, &opts);
	return NULL;
}

/*
 * A program that owns a map gives it back when nothing of it runs any more, not when its last
 * reference goes: until then it could take a frame of the next owner out of the map, and keep
 * it past the release of that one. A sleepable program, which parks nothing, owns the map here,
 * and another one that sleeps in a read section of RCU Tasks Trace keeps it from being freed.
 */
static void test_owner_grace(void)
{
	struct coro_park *old, *new = NULL;
	struct sleeper sleeper = {};
	struct bpf_program *prog;
	struct uffd_msg msg;
	struct pollfd pfd;
	int i, err, uffd = -1;
	bool sleeps = false;
	pthread_t thread;
	void *page;

	old = coro_park__open();
	if (!ASSERT_OK_PTR(old, "coro_park__open"))
		return;
	bpf_object__for_each_program(prog, old->obj)
		bpf_program__set_load_strategy(prog, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(coro_park__load(old), "coro_park__load") ||
	    !ASSERT_OK(load_bound(old->progs.drop_both, 0), "the first owner"))
		goto out;
	new = coro_park__open();
	if (!ASSERT_OK_PTR(new, "coro_park__open"))
		goto out;
	bpf_object__for_each_program(prog, new->obj)
		bpf_program__set_load_strategy(prog, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(bpf_map__reuse_fd(new->maps.slots, bpf_map__fd(old->maps.slots)),
		       "reuse_fd") ||
	    !ASSERT_OK(coro_park__load(new), "coro_park__load") ||
	    !ASSERT_OK(load_bound(new->progs.sleeps, 0), "sleeps"))
		goto out;
	/* the map has an owner */
	ASSERT_ERR(load_bound(new->progs.owner, 0), "owned");

	page = uffd_page(&uffd);
	if (!ASSERT_OK_PTR(page, "uffd_page"))
		goto out;
	sleeper.prog_fd = bpf_program__fd(new->progs.sleeps);
	sleeper.uaddr = (unsigned long)page;
	if (!ASSERT_OK(pthread_create(&thread, NULL, sleeper_thread, &sleeper), "pthread_create"))
		goto out;
	sleeps = true;
	pfd.fd = uffd;
	pfd.events = POLLIN;
	if (!ASSERT_EQ(poll(&pfd, 1, 10000), 1, "the program sleeps") ||
	    !ASSERT_EQ(read(uffd, &msg, sizeof(msg)), sizeof(msg), "uffd_msg"))
		goto out;

	/* Its last reference goes, and it is not freed while the other one sleeps. */
	coro_park__destroy(old);
	old = NULL;
	usleep(200000);
	err = load_bound(new->progs.owner, 0);
	ASSERT_ERR(err, "owned until its owner is freed");
	if (err)
		ASSERT_HAS_SUBSTR(log_buf, "holds the parked coro_frames of another program",
				  "owned until its owner is freed");

	if (!ASSERT_OK(uffd_fill(uffd, page), "uffd_fill"))
		goto out;
	pthread_join(thread, NULL);
	sleeps = false;
	for (i = 0; err && i < 10000; i++) {
		usleep(1000);
		err = load_bound(new->progs.owner, 0);
	}
	ASSERT_OK(err, "free once it is");
out:
	if (sleeps) {
		uffd_fill(uffd, page);
		pthread_join(thread, NULL);
	}
	if (uffd >= 0)
		close(uffd);
	coro_park__destroy(new);
	coro_park__destroy(old);
}

/* The syscall program that parks loaded, and the XDP program bound to it */
static struct coro_park_sys *load_sys(void)
{
	struct coro_park_sys *skel = coro_park_sys__open();

	if (!ASSERT_OK_PTR(skel, "coro_park_sys__open"))
		return NULL;
	bpf_program__set_load_strategy(skel->progs.xdp_resumer, BPF_PROG_LOAD_STRATEGY_MANUAL);
	if (!ASSERT_OK(coro_park_sys__load(skel), "coro_park_sys__load") ||
	    !ASSERT_OK(load_bound(skel->progs.xdp_resumer, bpf_program__fd(skel->progs.sys_owner)),
		       "xdp_resumer")) {
		coro_park_sys__destroy(skel);
		return NULL;
	}
	return skel;
}

static int run_sys(struct coro_park_sys *skel, enum coro_park_sys_op op)
{
	skel->bss->op = op;
	return run_syscall(skel->progs.sys_owner, 0);
}

/*
 * A sleepable program parks, an XDP program that is bound to it resumes the frame, and the
 * frame that is left when it goes is destroyed first.
 */
static void test_sleepable(void)
{
	struct coro_park_sys *skel = load_sys();
	struct coro_park_sys__bss bss = {};
	int bss_fd, zero = 0;
	__u32 id;

	if (!skel)
		return;
	bss_fd = dup(bpf_map__fd(skel->maps.bss));
	id = prog_id(skel->progs.sys_owner);
	if (!ASSERT_GE(bss_fd, 0, "bss_fd") || !id || run_sys(skel, SYS_PARK) ||
	    run_xdp(skel->progs.xdp_resumer, XDP_PASS) || run_sys(skel, SYS_PARK)) {
		coro_park_sys__destroy(skel);
		goto out;
	}
	ASSERT_EQ(skel->bss->resumed, 7, "resumed");
	/* a frame that it parks for a syscall program it resumes itself, and destroys one */
	if (run_sys(skel, SYS_PARK_SYS) || run_sys(skel, SYS_RESUME_SYS) ||
	    run_sys(skel, SYS_PARK_SYS)) {
		coro_park_sys__destroy(skel);
		goto out;
	}
	ASSERT_EQ(skel->bss->resumed, 107, "resumed, syscall");
	coro_park_sys__destroy(skel);
	if (released(id) && ASSERT_OK(bpf_map_lookup_elem(bss_fd, &zero, &bss), "bss"))
		ASSERT_EQ(bss.destroyed, 107, "destroyed");
out:
	if (bss_fd >= 0)
		close(bss_fd);
}

/*
 * The callback of a bpf_wq runs with no reference to its program, in a read section of RCU
 * Tasks Trace, and holds a parked frame there, which is in no map then. The bpf_wq and the
 * last reference of the program go meanwhile. The release waits for the callback before it
 * looks for frames: the frame is back in its slot by then, and is destroyed.
 */
static void test_sleepable_holds(void)
{
	struct coro_park_sys *skel = load_sys();
	int bss_fd = -1, go_fd = -1, works_fd = -1, zero = 0, i;
	struct coro_park_sys__bss bss = {};
	__u64 one = 1;
	__u32 id, next;

	if (!skel)
		return;
	bss_fd = dup(bpf_map__fd(skel->maps.bss));
	go_fd = dup(bpf_map__fd(skel->maps.go));
	works_fd = dup(bpf_map__fd(skel->maps.works));
	id = prog_id(skel->progs.sys_owner);
	if (!ASSERT_GE(bss_fd, 0, "bss_fd") || !ASSERT_GE(go_fd, 0, "go_fd") ||
	    !ASSERT_GE(works_fd, 0, "works_fd") || !id ||
	    run_sys(skel, SYS_PARK) || run_sys(skel, SYS_WQ)) {
		coro_park_sys__destroy(skel);
		goto out;
	}
	for (i = 0; i < 2000 && !READ_ONCE(skel->bss->holds); i++)
		usleep(1000);
	if (!ASSERT_EQ(skel->bss->holds, 1, "the callback holds the frame")) {
		coro_park_sys__destroy(skel);
		goto out;
	}
	/* the reference of the bpf_wq, and then all the others */
	ASSERT_OK(bpf_map_delete_elem(works_fd, &zero), "delete the bpf_wq");
	coro_park_sys__destroy(skel);
	usleep(300000);
	ASSERT_OK(bpf_prog_get_next_id(id - 1, &next), "get_next_id");
	ASSERT_EQ(next, id, "the program waits for its callback");
	if (ASSERT_OK(bpf_map_lookup_elem(bss_fd, &zero, &bss), "bss")) {
		ASSERT_EQ(bss.held, 0, "the callback has the frame");
		ASSERT_EQ(bss.destroyed, 0, "destroyed under the callback");
	}
	ASSERT_OK(bpf_map_update_elem(go_fd, &zero, &one, 0), "go");
	if (released(id) && ASSERT_OK(bpf_map_lookup_elem(bss_fd, &zero, &bss), "bss")) {
		ASSERT_EQ(bss.held, 1, "the callback put the frame back");
		ASSERT_EQ(bss.destroyed, 7, "destroyed");
	}
out:
	if (bss_fd >= 0)
		close(bss_fd);
	if (go_fd >= 0)
		close(go_fd);
	if (works_fd >= 0)
		close(works_fd);
}

/*
 * The time slice of may_goto is the program's on each CPU. A continuation that another program
 * calls starts its own: it is not ended by the time that its program's last run here began.
 */
static void test_time_slice(void)
{
	struct coro_park *skel;
	cpu_set_t old, one;

	if (!ASSERT_OK(sched_getaffinity(0, sizeof(old), &old), "sched_getaffinity"))
		return;
	CPU_ZERO(&one);
	CPU_SET(sched_getcpu(), &one);
	if (!ASSERT_OK(sched_setaffinity(0, sizeof(one), &one), "sched_setaffinity"))
		return;
	skel = load();
	if (!skel)
		goto out;
	if (run_op(skel, OP_PARK_LOOPS, XDP_PASS))
		goto out;
	/* longer than the slice */
	usleep(400000);
	if (run_syscall(skel->progs.resume_syscall, 0))
		goto out;
	ASSERT_EQ(skel->bss->looped, 300000, "looped");
	ASSERT_EQ(skel->bss->returned, 1, "returned");
out:
	coro_park__destroy(skel);
	sched_setaffinity(0, sizeof(old), &old);
}

/*
 * A function that is a continuation starts its slice in its first insns, also when a function
 * of the program calls it: they leave its arguments alone.
 */
static void test_slice_args(void)
{
	struct coro_park *skel = load();

	if (!skel)
		return;
	if (!run_op(skel, OP_PARK_TWO, XDP_PASS) && !run_op(skel, OP_CALL_TWO, XDP_PASS))
		ASSERT_EQ(skel->bss->second, 42, "second argument");
	coro_park__destroy(skel);
}

/*
 * A continuation puts back the slice of its caller, also when it has called another function
 * that is a continuation: a loop of the caller that only may_goto ends is ended by it.
 */
static void test_slice_nested(void)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = data,
		    .data_size_in = sizeof(data),
		    .repeat = 1);
	struct coro_park *skel = load();

	if (!skel)
		return;
	if (run_op(skel, OP_PARK_NESTED, XDP_PASS))
		goto out;
	skel->bss->op = OP_SPIN;
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.owner), &opts), "spin"))
		goto out;
	ASSERT_GT(skel->bss->rounds, 0, "rounds");
	ASSERT_EQ(skel->bss->nested, skel->bss->rounds, "nested");
	ASSERT_EQ(skel->bss->overran, 0, "the time of the loop is up");
out:
	coro_park__destroy(skel);
}

static void *spinner_thread(void *arg)
{
	struct coro_park_sys *skel = arg;
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	/* the kernel unwinds it when its time is up, whatever happened before */
	skel->bss->op = SYS_SPIN;
	bpf_prog_test_run_opts(bpf_program__fd(skel->progs.sys_owner), &opts);
	return NULL;
}

/*
 * A continuation that the kernel unwinds puts back the slice of its caller too. The program
 * that parks is in a loop that only may_goto ends, in a task. Another task on the same CPU
 * preempts it and runs an XDP program, which no task preempts, that resumes a frame of it: the
 * continuation uses up its time and is unwound. The loop goes on for the time that it has left:
 * it does not find the count of the continuation, which is 0.
 */
static void test_slice_unwound(void)
{
	struct coro_park_sys *skel;
	cpu_set_t old, one;
	pthread_t thread;
	int try;

	if (!ASSERT_OK(sched_getaffinity(0, sizeof(old), &old), "sched_getaffinity"))
		return;
	CPU_ZERO(&one);
	CPU_SET(sched_getcpu(), &one);
	if (!ASSERT_OK(sched_setaffinity(0, sizeof(one), &one), "sched_setaffinity"))
		return;
	skel = load_sys();
	if (!skel)
		goto out;
	/*
	 * Until this task has preempted the other one inside its loop: in_loop is 1 from the
	 * start of the loop until the kernel has unwound the program, see sys_unwound().
	 */
	for (try = 0; try < 5; try++) {
		skel->bss->in_loop = 0;
		skel->bss->interfered = 0;
		skel->bss->after = 0;
		if (run_sys(skel, SYS_PARK_SPINS) ||
		    !ASSERT_OK(pthread_create(&thread, NULL, spinner_thread, skel), "pthread_create"))
			goto out;
		usleep(50000);
		run_xdp(skel->progs.xdp_resumer, XDP_ABORTED);
		pthread_join(thread, NULL);
		if (skel->bss->interfered)
			break;
	}
	if (!ASSERT_LT(try, 5, "the loop was preempted"))
		goto out;
	ASSERT_GT(skel->bss->spun, 0, "the continuation used up its time");
	ASSERT_GT(skel->bss->after, 0, "the loop went on");
out:
	coro_park_sys__destroy(skel);
	sched_setaffinity(0, sizeof(old), &old);
}

void test_coro_park(void)
{
	if (test__start_subtest("time_slice"))
		test_time_slice();
	if (test__start_subtest("slice_args"))
		test_slice_args();
	if (test__start_subtest("slice_nested"))
		test_slice_nested();
	if (test__start_subtest("slice_unwound"))
		test_slice_unwound();
	if (test__start_subtest("owner_grace"))
		test_owner_grace();
	if (test__start_subtest("sleepable"))
		test_sleepable();
	if (test__start_subtest("sleepable_holds"))
		test_sleepable_holds();
	if (test__start_subtest("teardown"))
		test_teardown();
	if (test__start_subtest("held"))
		test_held();
	RUN_TESTS(coro_park_fail);
	if (test__start_subtest("bound"))
		test_bound();
	if (test__start_subtest("map_types"))
		test_map_types();
	if (test__start_subtest("ext"))
		test_ext();
	if (test__start_subtest("arena_stack"))
		test_arena_stack();
	if (test__start_subtest("again"))
		test_again();
	if (test__start_subtest("nodes"))
		test_nodes();
	if (test__start_subtest("unwound"))
		test_unwound();
	if (test__start_subtest("resume"))
		test_resume();
	if (test__start_subtest("destroy"))
		test_destroy();
}
