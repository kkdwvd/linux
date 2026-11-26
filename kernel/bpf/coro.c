// SPDX-License-Identifier: GPL-2.0
/*
 * BPF coroutine frames, and their resumption from the kernel; see include/linux/bpf_coro.h.
 */
#include <linux/bpf.h>
#include <linux/bpf_coro.h>
#include <linux/bpf_unwind.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/irq_work.h>
#include <linux/kasan.h>
#include <linux/llist.h>
#include <linux/memcontrol.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/rcupdate_trace.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <net/xdp.h>

/*
 * In front of every frame. The program gets the address behind it: the verifier bounds the
 * accesses through a PTR_TO_CORO_FRAME by the frame, and passes only the start of the frame
 * to a __coro_frame argument. The header is a multiple of 8 bytes, where a pointer has 4 too,
 * and kmalloc aligns the allocation to ARCH_KMALLOC_MINALIGN, 8 bytes at least on the
 * architectures whose JITs call kfuncs: the frame has the 8-byte alignment that the accesses
 * of the program need.
 */
struct bpf_coro_frame_hdr {
	/*
	 * Where the frame goes when it is freed, see "The frame cache" below. It is the cache
	 * of the program that allocated the frame, which is there for as long as the frame is.
	 */
	struct bpf_coro_frame_cache __percpu *cache;
	/*
	 * A parked frame that the kernel is to destroy, see bpf_coro_drop(). Or a free one
	 * beside the cache, see bpf_coro_frame_free_slow().
	 */
	struct llist_node drop;
	/* its size class there. 0: none, the memory is that of a host, see "Hosts" below */
	u8 class;
} __aligned(8);

static_assert(sizeof(struct bpf_coro_frame_hdr) % sizeof(u64) == 0);

static struct bpf_coro_frame_hdr *bpf_coro_frame_hdr(void *frame)
{
	return frame - sizeof(struct bpf_coro_frame_hdr);
}

/*
 * The lifetime of a frame.
 *
 * A frame takes no reference on its program: its allocation and its free write nothing that
 * another CPU reads. What keeps the image of the program for as long as one of its frames can
 * be resumed or destroyed is whoever can do that:
 * - The program itself, while it runs.
 * - A kfunc that keeps the frame it suspends, see bpf_coro_run(): it takes a reference on
 *   bpf_coro_frame_prog() before it returns, and puts it when it has resumed or freed the
 *   frame.
 * - A program that takes a parked frame out of a map and calls it, see "Parked frames" below:
 *   it is the frame's program, or it is bound to that program and holds it, see
 *   claim_coro_maps() in verifier.c.
 * - The kernel, which destroys the parked frames that a program drops or leaves behind: the
 *   program is not freed before that is done, see bpf_coro_prog_release().
 */
/*
 * The frame cache.
 *
 * A request that runs to its end where it arrived allocates a frame and frees it, and so does
 * the next one. So a program keeps the frames that it frees for its next ones, on each CPU and
 * for each size class in which it allocates. A frame that is freed on the CPU that allocated
 * it comes from there and goes back there, and the pair reads and writes one cache line of the
 * CPU besides the frame: no line that another CPU has, and nothing of the allocator or of a
 * memory cgroup. A frame that another CPU frees, where a continuation ends on an executor,
 * say, stays with that CPU, whose next frame it is.
 *
 * The classes are the kmalloc buckets that take the header and a frame of up to
 * BPF_MAX_REF_SLOTS slots, numbered from 1. A frame is allocated with the size of its class,
 * and so serves any later frame of the class. The verifier knows the size at each call: it
 * notes the classes that a program needs, see bpf_coro_frame_size(), and passes the class
 * along with the size, see bpf_coro_frame_alloc().
 *
 * Frames are allocated and freed in any context, also where no lock may be taken, and where
 * an interrupt or an NMI has interrupted the code below on its CPU. So a class is taken like
 * a cache of the BPF memory allocator, see unit_alloc() in memalloc.c: by a flag of the CPU
 * that is set while its frames are counted, with preemption off, and whoever finds the flag
 * set came over the code that set it and goes another way. Unlike there interrupts stay on,
 * and the other way is never a failure: an allocation goes to kmalloc_nolock(), a free puts
 * the frame on a list beside the cache that needs no lock. That is so on PREEMPT_RT too, where
 * the trylock of a local lock would be of no use in NMI and hard interrupt context; there
 * kmalloc_nolock() has no memory in those two contexts, as before.
 *
 * What the cache keeps follows the demand, between BPF_CORO_CACHE_MIN frames of a class and
 * what BPF_CORO_CACHE_BYTES and BPF_CORO_CACHE_MAX allow, by rules that an irq_work of the
 * CPU applies, see bpf_coro_frame_class_tend(). The BPF memory allocator has a low and a high
 * watermark for that, which are fixed, and refills and flushes at them in batches. Here the
 * room moves, and the hit path has no watermark to look at:
 * - Frames that find no room wait on the list. When that is longer than a batch, more frames
 *   end on the CPU than begin there. If the CPU has also gone to the allocator since the last
 *   time, the cache was too small for what goes in and out of it, and its room doubles. Else
 *   the frames are not wanted here, and are freed.
 * - When BPF_CORO_CACHE_MISSES allocations found no frame, more begin on the CPU than end
 *   there, and the irq_work makes a batch for the next ones.
 * - A batch is BPF_CORO_CACHE_BATCH frames, and twice as many each time, up to four times,
 *   where the irq_work does the same again and nothing went the other way: where frames
 *   only end on a CPU, or only begin. An irq_work is an interrupt, and a batch is what one
 *   buys.
 * - Every BPF_CORO_CACHE_AGE a CPU that did not run out of frames of a class since the last
 *   time gives back half of those it has, the ones it has had longest, with as much of its
 *   room, and what waits on the list: a cache that is not used empties within a few rounds.
 *
 * The cache is the program's, as are the frames in it. The task that loaded the program pays
 * for them, see bpf_coro_frames_memcg(): a frame is charged to its memory cgroup when it comes
 * from the allocator, and for as long as it is there, in use or in the cache. They all go back
 * when the program is freed, see bpf_coro_frames_free(). A CPU that goes offline keeps what it
 * has until then, or until it is back.
 */
/*
 * Hosts.
 *
 * A request that arrives in an object of the kernel, a packet in its buffer, can have its
 * frame there: the object is the HOST of the frame and lends it memory. Such a frame costs no
 * allocation and no free, and is in the cache lines that the request has brought in. It has
 * no life of its own:
 * - It is allocated by a kfunc of the host, which takes the size that the verifier checked
 *   against what such a host can lend, and gives a frame in the host or none. Never one from
 *   the cache: a coroutine is compiled for one kind of frame, and where its host has no
 *   room the request has none and ends there.
 * - Nothing frees it. It is there for as long as the program has the host, and the verifier
 *   ends it where the host goes, see REF_TYPE_HOSTED in bpf_verifier.h: whatever takes the
 *   host from the program takes the frame. bpf_coro_frame_free() does nothing for it.
 * - It is suspended only with its host in it: the continuation has the host to give up, and
 *   that is the end of the frame, also where the kernel destroys a parked frame for the
 *   program.
 * - It has the header: bpf_coro_frame_prog() and bpf_coro_drop() ask no question about where
 *   a frame is. So a program whose frames are all in hosts has a cache too, which is empty.
 *
 * The buffer of an XDP program is the one host so far, see bpf_coro_frame_alloc_xdp().
 */
#define BPF_CORO_CACHE_MIN	64
#define BPF_CORO_CACHE_MAX	1024
#define BPF_CORO_CACHE_BYTES	(256 << 10)
#define BPF_CORO_CACHE_BATCH	64
#define BPF_CORO_CACHE_MISSES	16
#define BPF_CORO_CACHE_AGE	(2 * HZ)

/* by class: 0 is no class, see bpf_coro_frame_alloc_slow() */
static const u16 bpf_coro_frame_sizes[] = { 0, 32, 64, 96, 128, 192, 256, 512, 1024 };

#define BPF_CORO_FRAME_CLASSES	ARRAY_SIZE(bpf_coro_frame_sizes)

static_assert(sizeof(struct bpf_coro_frame_hdr) + BPF_MAX_REF_SLOTS * BPF_REG_SIZE <= 1024);
static_assert(BPF_CORO_FRAME_CLASSES <=
	      BITS_PER_TYPE(typeof_member(struct bpf_prog_aux, coro_classes)));

/* @size is that of the header and the frame */
static unsigned int bpf_coro_frame_class(size_t size)
{
	/* in steps of 32 bytes up to 256 */
	static const u8 small[] = { 1, 2, 3, 4, 5, 5, 6, 6 };

	if (size <= 256)
		return small[(size - 1) / 32];
	return size <= 512 ? 7 : 8;
}

static unsigned int bpf_coro_frame_class_max(unsigned int class)
{
	return min(BPF_CORO_CACHE_MAX, BPF_CORO_CACHE_BYTES / bpf_coro_frame_sizes[class]);
}

/* What a CPU has of a size class: half a cache line */
struct bpf_coro_frame_class {
	/*
	 * With @active set and preemption off: frames[0..nr) are free, and KASAN has them as
	 * freed memory. @cap is how many frames[] takes now, and @size how many it has room for.
	 */
	struct bpf_coro_frame_hdr **frames;
	u16 nr;
	u16 cap;
	u16 size;
	/* allocations that found no frame, since the irq_work last made some */
	u16 misses;
	bool active;
	/* an allocation found no frame: since the list was last long, and since the last aging */
	bool missed;
	bool emptied;
	/* the irq_work frees or makes BPF_CORO_CACHE_BATCH << shift frames at a time */
	u8 shift:2;
	/* and what it did last for the class was to make some */
	u8 made:1;
	/* Without: the frames that found no room or @active set, by bpf_coro_frame_hdr::drop */
	atomic_t more_nr;
	struct llist_head more;
} __aligned(32);

static_assert(sizeof(struct bpf_coro_frame_class) == 32);

struct bpf_coro_frame_cache {
	struct bpf_coro_frame_class class[BPF_CORO_FRAME_CLASSES];
	struct bpf_coro_frames *owner;
	/* see bpf_coro_frame_cache_tend() */
	struct irq_work tend;
	atomic_t age;
};

/* What a program has for its frames: bpf_prog_aux::coro_frames */
struct bpf_coro_frames {
	struct bpf_coro_frame_cache __percpu *cache;
	struct bpf_prog *prog;
	/* who pays for the frames: the memory cgroup of the task that loaded the program */
	struct obj_cgroup *objcg;
	struct delayed_work age;
};

/*
 * What bpf_coro_frame_alloc() finds in place of the cache of a program whose last reference
 * is gone: no frame, and no class that takes one, see bpf_coro_frames_stop().
 */
static DEFINE_PER_CPU(struct bpf_coro_frame_cache, bpf_coro_no_frames);

/*
 * Is the class the caller's? It has preemption off, and the class until
 * bpf_coro_frame_class_let(). The compiler sees no reader of the flag, and nothing that ties
 * it to what the class has: the flag is written as told, and what it guards is read behind
 * the one write and written before the other.
 */
static __always_inline bool bpf_coro_frame_class_take(struct bpf_coro_frame_class *c)
{
	if (unlikely(READ_ONCE(c->active)))
		return false;
	WRITE_ONCE(c->active, true);
	barrier();
	return true;
}

static __always_inline void bpf_coro_frame_class_let(struct bpf_coro_frame_class *c)
{
	barrier();
	WRITE_ONCE(c->active, false);
}

/* The same for who has preemption on */
static bool bpf_coro_frame_class_trylock(struct bpf_coro_frame_class *c)
{
	preempt_disable();
	if (bpf_coro_frame_class_take(c))
		return true;
	preempt_enable();
	return false;
}

static void bpf_coro_frame_class_unlock(struct bpf_coro_frame_class *c)
{
	bpf_coro_frame_class_let(c);
	preempt_enable();
}

/*
 * A frame is charged to the memory cgroup of the task that loaded the program until it goes
 * back to the allocator, like what a map allocates, see bpf_map_kmalloc_nolock(). Not to
 * whoever is current: that is a task that the program interrupted, or nobody.
 */
static struct mem_cgroup *bpf_coro_frames_memcg(struct bpf_coro_frames *owner,
						struct mem_cgroup **old_memcg)
{
	struct mem_cgroup *memcg;

	memcg = owner->objcg ? get_mem_cgroup_from_objcg(owner->objcg) : root_mem_cgroup;
	*old_memcg = set_active_memcg(memcg);
	return memcg;
}

static void bpf_coro_frames_memcg_end(struct mem_cgroup *memcg, struct mem_cgroup *old_memcg)
{
	set_active_memcg(old_memcg);
	mem_cgroup_put(memcg);
}

/* A frame from the allocator, in any context, for an allocation that found none */
static noinline struct bpf_coro_frame_hdr *bpf_coro_frame_new(struct bpf_prog_aux *aux,
							      unsigned int class)
{
	struct bpf_coro_frames *owner = aux->coro_frames;
	struct mem_cgroup *memcg, *old_memcg;
	struct bpf_coro_frame_hdr *hdr;

	if (unlikely(!atomic64_read(&aux->refcnt)))
		return NULL;
	memcg = bpf_coro_frames_memcg(owner, &old_memcg);
	hdr = kmalloc_nolock(bpf_coro_frame_sizes[class], __GFP_ACCOUNT, NUMA_NO_NODE);
	bpf_coro_frames_memcg_end(memcg, old_memcg);
	if (!hdr)
		return NULL;
	hdr->cache = owner->cache;
	hdr->class = class;
	return hdr;
}

/* Back to the allocator, where it may take its locks: @nr frames of the cache */
static noinline void bpf_coro_frames_kfree(struct bpf_coro_frames *owner,
					   struct bpf_coro_frame_hdr **frames, unsigned int nr)
{
	while (nr--) {
		/* as much as is looked at here */
		kasan_mempool_unpoison_object(frames[nr], sizeof(*frames[nr]));
		WARN_ON_ONCE(frames[nr]->cache != owner->cache);
		kfree(frames[nr]);
	}
}

/* And the frames that were on a list. Returns how many they were. */
static noinline int bpf_coro_frames_kfree_list(struct bpf_coro_frames *owner,
					       struct llist_node *first)
{
	struct llist_node *node, *next;
	int nr = 0;

	llist_for_each_safe(node, next, first) {
		struct bpf_coro_frame_hdr *hdr = llist_entry(node, typeof(*hdr), drop);

		nr++;
		WARN_ON_ONCE(hdr->cache != owner->cache);
		kfree(hdr);
	}
	return nr;
}

/*
 * How long the list gets before the irq_work looks, and how many frames it makes when it
 * makes some. Where frames only end on a CPU, or only begin, each time is like the one before,
 * and the batch doubles: an irq_work is an interrupt.
 */
#define BPF_CORO_CACHE_SHIFT	2

static unsigned int bpf_coro_frame_class_batch(const struct bpf_coro_frame_class *c)
{
	return BPF_CORO_CACHE_BATCH << c->shift;
}

static void bpf_coro_frame_class_shift(struct bpf_coro_frame_class *c)
{
	if (c->shift < BPF_CORO_CACHE_SHIFT)
		c->shift++;
}

/* With the class: take in what is on the list, as far as there is room. */
static void bpf_coro_frame_class_fetch(struct bpf_coro_frame_class *c)
{
	struct llist_node *node, *next;
	int nr = 0;

	llist_for_each_safe(node, next, llist_del_all(&c->more)) {
		struct bpf_coro_frame_hdr *hdr = llist_entry(node, typeof(*hdr), drop);

		if (c->nr == c->cap) {
			llist_add(node, &c->more);
			continue;
		}
		nr++;
		/* KASAN has reported a frame that it does not take: nobody gets that again */
		if (kasan_mempool_poison_object(hdr))
			c->frames[c->nr++] = hdr;
	}
	atomic_sub(nr, &c->more_nr);
}

/* Room for @cap frames, as far as the class may have it: the cache was too small */
static void bpf_coro_frame_class_grow(struct bpf_coro_frame_cache *cache,
				      struct bpf_coro_frame_class *c, unsigned int class,
				      unsigned int cap)
{
	struct bpf_coro_frame_hdr **frames = NULL, **old = NULL;
	struct mem_cgroup *memcg, *old_memcg;

	cap = min(cap, bpf_coro_frame_class_max(class));
	if (cap <= c->cap)
		return;
	if (cap > c->size) {
		memcg = bpf_coro_frames_memcg(cache->owner, &old_memcg);
		frames = kmalloc_array(cap, sizeof(*frames),
				       GFP_NOWAIT | __GFP_NOWARN | __GFP_ACCOUNT);
		bpf_coro_frames_memcg_end(memcg, old_memcg);
		if (!frames)
			return;
	}
	if (!bpf_coro_frame_class_trylock(c)) {
		kfree(frames);
		return;
	}
	if (frames) {
		memcpy(frames, c->frames, c->nr * sizeof(*frames));
		old = c->frames;
		c->frames = frames;
		c->size = cap;
	}
	c->cap = cap;
	bpf_coro_frame_class_fetch(c);
	bpf_coro_frame_class_unlock(c);
	kfree(old);
}

/*
 * Allocations found no frame again and again: make a batch. When the frames of the batch
 * before are gone and none came back, frames only begin here, and the batch doubles. Returns
 * how many it made.
 */
static noinline int bpf_coro_frame_class_refill(struct bpf_coro_frame_cache *cache,
						struct bpf_coro_frame_class *c,
						unsigned int class)
{
	struct bpf_coro_frame_hdr *frames[BPF_CORO_CACHE_BATCH], *hdr;
	struct mem_cgroup *memcg, *old_memcg;
	unsigned int want, room, nr, got, made = 0;

	if (c->made && !READ_ONCE(c->nr) && !atomic_read(&c->more_nr))
		bpf_coro_frame_class_shift(c);
	want = bpf_coro_frame_class_batch(c);
	bpf_coro_frame_class_grow(cache, c, class, want);
	room = READ_ONCE(c->nr);
	room = c->cap > room ? c->cap - room : 0;
	want = min(want, room);
	memcg = bpf_coro_frames_memcg(cache->owner, &old_memcg);
	for (;;) {
		nr = min_t(unsigned int, want - made, ARRAY_SIZE(frames));
		for (got = 0; got < nr; got++) {
			hdr = kmalloc(bpf_coro_frame_sizes[class],
				      GFP_NOWAIT | __GFP_NOWARN | __GFP_ACCOUNT);
			if (!hdr)
				break;
			hdr->cache = cache->owner->cache;
			hdr->class = class;
			frames[got] = hdr;
		}
		if (!bpf_coro_frame_class_trylock(c))
			break;
		while (got && c->nr < c->cap) {
			made++;
			if (kasan_mempool_poison_object(frames[--got]))
				c->frames[c->nr++] = frames[got];
		}
		c->misses = 0;
		bpf_coro_frame_class_unlock(c);
		/* frames came back meanwhile, the allocator has no more, or that is all */
		if (got || made % ARRAY_SIZE(frames) || made >= want)
			break;
	}
	bpf_coro_frames_memcg_end(memcg, old_memcg);
	while (got)
		kfree(frames[--got]);
	return made;
}

/*
 * A class that was not out of frames since the last time gives back half of them, from the
 * bottom, where the ones are that it has had longest, as much of its room, and the list.
 */
static void bpf_coro_frame_class_age(struct bpf_coro_frame_cache *cache,
				     struct bpf_coro_frame_class *c, unsigned int class)
{
	struct bpf_coro_frame_hdr *frames[BPF_CORO_CACHE_BATCH];
	unsigned int left, nr;

	if (!bpf_coro_frame_class_trylock(c))
		return;
	left = c->nr > 8 ? DIV_ROUND_UP(c->nr, 2) : c->nr;
	if (c->emptied) {
		c->emptied = false;
		bpf_coro_frame_class_unlock(c);
		return;
	}
	c->shift = 0;
	c->made = false;
	for (;;) {
		nr = min_t(unsigned int, min(left, c->nr), BPF_CORO_CACHE_BATCH);
		memcpy(frames, c->frames, nr * sizeof(*frames));
		memmove(c->frames, c->frames + nr, (c->nr - nr) * sizeof(*frames));
		c->nr -= nr;
		c->cap = max_t(unsigned int, c->cap - nr, BPF_CORO_CACHE_MIN);
		bpf_coro_frame_class_unlock(c);
		bpf_coro_frames_kfree(cache->owner, frames, nr);
		left -= nr;
		if (!left || !nr || !bpf_coro_frame_class_trylock(c))
			break;
	}
	atomic_sub(bpf_coro_frames_kfree_list(cache->owner, llist_del_all(&c->more)), &c->more_nr);
}

/*
 * What the irq_work does for a class. It takes the class as anyone does, a few stores at a
 * time, and calls the allocator without it: on PREEMPT_RT it is a thread, and the allocator's
 * locks sleep.
 *
 * kfree_nolock() may not wait for a lock, so when the two sheaves that the allocator has for
 * the CPU are full it has nowhere to put an object and gives it to an irq_work of its own, one
 * for each object where interrupts are on. kmalloc_nolock() has the same trouble the other
 * way round: when the sheaves are empty it may not fill one, and takes each object from a
 * slab. A burst gets either of them there. kfree() and kmalloc() here move whole sheaves.
 */
static void bpf_coro_frame_class_tend(struct bpf_coro_frame_cache *cache,
				      struct bpf_coro_frame_class *c, unsigned int class)
{
	bool grow = false;

	if (atomic_read(&c->more_nr) > bpf_coro_frame_class_batch(c)) {
		if (bpf_coro_frame_class_trylock(c)) {
			bpf_coro_frame_class_fetch(c);
			grow = c->missed && c->cap < bpf_coro_frame_class_max(class);
			c->missed = false;
			bpf_coro_frame_class_unlock(c);
		}
		if (grow)
			bpf_coro_frame_class_grow(cache, c, class, c->cap * 2);
		/*
		 * Not wanted here, or no room to be had. Frames only end here: the next time
		 * is after twice as many.
		 */
		if (atomic_read(&c->more_nr) > bpf_coro_frame_class_batch(c)) {
			atomic_sub(bpf_coro_frames_kfree_list(cache->owner,
							      llist_del_all(&c->more)),
				   &c->more_nr);
			if (!grow)
				bpf_coro_frame_class_shift(c);
			c->made = false;
		}
	}
	if (READ_ONCE(c->misses) >= BPF_CORO_CACHE_MISSES)
		c->made = bpf_coro_frame_class_refill(cache, c, class) > 0;
}

static void bpf_coro_frame_cache_tend(struct irq_work *work)
{
	struct bpf_coro_frame_cache *cache = container_of(work, struct bpf_coro_frame_cache, tend);
	bool age = atomic_xchg(&cache->age, 0);
	unsigned int class;

	for (class = 1; class < BPF_CORO_FRAME_CLASSES; class++) {
		struct bpf_coro_frame_class *c = &cache->class[class];

		if (!c->size)
			continue;
		bpf_coro_frame_class_tend(cache, c, class);
		if (age)
			bpf_coro_frame_class_age(cache, c, class);
	}
}

/* Every BPF_CORO_CACHE_AGE: have the CPUs that keep frames look at what they did not use. */
static void bpf_coro_frames_age(struct work_struct *work)
{
	struct bpf_coro_frames *owner = container_of(to_delayed_work(work), typeof(*owner), age);
	unsigned int class, cpu;

	cpus_read_lock();
	for_each_online_cpu(cpu) {
		struct bpf_coro_frame_cache *cache = per_cpu_ptr(owner->cache, cpu);

		for (class = 1; class < BPF_CORO_FRAME_CLASSES; class++) {
			struct bpf_coro_frame_class *c = &cache->class[class];

			if (!READ_ONCE(c->nr) && !atomic_read(&c->more_nr))
				continue;
			atomic_set(&cache->age, 1);
			irq_work_queue_on(&cache->tend, cpu);
			break;
		}
	}
	cpus_read_unlock();
	schedule_delayed_work(&owner->age, BPF_CORO_CACHE_AGE);
}

/**
 * bpf_coro_frame_size - note the size of a frame that a program allocates
 * @aux: the program
 * @size: what it passes to bpf_coro_frame_alloc()
 *
 * Returns what the call passes in place of @size: the size, and its class above it.
 */
u64 bpf_coro_frame_size(struct bpf_prog_aux *aux, u64 size)
{
	u64 class = bpf_coro_frame_class(sizeof(struct bpf_coro_frame_hdr) + size);

	aux->coro_classes |= BIT(class);
	return class << 32 | size;
}

/**
 * bpf_coro_frames_hosted - note that a program has frames in hosts
 * @aux: the program, in the verifier
 *
 * They are of no class, and the program has a cache for their headers to name, see "Hosts"
 * above.
 */
void bpf_coro_frames_hosted(struct bpf_prog_aux *aux)
{
	aux->coro_classes |= BIT(0);
}

/**
 * bpf_coro_frames_init - give a program that allocates frames its cache
 * @prog: the program, which passed the verifier
 *
 * Process context: the task that loads the program, which pays for the cache and its frames.
 */
int bpf_coro_frames_init(struct bpf_prog *prog)
{
	unsigned long classes = prog->aux->coro_classes;
	struct bpf_coro_frames *owner;
	unsigned int class, cpu;

	if (!classes)
		return 0;
	owner = kzalloc(sizeof(*owner), GFP_KERNEL_ACCOUNT);
	if (!owner)
		return -ENOMEM;
	owner->prog = prog;
	INIT_DEFERRABLE_WORK(&owner->age, bpf_coro_frames_age);
	/* from here on bpf_coro_frames_free() frees what there is, when the program goes */
	prog->aux->coro_frames = owner;
	owner->cache = alloc_percpu_gfp(struct bpf_coro_frame_cache, GFP_KERNEL_ACCOUNT);
	if (!owner->cache)
		return -ENOMEM;
	for_each_possible_cpu(cpu) {
		struct bpf_coro_frame_cache *cache = per_cpu_ptr(owner->cache, cpu);

		cache->owner = owner;
		init_irq_work(&cache->tend, bpf_coro_frame_cache_tend);
		/* class 0 keeps nothing, see bpf_coro_frames_hosted() */
		class = 1;
		for_each_set_bit_from(class, &classes, BPF_CORO_FRAME_CLASSES) {
			struct bpf_coro_frame_class *c = &cache->class[class];

			c->frames = kmalloc_array_node(BPF_CORO_CACHE_MIN, sizeof(*c->frames),
						       GFP_KERNEL_ACCOUNT, cpu_to_node(cpu));
			if (!c->frames)
				return -ENOMEM;
			c->size = BPF_CORO_CACHE_MIN;
			c->cap = BPF_CORO_CACHE_MIN;
		}
	}
#ifdef CONFIG_MEMCG
	if (memcg_bpf_enabled())
		owner->objcg = get_obj_cgroup_from_current();
#endif
	prog->aux->coro_cache = owner->cache;
	schedule_delayed_work(&owner->age, BPF_CORO_CACHE_AGE);
	return 0;
}

/**
 * bpf_coro_frames_stop - the last reference of a program is gone
 * @prog: the program
 *
 * It gets no frame from now on, whatever its cache has: bpf_coro_frame_alloc() finds a cache
 * that has none, and bpf_coro_frame_new() gives none. Code of the program that got a frame
 * before ends with a grace period, as code that saw the count before it dropped did. Any
 * context.
 */
void bpf_coro_frames_stop(struct bpf_prog *prog)
{
	if (prog->aux->coro_frames)
		WRITE_ONCE(prog->aux->coro_cache, &bpf_coro_no_frames);
}

/**
 * bpf_coro_frames_free - free the cache of a program, and the frames in it
 * @prog: the program, which is freed
 *
 * No frame of the program is left outside: what holds one holds the program, see "The
 * lifetime of a frame" above, and whoever frees one has it until the free has returned.
 * Process context.
 */
void bpf_coro_frames_free(struct bpf_prog *prog)
{
	struct bpf_coro_frames *owner = prog->aux->coro_frames;
	unsigned int class, cpu;

	if (!owner)
		return;
	cancel_delayed_work_sync(&owner->age);
	for_each_possible_cpu(cpu) {
		struct bpf_coro_frame_cache *cache;

		if (!owner->cache)
			break;
		cache = per_cpu_ptr(owner->cache, cpu);
		irq_work_sync(&cache->tend);
		for (class = 1; class < BPF_CORO_FRAME_CLASSES; class++) {
			struct bpf_coro_frame_class *c = &cache->class[class];

			bpf_coro_frames_kfree(owner, c->frames, c->nr);
			bpf_coro_frames_kfree_list(owner, llist_del_all(&c->more));
			kfree(c->frames);
		}
	}
	free_percpu(owner->cache);
	if (owner->objcg)
		obj_cgroup_put(owner->objcg);
	kfree(owner);
}

/*
 * An allocation that found no frame in the cache: the class has none, with @mine, or an
 * interrupt came over the code that has the class. Preemption is off as in
 * bpf_coro_frame_alloc(), and on again when this returns.
 */
static noinline void *bpf_coro_frame_alloc_slow(struct bpf_prog_aux *aux, u64 size__k,
						struct bpf_coro_frame_class *c, bool mine)
{
	size_t size = sizeof(struct bpf_coro_frame_hdr) + (u32)size__k;
	struct bpf_coro_frame_hdr *hdr = NULL;
	unsigned int class = size__k >> 32;
	struct bpf_coro_frame_cache *cache;
	bool tend = false;

	/* the one that the class is of: the program's may have gone since, to the one above */
	cache = container_of(c, struct bpf_coro_frame_cache, class[class]);

	/* a call that passes more than one size: the verifier left the class to us */
	if (!class) {
		if (mine)
			bpf_coro_frame_class_let(c);
		class = bpf_coro_frame_class(size);
		c = &cache->class[class];
		mine = bpf_coro_frame_class_take(c);
	}
	if (mine) {
		if (!llist_empty(&c->more))
			bpf_coro_frame_class_fetch(c);
		if (c->nr) {
			hdr = c->frames[--c->nr];
		} else if (c->cap) {
			c->missed = true;
			c->emptied = true;
			tend = ++c->misses == BPF_CORO_CACHE_MISSES;
		}
		bpf_coro_frame_class_let(c);
	}
	/* not with the class: the irq_work comes at once where interrupts are on */
	if (tend)
		irq_work_queue(&cache->tend);
	preempt_enable();
	if (hdr)
		kasan_mempool_unpoison_object(hdr, size);
	else
		hdr = bpf_coro_frame_new(aux, class);
	return hdr ? hdr + 1 : NULL;
}

/*
 * A free that found no room in the cache, or an interrupt came over the code that has the
 * class: the frame waits on the list, which the CPU takes in when it has no frame left, and
 * which the irq_work looks at when it is long. Class 0 never has room. Preemption as above.
 */
static noinline void bpf_coro_frame_free_slow(struct bpf_coro_frame_hdr *hdr,
					      struct bpf_coro_frame_class *c)
{
	struct bpf_coro_frame_cache *cache = this_cpu_ptr(hdr->cache);

	/*
	 * The memory is that of a host, and goes where the host goes. No program frees such a
	 * frame. A kfunc that kept one does where it cannot resume it, and what the frame
	 * holds is not released then, see bpf_coro.h: the host is among that.
	 */
	if (!hdr->class) {
		preempt_enable();
		return;
	}
	llist_add(&hdr->drop, &c->more);
	if (atomic_inc_return(&c->more_nr) > bpf_coro_frame_class_batch(c))
		irq_work_queue(&cache->tend);
	preempt_enable();
}

__bpf_kfunc_start_defs();

/*
 * Coroutine frames are heap memory whose contents the verifier tracks slot by slot like the
 * program stack, see PTR_TO_CORO_FRAME. The size is a verifier-checked constant, so the
 * allocation and the tracked size agree, and the verifier passes it with its class in the
 * upper half, see bpf_fixup_kfunc_call(): the frame is the one that the class last took, in
 * some twenty instructions. A program whose last reference is gone, and which only runs until
 * a grace period ends, gets no frame, whatever its cache has, see bpf_coro_frames_stop(): so
 * does the destroy function of a frame that such a program left parked, and
 * bpf_coro_prog_release() comes to an end.
 */
__bpf_kfunc void *bpf_coro_frame_alloc(u64 size__k, void *ctx__ign, struct bpf_prog_aux *aux)
{
	struct bpf_coro_frame_class *c;
	struct bpf_coro_frame_hdr *hdr;
	unsigned int nr;

	preempt_disable();
	c = &this_cpu_ptr(READ_ONCE(aux->coro_cache))->class[size__k >> 32];
	if (unlikely(!bpf_coro_frame_class_take(c)))
		return bpf_coro_frame_alloc_slow(aux, size__k, c, false);
	nr = c->nr;
	if (unlikely(!nr))
		return bpf_coro_frame_alloc_slow(aux, size__k, c, true);
	hdr = c->frames[nr - 1];
	c->nr = nr - 1;
	bpf_coro_frame_class_let(c);
	preempt_enable();
	/* its header is as it was when the frame went into the cache */
	kasan_mempool_unpoison_object(hdr, sizeof(*hdr) + (u32)size__k);
	return hdr + 1;
}

/*
 * Free a frame. It is the kfunc, and what kernel code frees a frame with, in any context: the
 * program of the frame is there, see "The lifetime of a frame" above, and so is its cache.
 */
__bpf_kfunc void bpf_coro_frame_free(void *p__coro_frame)
{
	struct bpf_coro_frame_hdr *hdr = bpf_coro_frame_hdr(p__coro_frame);
	struct bpf_coro_frame_class *c;
	unsigned int nr;

	preempt_disable();
	c = &this_cpu_ptr(hdr->cache)->class[hdr->class];
	if (unlikely(!bpf_coro_frame_class_take(c)))
		return bpf_coro_frame_free_slow(hdr, c);
	nr = c->nr;
	if (unlikely(nr == c->cap)) {
		bpf_coro_frame_class_let(c);
		return bpf_coro_frame_free_slow(hdr, c);
	}
	/* KASAN has reported a frame that it does not take, and nobody gets that one again */
	if (kasan_mempool_poison_object(hdr)) {
		c->frames[nr] = hdr;
		c->nr = nr + 1;
	}
	bpf_coro_frame_class_let(c);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(bpf_coro_frame_free);

#ifdef CONFIG_NET
/**
 * bpf_coro_frame_alloc_xdp - a coroutine frame in the headroom of the packet
 * @size__k: the size of the frame, which the verifier checked against bpf_coro_frame_xdp_max()
 * @ctx: the context of the XDP program
 * @aux: the program
 *
 * The buffer of the packet is the host of the frame, see "Hosts" above and
 * xdp_buff_lend_headroom(): the header is behind the room for struct xdp_frame, and the frame
 * behind the header. The frame is good for the rest of the invocation, and nothing frees it.
 * A program that keeps the packet with bpf_xdp_frame_steal() keeps the frame with it, for as
 * long as it has the packet: until it sends the packet, gives it back, or puts it elsewhere.
 * A frame that is suspended has the packet in one of its slots.
 *
 * Returns the frame, or NULL: the buffer cannot lend that much or has lent already, see
 * xdp_buff_lend_headroom(), or the last reference of the program is gone, see
 * bpf_coro_frames_stop().
 */
__bpf_kfunc void *bpf_coro_frame_alloc_xdp(u64 size__k, struct xdp_md *ctx,
					   struct bpf_prog_aux *aux)
{
	struct bpf_coro_frame_cache __percpu *cache = READ_ONCE(aux->coro_cache);
	struct bpf_coro_frame_hdr *hdr;

	if (unlikely(cache == &bpf_coro_no_frames))
		return NULL;
	hdr = xdp_buff_lend_headroom((struct xdp_buff *)ctx, sizeof(*hdr) + size__k);
	if (unlikely(!hdr))
		return NULL;
	hdr->cache = cache;
	hdr->class = 0;
	return hdr + 1;
}
#endif

__bpf_kfunc_end_defs();

/* The largest frame that fits in the headroom which every driver gives, for the verifier */
u32 bpf_coro_frame_xdp_max(void)
{
	return round_down(XDP_PACKET_HEADROOM - sizeof(struct xdp_frame) -
			  sizeof(struct bpf_coro_frame_hdr), sizeof(u64));
}

/*
 * The program of @frame, for the kfunc that keeps the frame: it holds the program for as long as
 * it has the frame, see "The lifetime of a frame" above.
 */
struct bpf_prog *bpf_coro_frame_prog(void *frame)
{
	return raw_cpu_ptr(bpf_coro_frame_hdr(frame)->cache)->owner->prog;
}
EXPORT_SYMBOL_GPL(bpf_coro_frame_prog);

/* The task that runs bpf_coro_run() on this CPU at each context level, see bpf_coro_run(). */
struct bpf_coro_runners {
	struct task_struct *task[4];
};

static DEFINE_PER_CPU(struct bpf_coro_runners, bpf_coro_runners);

/*
 * Like interrupt_context_level(), but on PREEMPT_RT too, where softirqs are served in task
 * context and preempt_count() doesn't tell.
 */
static int bpf_coro_run_level(void)
{
	if (in_nmi())
		return 3;
	if (in_hardirq())
		return 2;
	return in_serving_softirq() ? 1 : 0;
}

/*
 * Resume the coroutine of @frame: call the resume function in its first slot with the frame
 * as its argument. It is a subprogram of the program of the frame, which the caller holds, and
 * runs like any invocation of the program, under RCU with migration disabled, in a context
 * where the kfuncs of the program type are valid, which the caller sees to. Like the call of
 * any async callback it is an invocation of its own for the time of may_goto, see
 * bpf_timed_may_goto_save().
 *
 * It is never called inside an invocation of a program, from a kfunc that the program calls:
 * a continuation that suspends its frame again to such a kfunc would nest without bound. Where
 * that happens the same task is in here twice at the same context level of the CPU. The
 * warning catches that much, see bpf_coro_runners: not a kfunc that resumes a frame in the
 * call of a program that no bpf_coro_run() entered, nor one that nests while another task's
 * call of this CPU, which was preempted, holds the task level.
 *
 * The continuation owns the frame and may free it. The caller puts its reference on the
 * program after the call, which may be the last one: a program is freed after a grace period
 * of RCU, or of RCU Tasks Trace if it runs sleepable, see __bpf_prog_put_noref(), and the call
 * and what follows it here are in a read section of the one that applies.
 *
 * The call has a landing pad, like the call of a helper whose callback may unwind, see
 * bpf_call_cb(). The verifier has a continuation leave with kexit when the kernel unwinds it,
 * see push_coro_suspend(), and kexit returns here, behind the label: the pads of the program
 * have released what the continuation held. Nothing on the way to it says who is told, so this
 * tells a struct_ops, as bpf_prog_unwound_to_kernel() would where kexit finds no landing pad.
 * unwind_exit of the program comes to the label too: the continuation did not return either,
 * and nobody else is told, as where such a frame returns into the kernel.
 *
 * Returns true when the continuation did not return: the kernel unwound it, or the program's
 * own unwinding left it. The kfunc can react, by closing a connection or waking a waiter, say.
 */
static noinline bool __bpf_coro_run(void *frame, int slot)
{
	struct bpf_prog *prog = bpf_coro_frame_prog(frame);
	bpf_callback_t resume = READ_ONCE(((bpf_callback_t *)frame)[slot]);
	bool sleepable = bpf_prog_runs_sleepable(prog);
	struct bpf_timed_may_goto saved;
	struct task_struct *runner;
	bool unwound = false;
	u64 ret, kind;
	int level;

	if (sleepable)
		rcu_read_lock_trace();
	rcu_read_lock();
	migrate_disable();
	level = bpf_coro_run_level();
	runner = this_cpu_cmpxchg(bpf_coro_runners.task[level], NULL, current);
	WARN_ONCE(runner == current, "bpf_coro_run() inside a BPF program\n");
	bpf_timed_may_goto_save(prog, &saved);
	bpf_call_cb(resume, frame, 0, 0, 0, 0, ret, kind, left);
	goto done;
left:
	unwound = true;
	if (kind)
		bpf_prog_unwound_to_kernel((unsigned long)resume);
done:
	bpf_timed_may_goto_restore(prog, &saved);
	if (!runner)
		this_cpu_write(bpf_coro_runners.task[level], NULL);
	migrate_enable();
	rcu_read_unlock();
	if (sleepable)
		rcu_read_unlock_trace();
	return unwound;
}

bool bpf_coro_run(void *frame)
{
	return __bpf_coro_run(frame, 0);
}
EXPORT_SYMBOL_GPL(bpf_coro_run);

/*
 * Parked frames.
 *
 * bpf_coro_park_xdp() and bpf_coro_park_syscall() suspend a coroutine like a kfunc that keeps
 * the frame, and give the frame back to the program, as a pointer that it owns and can only
 * move: into a kptr field of a map value or of an allocated object, and out of it again with
 * bpf_kptr_xchg(). The kernel resumes no such frame. A program does, when it has the pointer:
 * it loads the resume function from the first slot of the frame, or the destroy function from
 * the second one, and calls it with the frame, see check_coro_callx(). No kernel code is on
 * that way, so the continuation was verified for the context that calls it: the kfunc names
 * the type of program whose context that is, the continuation is verified as code of such a
 * program from the suspension on, and the type of the pointer says so to whoever holds it.
 *
 * Where no program calls the destroy function the kernel does: bpf_coro_drop_xdp() and
 * bpf_coro_drop_syscall() for a program that is not of the type the frame was parked for, or
 * that a landing pad stands in for, the destructors of the kptr fields when an object goes
 * with a frame in it, and bpf_coro_prog_release() for all that is left when the program of
 * the frames goes. That may be in any context, so the frame waits on a list of the CPU for a
 * work item in a context of the type: softirq with a network context for XDP, a kernel thread
 * for a syscall program.
 *
 * The program that calls a frame is the frame's own or holds it, see "The lifetime of a
 * frame" above. A frame goes from one program to another through a map only, so a map whose
 * values can hold frames has one owner, the program that parks them, and is used by that
 * program and by the programs that are bound to it, see claim_coro_maps() in verifier.c.
 */
struct bpf_coro_xdp {
};

struct bpf_coro_syscall {
};

struct bpf_coro_drops {
	struct llist_head frames;
	struct irq_work irq_work;
	struct work_struct work;
	bool net;
};

static void bpf_coro_drop_work(struct work_struct *work)
{
	struct bpf_coro_drops *drops = container_of(work, struct bpf_coro_drops, work);
	struct bpf_net_context net_ctx, *net = NULL;
	struct llist_node *node, *next;

	llist_for_each_safe(node, next, llist_del_all(&drops->frames)) {
		void *frame = container_of(node, struct bpf_coro_frame_hdr, drop) + 1;

		if (drops->net) {
			local_bh_disable();
			net = bpf_net_ctx_set(&net_ctx);
		}
		/* The destroy function frees the frame, also when the kernel unwinds it. */
		__bpf_coro_run(frame, 1);
		if (drops->net) {
			bpf_net_ctx_clear(net);
			local_bh_enable();
		}
	}
}

/* Queueing work takes locks: not where the frame is dropped, which may be NMI. */
static void bpf_coro_drop_irq_work(struct irq_work *irq_work)
{
	struct bpf_coro_drops *drops = container_of(irq_work, struct bpf_coro_drops, irq_work);

	queue_work(drops->net ? system_bh_wq : system_percpu_wq, &drops->work);
}

static DEFINE_PER_CPU(struct bpf_coro_drops, bpf_coro_drops_xdp) = {
	.frames = LLIST_HEAD_INIT(frames),
	.irq_work = IRQ_WORK_INIT(bpf_coro_drop_irq_work),
	.net = true,
};

static DEFINE_PER_CPU(struct bpf_coro_drops, bpf_coro_drops_syscall) = {
	.frames = LLIST_HEAD_INIT(frames),
	.irq_work = IRQ_WORK_INIT(bpf_coro_drop_irq_work),
};

/* The work destroys what is on its own list, so the list of any CPU will do. */
static void bpf_coro_drop(void *frame, struct bpf_coro_drops *drops)
{
	struct bpf_coro_frame_hdr *hdr = bpf_coro_frame_hdr(frame);

	/* first, see bpf_coro_prog_release() */
	atomic_long_inc(&bpf_coro_frame_prog(frame)->aux->coro_drops);
	llist_add(&hdr->drop, &drops->frames);
	irq_work_queue(&drops->irq_work);
}

/* All that was given to bpf_coro_drop() is destroyed, as far as it has got to its list. */
static void bpf_coro_drops_flush(void)
{
	struct bpf_coro_drops *drops;
	int cpu;

	for_each_possible_cpu(cpu) {
		drops = &per_cpu(bpf_coro_drops_xdp, cpu);
		irq_work_sync(&drops->irq_work);
		flush_work(&drops->work);
		drops = &per_cpu(bpf_coro_drops_syscall, cpu);
		irq_work_sync(&drops->irq_work);
		flush_work(&drops->work);
	}
}

/**
 * bpf_coro_prog_release - destroy the parked frames of a program whose last reference is gone
 * @prog: the program, which parks frames
 *
 * No frame holds the program, so nothing but this stands between a parked frame and the day
 * on which its functions are freed. Whatever could call one is going: the programs that are
 * bound to @prog held it until they were freed, and what still runs of them and of @prog
 * itself ends with a grace period. The frames are in the maps that @prog owns, see
 * claim_coro_maps() in verifier.c, or on their way out of one, in a destructor or on a list of
 * bpf_coro_drop(). The kernel destroys them all, in the context of their type, while all of
 * @prog is still there.
 *
 * A destroy function is code of @prog, and may move another frame from one value to another,
 * or drop one. So this looks again until a round finds nothing: no frame in a map, and no
 * frame given to bpf_coro_drop() from before the round began until all that was on the lists
 * when it ended has been destroyed. bpf_coro_drop() counts first, in a section that a grace
 * period waits for. Then no code of @prog has run in the round, nothing has moved, and there
 * is no frame. That round comes: a destroy function gets no new frame, see
 * bpf_coro_frame_alloc(), and suspends none, see push_coro_suspend() in verifier.c, so each
 * one that runs leaves one frame less.
 *
 * Process context, in which it sleeps.
 */
void bpf_coro_prog_release(struct bpf_prog *prog)
{
	struct bpf_prog_aux *aux = prog->aux;
	struct bpf_map *map;
	long drops;
	u32 i;

	/*
	 * Code of it that may sleep, the program or an async callback, holds frames in a read
	 * section of RCU Tasks Trace: they are back in a map, or on a list, when it has ended.
	 */
	if (bpf_prog_runs_sleepable(prog))
		synchronize_rcu_tasks_trace();
	do {
		drops = atomic_long_read(&aux->coro_drops);
		synchronize_rcu();
		bpf_coro_drops_flush();
		/* for the objects that go with their frames, see __bpf_obj_drop_impl() */
		migrate_disable();
		for (i = 0; i < aux->used_map_cnt; i++) {
			map = aux->used_maps[i];
			if (READ_ONCE(map->coro_owner) == aux)
				map->ops->map_free_parked(map);
		}
		migrate_enable();
		/* something was found: it is on a list now, and the next round begins with it */
		if (drops != atomic_long_read(&aux->coro_drops))
			continue;
		synchronize_rcu();
		bpf_coro_drops_flush();
	} while (drops != atomic_long_read(&aux->coro_drops));
}

__bpf_kfunc_start_defs();

/**
 * bpf_coro_park_xdp - suspend a coroutine for an XDP program to resume
 * @frame__coro_suspend: the frame
 *
 * The frame is the program's again, as a pointer that it can keep in a kptr field. The resume
 * and the destroy function in its first two slots are verified as code of an XDP program from
 * here on, whatever program this is, and an XDP program that holds the pointer calls them:
 * this program, or one that is bound to it and takes the pointer out of a map of this one.
 */
__bpf_kfunc struct bpf_coro_xdp *bpf_coro_park_xdp(void *frame__coro_suspend)
{
	return frame__coro_suspend;
}

/**
 * bpf_coro_park_syscall - suspend a coroutine for a syscall program to resume
 * @frame__coro_suspend: the frame
 *
 * Like bpf_coro_park_xdp(), for a syscall program and the kernel threads that it runs.
 */
__bpf_kfunc struct bpf_coro_syscall *bpf_coro_park_syscall(void *frame__coro_suspend)
{
	return frame__coro_suspend;
}

/**
 * bpf_coro_drop_xdp - have the kernel destroy a parked coroutine
 * @coro: the frame
 *
 * The destroy function of the frame runs soon, in softirq context. It takes the frame alone
 * and is KF_RELEASE with no other flag: a landing pad calls it too.
 */
__bpf_kfunc void bpf_coro_drop_xdp(struct bpf_coro_xdp *coro)
{
	bpf_coro_drop(coro, raw_cpu_ptr(&bpf_coro_drops_xdp));
}

/**
 * bpf_coro_drop_syscall - have the kernel destroy a parked coroutine
 * @coro: the frame
 *
 * Like bpf_coro_drop_xdp(); the destroy function runs in a kernel thread.
 */
__bpf_kfunc void bpf_coro_drop_syscall(struct bpf_coro_syscall *coro)
{
	bpf_coro_drop(coro, raw_cpu_ptr(&bpf_coro_drops_syscall));
}

/* The destructors of kptr fields that hold a parked frame */
__bpf_kfunc void bpf_coro_xdp_dtor(void *coro)
{
	bpf_coro_drop(coro, raw_cpu_ptr(&bpf_coro_drops_xdp));
}
CFI_NOSEAL(bpf_coro_xdp_dtor);

__bpf_kfunc void bpf_coro_syscall_dtor(void *coro)
{
	bpf_coro_drop(coro, raw_cpu_ptr(&bpf_coro_drops_syscall));
}
CFI_NOSEAL(bpf_coro_syscall_dtor);

__bpf_kfunc_end_defs();

/* Does a kptr field with destructor @dtor hold a parked frame? See bpf_record_holds_parked(). */
bool bpf_coro_is_parked_dtor(void (*dtor)(void *))
{
	return dtor == bpf_coro_xdp_dtor || dtor == bpf_coro_syscall_dtor;
}

/*
 * @prog is freed, and the maps that could hold its parked frames, see claim_coro_maps() in
 * verifier.c, are nobody's again: no frame of it is left, see bpf_coro_prog_release(), and no
 * program that could put one there.
 *
 * Not at its last put: code of it may run on until a grace period ends, and would find the
 * frames of the next owner in the map, which it does not hold: it could keep one past that
 * owner's release. bpf_prog_free_deferred() calls this where it gives up the maps of the
 * program altogether, behind the grace period of __bpf_prog_put_noref(): nothing of the
 * program runs there that could use a map, or the map itself would go under it. A program
 * that did not load never ran.
 */
void bpf_coro_prog_disown(struct bpf_prog *prog)
{
	struct bpf_prog_aux *aux = prog->aux;
	u32 i;

	for (i = 0; i < aux->used_map_cnt; i++)
		cmpxchg(&aux->used_maps[i]->coro_owner, aux, NULL);
}

BTF_KFUNCS_START(bpf_coro_park_kfunc_ids)
BTF_ID_FLAGS(func, bpf_coro_park_xdp, KF_ACQUIRE)
BTF_ID_FLAGS(func, bpf_coro_park_syscall, KF_ACQUIRE)
BTF_ID_FLAGS(func, bpf_coro_drop_xdp, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_coro_drop_syscall, KF_RELEASE)
BTF_KFUNCS_END(bpf_coro_park_kfunc_ids)

static const struct btf_kfunc_id_set bpf_coro_park_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_coro_park_kfunc_ids,
};

#ifdef CONFIG_NET
BTF_KFUNCS_START(bpf_coro_xdp_kfunc_ids)
BTF_ID_FLAGS(func, bpf_coro_frame_alloc_xdp, KF_ACQUIRE | KF_RET_NULL | KF_IMPLICIT_ARGS)
BTF_KFUNCS_END(bpf_coro_xdp_kfunc_ids)

static const struct btf_kfunc_id_set bpf_coro_xdp_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_coro_xdp_kfunc_ids,
};
#endif

BTF_ID_LIST(bpf_coro_dtor_ids)
BTF_ID(struct, bpf_coro_xdp)
BTF_ID(func, bpf_coro_xdp_dtor)
BTF_ID(struct, bpf_coro_syscall)
BTF_ID(func, bpf_coro_syscall_dtor)

static int __init bpf_coro_init(void)
{
	const struct btf_id_dtor_kfunc dtors[] = {
		{ .btf_id = bpf_coro_dtor_ids[0], .kfunc_btf_id = bpf_coro_dtor_ids[1] },
		{ .btf_id = bpf_coro_dtor_ids[2], .kfunc_btf_id = bpf_coro_dtor_ids[3] },
	};
	int cpu, ret;

	for_each_possible_cpu(cpu) {
		INIT_WORK(&per_cpu(bpf_coro_drops_xdp, cpu).work, bpf_coro_drop_work);
		INIT_WORK(&per_cpu(bpf_coro_drops_syscall, cpu).work, bpf_coro_drop_work);
	}
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_coro_park_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &bpf_coro_park_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_coro_park_kfunc_set);
#ifdef CONFIG_NET
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_coro_xdp_kfunc_set);
#endif
	return ret ?: register_btf_id_dtor_kfuncs(dtors, ARRAY_SIZE(dtors), THIS_MODULE);
}
late_initcall(bpf_coro_init);
