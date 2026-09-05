// SPDX-License-Identifier: GPL-2.0
/*
 * BPF coroutine frames; see include/linux/bpf_coro.h.
 */
#include <linux/bpf.h>
#include <linux/bpf_coro.h>
#include <linux/btf.h>
#include <linux/irq_work.h>
#include <linux/llist.h>
#include <linux/slab.h>

/*
 * In front of every frame. The program gets the address behind it: the verifier bounds the
 * accesses through a PTR_TO_CORO_FRAME by the frame, and passes only the start of the frame
 * to a __coro_frame argument. The header is 8 bytes, also where a pointer has 4, and kmalloc
 * aligns the allocation to ARCH_KMALLOC_MINALIGN, 8 bytes at least on the architectures whose
 * JITs call kfuncs: the frame has the 8-byte alignment that the accesses of the program need.
 */
struct bpf_coro_frame_hdr {
	/* the program that allocated the frame, which the frame holds a reference on */
	struct bpf_prog *prog;
} __aligned(8);

static_assert(sizeof(struct bpf_coro_frame_hdr) == sizeof(u64));

static struct bpf_coro_frame_hdr *bpf_coro_frame_hdr(void *frame)
{
	return frame - sizeof(struct bpf_coro_frame_hdr);
}

/*
 * The frames that hold the last reference on their program. bpf_prog_put() frees the
 * program then, which takes locks and queues work: a program in NMI, or one that traces the
 * code holding such a lock, may do neither. irq_work does it in their place. Such a frame is
 * dead, and its first 8 bytes link it into the list, see bpf_coro_frame_alloc().
 */
struct bpf_coro_free_list {
	struct llist_head frames;
	struct irq_work work;
};

static void bpf_coro_free_deferred(struct irq_work *work)
{
	struct bpf_coro_free_list *list = container_of(work, struct bpf_coro_free_list, work);
	struct llist_node *node, *next;
	struct bpf_coro_frame_hdr *hdr;

	llist_for_each_safe(node, next, llist_del_all(&list->frames)) {
		hdr = bpf_coro_frame_hdr(node);
		bpf_prog_put(hdr->prog);
		kfree_nolock(hdr);
	}
}

static DEFINE_PER_CPU(struct bpf_coro_free_list, bpf_coro_free_lists) = {
	.frames = LLIST_HEAD_INIT(frames),
	.work = IRQ_WORK_INIT(bpf_coro_free_deferred),
};

__bpf_kfunc_start_defs();

/*
 * Coroutine frames are heap memory whose contents the verifier tracks slot by slot like the
 * program stack, see PTR_TO_CORO_FRAME. The size is a verifier-checked constant, so the
 * allocation and the tracked size agree, except that a frame has room for the llist_node of
 * its free. The frame holds a reference on the program: a program whose last reference is
 * gone, and which only runs until a grace period ends, gets no frame.
 */
__bpf_kfunc void *bpf_coro_frame_alloc(u64 size__k, void *ctx__ign, struct bpf_prog_aux *aux)
{
	struct bpf_coro_frame_hdr *hdr;
	struct bpf_prog *prog;

	hdr = kmalloc_nolock(sizeof(*hdr) + max_t(u64, size__k, sizeof(struct llist_node)),
			     __GFP_ACCOUNT, NUMA_NO_NODE);
	if (!hdr)
		return NULL;
	prog = bpf_prog_inc_not_zero(aux->prog);
	if (IS_ERR(prog)) {
		kfree_nolock(hdr);
		return NULL;
	}
	hdr->prog = prog;
	return hdr + 1;
}

/*
 * Free a frame and drop its reference on the program. It is the kfunc, and what kernel code
 * frees a frame with: it may be called in any context.
 */
__bpf_kfunc void bpf_coro_frame_free(void *p__coro_frame)
{
	struct bpf_coro_frame_hdr *hdr = bpf_coro_frame_hdr(p__coro_frame);
	struct bpf_coro_free_list *list;

	/* Not the last reference: the program stays, and the memory goes at once. */
	if (atomic64_add_unless(&hdr->prog->aux->refcnt, -1, 1)) {
		kfree_nolock(hdr);
		return;
	}
	/* The work frees what is on its own list, so the list of any CPU will do. */
	list = raw_cpu_ptr(&bpf_coro_free_lists);
	llist_add(p__coro_frame, &list->frames);
	irq_work_queue(&list->work);
}
EXPORT_SYMBOL_GPL(bpf_coro_frame_free);

__bpf_kfunc_end_defs();
