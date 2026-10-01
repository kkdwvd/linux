/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF coroutines suspended into the kernel.
 *
 * A kfunc that takes a frame through a __coro_suspend argument owns it until
 * it resumes the coroutine: the frame's first slot holds the address of the
 * compiler-generated resume function, a BPF subprogram taking the frame as
 * its only argument. bpf_coro_cont embeds in the kernel object that waits
 * for the event (an I/O request, say) and resumes the frame from BH context
 * once the event has happened, holding a reference on the program whose
 * code the resume function is.
 */
#ifndef _LINUX_BPF_CORO_H
#define _LINUX_BPF_CORO_H

#include <linux/types.h>
#include <linux/workqueue.h>

struct bpf_prog;
struct bpf_prog_aux;

struct bpf_coro_cont {
	struct work_struct work;
	struct bpf_prog *prog;
	void *frame;
	/* Called after the resume returns, to free the embedding object. */
	void (*fini)(struct bpf_coro_cont *cont);
};

/* A disk read into arena memory that resumes a coroutine when it completes. */
struct bpf_blk_io {
	__u64 sector;
	__u32 dev;	/* MKDEV(major, minor) as given to bpf_blk_open() */
	__u32 len;	/* bytes, a multiple of 512, at most BPF_BLK_IO_MAX */
	__s32 status;	/* 0 or -errno, written on completion */
	__u32 flags;
};

#define BPF_BLK_IO_MAX	(64 * 1024)

#ifdef CONFIG_BPF_SYSCALL
void bpf_coro_cont_init(struct bpf_coro_cont *cont, void *frame, struct bpf_prog_aux *aux,
			void (*fini)(struct bpf_coro_cont *cont));
void bpf_coro_cont_resume(struct bpf_coro_cont *cont);
void bpf_coro_cont_resume_now(struct bpf_coro_cont *cont);
void bpf_coro_run(void *frame);
#endif

#endif /* _LINUX_BPF_CORO_H */
