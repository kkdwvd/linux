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

#ifdef CONFIG_BPF_SYSCALL
void bpf_coro_cont_init(struct bpf_coro_cont *cont, void *frame, struct bpf_prog_aux *aux,
			void (*fini)(struct bpf_coro_cont *cont));
void bpf_coro_cont_resume(struct bpf_coro_cont *cont);
void bpf_coro_cont_resume_now(struct bpf_coro_cont *cont);
void bpf_coro_run(void *frame);
#endif

#endif /* _LINUX_BPF_CORO_H */
