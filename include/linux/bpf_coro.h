/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF coroutine frames, and their resumption from the kernel.
 *
 * bpf_coro_frame_alloc() gives a program the frame that the compiler-generated code of a
 * coroutine keeps its state in. A header in front of the frame, which the program cannot
 * reach, holds a reference on the program: the program stays loaded while one of its frames
 * exists, whoever owns the frame. Whoever frees a frame does so with bpf_coro_frame_free(),
 * which drops the reference.
 *
 * A kfunc that takes a frame through a __coro_suspend argument owns the frame from then on.
 * The frame's first slot holds the address of the coroutine's resume function, a subprogram
 * taking the frame as its only argument, which the verifier checked as the continuation of
 * the suspend point. Once the event that the kfunc waits for has happened, the kfunc resumes
 * the coroutine exactly once with bpf_coro_run(), and the continuation owns the frame then.
 * It does so later, from kernel context in which the kfuncs of every type of program that
 * may call the kfunc are valid: softirq, irq_work or a workqueue, as the kfunc arranges. Its
 * caller may be the continuation of a frame that was parked for a program of another type
 * than the one it is in, see kernel/bpf/coro.c, and the next continuation is verified as code
 * of that type. Never inside an invocation of a
 * program, in the call that took the frame or in another kfunc that a program calls, also
 * when the kfunc fails after it took the frame. bpf_coro_run() returns true when the
 * continuation did not return: the kernel unwound it, or the program's own unwinding left it.
 * Or the kfunc frees the frame with bpf_coro_frame_free() without resuming it, which does not
 * release the references that the coroutine keeps in the slots of the frame.
 */
#ifndef _LINUX_BPF_CORO_H
#define _LINUX_BPF_CORO_H

#include <linux/types.h>

#ifdef CONFIG_BPF_SYSCALL
void bpf_coro_frame_free(void *frame);
bool bpf_coro_run(void *frame);
#else
static inline void bpf_coro_frame_free(void *frame)
{
}

static inline bool bpf_coro_run(void *frame)
{
	return false;
}
#endif

#endif /* _LINUX_BPF_CORO_H */
