/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF coroutine frames.
 *
 * bpf_coro_frame_alloc() gives a program the frame that the compiler-generated code of a
 * coroutine keeps its state in. A header in front of the frame, which the program cannot
 * reach, holds a reference on the program: the program stays loaded while one of its frames
 * exists, whoever owns the frame. Whoever frees a frame does so with bpf_coro_frame_free(),
 * which drops the reference.
 */
#ifndef _LINUX_BPF_CORO_H
#define _LINUX_BPF_CORO_H

#include <linux/types.h>

#ifdef CONFIG_BPF_SYSCALL
void bpf_coro_frame_free(void *frame);
#else
static inline void bpf_coro_frame_free(void *frame)
{
}
#endif

#endif /* _LINUX_BPF_CORO_H */
