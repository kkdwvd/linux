// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/*
 * System calls issued by BPF io threads on behalf of their process.
 *
 * A BPF io thread, see bpf_kthread_create_io(), is a thread of a user
 * process that runs a BPF callback instead of returning to user space.
 * bpf_sys_exec() lets that callback run a system call as the process
 * would have: the thread shares the process's address space, so user
 * pointers in the arguments mean what they mean to the process, and its
 * file table and credentials, so the call is permitted exactly as if the
 * process had made it. This is the kernel half of exception-less system
 * calls: the process posts requests to memory it shares with the program
 * and the program executes them here, without a mode switch.
 *
 * The call goes through the architecture's system call table like a trap
 * would, only without the entry work that a trap does for the task that
 * trapped: no seccomp or audit, no ptrace, no signal delivery or restart.
 * The system calls that depend on that work, or that act on the calling
 * thread itself rather than its process (exit, clone, exec, signals,
 * credentials, futexes, io_uring, bpf, and the like), are refused.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/nospec.h>
#include <linux/sched/signal.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <asm/syscall.h>

static DECLARE_BITMAP(bpf_sys_exec_allowed, NR_syscalls) __ro_after_init;

/*
 * File, socket and memory operations, and the clock and identity reads a
 * server loop makes. The list is a policy of this prototype, not a
 * security boundary: everything here is permitted to the process anyway.
 */
static const unsigned int bpf_sys_exec_allowlist[] __initconst = {
	__NR_read, __NR_write, __NR_pread64, __NR_pwrite64, __NR_readv, __NR_writev,
	__NR_preadv, __NR_pwritev, __NR_preadv2, __NR_pwritev2,
	__NR_recvfrom, __NR_sendto, __NR_recvmsg, __NR_sendmsg, __NR_recvmmsg, __NR_sendmmsg,
	__NR_accept, __NR_accept4, __NR_connect, __NR_shutdown, __NR_socket, __NR_socketpair,
	__NR_bind, __NR_listen, __NR_setsockopt, __NR_getsockopt, __NR_getsockname,
	__NR_getpeername,
	__NR_close, __NR_open, __NR_openat, __NR_openat2, __NR_creat, __NR_dup, __NR_dup2,
	__NR_dup3, __NR_fcntl, __NR_ioctl, __NR_pipe, __NR_pipe2, __NR_eventfd, __NR_eventfd2,
	__NR_epoll_create, __NR_epoll_create1, __NR_epoll_ctl, __NR_epoll_wait, __NR_epoll_pwait,
	__NR_epoll_pwait2, __NR_poll, __NR_ppoll, __NR_select, __NR_pselect6,
	__NR_stat, __NR_fstat, __NR_lstat, __NR_newfstatat, __NR_statx, __NR_lseek,
	__NR_fsync, __NR_fdatasync, __NR_sync_file_range, __NR_truncate, __NR_ftruncate,
	__NR_fallocate, __NR_fadvise64, __NR_flock, __NR_getdents64, __NR_mkdir, __NR_mkdirat,
	__NR_unlink, __NR_unlinkat, __NR_rename, __NR_renameat, __NR_renameat2, __NR_readlink,
	__NR_readlinkat, __NR_access, __NR_faccessat, __NR_faccessat2, __NR_chmod, __NR_fchmod,
	__NR_fchmodat, __NR_chown, __NR_fchown, __NR_fchownat, __NR_utimensat, __NR_getcwd,
	__NR_sendfile, __NR_splice, __NR_tee, __NR_vmsplice, __NR_copy_file_range,
	__NR_memfd_create,
	__NR_mmap, __NR_munmap, __NR_mprotect, __NR_madvise, __NR_mremap, __NR_msync,
	__NR_mincore, __NR_mlock, __NR_munlock, __NR_brk,
	__NR_getpid, __NR_getppid, __NR_gettid, __NR_getuid, __NR_geteuid, __NR_getgid,
	__NR_getegid, __NR_getcpu, __NR_getrandom, __NR_uname, __NR_sysinfo, __NR_times,
	__NR_getrusage, __NR_sched_yield, __NR_nanosleep, __NR_clock_nanosleep,
	__NR_clock_gettime, __NR_clock_getres, __NR_gettimeofday, __NR_time,
};

bool bpf_kthread_is_current_io(struct bpf_kthread *kthread);

__bpf_kfunc_start_defs();

/*
 * Run system call @nr with the six arguments in @args on behalf of the
 * process of the BPF io thread @kthread, which must be the calling thread.
 * Returns the system call's result; a call interrupted by the thread's
 * stop returns -EINTR, one not on the allowlist -ENOSYS, and a caller that
 * is not the io thread gets -EPERM.
 */
__bpf_kfunc long bpf_sys_exec(struct bpf_kthread *kthread, u32 nr, const u64 *args,
			      u32 args__sz)
{
	struct pt_regs regs = {};
	long ret;

	if (args__sz != 6 * sizeof(u64))
		return -EINVAL;
	if (!bpf_kthread_is_current_io(kthread))
		return -EPERM;
	if (nr >= NR_syscalls || !test_bit(nr, bpf_sys_exec_allowed))
		return -ENOSYS;
	if (fatal_signal_pending(current))
		return -EINTR;
	nr = array_index_nospec(nr, NR_syscalls);

	regs.orig_ax = nr;
	regs.di = args[0];
	regs.si = args[1];
	regs.dx = args[2];
	regs.r10 = args[3];
	regs.r8 = args[4];
	regs.r9 = args[5];
	ret = sys_call_table[nr](&regs);

	switch (ret) {
	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
	case -ERESTART_RESTARTBLOCK:
		ret = -EINTR;
		break;
	}
	return ret;
}

/*
 * Signal the eventfd @fd of the calling io thread's process: the way a
 * program wakes a process thread that sleeps in read() on it.
 */
__bpf_kfunc int bpf_eventfd_signal(int fd)
{
	struct eventfd_ctx *ctx;

	if (!current->files)
		return -EBADF;
	ctx = eventfd_ctx_fdget(fd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);
	eventfd_signal(ctx);
	eventfd_ctx_put(ctx);
	return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_sys_exec_kfunc_ids)
BTF_ID_FLAGS(func, bpf_sys_exec, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_eventfd_signal)
BTF_KFUNCS_END(bpf_sys_exec_kfunc_ids)

static const struct btf_kfunc_id_set bpf_sys_exec_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_sys_exec_kfunc_ids,
};

static int __init bpf_sys_exec_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(bpf_sys_exec_allowlist); i++)
		if (bpf_sys_exec_allowlist[i] < NR_syscalls)
			__set_bit(bpf_sys_exec_allowlist[i], bpf_sys_exec_allowed);
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_sys_exec_kfunc_set);
}
late_initcall(bpf_sys_exec_init);
