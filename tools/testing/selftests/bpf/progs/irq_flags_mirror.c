// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern void bpf_local_irq_save(unsigned long *) __ksym;
extern void bpf_local_irq_restore(unsigned long *) __ksym;

int param;
/* The slot the program saves its flags into: the handle of the flags. */
__u64 flags_slot;
/* The handle of the flags the unwinder restored. */
__u64 restored;

/* BTF FUNC records are not generated for kfuncs referenced from inline assembly */
void __kfunc_btf_root(unsigned long *flags)
{
	bpf_local_irq_save(flags);
}

SEC("fentry/bpf_unwind_release")
int BPF_PROG(release_hook, struct bpf_resource *res, void *handle, void *flags)
{
	if (res->kind == BPF_RESOURCE_IRQ_FLAG && (__u64)handle == flags_slot)
		restored = (__u64)handle;
	return 0;
}

/*
 * Saves the flags its caller points at, at one of two instructions by what
 * the test says, and spins until the may_goto cancels the program. It keeps
 * no pointer to the slot at the loop, so the flags are restored from their
 * mirror, which the saving instruction stores: the two paths must not be
 * joined, since each lists the mirror of its own instruction. In assembly,
 * so that the compiler cannot merge the two calls into one.
 */
static __naked __noinline __used void save_and_spin(unsigned long *flags, int which)
{
	asm volatile (
	"if r2 == 0 goto 1f;"
	"call %[bpf_local_irq_save];"
	"goto 2f;"
"1:"
	"call %[bpf_local_irq_save];"
"2:"
	"may_goto 3f;"
	"goto 2b;"
"3:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_local_irq_save)
	: __clobber_all);
}

SEC("tc")
int irq_flags_saved_twice(struct __sk_buff *ctx)
{
	unsigned long flags;

	flags_slot = (__u64)&flags;
	save_and_spin(&flags, param);
	bpf_local_irq_restore(&flags);
	return 0;
}
