/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __BPF_EXCEPTION_H
#define __BPF_EXCEPTION_H

#include <linux/bpfptr.h>
#include <linux/types.h>

union bpf_attr;
struct bpf_verifier_env;
struct bpf_insn;

int bpf_exc_check_info(struct bpf_verifier_env *env, const union bpf_attr *attr,
		       bpfptr_t uattr);
bool bpf_is_unwind_kfunc(const struct bpf_insn *insn);
int bpf_exc_lower(struct bpf_verifier_env *env);

#endif /* __BPF_EXCEPTION_H */
