/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* A fault in the arena ends the prog. In nine RCU sections it is skipped: a pad leaves eight. */
#define __nine(x) ({ x; x; x; x; x; x; x; x; x; })
#define skip_faults()	__nine(bpf_rcu_read_lock())
#define unwind_faults()	__nine(bpf_rcu_read_unlock())
#define skipped(expr)	({ long __v; skip_faults(); __v = (expr); unwind_faults(); __v; })
