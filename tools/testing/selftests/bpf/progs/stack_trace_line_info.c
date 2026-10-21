// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

char trace[8192];
char symbol[1024];
int trace_len;
int symbol_len;
volatile int trace_marker;
bool print_stack;
bool backtrace;
__u64 symbol_addr;
__u32 symbol_size;

static __noinline int stack_trace_leaf(void)
{
	int ret;

#line 100 "stack_trace_line_info.c"
	ret = bpf_kfunc_stack_trace(trace, sizeof(trace), print_stack);
#line 101
	return ret < 0 ? ret : ret + 1;
}

static __noinline int stack_trace_middle(void)
{
	int ret;

#line 200
	ret = stack_trace_leaf();
#line 201
	return ret < 0 ? ret : ret + 1;
}

SEC("tc")
int stack_trace_main(struct __sk_buff *skb)
{
#line 300
	trace_len = stack_trace_middle();
#line 301 "directory/stack trace).c"
	trace_marker = 1;
#line 302 "long_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.c"
	trace_marker = 2;
#line 303 "stack_trace_line_info.c"
	return 0;
}

SEC("tc")
int stack_trace_symbol(struct __sk_buff *skb)
{
	__u32 size = symbol_size;

	if (size > sizeof(symbol) - 2)
		return 1;
	symbol_len = bpf_kfunc_stack_trace_symbol(symbol + 1, size, symbol_addr, backtrace);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
