// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* global data of the object is in arena */
char data_in_arena SEC(".arena.data");

int counter = 5;
long pair[2] = { 1, 2 };
int x = 42;
long sum;
long table[4];
struct {
	long v[8];
} aligned64 __attribute__((aligned(64)));
const volatile int ro = 7;
const volatile long ro_table[4] = { 10, 20, 30, 40 };

/* const strings stay in a map for helpers and kfuncs, a copy of them is in arena */
const char hello[] SEC(".rodata.str.hello") = "hello";

/* pointers to data that are stored in data */
int *px = &x;
const char *str = hello;
int *const volatile cpx SEC(".data.rel.ro") = &x;

SEC("syscall")
int use_data(void *ctx)
{
	int i;

	for (i = 0; i < 4; i++)
		table[i] = ro_table[i] + i;
	sum = counter + ro + pair[0] + pair[1];
	counter++;
	__sync_fetch_and_add(&pair[1], 3);
	return sum;
}

typedef int (*op_fn)(int);

static __noinline int add1(int v)
{
	return v + 1;
}

/*
 * Pointers to functions and to data in read-only data, which is in arena like
 * the rest of the data. [WIP] The pointer to a function holds the JITed
 * address of a copy of the function in the first program loaded that has one:
 * a program that calls through numbers, or one that takes the address of the
 * function, whether or not it calls through the pointer, see func_addrs.
 * Volatile, so that the compiler doesn't replace the pointers with what they
 * point to.
 */
static const volatile struct {
	op_fn fn;
	int *data;
	const char *name;
} ops SEC(".data.rel.ro") = { add1, &x, hello };

/* what the program loaded from ops.fn */
unsigned long ops_fn;

SEC("syscall")
int use_ops(void *ctx)
{
	/* a program has the arena when its code refers to it */
	counter++;
	ops_fn = (unsigned long)ops.fn;
	return *ops.data + 1 + ops.name[1];
}

/*
 * [WIP] Pointers to functions in data, in a program that doesn't call through
 * them: a slot that holds the address of a static function, like the
 * terminate handler of the C++ runtime, and the addresses that ld_imm64 takes.
 * The slot is filled with the JITed address of the copy of the function that
 * the program got for arena data, and ld_imm64 takes the address of the same
 * copy. An address compares equal however it is obtained: loaded from the
 * slot, taken in code, or stored to the slot and loaded back.
 */
typedef void (*handler_fn)(void);

static __noinline void default_handler(void)
{
	counter += 1;
}

static __noinline void other_handler(void)
{
	counter += 10;
}

/*
 * Its address is taken in code that the verifier doesn't reach, and it's in
 * a slot: the kernel verifies and keeps it all the same, and the slot is
 * filled
 */
static __noinline void dead_handler(void)
{
	counter += 100;
}

/*
 * In a section of its own, as the C++ runtime's handler is. Volatile: the
 * program loads what it stored, the compiler doesn't know it. Not of the
 * typedef, which the skeleton wouldn't have.
 */
void (*volatile handler)(void) SEC(".data.handler") = default_handler;
void (*volatile dead_slot)(void) SEC(".data.handler") = dead_handler;
/* the initial slot, the addresses that ld_imm64 took, the slot after the store */
unsigned long handler_initial, handler_default, handler_other, handler_stored;

SEC("syscall")
int func_addrs(void *ctx)
{
	unsigned long zero = 0;
	handler_fn prev;

	/* the compiler doesn't know zero, the verifier does: dead code to it */
	asm volatile("" : "+r"(zero));
	if (zero)
		dead_slot = dead_handler;

	handler_initial = (unsigned long)handler;
	handler_default = (unsigned long)default_handler;
	handler_other = (unsigned long)other_handler;
	if (!handler_initial)
		return 1;
	if (handler != default_handler)
		return 2;
	prev = handler;
	handler = other_handler;
	if (prev != default_handler)
		return 3;
	handler_stored = (unsigned long)handler;
	if (handler != other_handler)
		return 4;
	handler = default_handler;
	/* the pointer in read-only data, too */
	ops_fn = (unsigned long)ops.fn;
	if (ops.fn != add1)
		return 5;
	return 0;
}

SEC("syscall")
int use_ptrs(void *ctx)
{
	unsigned long addr = (unsigned long)&aligned64;
	char local[4] = "abc";

	/* hide the address from the compiler, it knows that '& 63' is 0 */
	asm volatile ("" : "+r"(addr));
	if (addr & 63)
		return 1;
	aligned64.v[7] = 7;
	if (*px != 42)
		return 2;
	*px = 43;
	if (x != 43 || *cpx != 43)
		return 3;
	if (str[0] != 'h' || str[4] != 'o' || str[5])
		return 4;
	/* a plain literal is in arena, which a helper can't read */
	if (bpf_strncmp(local, sizeof(local), BPF_CONST_STR("abc")))
		return 5;
	return 0;
}

char out[16];

/* format strings are in a map */
SEC("syscall")
int use_printk(void *ctx)
{
	char buf[sizeof(out)];
	int i, n;

	bpf_printk("counter %d", counter);
	n = BPF_SNPRINTF(buf, sizeof(buf), "%d-%d", x, ro);
	for (i = 0; i < sizeof(out); i++)
		out[i] = buf[i];
	return n;
}

char _license[] SEC("license") = "GPL";
