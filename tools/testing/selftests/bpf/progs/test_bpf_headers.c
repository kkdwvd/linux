// SPDX-License-Identifier: GPL-2.0
/*
 * Compile the same interfaces as C and C++, without a generated vmlinux.h.
 */
#include <linux/bpf.h>
#if defined(__aarch64__) || defined(__TARGET_ARCH_arm64)
/* tools/include/uapi/linux/types.h omits the type used by arm64 ptrace.h. */
typedef unsigned __int128 __u128;
#endif
#include <asm/ptrace.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/usdt.bpf.h>

struct array_definition {
	int unused;
	__array(values, int);
};

struct qualified_fields {
	const int c;
	volatile int v;
	const volatile int cv;
	const int *ptr;
	const int array[2];
};

#ifdef __cplusplus
static_assert(__is_same(___type(((struct qualified_fields *)0), c), int), "const");
static_assert(__is_same(___type(((struct qualified_fields *)0), v), int), "volatile");
static_assert(__is_same(___type(((struct qualified_fields *)0), cv), int), "const volatile");
static_assert(__is_same(___type(((struct qualified_fields *)0), ptr), const int *), "pointer");
static_assert(__is_same(___type(((struct qualified_fields *)0), array), int[2]), "array");
extern "C" {
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
_Static_assert(bpf_htons(0x1234) == 0x3412, "htons");
_Static_assert(bpf_ntohs(0x1234) == 0x3412, "ntohs");
_Static_assert(bpf_htonl(0x12345678) == 0x78563412, "htonl");
_Static_assert(bpf_ntohl(0x12345678) == 0x78563412, "ntohl");
_Static_assert(bpf_cpu_to_be64(0x123456789abcdef0ULL) == 0xf0debc9a78563412ULL, "cpu_to_be64");
_Static_assert(bpf_be64_to_cpu(0x123456789abcdef0ULL) == 0xf0debc9a78563412ULL, "be64_to_cpu");
#else
_Static_assert(bpf_htons(0x1234) == 0x1234, "htons");
_Static_assert(bpf_ntohs(0x1234) == 0x1234, "ntohs");
_Static_assert(bpf_htonl(0x12345678) == 0x12345678, "htonl");
_Static_assert(bpf_ntohl(0x12345678) == 0x12345678, "ntohl");
_Static_assert(bpf_cpu_to_be64(0x123456789abcdef0ULL) == 0x123456789abcdef0ULL, "cpu_to_be64");
_Static_assert(bpf_be64_to_cpu(0x123456789abcdef0ULL) == 0x123456789abcdef0ULL, "be64_to_cpu");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} values SEC(".maps");

struct small1 { __u8 a; };
struct small2 { __u16 a; };
struct small4 { __u32 a; };
struct small8 { __u64 a; };
struct large16 { __u64 a, b; };
struct const_member { const __u64 a; };
union either8 { __u64 a; long b; };
enum number { ONE = 1, TWO = 2 };

static int BPF_PROG(typed_args, int *p, const int *q, signed char s,
		   unsigned short u, enum number e, bool b)
{
	return p == q && *p == 42 && s == -1 && u == 65535 && e == TWO && b;
}

static int BPF_PROG2(aggregate_args, struct small1, a, struct small2, b,
		    struct small4, c, struct small8, d, struct large16, e,
		    union either8, f, struct const_member, g, int *, p,
		    enum number, n, signed char, s)
{
	return a.a == 0x12 && b.a == 0x1234 && c.a == 0x12345678 &&
	       d.a == 0x123456789abcdef0ULL && e.a == 9 && e.b == 10 &&
	       f.a == 11 && g.a == 12 && *p == 42 && n == TWO && s == -1;
}

static __attribute__((unused)) int BPF_KPROBE(probe_args, int *p, long v)
{
	return *p == v;
}

static __attribute__((unused)) int BPF_KRETPROBE(return_arg, int *p)
{
	return *p;
}

static __attribute__((unused)) int BPF_UPROBE(uprobe_args, int *p)
{
	return *p;
}

static __attribute__((unused)) int BPF_URETPROBE(uretprobe_arg, int *p)
{
	return *p;
}

static __attribute__((unused)) int BPF_USDT(usdt_no_args)
{
	return 0;
}

static int BPF_PROG(no_args)
{
	return 1;
}

static int BPF_PROG2(no_args2)
{
	return 1;
}

static __attribute__((unused)) bool weak_exists(void)
{
	return bpf_ksym_exists(bpf_iter_num_new);
}

static long snprintf_args(char *buf, int size)
{
	return BPF_SNPRINTF(buf, size, "%s %d", "value", 42);
}

static __attribute__((unused)) long printf_args(struct seq_file *seq)
{
	BPF_SEQ_PRINTF(seq, "%s %d", "value", 42);
	bpf_printk("%s %s %s %s", "a", "b", "c", "d");
	return BPF_SNPRINTF(NULL, 0, "no arguments");
}

#if defined(__bpf__)

/*
 * These are compile-only wrappers. UAPI register member names can differ
 * from vmlinux BTF names, so do not load their CO-RE relocations.
 */
static __attribute__((unused)) int BPF_KSYSCALL(syscall_args, int *p, long n)
{
	return *p == n;
}

SEC("socket")
int cpp_helpers(struct __sk_buff *ctx)
{
	struct small8 object = { 42 };
	int key = 0, value = ctx->len, sum = 0, n, *cur;
	int *found = NULL;
	_Bool have_iter = bpf_ksym_exists(bpf_iter_num_new);
	char buf[16];

	if (container_of(&object.a, struct small8, a) != &object || !have_iter)
		return 1;
	if (bpf_map_update_elem(&values, &key, &value, BPF_ANY))
		return 2;
	found = (int *)bpf_map_lookup_elem(&values, &key);
	if (!found || *found != value)
		return 3;
	if (snprintf_args(buf, sizeof(buf)) != 9 || buf[0] != 'v' ||
	    buf[6] != '4' || buf[7] != '2' || buf[8])
		return 4;
	bpf_for_each(num, cur, 0, 4)
		sum += *cur;
	bpf_for(n, 0, 4)
		sum += n;
	bpf_repeat(4)
		sum++;
	return sum;
}

SEC("socket")
int cpp_tracing(struct __sk_buff *ctx)
{
	int value = 42;
	unsigned long long args[] = { (__u64)&value, (__u64)&value, -1ULL, 65535, TWO, 1 };
	unsigned long long aggregates[] = {
		0x12, 0x1234, 0x12345678, 0x123456789abcdef0ULL, 9, 10,
		11, 12, (__u64)&value, TWO, -1ULL,
	};
	if (!typed_args(args) || !aggregate_args(aggregates) || !no_args(args) || !no_args2(args))
		return 1;
#if defined(__TARGET_ARCH_x86)
	struct pt_regs regs = {};

	PT_REGS_PARM1(&regs) = (__u64)&value;
	PT_REGS_PARM2(&regs) = 42;
	PT_REGS_RC(&regs) = (__u64)&value;
	if (!probe_args(&regs) || return_arg(&regs) != 42 ||
	    uprobe_args(&regs) != 42 || uretprobe_arg(&regs) != 42)
		return 2;
#endif
	return 0;
}

SEC("socket")
int cpp_endian(struct __sk_buff *ctx)
{
	__u16 a = ctx->len;
	__u32 b = ctx->len;
	__u64 c = ctx->len;

	return bpf_ntohs(bpf_htons(a)) != a ||
	       bpf_ntohl(bpf_htonl(b)) != b ||
	       bpf_be64_to_cpu(bpf_cpu_to_be64(c)) != c;
}

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

SEC("socket")
int cpp_core(struct __sk_buff *ctx)
{
	struct bpf_insn insn = {};
	const volatile struct bpf_insn *qualified = &insn;
	struct callback_head chain = {};

	insn.off = ctx->len;
	if (BPF_CORE_READ(qualified, off) != (short)ctx->len ||
	    BPF_PROBE_READ(qualified, off) != (short)ctx->len)
		return 1;
	chain.next = &chain;
	if (BPF_CORE_READ(&chain, next, next) != &chain)
		return 2;
	BPF_CORE_WRITE_BITFIELD(&insn, dst_reg, 7);
	BPF_CORE_WRITE_BITFIELD(&insn, src_reg, 3);
	if (BPF_CORE_READ_BITFIELD(&insn, dst_reg) != 7 ||
	    BPF_CORE_READ_BITFIELD_PROBED(&insn, src_reg) != 3)
		return 3;
	if (!bpf_core_type_exists(struct bpf_insn) ||
	    !bpf_core_field_exists(struct bpf_insn, off) ||
	    bpf_core_field_size(struct bpf_insn, off) != sizeof(insn.off) ||
	    bpf_core_type_size(struct bpf_insn) != sizeof(insn) ||
	    !bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_ARRAY) ||
	    bpf_core_enum_value(enum bpf_map_type, BPF_MAP_TYPE_ARRAY) != BPF_MAP_TYPE_ARRAY)
		return 4;
	return 0;
}

int usdt_result;

SEC("usdt")
int BPF_USDT(cpp_usdt, int n, const int *ptr)
{
	int value = 0;

	if (bpf_probe_read_user(&value, sizeof(value), ptr))
		return 0;
	if (n == -7 && value == 42 && bpf_usdt_arg_cnt(ctx) == 2 &&
	    bpf_usdt_arg_size(ctx, 0) == sizeof(n) && bpf_usdt_cookie(ctx) == 123)
		usdt_result++;
	return 0;
}

char _license[] SEC("license") = "GPL";
#endif

#ifdef __cplusplus
}
#endif
