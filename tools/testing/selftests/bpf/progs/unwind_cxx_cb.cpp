// SPDX-License-Identifier: GPL-2.0
/*
 * C++ exceptions through the helpers that call a callback. A callback that
 * throws leaves with unwind_exit, the helper leaves to the pad of the
 * unwind_goto after its call, and the caller catches. The helpers that call a
 * sync callback aren't declared noexcept, since they leave the way the callback
 * leaves, so llvm follows their calls with unwind_goto like the call of a
 * subprog, and with what the callback unwound with in r0: the exception
 * object, which the catch checks for the one that was thrown.
 *
 * vmlinux.h and bpf_helpers.h are not C++.
 */
#define SEC(name) __attribute__((section(name), used))
#define __ksym __attribute__((section(".ksyms")))
#define __noinline __attribute__((noinline))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) __typeof__(val) *name

/* The test puts the number for the prog behind the Ethernet header test_run wants */
#define ETH_HLEN 14

#ifdef __BPF_FEATURE_UNWIND

struct __sk_buff {
	unsigned int len;
};

extern "C" {
void bpf_rcu_read_lock(void) noexcept __ksym;
void bpf_rcu_read_unlock(void) noexcept __ksym;

/* Starts an unwind. Not a kfunc: llvm lowers the call and it doesn't come back. */
int _Unwind_RaiseException(void *exc);

/*
 * All that is left of the C++ runtime. The exception that unwinds is a number,
 * as an object in arena would be, and __cxa_begin_catch() keeps what the
 * landing pad was given in r0.
 */
#define EXCEPTION 77

static char exc_obj[16];
unsigned long caught;

__always_inline void *__cxa_allocate_exception(unsigned long size) noexcept
{
	return exc_obj;
}

__always_inline void __cxa_throw(void *exc, void *tinfo, void (*dtor)(void *))
{
	_Unwind_RaiseException((void *)EXCEPTION);
}

__always_inline void *__cxa_begin_catch(void *exc) noexcept
{
	caught = (unsigned long)exc;
	return exc_obj;
}

__always_inline void __cxa_end_catch(void) noexcept
{
}
}

/*
 * As bpf_helper_defs.h declares them: the helpers that call a sync callback
 * without noexcept, see is_sync_callback_calling_function() in the verifier.
 */
static long (* const bpf_loop)(unsigned int nr_loops, void *callback_fn, void *callback_ctx,
			       unsigned long flags) =
	(long (*)(unsigned int, void *, void *, unsigned long)) 181;
static long (* const bpf_for_each_map_elem)(void *map, void *callback_fn, void *callback_ctx,
					    unsigned long flags) =
	(long (*)(void *, void *, void *, unsigned long)) 164;

/* Named: a variable of an unnamed type has internal linkage in C++ */
struct array_map {
	__uint(type, 2);	/* BPF_MAP_TYPE_ARRAY */
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, long);
} array SEC(".maps");

/* One decimal digit per destructor, in the order they ran */
volatile int dtors SEC(".data.dtors");

/* How often the callback ran. The prog resets it. */
int runs;

/* The callback throws on the run with this index */
int throw_at;

/*
 * 0 at run time, which the verifier can't see: bpf_loop() isn't inlined with it
 * and the helper itself calls the callback.
 */
volatile unsigned long loop_flags;

/* The verifier insists that it's undone on every path out of the callback */
struct rcu_guard {
	__always_inline rcu_guard()
	{
		bpf_rcu_read_lock();
	}
	__always_inline ~rcu_guard()
	{
		bpf_rcu_read_unlock();
		dtors = dtors * 10 + 1;
	}
};

/* The callback of bpf_loop(): the guard's destructor runs on the way out */
static long loop_cb(unsigned long i, void *ctx)
{
	rcu_guard guard;

	runs++;
	if (i == (unsigned long)throw_at)
		throw 1;
	return 0;
}

/* The callback of bpf_for_each_map_elem(): the key is the index */
static long each_cb(void *map, int *key, long *value, void *ctx)
{
	runs++;
	if (*key == throw_at)
		throw 1;
	return 0;
}

static __always_inline int loop(struct __sk_buff *skb, unsigned long flags)
{
	runs = 0;
	dtors = 0;
	throw_at = 2;
	try {
		return bpf_loop(skb->len - ETH_HLEN, (void *)loop_cb, nullptr, flags);
	} catch (...) {
		return caught == EXCEPTION ? 40 + runs : 99;
	}
}

/* The verifier inlines the loop: the pad is the one of a subprog call */
extern "C" SEC("tc") int loop_catches(struct __sk_buff *skb)
{
	return loop(skb, 0);
}

/* The helper calls the callback, and has a pad of its own */
extern "C" SEC("tc") int loop_helper_catches(struct __sk_buff *skb)
{
	return loop(skb, loop_flags);
}

/* A lambda converted to a function pointer is a static subprog like any other */
static inline int loop_with_lambda(unsigned int nr_loops)
{
	long (*cb)(unsigned long, void *) = [](unsigned long i, void *ctx) -> long {
		runs++;
		if (i == (unsigned long)throw_at)
			throw 1;
		return 0;
	};

	return bpf_loop(nr_loops, (void *)cb, nullptr, 0);
}

extern "C" SEC("tc") int loop_lambda_catches(struct __sk_buff *skb)
{
	runs = 0;
	dtors = 0;
	throw_at = 2;
	try {
		return loop_with_lambda(skb->len - ETH_HLEN);
	} catch (...) {
		return caught == EXCEPTION ? 40 + runs : 99;
	}
}

/* Throws on the element with the key it is given, if there is one */
extern "C" SEC("tc") int for_each_catches(struct __sk_buff *skb)
{
	runs = 0;
	dtors = 0;
	throw_at = skb->len - ETH_HLEN;
	try {
		return bpf_for_each_map_elem(&array, (void *)each_cb, nullptr, 0);
	} catch (...) {
		return caught == EXCEPTION ? 40 + runs : 99;
	}
}

#endif

char _license[] SEC("license") = "GPL";
