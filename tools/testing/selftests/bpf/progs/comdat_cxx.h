/* SPDX-License-Identifier: GPL-2.0 */
/*
 * What C++ defines in every translation unit that uses it, each time in a
 * COMDAT group of its own: inline functions that are not inlined, inline
 * variables and template instances. Like unwind_cxx.cpp, this doesn't use
 * vmlinux.h and bpf_helpers.h, which are not C++.
 */
#ifndef __COMDAT_CXX_H
#define __COMDAT_CXX_H

#define SEC(name) __attribute__((section(name), used))
#define __noinline __attribute__((noinline))
#define __hidden __attribute__((visibility("hidden")))

struct __sk_buff {
	unsigned int len;
};

/* .bss.calls, .data.base and .rodata.primes */
inline int calls;
inline int base = 100;
inline constexpr int primes[] = { 2, 3, 5, 7, 11, 13, 17, 19 };

struct pair {
	int a;
	int b;
};

/*
 * Hidden, so it is verified as a static function: a global one may get a NULL
 * pointer.
 */
inline __noinline __hidden int sum(const pair *p)
{
	return p->a + p->b;
}

inline __noinline int prime_sum(unsigned int i)
{
	pair p = { primes[i % 8], base };

	calls++;
	return sum(&p);
}

/* .text and .bss for each of counter<int> and counter<long> */
template <typename T>
struct counter {
	static inline T count;

	static __noinline T bump(T by)
	{
		count += by;
		return count;
	}
};

/*
 * Data in a section with an explicit name, which each group has one of, is
 * in the map of the name like that of comdat_cxx.cpp. A name that is the one
 * the compiler gives, .data.same for same, can't be told apart from it and
 * joins .data.
 */
inline int tag_a SEC(".data.tags") = 1;
inline int tag_b SEC(".data.tags") = 2;
inline int same SEC(".data.same") = 6;

/*
 * The vtables of classes whose virtual methods are inline, in .rodata.<name>
 * of a group, and the methods, which are hidden so that the vtables can point
 * to them, as callx calls static functions only
 */
struct __hidden shape {
	virtual int area(int x) const noexcept
	{
		return x * x;
	}
};

struct __hidden twice : shape {
	int area(int x) const noexcept override
	{
		return 2 * x * x;
	}
};

#endif
