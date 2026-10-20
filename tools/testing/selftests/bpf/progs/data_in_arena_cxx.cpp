// SPDX-License-Identifier: GPL-2.0
/*
 * C++ classes with virtual functions in an object that keeps its data in
 * arena. The vtables, the type_info objects and their names are read-only
 * data with pointers, which is in arena too. A program reaches them through
 * numbers: it loads the vptr of an object from arena, a function from the
 * vtable, and calls it with callx of a number. libbpf puts the JITed address
 * of the function there, of the first program that has it.
 *
 * vmlinux.h and bpf_helpers.h are not C++.
 */
#define SEC(name) __attribute__((section(name), used))
#define __ksym __attribute__((section(".ksyms")))
#define __noinline __attribute__((noinline))

/* global data of the object is in arena */
char data_in_arena SEC(".arena.data");

/*
 * The vtables of the type_info classes, which the type_info objects of the
 * classes below point to. The C++ runtime defines them, and nothing calls
 * through them here.
 */
extern "C" {
extern const unsigned long class_type_info_vtable[4]
	__asm__("_ZTVN10__cxxabiv117__class_type_infoE");
extern const unsigned long si_class_type_info_vtable[4]
	__asm__("_ZTVN10__cxxabiv120__si_class_type_infoE");
const unsigned long class_type_info_vtable[4] = {};
const unsigned long si_class_type_info_vtable[4] = {};
}

/* An object in arena, constructed by a program */
inline void *operator new(unsigned long, void *p) noexcept
{
	return p;
}

/*
 * What the deleting destructors in the vtables call. Nothing is deleted here.
 * -fvisibility-global-new-delete=force-hidden makes them static to the
 * verifier.
 */
void operator delete(void *) noexcept
{
}

void operator delete(void *, unsigned long) noexcept
{
}

/* One decimal digit per destructor, in the order they ran */
long dtors;

/* static functions to the verifier, which callx of a number may call */
namespace {

struct Shape {
	long id;

	constexpr Shape(long id) : id(id) {}
	virtual long area() const
	{
		return 0;
	}
	virtual long sides() const
	{
		return id;
	}
	/* a string literal, which is in arena with the rest of the data */
	virtual const char *name() const
	{
		return "shape";
	}
};

struct Rect : Shape {
	long w, h;

	constexpr Rect(long w, long h) : Shape(1), w(w), h(h) {}
	long area() const override
	{
		return w * h;
	}
	long sides() const override
	{
		return 4;
	}
	const char *name() const override
	{
		return "rect";
	}
};

struct Square : Rect {
	constexpr Square(long s) : Rect(s, s) {}
	long area() const override
	{
		return w * w + 1000;
	}
	const char *name() const override
	{
		return "square";
	}
};

/*
 * A virtual destructor, which the destructor of the derived class calls
 * directly, and a function that a qualified call calls directly. Both are in
 * the vtable of the base class too, and called through it. Not inlined, so
 * that the calls stay. Only constructed by a program: a static object with a
 * destructor would need it registered to run at exit.
 */
struct Node {
	long v;

	constexpr Node(long v) : v(v) {}
	__noinline virtual ~Node()
	{
		dtors = dtors * 10 + 1;
	}
	__noinline virtual long f() const
	{
		return v;
	}
};

struct Leaf : Node {
	constexpr Leaf(long v) : Node(v) {}
	~Leaf() override
	{
		dtors = dtors * 10 + 2;
	}
	long f() const override
	{
		return Node::f() * 10;
	}
};

}

/* constant initialized: libbpf puts the addresses of the vtables in the vptrs */
constinit Rect rect(3, 4);
constinit Square square(5);
constinit Shape shape(7);

/* constructed by a program, which stores the address of the vtable */
alignas(Square) char square2_buf[sizeof(Square)];

/* the program can't tell what they point to */
Shape *shapes[4] = { &rect, &square, &shape };

struct ctx {
	unsigned long vptr;		/* of square2, which the program stored */
	unsigned long static_vptr;	/* of square, which libbpf put there */
	long area;
	long sides;
};

static __noinline long sum_area(void)
{
	long sum = 0;

	for (int i = 0; i < 4; i++)
		if (shapes[i])
			sum += shapes[i]->area();
	return sum;
}

extern "C" SEC("syscall") int virtual_calls(struct ctx *ctx)
{
	Shape *s = new (square2_buf) Square(6);

	shapes[3] = s;
	ctx->vptr = *(unsigned long *)s;
	ctx->static_vptr = *(unsigned long *)&square;
	ctx->area = sum_area();
	ctx->sides = shapes[0]->sides() * 100 + shapes[1]->sides() * 10 + shapes[2]->sides();
	return 0;
}

alignas(Leaf) char node_buf[sizeof(Leaf)];
alignas(Leaf) char leaf_buf[sizeof(Leaf)];
Node *nodes[2];

/* the compiler doesn't know what the vptr of the object is */
static Node *opaque(Node *n)
{
	asm volatile("" : "+r"(n) : : "memory");
	return n;
}

extern "C" SEC("syscall") int destructors(struct ctx *ctx)
{
	Node *n;
	int i;

	nodes[0] = new (node_buf) Node(3);
	nodes[1] = new (leaf_buf) Leaf(4);
	ctx->vptr = *(unsigned long *)nodes[0];
	ctx->static_vptr = *(unsigned long *)nodes[1];

	n = opaque(nodes[1]);
	ctx->area = opaque(nodes[0])->f() + n->f() + n->Node::f() * 100;

	dtors = 0;
	for (i = 0; i < 2; i++)
		opaque(nodes[i])->~Node();
	ctx->sides = dtors;
	return 0;
}

#ifdef __BPF_FEATURE_UNWIND
/*
 * What is left of the C++ runtime for exceptions. __cxa_throw keeps the
 * address of the destructor of the thrown object in arena, and the end of
 * the handler calls it from there, through a number, as the runtime of
 * std::bpf does.
 */
extern "C" {
int _Unwind_RaiseException(void *exc);

alignas(8) char exc_obj[16];
/* a destructor doesn't throw */
void (*exc_dtor)(void *) noexcept;

inline __attribute__((always_inline)) void *__cxa_allocate_exception(unsigned long size) noexcept
{
	return exc_obj;
}

inline __attribute__((always_inline)) void __cxa_throw(void *exc, void *tinfo,
						       void (*dtor)(void *))
{
	exc_dtor = (void (*)(void *) noexcept)dtor;
	_Unwind_RaiseException(exc);
}

inline __attribute__((always_inline)) void *__cxa_begin_catch(void *exc) noexcept
{
	return exc;
}

inline __attribute__((always_inline)) void __cxa_end_catch(void) noexcept
{
	exc_dtor(exc_obj);
}

[[noreturn]] void bpf_throw(unsigned long cookie) noexcept __ksym;
}

namespace std {

/*
 * clang keeps the unwind edge of a call through a pointer whatever the
 * pointee's exception specification says, since the kernel checks the call
 * against every function the pointer could hold. So __cxa_end_catch(), which
 * is noexcept and calls the destructor through exc_dtor, has a terminate
 * handler, and the handler calls std::terminate(), which the object has to
 * define to link. Nothing reaches it: the destructor does not throw. It ends
 * the program as the runtime of std::bpf does.
 */
[[noreturn]] void terminate() noexcept
{
	bpf_throw(0);
}

}

namespace {

/*
 * Its destructor runs on an object on the stack, called directly, and on the
 * thrown object, through the address that the throw takes
 */
struct Error {
	long code;

	constexpr Error(long code) : code(code) {}
	__noinline ~Error()
	{
		dtors = dtors * 10 + code;
	}
};

}

static __noinline long might_throw(long v)
{
	Error e(1);

	asm volatile("" : : "r"(&e) : "memory");
	if (v > 0)
		throw Error(2);
	return v;
}

extern "C" SEC("syscall") int throws(struct ctx *ctx)
{
	long v = 1;

	asm volatile("" : "+r"(v));
	dtors = 0;
	try {
		ctx->area = might_throw(v);
	} catch (...) {
		ctx->area = -1;
	}
	ctx->vptr = (unsigned long)exc_dtor;
	ctx->sides = dtors;
	return 0;
}
#endif

static __noinline int str_is(const char *s, const char *expect)
{
	int i;

	for (i = 0; i < 16; i++) {
		if (s[i] != expect[i])
			return 0;
		if (!s[i])
			return 1;
	}
	return 0;
}

/*
 * The string literals that the virtual functions return are in arena, where
 * the program reads them through what the calls return, like the literals it
 * compares them with.
 */
extern "C" SEC("syscall") int virtual_names(struct ctx *ctx)
{
	if (!str_is(shapes[0]->name(), "rect"))
		return 1;
	if (!str_is(shapes[1]->name(), "square"))
		return 2;
	if (!str_is(shapes[2]->name(), "shape"))
		return 3;
	return 0;
}

/* The second program calls the functions of the first one */
extern "C" SEC("syscall") int virtual_calls2(struct ctx *ctx)
{
	ctx->area = sum_area();
	ctx->sides = shapes[3] ? shapes[3]->sides() : -1;
	return 0;
}

/*
 * The type_info of a class is at vtable[-1], with its name after its own
 * vptr, and that of a single base after the name: a chain of pointers in
 * read-only data that the program follows through numbers.
 */
struct type_info {
	const void *vptr;
	const char *name;
	const type_info *base;
};

/* in arena, unlike string literals */
char square_name[] = "N12_GLOBAL__N_16SquareE";
char rect_name[] = "N12_GLOBAL__N_14RectE";
char shape_name[] = "N12_GLOBAL__N_15ShapeE";

static __noinline int name_is(const type_info *ti, const char *name)
{
	int i;

	for (i = 0; i < 32; i++) {
		if (ti->name[i] != name[i])
			return 0;
		if (!name[i])
			return 1;
	}
	return 0;
}

extern "C" SEC("syscall") int type_names(void *ctx)
{
	const unsigned long *vtable = *(const unsigned long **)&square;
	const type_info *ti = (const type_info *)vtable[-1];

	/* offset to top */
	if (vtable[-2])
		return 1;
	if (!name_is(ti, square_name))
		return 2;
	if (ti->vptr != &si_class_type_info_vtable[2])
		return 3;
	if (!name_is(ti->base, rect_name))
		return 4;
	if (!name_is(ti->base->base, shape_name))
		return 5;
	if (ti->base->base->vptr != &class_type_info_vtable[2])
		return 6;
	return 0;
}

char _license[] SEC("license") = "GPL";
