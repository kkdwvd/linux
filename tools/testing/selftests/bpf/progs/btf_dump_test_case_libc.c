// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * BTF-to-C dumper test validating that the kernel's types named like the C
 * library's, the names of <time.h>, <signal.h> and <sched.h>, are emitted
 * for C++ under the ___kernel suffix, and every declaration that names one
 * once per language, with the C output unchanged.
 */
/* ----- START-EXPECTED-OUTPUT ----- */
typedef int __kernel_timer_t;

#ifdef __cplusplus
typedef __kernel_timer_t timer_t___kernel;
#else
typedef __kernel_timer_t timer_t;
#endif

#ifdef __cplusplus
typedef struct {
	unsigned long sig[1];
} sigset_t___kernel;
#else
typedef struct {
	unsigned long sig[1];
} sigset_t;
#endif

struct sigaltstack {
	void *ss_sp;
	int ss_flags;
	unsigned long ss_size;
};

#ifdef __cplusplus
typedef struct sigaltstack stack_t___kernel;
#else
typedef struct sigaltstack stack_t;
#endif

struct siginfo;

#ifdef __cplusplus
typedef struct siginfo siginfo_t___kernel;
#else
typedef struct siginfo siginfo_t;
#endif

#ifdef __cplusplus
struct itimerspec___kernel;
#else
struct itimerspec;
#endif

#ifdef __cplusplus
struct tm___kernel;
#else
struct tm;
#endif

#ifdef __cplusplus
struct sigevent___kernel;
#else
struct sigevent;
#endif

#ifdef __cplusplus
struct sched_param___kernel;
#else
struct sched_param;
#endif

struct k_itimer {
#ifdef __cplusplus
	struct tm___kernel *tm;
#else
	struct tm *tm;
#endif
#ifdef __cplusplus
	timer_t___kernel it_id;
#else
	timer_t it_id;
#endif
#ifdef __cplusplus
	timer_t___kernel it_flags: 4;
#else
	timer_t it_flags: 4;
#endif
#ifdef __cplusplus
	struct sigevent___kernel *notify;
#else
	struct sigevent *notify;
#endif
#ifdef __cplusplus
	const sigset_t___kernel *masks[2];
#else
	const sigset_t *masks[2];
#endif
#ifdef __cplusplus
	int (*setparam)(struct sched_param___kernel *);
#else
	int (*setparam)(struct sched_param *);
#endif
#ifdef __cplusplus
	stack_t___kernel stack __attribute__((btf_decl_tag("tag")));
#else
	stack_t stack __attribute__((btf_decl_tag("tag")));
#endif
#ifdef __cplusplus
	siginfo_t___kernel *info;
#else
	siginfo_t *info;
#endif
#ifdef __cplusplus
	struct itimerspec___kernel *spec;
#else
	struct itimerspec *spec;
#endif
};

#ifdef __cplusplus
struct tm___kernel {
#else
struct tm {
#endif
	int tm_sec;
	long tm_year;
#ifdef __cplusplus
	struct tm___kernel *tm;
#else
	struct tm *tm;
#endif
	struct k_itimer *owner;
};

#ifdef __cplusplus
struct sigaction___kernel {
#else
struct sigaction {
#endif
	void (*sa_handler)(int);
	unsigned long sa_flags;
#ifdef __cplusplus
	sigset_t___kernel sa_mask;
#else
	sigset_t sa_mask;
#endif
};

#ifdef __cplusplus
union sigval___kernel {
#else
union sigval {
#endif
	int sival_int;
	void *sival_ptr;
};

#ifdef __cplusplus
typedef union sigval___kernel sigval_t;
#else
typedef union sigval sigval_t;
#endif

#ifdef __cplusplus
struct sigevent___kernel {
#else
struct sigevent {
#endif
	sigval_t sigev_value;
	int sigev_signo;
	union {
		int _tid;
		struct {
			void (*_function)(sigval_t);
		} _sigev_thread;
	} _sigev_un;
};

#ifdef __cplusplus
struct sched_param___kernel {
#else
struct sched_param {
#endif
	int sched_priority;
};

/*------ END-EXPECTED-OUTPUT ------ */

int f(struct {
	struct k_itimer _1;
	struct tm _2;
	struct sigaction _3;
	struct sigevent _4;
} *_)
{
	return 0;
}
