// SPDX-License-Identifier: GPL-2.0
/*
 * Resuming BPF coroutine frames from the kernel; see include/linux/bpf_coro.h.
 */
#include <linux/bpf.h>
#include <linux/bpf_coro.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/workqueue.h>

/*
 * Call the frame's resume function with the frame as its argument. The
 * function is a subprogram of a program this caller holds a reference to;
 * it runs like any program invocation, under RCU with migration disabled,
 * and from BH context here, which is what the verifier assumed for the
 * program type's kfuncs.
 */
void bpf_coro_run(void *frame)
{
	bpf_callback_t resume = READ_ONCE(*(bpf_callback_t *)frame);

	rcu_read_lock();
	migrate_disable();
	resume((u64)(long)frame, 0, 0, 0, 0);
	migrate_enable();
	rcu_read_unlock();
}

static void bpf_coro_cont_work(struct work_struct *work)
{
	struct bpf_coro_cont *cont = container_of(work, struct bpf_coro_cont, work);
	struct bpf_prog *prog = cont->prog;

	pr_debug("bpf_coro: resuming frame %px fn %px cpu %d softirq %d\n", cont->frame,
			    *(void **)cont->frame, smp_processor_id(), !!in_serving_softirq());
	bpf_coro_run(cont->frame);
	pr_debug("bpf_coro: resumed frame %px\n", cont->frame);
	if (cont->fini)
		cont->fini(cont);
	bpf_prog_put(prog);
}

void bpf_coro_cont_init(struct bpf_coro_cont *cont, void *frame, struct bpf_prog_aux *aux,
			void (*fini)(struct bpf_coro_cont *cont))
{
	/* The program is running, so its count is positive. */
	bpf_prog_inc(aux->prog);
	cont->prog = aux->prog;
	cont->frame = frame;
	cont->fini = fini;
	INIT_WORK(&cont->work, bpf_coro_cont_work);
}

/* Resume from BH context on this CPU; callable from any context. */
void bpf_coro_cont_resume(struct bpf_coro_cont *cont)
{
	WARN_ON_ONCE(!queue_work(system_bh_highpri_wq, &cont->work));
}

/* Resume right here, from a context that already allows running programs. */
void bpf_coro_cont_resume_now(struct bpf_coro_cont *cont)
{
	bpf_coro_cont_work(&cont->work);
}
