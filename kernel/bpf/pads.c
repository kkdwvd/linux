// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landing pads that the verifier emits.
 *
 * A SITE is an insn at which the verifier lets a frame unwind although the program has no code
 * for that:
 *   - may_goto that the verifier adds
 *   - may_goto that the program has, in a subprog that can unwind: when its time is up the program
 *     ends, it does not go where the insn says, see check_may_goto_site() in verifier.c
 *   - the check at the entry of a recursive subprog
 *   - a call of a subprog that comes back with unwind_exit and has no unwind_goto after it
 *   - a call of a helper whose callback comes back that way
 *   - a load, a store or an atomic insn in arena, when it faults, in a subprog that can unwind
 *   - a call of bpf_throw(). No call is made: the insn becomes a jump to the pad.
 * The resources that the frame acquired since its entry have to be released on the way out. The
 * code that does it is a LANDING PAD: calls of the functions that the program itself would call,
 * then the value in r0 and kexit, or exit in a frame that the kernel called.
 *
 *	bpf_rcu_read_lock();				   call bpf_rcu_read_lock
 *	do {						1: ...
 *		p = bpf_map_lookup_elem(&map, &key);	   call bpf_map_lookup_elem
 *	} while (!p);					   may_goto pad
 *	v = *p;						   if r0 == 0 goto 1b
 *	bpf_rcu_read_unlock();				   ...
 *	return v;					   exit
 *						      pad: call bpf_rcu_read_unlock
 *							   r0 = 0
 *							   exit
 *
 * The work is split in layers:
 *
 *   who         A frame releases what it acquired since its entry, and what a subprog that it
 *               called returned with. A landing pad that a caller has in the program is code
 *               like any other.
 *   plan        bpf_pad_visit(). One per site: what the pad has to release. A state that leaves
 *               its frame at a site VISITS the plan. The plan has to serve all states that visit
 *               it. If it cannot that is a CONFLICT.
 *   main pass   unwind_frame() in verifier.c. After the visit what the frame acquired is
 *               dropped from the state, by the functions that a release call of the program ends
 *               up in, and what is left of the state goes to the caller.
 *   settle      bpf_pads_settle(), after a pass that counts. A conflict is an error of the
 *               pass, like any other: of the state that visits, or of the site. Unless the
 *               frame cannot unwind and the site has another way out.
 *   code        bpf_pad_insns(). The insns of the pad of a plan, and their aux data.
 *   emission    bpf_insert_sites() in fixups.c, after the main pass.
 *
 * The main pass does not see the insns of a pad. They are trusted, like all that the verifier
 * emits. So a plan has to be right for every state that gets to its site. All that the code of a pad
 * fixes is compared on each visit: the calls and their constant arguments, the places, the order,
 * the number of sections. A call that the type of the program cannot make is a conflict, see
 * get_release(). The pad of a callee releases pointers under the locks of its callers. A call that
 * the program could not make there is a conflict too, except the free of an object that has only
 * memory to give back, see can_release_under_lock(). So is a release that may sleep where the pad
 * cannot get to a sleepable context, see bpf_pad_visit().
 *
 * A state that is pruned or joined on the way does not get to the site. The state that it was found
 * within, or was joined with, visits for both. The pad is right for it too, because a plan is made
 * of what the main pass compares before one state stands for another. Two states meet only with
 * the same join key, see bpf_same_join_key() and same_refs(): the numbers of sections, refs[] entry
 * by entry, what each frame had at its entry, the objects in the stack that are held. Then
 * bpf_state_subsumes() compares what is in the registers and stack slots that are live at the
 * site. Where two states differ there bpf_states_join() does not refuse: the state that goes on has
 * nothing that can be read at that place, so it is no place of a plan and not 0 either. What is
 * not live is gone before the states meet, see bpf_clean_verifier_state().
 *
 * Plans live as long as a pass. A pass that is kept keeps its plans, see bpf_pads_move(). What
 * one pass gives to the next one grows to the safe side: did_unwind of a global subprog,
 * fault_full, and which subprogs are stuck. bail_unwinds that is cleared late goes to the second
 * run of the same pass only, see check_funcs().
 *
 * The frames of a program are unwound one by one. The pad of a frame ends in kexit, which goes to
 * kgoto after the call in the caller, and that goes to the pad of the caller:
 *
 *	static int wait(void)				wait:
 *	{						1: ...
 *		do {					   may_goto pad
 *			...				   if r0 == 0 goto 1b
 *		} while (!p);				   ...
 *		return *p;				   exit
 *	}					      pad: r0 = 0
 *							   r2 = 0
 *							   kexit
 *	bpf_rcu_read_lock();				prog:
 *	v = wait();					   call bpf_rcu_read_lock
 *	bpf_rcu_read_unlock();				   call wait
 *	return v;					   kgoto pad
 *							   ...
 *							   exit
 *						      pad: call bpf_rcu_read_unlock
 *							   r0 = 0
 *							   exit
 *
 * With bpf_loop(n, wait, ...) in place of wait() it is the same code. The helper is a frame of the
 * kernel between the two. It has a pad of its own, see bpf_call_cb(): kexit of the callback goes
 * there, the helper releases what it holds itself and goes to kgoto after its call.
 *
 * kgoto and kexit are insns that only the verifier emits. A program unwinds too, in C++ or Rust,
 * with insns of its own: unwind_exit leaves a frame and goes to unwind_goto after the call, where
 * the program has a landing pad, which is code like any other. It can end the unwinding and go on.
 * WHAT THE KERNEL UNWINDS MUST NOT BE CAUGHT: the program was stopped because it ran out of time
 * or of stack, faulted, or called bpf_throw(). kexit does not go to unwind_goto, a state that the
 * kernel unwound is marked for it, BPF_KUNWOUND, and at a call that has unwind_goto of the program
 * such a state goes to a pad of the verifier all the same, see check_unwound_arrival():
 *
 *	try {						   call wait
 *		v = wait();				   unwind_goto catch	unwind_exit
 *	} catch (...) {					   kgoto pad		kexit
 *		v = 0;					   ...
 *	}					    catch: ...
 *							   exit
 *						      pad: r0 = 0
 *							   exit
 *
 * A landing pad that can go on with the program does not run on the way: the pad of the verifier
 * releases what the frame holds of the kernel.
 *
 * A landing pad that ONLY RESUMES does run: it cannot catch, and what it does is what the program
 * wants done when a frame is left. A destructor of C++ or drop glue of Rust unlocks a lock word in
 * arena, frees memory there. Which pads those are is asked of the control flow graph, before the
 * main pass, see bpf_find_kernel_pads(): from the pad no insn that returns to the caller can be
 * reached, and unwind_exit can. At such a call kgoto goes to an ENTRY in front of the pad of the
 * program, BPF_SITE_KENTRY, and unwind_exit that the pad ends in becomes a jump to code that leaves
 * the frame as a pad of the verifier does, BPF_SITE_REMAINDER:
 *
 *	{						   ...
 *		Guard g;				   call wait
 *							   unwind_goto stub
 *		v = wait();				   kgoto entry
 *	}						   ...
 *						      pad: r6 = r0
 *							   call ~Guard
 *							   r0 = r6
 *							   gotol rest
 *							   ...
 *						     stub: *(u64 *)(r10 - 8) = 0
 *							   gotol pad
 *						    entry: *(u64 *)(r10 - 8) = 1
 *							   r0 = 0
 *							   gotol pad
 *						     rest: ax = *(u64 *)(r10 - 8)
 *							   if ax == 0 goto 1f
 *							   r0 = V
 *							   r2 = 0
 *							   kexit
 *							1: unwind_exit
 *
 * K, the word at r10 - 8 here, is a hidden word of the frame that says whether the kernel unwinds
 * it: the entry of a pad sets it. The main pass has the same in the frame of a state: 'forced',
 * see enter_kernel_pad() in verifier.c. From there the pad is verified once more, with what the
 * frame holds when the kernel unwinds the callee and with 0 in R0. An error on that way is an
 * error of the program. A forced frame has two ways out, and both leave with kexit and the value
 * of the kernel:
 *   - unwind_exit of the program. The program has released what it wanted to, and the verifier
 *     releases what the frame still holds. That needs a plan like any site, with places that are
 *     good at that insn. No register is read there any more, so the entry of the pad copies the
 *     pointers that the frame holds into SAVE WORDS, hidden words like K, see visit_saves(): each
 *     is a place wherever the frame is left. What else the frame holds, a lock, irq flags, an
 *     object in the stack, has a place of its own there or none.
 *   - A site of the frame, in the pad: a destructor loops until its time is up, faults in arena,
 *     calls what is unwound in turn. The states that leave a forced frame have a plan of their own
 *     there, BPF_SITE_FORCED, and its pad loads the value that the frame has, not the one of the
 *     site: the first start of an unwinding decides what the program returns. Where a frame gets
 *     to a site in both ways a test of K picks the pad.
 * No plan for one of them is an error of the program, as it is at any site: THE KERNEL ENTERS A
 * LANDING PAD THAT ONLY RESUMES, OR THE PROGRAM IS REJECTED, see bpf_pads_settle(). No pad is
 * passed by for what the verifier cannot arrange around it. The same if the stack has no room
 * for the hidden words.
 * And WHAT THE KERNEL UNWINDS CANNOT BE CAUGHT still holds: a forced frame never returns to its
 * caller, and no state of the normal path is joined with one of a forced frame.
 *
 * NOTHING ON THE NORMAL PATH WRITES K. A function does not clear the word where it begins: that
 * would be a store per call, paid by a path that never unwinds. A frame finds there what an
 * earlier frame at that depth left, 1 as well as 0, and on a private stack what the last
 * invocation left. The word is written on the two edges that take a frame from the normal path
 * into a landing pad, see find_pad_code() for the kinds of code:
 *   - unwind_exit of a callee comes back to unwind_goto of the program: that goes to a STUB, which
 *     clears K and goes on to the pad, see collect_stubs() in fixups.c.
 *   - kexit of a callee comes back to kgoto: the entry sets K, without reading it first, see
 *     bpf_pad_kentry_insns().
 * All that reads K stands in pad code: an entry behind a call in pad code, which tests K, a unit
 * of two pads behind a test, and what stands in for unwind_exit. Pad code and the normal path
 * share no insn, so a frame gets to a reader over one of the two edges, and from there on the word
 * is written. Both edges must write, and no other may: the code that reads K as 1 releases from
 * the save words, so on an edge that lacks its store a kfunc would release what the program chose
 * to leave in that word. And behind a call in pad code neither edge writes. A frame that the
 * kernel unwinds gets there: a stub would clear its K and let it leave as one that the program
 * unwinds, and an entry without its test would replace the value and the handles that the first
 * entry kept. There unwind_goto of the program keeps its target and the entry tests.
 * Where the code is emitted, collect_pads() and insert_unwind_gotos() in fixups.c check that
 * every reader stands in pad code, and that every unwind_goto of the program goes to a stub or
 * follows a call in pad code. A program that fails there does not load.
 * A MIXED function, in which an insn is pad code and on the normal path as well, has neither
 * store: its entry clears K, see bpf_pad_entry_insns(), no unwind_goto goes to a stub, and every
 * entry tests.
 *
 * The other way around a frame that has no unwind_goto at a call can be on the way of unwind_exit
 * of the program, BPF_SITE_CALL. The verifier gives it unwind_goto and a pad, as upstream does not:
 * that pad ends in unwind_exit and passes on what the callee left in R0, see
 * bpf_pad_passes_on(), to a landing pad of the program above. Not in a global subprog: its callers
 * get a number, bpf_unwound_retval(), whatever the callee left and whether the program has
 * bpf_throw() or not. So a call can have a pad of each kind, and a subprog can be left in both ways.
 *
 * A section has no handle: the plan has their number. A frame can also be in fewer sections than
 * it was called in: a function that is called under a lock, drops it and takes it again, where the
 * lock is a section with preemption disabled and a word in arena.
 *
 *	static void *grow(struct pool *pool)		grow:
 *	{						   call bpf_preempt_enable
 *		unlock(pool);				   ...
 *		p = bpf_arena_alloc_pages(...);		   r1 = *(u64 *)(r0 + 0)
 *		v = *p;					   unwind_goto pad
 *		lock(pool);				   call bpf_preempt_disable
 *		return p;				   exit
 *	}					      pad: call bpf_preempt_disable
 *							   r0 = 0
 *							   r2 = 0
 *							   kexit
 *
 * The pad ENTERS what the frame has left: the frame is unwound with the sections of its call,
 * wherever it is left, and the pad of the caller leaves what the caller entered. A section can
 * always be entered again, and nothing is read under it: only the count has to be right when the
 * program ends. Without that the caller would be in one section more or less by the site at which
 * the callee was left, and no store in the caller can follow what the callee does.
 * A frame that has entered such a section again can hold what only a sleepable context may release.
 * Its pad leaves the sections of the callers once more for that, see bpf_pad_visit().
 * What a caller has that only a section protects is not kept by the count: where the pad releases
 * the pointers it can be in no section at all, and the main pass looks at the state as it is there,
 * see release_frame_resources() in verifier.c.
 * Every other resource that the frame
 * acquired is an ENTRY of the plan. Its release takes a handle: the address of the lock, of
 * the irq flags. A PLACE is where the pad finds it: a register or a stack slot of the program that
 * is live at the site, a constant address. What is there may differ from the handle by a constant,
 * the delta: a pointer to a map value will do for the lock in it, R10 for irq flags in the stack.
 *
 *	v = bpf_map_lookup_elem(&map, &key);		   r6 = r0
 *	...						   ...
 *	bpf_spin_lock(&v->lock);			   call bpf_spin_lock
 *	do {						1: r1 = *(u64 *)(r6 + 8)
 *		i = v->idx;				   may_goto pad
 *	} while (i >= 4);				   if r1 > 3 goto 1b
 *	...						   ...
 *						      pad: r1 = r6
 *							   call bpf_spin_unlock
 *							   r0 = 0
 *							   exit
 *
 * A state may have the handle in several places, the CANDIDATES. Those that all visits which hold
 * the entry have in common stay, one of them is emitted. The calls of a pad clobber R0-R5: they are
 * places for the first argument of the first call only, see settle_ent().
 *
 * A pointer that a helper or a kfunc returned and that has to be released is its own handle. A copy
 * of it, a pointer to a node in the object, a socket that a helper has cast are places of one
 * entry. What releases it follows from its type, see ref_release(). An iterator
 * and a dynptr that has to be released are objects in the stack, like irq flags. If a caller has
 * the object, a pointer to it is a place.
 * The release and the place tell the entries of a plan apart, see visit_refs().
 *
 *	t = bpf_task_from_pid(pid);			   call bpf_task_from_pid
 *	...						   r6 = r0
 *	v = wait();					   ...
 *	bpf_task_release(t);				   call wait
 *							   unwind_goto pad
 *							   ...
 *						      pad: r1 = r6
 *							   call bpf_task_release
 *							   r0 = 0
 *							   exit
 *
 * WHETHER an entry is held when the pad runs, see settle_ent():
 *   - All visits hold it: the program counter tells.
 *   - A candidate is 0 on all visits that don't: the pad tests it. That is how the program itself
 *     tells, a pointer that is NULL as long as there is nothing to release.
 *   - Otherwise the function gets hidden slots, see below, or there is a conflict.
 * A pointer that the program has not compared with NULL yet when it gets to the site is tested too.
 *
 *	t = NULL;					   r6 = 0
 *	if (pid)					   if r1 == 0 goto 1f
 *		t = bpf_task_from_pid(pid);		   call bpf_task_from_pid
 *	v = wait();					   r6 = r0
 *	if (t)						1: call wait
 *		bpf_task_release(t);			   unwind_goto pad
 *							   ...
 *						      pad: r1 = r6
 *							   if r1 == 0 goto 2f
 *							   call bpf_task_release
 *							2: r0 = 0
 *							   exit
 *
 * A pad has one order, see enum pad_turn, among equals that of refs[], the youngest first. Locks
 * and irq flags have to be released that way, and a dynptr ahead of the pointer that it was made
 * from. States that acquired them in different orders can be a conflict.
 *
 * An ACCESS TO ARENA has unwind_goto after it like a call. It is no code: the handler of the fault
 * looks it up. The pad gets the registers and the stack as they were before the access.
 *
 *	t = bpf_task_from_pid(pid);			   r6 = r0
 *	...						   ...
 *	v = node->val;					   r1 = *(u64 *)(r7 + 8)
 *	bpf_task_release(t);				   unwind_goto pad
 *							   ...
 *						      pad: r1 = r6
 *							   call bpf_task_release
 *							   r0 = 0
 *							   exit
 *
 * A conflict rejects the program here as at any other site, and so does one at a call that has
 * such accesses below it. Without unwind_goto the handler skips the access, a load reads 0: that
 * is what an access does in a subprog that cannot unwind, and may_goto of the program jumps where
 * the program says there. What such a frame calls does the same, see stuck_frame_calls() in
 * verifier.c, also where another frame calls it: an insn has one answer.
 * At most accesses the frame holds nothing. They have no unwind_goto either: a bit in the entry
 * that an access has in the exception table sends the handler to one pad per function, 'r0 = V'
 * and the exit, see append_pads() in fixups.c.
 *
 * THE VALUE goes from the frame where the unwinding starts to the one that ends it, in R0, and the
 * program returns it. What the verifier unwinds has bpf_unwound_retval(). In a program without
 * bpf_throw() each pad loads it. With it a pad after a call passes on what kexit of the callee
 * left in R0. Its own calls clobber R0, so the value waits in a hidden word of the frame, below
 * the stack of the function. A pad without a call has none. R2 is 0 at kexit: nothing reads it
 * yet, and nothing of a callback gets through the frame of its helper but R0.
 * The pad of bpf_throw() starts with the argument, in R1. The pads of the main program hand the
 * value to the exception callback if there is one, and return what that returns.
 *
 *	t = bpf_task_from_pid(pid);			   ...
 *	if (bad)					   r1 = 7
 *		bpf_throw(7);				   gotol pad
 *	bpf_task_release(t);				   ...
 *						      pad: *(u64 *)(r10 - 8) = r1
 *							   r1 = r6
 *							   call bpf_task_release
 *							   r0 = *(u64 *)(r10 - 8)
 *							   unwind_exit
 *
 * HIDDEN SLOTS are the fallback for what neither the program counter nor a place tells. Here only
 * the program knows what 'own' means:
 *
 *	if (x)						   *(u64 *)(r10 - 8) = 0
 *		t = bpf_task_from_pid(a);		   *(u64 *)(r10 - 16) = 0
 *	else						   ...
 *		t = bpf_task_from_pid(b);		   call bpf_task_from_pid
 *	own = !!t;					   *(u64 *)(r10 - 8) = r0
 *	if (!t)						   ...
 *		t = bpf_get_current_task_btf();		   call bpf_task_from_pid
 *	v = wait(t);					   *(u64 *)(r10 - 16) = r0
 *	if (own)					   ...
 *		bpf_task_release(t);			   call wait
 *							   unwind_goto pad
 *							   ...
 *							   ax = *(u64 *)(r10 - 8)
 *							   if ax != r1 goto 1f
 *							   *(u64 *)(r10 - 8) = 0
 *							   goto 2f
 *							1: ax = *(u64 *)(r10 - 16)
 *							   if ax != r1 goto 2f
 *							   *(u64 *)(r10 - 16) = 0
 *							2: call bpf_task_release
 *							   ...
 *						      pad: r1 = *(u64 *)(r10 - 16)
 *							   if r1 == 0 goto 3f
 *							   call bpf_task_release
 *							3: r1 = *(u64 *)(r10 - 8)
 *							   if r1 == 0 goto 4f
 *							   call bpf_task_release
 *							4: r0 = 0
 *							   exit
 *
 * Each call that acquires has a slot of its own, below the stack of the function, where no access
 * of the program gets. The slots of a frame that are not 0 are, one to one, what the frame holds:
 *   entry       all slots are 0
 *   acquire     the slot takes what the release takes: R0, the address of a lock or of an object
 *   release     the slot that has the handle is cleared. It is found at run time.
 *   pad         'if (slot) release(slot)' over the slots, the same at all sites of the function
 * The stores follow from the insn and from what the main pass notes where it processes the insn,
 * see bpf_pad_note_acquire() and what follows it, never from the states at a site: a state that was
 * pruned or joined on the way does not get there, and which insn acquired a reference is not
 * compared when that is done. What no store can follow is noted as well, see 'no_slots'.
 * A function has slots for a GROUP of classes, see enum bpf_pad_group and settle_slots(). All its
 * pads release that group through the slots alone. All else stays as it is: a program that needs no
 * slot has no store and no byte of stack for them.
 * A pointer that no place has at a site is in its slot as well: the compiler keeps nothing over a
 * call of a function that never returns. An iterator and a dynptr are references like a pointer to
 * the main pass. One that no place has may stand for an object that the program has overwritten, so
 * that is for functions in which no insn acquires such an object, see acquires_stack_obj().
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/* The kfunc that releases a resource, by enum bpf_pad_class */
BTF_ID_LIST(pad_kfuncs)
BTF_ID(func, bpf_rcu_read_unlock)
BTF_ID(func, bpf_preempt_enable)
BTF_ID(func, bpf_local_irq_restore)
BTF_ID(func, bpf_res_spin_unlock)
BTF_ID(func, bpf_res_spin_unlock_irqrestore)

/* The kfunc that enters a section, by enum bpf_pad_class */
BTF_ID_LIST(pad_enter_kfuncs)
BTF_ID(func, bpf_rcu_read_lock)
BTF_ID(func, bpf_preempt_disable)

/* They free an object of the program, and one per cpu */
BTF_ID_LIST(pad_obj_drop)
BTF_ID(func, bpf_obj_drop)
BTF_ID(func, bpf_percpu_obj_drop)

/* It releases the dynptr of bpf_dynptr_from_file() */
BTF_ID_LIST_SINGLE(pad_file_discard, func, bpf_dynptr_file_discard)

static struct bpf_insn helper_call(enum bpf_func_id func_id)
{
	return BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, func_id);
}

/* The insn of a pad that releases one resource of @class. A pointer: see ref_release(). */
static struct bpf_insn release_call(enum bpf_pad_class class)
{
	if (class == BPF_PAD_SPIN_LOCK)
		return helper_call(BPF_FUNC_spin_unlock);
	return BPF_CALL_KFUNC(0, pad_kfuncs[class]);
}

/* The insn of a pad that enters a section of @class once more */
static struct bpf_insn enter_call(enum bpf_pad_class class)
{
	return BPF_CALL_KFUNC(0, pad_enter_kfuncs[class]);
}

static bool is_obj_drop(const struct bpf_insn *insn)
{
	return bpf_pseudo_kfunc_call(insn) && !insn->off &&
	       (insn->imm == pad_obj_drop[0] || insn->imm == pad_obj_drop[1]);
}

/* The second argument of the helper that @insn calls is flags */
static bool takes_flags(const struct bpf_insn *insn)
{
	if (!bpf_helper_call(insn))
		return false;
	switch (insn->imm) {
	case BPF_FUNC_ringbuf_discard:
	case BPF_FUNC_ringbuf_discard_dynptr:
		return true;
	}
	return false;
}

/*
 * bpf_iter_<type>_destroy() for the iterator whose first slot is @iter: the type of the object
 * names it, see btf_check_iter_kfuncs(). If that is a type of a module, the index of its BTF in
 * fd_array goes to *@off, from @insn if that is a call of a kfunc of the same BTF.
 */
static s32 iter_destroy_kfunc(struct bpf_verifier_env *env, const struct bpf_reg_state *iter,
			      const struct bpf_insn *insn, s16 *off)
{
	const struct btf *btf = iter->iter.btf;
	const struct btf_type *t = btf_type_by_id(btf, iter->iter.btf_id);
	struct bpf_call_arg_meta meta;
	char name[128];

	*off = 0;
	if (btf_is_module(btf)) {
		if (!bpf_pseudo_kfunc_call(insn) || !insn->imm ||
		    bpf_fetch_kfunc_arg_meta(env, insn->imm, insn->off, &meta) || meta.btf != btf)
			return -ENOENT;
		*off = insn->off;
	}
	snprintf(name, sizeof(name), "%s_destroy", btf_name_by_offset(btf, t->name_off));
	return btf_find_by_name_kind(btf, name, BTF_KIND_FUNC);
}

/* Does bpf_sk_release() take what is in @reg? A socket, or what a helper has cast one to. */
static bool reg_is_sock(const struct bpf_reg_state *reg)
{
	if (type_is_sk_pointer(base_type(reg->type)))
		return true;
#ifdef CONFIG_NET
	if (base_type(reg->type) == PTR_TO_BTF_ID && btf_is_vmlinux(reg->btf))
		for (int i = 0; i < MAX_BTF_SOCK_TYPE; i++)
			if (reg->btf_id == btf_sock_ids[i])
				return true;
#endif
	return false;
}

/*
 * The call that releases the pointer in @reg. Its type tells: that is all that the verifier asks of
 * the argument of a release, whichever insn acquired the pointer. An object of the program is freed.
 * A kernel object: see btf_find_release_kfunc(). If a kfunc of a module returned the pointer @off is
 * the index of its BTF in fd_array, and that BTF comes first: nf_conn is a type of vmlinux, and the
 * kfuncs for it may be in a module.
 */
static int type_release(struct bpf_verifier_env *env, const struct bpf_reg_state *reg, s16 off,
			struct bpf_insn *release)
{
	const struct btf *btf = reg->btf;
	s32 id = -ENOENT;

	if (base_type(reg->type) != PTR_TO_BTF_ID)
		return -ENOENT;
	if (!btf_is_kernel(btf)) {
		*release = BPF_CALL_KFUNC(0, pad_obj_drop[!!(reg->type & MEM_PERCPU)]);
		return 0;
	}
	if (btf_is_module(btf)) {
		id = btf_find_release_kfunc(btf, reg->btf_id, env->prog);
		/* the module releases it itself, and nothing says where its BTF is in fd_array */
		if (id >= 0 && !off)
			return -ENOENT;
		if (id < 0) {
			btf = btf_base_btf(btf);
			off = 0;
		}
	}
	if (id < 0)
		id = btf_find_release_kfunc(btf, reg->btf_id, env->prog);
	*release = BPF_CALL_KFUNC(off, id);
	return min(id, 0);
}

/*
 * The call that releases the pointer @ref, which is in @reg. If @ref is an object in the stack
 * @reg is its first slot, @iter: that of an iterator.
 * What the main pass compares before one state stands for another decides: the type of what is in
 * @reg, the kind of the object, and whether @ref came with a __ref argument, see same_refs() and
 * bpf_same_join_key(). The insn that acquired @ref is not compared, and a join keeps one of two.
 * It is asked what the type leaves open:
 *   - Which helper made a socket or a record of a ring buffer. That is believed only where @reg
 *     is what such a helper returns.
 *   - Where the BTF of a module is in fd_array, if the insn is a call of a kfunc. Its index is
 *     taken as it is, with no test of @reg. R0 of a kfunc has the BTF of that kfunc, see
 *     check_kfunc_call(), a helper that casts a socket gives it a type of vmlinux, and a join
 *     keeps a register only where both states have one type in it. So a pointer to a type of
 *     a module that a kfunc acquired came out of a kfunc of that module, and the index is that
 *     of the BTF in which type_release() finds the kfunc. Where @reg has a type of vmlinux and
 *     the index is one of a module, the kfunc is looked up in the sets of that module like any
 *     call of the program, see get_release(): unless the module has registered that very
 *     function it is no kfunc there, and that is a conflict.
 */
static int ref_release(struct bpf_verifier_env *env, const struct bpf_reference_state *ref,
		       const struct bpf_reg_state *reg, bool iter, struct bpf_insn *release)
{
	const struct bpf_insn *insn = &env->prog->insnsi[ref->insn_idx];
	s16 off;
	s32 id;

	if (iter) {
		id = iter_destroy_kfunc(env, reg, insn, &off);
		*release = BPF_CALL_KFUNC(off, id);
		return min(id, 0);
	}
	if (reg->type == CONST_PTR_TO_DYNPTR) {
		if (reg->dynptr.type == BPF_DYNPTR_TYPE_FILE)
			*release = BPF_CALL_KFUNC(0, pad_file_discard[0]);
		else if (reg->dynptr.type == BPF_DYNPTR_TYPE_RINGBUF)
			*release = helper_call(BPF_FUNC_ringbuf_discard_dynptr);
		else
			return -ENOENT;
		return 0;
	}
	/* no insn acquired a __ref argument of struct_ops */
	if (ref->ctx_arg)
		return type_release(env, reg, 0, release);
	if (bpf_pseudo_kfunc_call(insn))
		return type_release(env, reg, insn->off, release);
	if (!bpf_helper_call(insn))
		return type_release(env, reg, 0, release);
	switch (insn->imm) {
	case BPF_FUNC_sk_lookup_tcp:
	case BPF_FUNC_sk_lookup_udp:
	case BPF_FUNC_skc_lookup_tcp:
	case BPF_FUNC_map_lookup_elem:
		if (!reg_is_sock(reg))
			break;
		*release = helper_call(BPF_FUNC_sk_release);
		return 0;
	case BPF_FUNC_ringbuf_reserve:
		if (base_type(reg->type) != PTR_TO_MEM || !(reg->type & MEM_RINGBUF))
			break;
		*release = helper_call(BPF_FUNC_ringbuf_discard);
		return 0;
	case BPF_FUNC_kptr_xchg:
		return type_release(env, reg, 0, release);
	}
	return -ENOENT;
}

/*
 * A pad is going to call what @insn calls, if the program can call that. The passes that follow the
 * emission look for the descriptor of a kfunc, which the program gets here, and for the prototype
 * of a helper.
 * Returns the reason of a conflict.
 */
static int get_release(struct bpf_verifier_env *env, const struct bpf_insn *insn)
{
	const struct bpf_func_proto *fn;
	u32 log_level = env->log.level;
	struct bpf_call_arg_meta meta;
	int err;

	if (bpf_helper_call(insn))
		return bpf_get_helper_proto(env, insn->imm, &fn) ? BPF_CONFLICT_NO_RELEASE : 0;
	env->log.level = 0;
	err = bpf_add_kfunc_call(env, insn->imm, insn->off);
	err = err ?: bpf_fetch_kfunc_arg_meta(env, insn->imm, insn->off, &meta);
	env->log.level = log_level;
	if (err == -ENOMEM)
		return err;
	return err ? BPF_CONFLICT_NO_RELEASE : 0;
}

/* May what @insn calls sleep? The program itself calls that in a sleepable context only. */
static bool call_sleeps(struct bpf_verifier_env *env, const struct bpf_insn *insn)
{
	const struct bpf_func_proto *fn;
	struct bpf_call_arg_meta meta;

	if (bpf_helper_call(insn))
		return !bpf_get_helper_proto(env, insn->imm, &fn) && fn->might_sleep;
	return !bpf_fetch_kfunc_arg_meta(env, insn->imm, insn->off, &meta) &&
	       bpf_is_kfunc_sleepable(&meta);
}

struct bpf_pad_plan *bpf_pad_plan(const struct bpf_insn_aux_data *aux, enum bpf_site_kind kind)
{
	struct bpf_pad_plan *plan;

	for (plan = aux->pad_plans; plan; plan = plan->next)
		if (plan->kind == kind)
			return plan;
	return NULL;
}

/* @callee came back to the call of @plan, at @call_idx: it takes its place in the list */
static int plan_add_callee(struct bpf_verifier_env *env, struct bpf_pad_plan *plan, int call_idx,
			   u32 callee)
{
	u32 n = plan->nr_callees, mid, lo = 0, hi = n, *list;

	while (lo < hi) {
		mid = (lo + hi) / 2;
		if (plan->callee[mid] < callee)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < n && plan->callee[lo] == callee)
		return 0;
	/* the list has room for the next power of two */
	if (!(n & (n - 1))) {
		list = krealloc_array(plan->callee, n ? 2 * n : 1, sizeof(*list), BPF_VERIFIER_GFP);
		if (!list)
			return -ENOMEM;
		plan->callee = list;
	}
	/* callx can have many callees, and each new one moves those above it */
	bpf_add_cost(env, (n - lo) * sizeof(*list) / 64, BPF_COST_SCAN);
	memmove(&plan->callee[lo + 1], &plan->callee[lo], (n - lo) * sizeof(*list));
	plan->callee[lo] = callee;
	plan->nr_callees++;
	/* what bpf_pad_skip_faults() found below the function of the call is no longer all */
	if (bpf_find_containing_subprog(env, call_idx)->skip_gen)
		env->pad_skip_gen++;
	return 0;
}

/* A new plan is the empty one: the pad releases nothing. NULL if there is no memory. */
struct bpf_pad_plan *bpf_pad_plan_get(struct bpf_verifier_env *env, int insn_idx,
				      enum bpf_site_kind kind)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	struct bpf_pad_plan *plan = bpf_pad_plan(aux, kind);

	if (plan)
		return plan;
	plan = kzalloc_obj(*plan, BPF_VERIFIER_GFP);
	if (!plan)
		return NULL;
	plan->kind = kind;
	plan->nulls.regs = U16_MAX;
	plan->nulls.unsaved = U16_MAX;
	bitmap_fill(plan->nulls.slots, MAX_BPF_STACK_SLOTS);
	plan->next = aux->pad_plans;
	aux->pad_plans = plan;
	return plan;
}

/*
 * @callee was left with unwind_exit and comes back to the call at @call_idx, which is a site of
 * @kind, BPF_SITE_CALL. Or it was left with kexit: BPF_SITE_KCALL.
 */
int bpf_pad_note_callee(struct bpf_verifier_env *env, int call_idx, int callee,
			enum bpf_site_kind kind)
{
	struct bpf_pad_plan *plan = bpf_pad_plan_get(env, call_idx, kind);

	if (!plan)
		return -ENOMEM;
	return plan_add_callee(env, plan, call_idx, callee);
}

static void free_plans(struct bpf_pad_plan *plan)
{
	struct bpf_pad_plan *next;

	for (; plan; plan = next) {
		next = plan->next;
		kfree(plan->ents);
		kfree(plan->callee);
		kfree(plan);
	}
}

void bpf_pad_plans_free(struct bpf_insn_aux_data *aux)
{
	free_plans(aux->pad_plans);
	aux->pad_plans = NULL;
}

/* A pass or a path-sensitive run begins */
void bpf_pads_new_round(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i;

	env->pads_late = false;
	env->pad_skip_gen++;
	for (i = 0; i < env->prog->len; i++, aux++) {
		bpf_pad_plans_free(aux);
		kfree(aux->pad_note);
		aux->pad_note = NULL;
	}
}

/*
 * The plans and the notes are what a pass found, like the fixups of the insns, and a pass that
 * is kept can become the result when a later one has an error. So they move with the snapshot
 * of the pass, see copy_snapshot(): to @moved, which has an entry per insn, if @save, else back
 * from there. What was at the destination is freed, and the source has nothing after that.
 */
void bpf_pads_move(struct bpf_verifier_env *env, struct bpf_pads_moved *moved, bool save)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i;

	env->pad_skip_gen++;
	for (i = 0; i < env->prog->len; i++, aux++, moved++) {
		if (save) {
			free_plans(moved->plans);
			kfree(moved->note);
			moved->plans = aux->pad_plans;
			moved->note = aux->pad_note;
			aux->pad_plans = NULL;
			aux->pad_note = NULL;
		} else {
			free_plans(aux->pad_plans);
			kfree(aux->pad_note);
			aux->pad_plans = moved->plans;
			aux->pad_note = moved->note;
			moved->plans = NULL;
			moved->note = NULL;
		}
	}
}

/* The snapshot that has @moved of @cnt insns is freed */
void bpf_pads_free_moved(struct bpf_pads_moved *moved, u32 cnt)
{
	u32 i;

	for (i = 0; i < cnt; i++) {
		free_plans(moved[i].plans);
		kfree(moved[i].note);
	}
}

/*
 * How many sections of @class the current frame of @st is in beyond those that it was called in:
 * what it entered and did not leave, and what a subprog that it called returned with. Less than 0
 * if it has left sections of its callers, itself or in a subprog that returned.
 */
static int frame_sections(const struct bpf_verifier_state *st, enum bpf_pad_class class)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];

	if (class == BPF_PAD_RCU)
		return st->active_rcu_locks - frame->call_rcu_locks;
	return st->active_preempt_locks - frame->call_preempt_locks;
}

/*
 * How many sections of @class that its callers entered the current frame of @st is in when its pad
 * gets to the pointers: the pad has left what the frame is in beyond the sections of its call
 */
static int caller_sections(const struct bpf_verifier_state *st, enum bpf_pad_class class)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];

	if (class == BPF_PAD_RCU)
		return min(st->active_rcu_locks, frame->call_rcu_locks);
	return min(st->active_preempt_locks, frame->call_preempt_locks);
}

/*
 * Can the pad of the current frame of @st call what may sleep when it gets to the pointers? The
 * program can where it is sleepable, holds no lock and no irq flags and is in no section, see
 * in_sleepable_context() in verifier.c. The pad has released the locks and the irq flags of the
 * frame by then and has left its sections. What the callers hold is still held.
 * @leaves: the pad leaves the sections of the callers as well, see bpf_pad_visit(). Only if the
 * frame has been out of all of them since its call: entry_rcu_locks and entry_preempt_locks are
 * the fewest that it has been in, see release_context_state(), and have to be 0 either way.
 */
static bool pad_can_sleep(const struct bpf_verifier_state *st, bool leaves)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	int i;

	if (!st->in_sleepable || frame->entry_rcu_locks || frame->entry_preempt_locks)
		return false;
	for (i = 0; i <= st->curframe; i++)
		if (st->frame[i]->in_rcu_callback_fn)
			return false;
	for (i = 0; i < frame->entry_refs; i++)
		if (st->refs[i].type != REF_TYPE_PTR)
			return false;
	return leaves || (!caller_sections(st, BPF_PAD_RCU) && !caller_sections(st, BPF_PAD_PREEMPT));
}

/* The class of @ref */
static int ref_class(const struct bpf_reference_state *ref)
{
	switch (ref->type) {
	case REF_TYPE_PTR:
		return BPF_PAD_REF;
	case REF_TYPE_IRQ:
		return BPF_PAD_IRQ;
	case REF_TYPE_LOCK:
		return BPF_PAD_SPIN_LOCK;
	case REF_TYPE_RES_LOCK:
		return BPF_PAD_RES_LOCK;
	case REF_TYPE_RES_LOCK_IRQ:
		return BPF_PAD_RES_LOCK_IRQ;
	default:
		return -ENOENT;
	}
}

/* Where the lock of @class is in what @rec describes */
static int lock_off(const struct btf_record *rec, enum bpf_pad_class class)
{
	if (class == BPF_PAD_SPIN_LOCK)
		return btf_record_has_field(rec, BPF_SPIN_LOCK) ? rec->spin_lock_off : -ENOENT;
	return btf_record_has_field(rec, BPF_RES_SPIN_LOCK) ? rec->res_spin_lock_off : -ENOENT;
}

/*
 * If @reg, which is at (@loc, @at), points into the map value or the object that the lock @ref
 * is in, at a constant offset, that is a candidate. It is what the release asks of its argument,
 * see process_spin_lock(): all candidates of a visit give the same handle.
 */
static void add_lock_cand(struct bpf_pad_place *cand, int *nr, const struct bpf_reg_state *reg,
			  const struct bpf_reference_state *ref, enum bpf_place_loc loc, int at)
{
	const struct btf_struct_meta *meta;
	const struct btf_record *rec;
	s64 delta;
	int off;

	if (*nr == BPF_PAD_MAX_CANDS || reg->id != ref->id || !tnum_is_const(reg->var_off))
		return;
	if (reg->type == PTR_TO_MAP_VALUE && reg->map_ptr == ref->ptr) {
		rec = reg->map_ptr->record;
	} else if (reg->type == (PTR_TO_BTF_ID | MEM_ALLOC) && reg->btf == ref->ptr) {
		meta = btf_find_struct_meta(reg->btf, reg->btf_id);
		rec = meta ? meta->record : NULL;
	} else {
		return;
	}
	off = lock_off(rec, ref_class(ref));
	delta = (s64)reg->var_off.value - off;
	if (off < 0 || delta < -S32_MAX || delta > S32_MAX)
		return;
	cand[(*nr)++] = (struct bpf_pad_place){ .loc = loc, .at = at, .delta = delta };
}

/*
 * If @reg, which is at (@loc, @at), is the pointer @ref plus a constant, that is a candidate:
 * a copy, a pointer to a node in an object, what a helper made of a socket. But not the
 * result of bpf_skc_to_mptcp_sock(): it has the id of the socket and is another socket.
 */
static void add_ref_cand(struct bpf_pad_place *cand, int *nr, const struct bpf_reg_state *reg,
			 const struct bpf_reference_state *ref, enum bpf_place_loc loc, int at)
{
	s64 delta = reg->var_off.value;

	if (*nr == BPF_PAD_MAX_CANDS || reg->id != ref->id || reg->type == SCALAR_VALUE ||
	    reg->type == NOT_INIT || !tnum_is_const(reg->var_off) ||
	    delta < -S32_MAX || delta > S32_MAX)
		return;
#ifdef CONFIG_NET
	if (base_type(reg->type) == PTR_TO_BTF_ID && btf_is_vmlinux(reg->btf) &&
	    reg->btf_id == btf_sock_ids[BTF_SOCK_TYPE_MPTCP])
		return;
#endif
	cand[(*nr)++] = (struct bpf_pad_place){ .loc = loc, .at = at, .delta = delta,
						.maybe_null = type_may_be_null(reg->type) };
}

/*
 * If @reg, which is at (@loc, @at), points to the stack of the same frame as @obj, at a constant
 * offset, that is a candidate.
 */
static void add_obj_cand(struct bpf_pad_place *cand, int *nr, const struct bpf_reg_state *reg,
			 const struct bpf_reg_state *obj, enum bpf_place_loc loc, int at)
{
	s64 delta = reg->var_off.value - obj->var_off.value;

	if (*nr == BPF_PAD_MAX_CANDS || reg->type != PTR_TO_STACK || reg->frameno != obj->frameno ||
	    !tnum_is_const(reg->var_off) || delta < -S32_MAX || delta > S32_MAX)
		return;
	cand[(*nr)++] = (struct bpf_pad_place){ .loc = loc, .at = at, .delta = delta };
}

static void add_cand(struct bpf_pad_place *cand, int *nr, const struct bpf_reg_state *reg,
		     const struct bpf_reference_state *ref, const struct bpf_reg_state *obj,
		     enum bpf_place_loc loc, int at)
{
	if (obj)
		add_obj_cand(cand, nr, reg, obj, loc, at);
	else if (ref->type == REF_TYPE_PTR)
		add_ref_cand(cand, nr, reg, ref, loc, at);
	else
		add_lock_cand(cand, nr, reg, ref, loc, at);
}

/*
 * The places of the current frame of @st that have the handle of @ref, a lock or a pointer, at
 * @insn_idx: R6-R9 and stack slots, then R0-R5, which are dead after a call. If @ref is an object
 * in the stack of a caller @obj is its address.
 * A register or a stack slot that is not live there is no place: the passes that follow use
 * such a register, remove the store to such a slot, and states that differ in it are the same to
 * the main pass. Nor is a register of which only the lower half is live: the pad reads 64 bits, and
 * 'w6 = 0' is zero extended only if an insn of the program reads the upper half, see zext_dst.
 * Nor is a slot of the spills around bpf_fastcall calls: they are removed unless the
 * main pass sees another access to the slot, and it does not see the pad.
 */
static int find_cands(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
		      int insn_idx, const struct bpf_reference_state *ref,
		      const struct bpf_reg_state *obj, struct bpf_pad_place *cand)
{
	const struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	const struct bpf_func_state *frame = st->frame[st->curframe];
	int fastcall_off = env->subprog_info[frame->subprogno].fastcall_stack_off;
	const struct bpf_stack_state *slot;
	int i, off, nr = 0;

	for (i = BPF_REG_6; i < BPF_REG_FP; i++)
		if (aux->live_hi32_before & BIT(i))
			add_cand(cand, &nr, &frame->regs[i], ref, obj, BPF_PLACE_REG, i);
	for (i = 0; i < bpf_stack_nr_slots(frame); i++) {
		slot = bpf_stack_slot(frame, i);
		off = -(i + 1) * BPF_REG_SIZE;
		if (test_bit(i, aux->live_stack_before) && bpf_spill_size(slot) == BPF_REG_SIZE &&
		    off >= fastcall_off)
			add_cand(cand, &nr, &slot->spilled_ptr, ref, obj, BPF_PLACE_SPILL, off);
	}
	for (i = BPF_REG_0; i < BPF_REG_6; i++)
		if (aux->live_hi32_before & BIT(i))
			add_cand(cand, &nr, &frame->regs[i], ref, obj, BPF_PLACE_REG, i);
	return nr;
}

/* The places that have the address of the lock @ref, see find_cands() */
static int find_lock_cands(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			   int insn_idx, const struct bpf_reference_state *ref,
			   struct bpf_pad_place *cand)
{
	struct bpf_pad_place kept[BPF_PAD_MAX_CANDS];
	const struct bpf_map *map;
	int i, off, nr = 0, nr_kept;
	u64 addr;

	/* A lock in a global variable, the only value of an array: no id, a constant address. */
	for (i = 0; !ref->id && i < env->used_map_cnt; i++) {
		map = env->used_maps[i];
		off = lock_off(map->record, ref_class(ref));
		if (map != ref->ptr || map->map_type != BPF_MAP_TYPE_ARRAY || off < 0 ||
		    map->ops->map_direct_value_addr(map, &addr, off))
			continue;
		cand[nr++] = (struct bpf_pad_place){ .loc = BPF_PLACE_MAP_VALUE, .at = i,
						     .delta = -off };
	}
	/* One insn may take one of several such locks. The program keeps the address to unlock. */
	nr_kept = min(find_cands(env, st, insn_idx, ref, NULL, kept), BPF_PAD_MAX_CANDS - nr);
	memcpy(&cand[nr], kept, nr_kept * sizeof(*cand));
	return nr + nr_kept;
}

/*
 * A register of the current frame of @st, spilled or not, live or not, that has the pointer @ref:
 * it tells the type. R0-R5 come last. NULL if there is none.
 */
static const struct bpf_reg_state *ref_reg(const struct bpf_verifier_state *st,
					   const struct bpf_reference_state *ref)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_stack_state *slot;
	int i;

	for (i = 0; i < bpf_stack_nr_slots(frame); i++) {
		slot = bpf_stack_slot(frame, i);
		if (bpf_is_spilled_reg(slot) && slot->spilled_ptr.id == ref->id)
			return &slot->spilled_ptr;
	}
	for (i = BPF_REG_9; i >= BPF_REG_0; i--)
		if (frame->regs[i].type != NOT_INIT && frame->regs[i].id == ref->id)
			return &frame->regs[i];
	return NULL;
}

/*
 * Slot @spi of @frame is the first one of an iterator. Is the iterator all that its destructor asks
 * for? The program can write to the other slots, and it can leave what protects an iterator that
 * RCU protects. Then nothing can destroy the iterator any more.
 */
static bool iter_is_valid(const struct bpf_func_state *frame, int spi)
{
	const struct bpf_reg_state *reg = &bpf_stack_slot(frame, spi)->spilled_ptr;
	const struct btf_type *t = btf_type_by_id(reg->iter.btf, reg->iter.btf_id);

	return !bpf_iter_slots_valid_init(frame, spi, reg->iter.btf, reg->iter.btf_id,
					  t->size / BPF_REG_SIZE);
}

/*
 * Is slot @spi of @frame the first one of the object @ref: irq flags, an iterator, a dynptr?
 * A store to a slot of irq flags or of a dynptr leaves nothing of them.
 */
static bool slot_is_obj(const struct bpf_func_state *frame, int spi,
			const struct bpf_reference_state *ref)
{
	const struct bpf_reg_state *reg = &bpf_stack_slot(frame, spi)->spilled_ptr;

	switch (bpf_stack_slot(frame, spi)->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_IRQ_FLAG:
		return reg->id == ref->id;
	case STACK_ITER:
		return reg->id == ref->id && iter_is_valid(frame, spi);
	case STACK_DYNPTR:
		/* any other dynptr is made from a pointer, and that is what @ref is */
		return reg->dynptr.first_slot && reg->parent_id == ref->id &&
		       (reg->dynptr.type == BPF_DYNPTR_TYPE_RINGBUF ||
			reg->dynptr.type == BPF_DYNPTR_TYPE_FILE);
	}
	return false;
}

/*
 * If @ref is an object in the stack: the places that have its address at @insn_idx. R10 if the
 * current frame of @st has the object. If a caller has it, what find_cands() finds: the function
 * got a pointer and made the object there, like the constructor of a guard. A clone of a dynptr is
 * one more place of the same resource. *@obj: the first slot of the object.
 */
static int find_obj_cands(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			  int insn_idx, const struct bpf_reference_state *ref,
			  struct bpf_pad_place *cand, const struct bpf_stack_state **obj)
{
	const struct bpf_func_state *frame;
	struct bpf_reg_state addr;
	int f, i, nr = 0;

	for (f = st->curframe; f >= 0 && !nr; f--) {
		frame = st->frame[f];
		for (i = 0; i < bpf_stack_nr_slots(frame) && nr < BPF_PAD_MAX_CANDS; i++) {
			if (!slot_is_obj(frame, i, ref))
				continue;
			*obj = nr ? *obj : bpf_stack_slot(frame, i);
			if (f == st->curframe) {
				cand[nr++] = (struct bpf_pad_place){ .loc = BPF_PLACE_REG,
								     .at = BPF_REG_FP,
								     .delta = (i + 1) * BPF_REG_SIZE };
				continue;
			}
			addr = frame->regs[BPF_REG_FP];
			addr.var_off = tnum_const(-(i + 1) * BPF_REG_SIZE);
			return find_cands(env, st, insn_idx, ref, &addr, cand);
		}
	}
	return nr;
}

static bool reg_is_null(const struct bpf_reg_state *reg)
{
	return reg->type == SCALAR_VALUE && tnum_equals_const(reg->var_off, 0);
}

static void find_nulls(const struct bpf_func_state *frame, struct bpf_pad_nulls *nulls)
{
	const struct bpf_stack_state *slot;
	int i, j;

	memset(nulls, 0, sizeof(*nulls));
	nulls->unsaved = ~frame->saved_mask;
	for (i = BPF_REG_0; i < BPF_REG_FP; i++)
		if (reg_is_null(&frame->regs[i]))
			nulls->regs |= BIT(i);
	for (i = 0; i < bpf_stack_nr_slots(frame); i++) {
		slot = bpf_stack_slot(frame, i);
		for (j = 0; j < BPF_REG_SIZE && slot->slot_type[j] == STACK_ZERO; j++)
			;
		if (j == BPF_REG_SIZE ||
		    (bpf_spill_size(slot) == BPF_REG_SIZE && reg_is_null(&slot->spilled_ptr)))
			__set_bit(i, nulls->slots);
	}
}

/*
 * An address in the stack and the address of a map value are never 0. A save word is 0 in a frame
 * whose entry has put nothing there. Where it has, the word keeps the handle when the program
 * releases what it is for: not 0, and not held.
 */
static bool place_is_null(const struct bpf_pad_nulls *nulls, const struct bpf_pad_place *place)
{
	if (place->loc == BPF_PLACE_SAVED)
		return nulls->unsaved & BIT(place->at);
	if (place->loc == BPF_PLACE_REG)
		return nulls->regs & BIT(place->at);
	return place->loc == BPF_PLACE_SPILL &&
	       test_bit(-place->at / BPF_REG_SIZE - 1, nulls->slots);
}

/*
 * The candidates for argument @arg of the release that @ent and @new have in common go to @cand.
 * Returns how many there are.
 */
static int common_cands(const struct bpf_pad_ent *ent, const struct bpf_pad_ent *new, int arg,
			struct bpf_pad_place *cand)
{
	const struct bpf_pad_place *old = ent->cand[arg], *place = new->cand[arg];
	int i, j, n = 0;

	for (i = 0; i < ent->nr_cands[arg]; i++) {
		for (j = 0; j < new->nr_cands[arg]; j++) {
			if (old[i].loc != place[j].loc || old[i].at != place[j].at ||
			    old[i].delta != place[j].delta)
				continue;
			cand[n] = old[i];
			cand[n++].maybe_null |= place[j].maybe_null;
			break;
		}
	}
	return n;
}

/*
 * Can a pad free an object of type @btf_id of the program with the call @release? That runs the
 * destructors of its fields. Under a lock of a caller: see can_release_under_lock().
 * A tracing program must not do that to fields that are not NMI safe, see check_kfunc_call().
 * bpf_percpu_obj_drop() takes no description of fields: a per-cpu object has none that the kernel
 * looks after, bpf_percpu_obj_new() makes no other. The type of a pointer behind __percpu_kptr can
 * have such fields all the same, and bpf_fixup_kfunc_call() takes a call that frees that type
 * for a bug of the verifier. No pad makes that call.
 */
static bool can_free_obj(struct bpf_verifier_env *env, const struct bpf_insn *release, u32 btf_id)
{
	const struct btf *btf = env->prog->aux->btf;
	const struct btf_struct_meta *meta = btf_find_struct_meta(btf, btf_id);

	if (meta && release->imm == pad_obj_drop[1])
		return false;
	if (meta && bpf_prog_may_run_in_nmi(env) && btf_record_has_nmi_unsafe_fields(meta->record))
		return false;
	return true;
}

/*
 * Can a pad of @frame make the call of @ent, which releases a pointer, an iterator or a dynptr,
 * under the locks that are held then? Those of its callers are: what the callers hold is in the
 * first entry_refs of refs[] of @st. The pad has released the locks of its own frame by then,
 * unless RCU protects @ent: such an iterator goes ahead of them, see enum pad_turn, and every
 * lock in refs[] counts. The frame takes its locks behind the insn that made the iterator, where
 * a hidden slot got its release, so for them the visit asks: ref_ent() is called for every
 * state that holds the iterator.
 * Under a lock a program may call only a kfunc that is KF_SPINLOCK_SAFE, see do_check_insn(), and
 * so may its pad: the release of a kernel object runs code of its owner. The program has no such
 * call for an object of its own. The pad frees one there all the same if that runs no destructor
 * of a field, see bpf_obj_free_runs_dtor(): it only gives the memory back.
 */
static bool can_release_under_lock(struct bpf_verifier_env *env,
				   const struct bpf_verifier_state *st,
				   const struct bpf_func_state *frame, const struct bpf_pad_ent *ent)
{
	u32 i, nr = ent->rcu ? st->acquired_refs : frame->entry_refs;
	struct bpf_call_arg_meta meta;

	if (ent->class < BPF_PAD_REF)
		return true;
	for (i = 0; i < nr && !(st->refs[i].type & REF_TYPE_LOCK_MASK); i++)
		;
	if (i == nr)
		return true;
	if (is_obj_drop(&ent->release))
		return !bpf_obj_free_runs_dtor(env->prog->aux->btf, ent->obj_type);
	return bpf_pseudo_kfunc_call(&ent->release) &&
	       !bpf_fetch_kfunc_arg_meta(env, ent->release.imm, ent->release.off, &meta) &&
	       (meta.kfunc_flags & KF_SPINLOCK_SAFE);
}

/*
 * What the release of @ent needs beside the handle, which is in @reg. Flags, the second argument:
 * they are 0. The type of an object of the program: that is no argument. It is in the aux data of
 * the call that frees the object, see bpf_insn_aux_data::kptr_struct_meta, so a call of a pad frees
 * one type. Its id in the BTF of the program names it.
 */
static int ent_imm(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
		   const struct bpf_reg_state *reg)
{
	if (is_obj_drop(&ent->release)) {
		if (reg->btf != env->prog->aux->btf)
			return BPF_CONFLICT_NO_PLACE;
		if (!can_free_obj(env, &ent->release, reg->btf_id))
			return BPF_CONFLICT_NO_RELEASE;
		ent->obj_type = reg->btf_id;
	}
	if (takes_flags(&ent->release))
		ent->cand[1][ent->nr_cands[1]++] = (struct bpf_pad_place){ .loc = BPF_PLACE_IMM };
	return 0;
}

/* See ref_ent(). @ref is a pointer. */
static int ptr_ent(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
		   const struct bpf_verifier_state *st, int insn_idx,
		   const struct bpf_reference_state *ref)
{
	const struct bpf_reg_state *regs = st->frame[st->curframe]->regs, *reg = ref_reg(st, ref);

	if (!reg)
		return BPF_CONFLICT_NO_PLACE;
	if (ref_release(env, ref, reg, false, &ent->release))
		return BPF_CONFLICT_NO_RELEASE;
	ent->nr_cands[0] = find_cands(env, st, insn_idx, ref, NULL, ent->cand[0]);
	if (!ent->nr_cands[0] && reg >= &regs[BPF_REG_0] && reg <= &regs[BPF_REG_5])
		return BPF_CONFLICT_CALLER_SAVED;
	return ent_imm(env, ent, reg);
}

/* Does the call of @ent release what save word @word of @sub is for? See visit_saves(). */
static bool ent_is_saved_kind(const struct bpf_subprog_info *sub, int word,
			      const struct bpf_pad_ent *ent)
{
	const struct bpf_pad_save *save = &sub->saves[word];

	return save->set && ent->class == BPF_PAD_REF && !ent->rcu &&
	       ent->obj_type == save->obj_type &&
	       !memcmp(&ent->release, &save->release, sizeof(ent->release));
}

/*
 * See ref_ent(). The entry of the landing pad has put the pointer @ref into a save word of the
 * frame: a place that is good wherever the frame is left, whatever the program has read or
 * overwritten since. @err: what ptr_ent() made of the registers.
 * If no register has the pointer any more, or only one that the calls of a pad clobber, the word
 * is the only place. What releases the pointer follows from its type, which went with the
 * registers. So the functions keep one kind of thing in a word, see visit_saves(): that says it.
 * A register that says something else than the word is for is a conflict: neither is believed.
 */
static int saved_ptr_ent(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
			 const struct bpf_verifier_state *st, const struct bpf_reference_state *ref,
			 int err)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_subprog_info *sub = &env->subprog_info[frame->subprogno];
	const struct bpf_pad_save *save = &sub->saves[ref->saved - 1];
	struct bpf_pad_place *cand = ent->cand[0];
	int i, n = ent->nr_cands[0];

	if (verifier_bug_if(!save->set, env, "save word %d of func#%d has no pointer",
			    ref->saved - 1, frame->subprogno))
		return -EFAULT;
	if (err == BPF_CONFLICT_NO_PLACE || err == BPF_CONFLICT_CALLER_SAVED) {
		ent->release = save->release;
		if (is_obj_drop(&ent->release)) {
			if (!can_free_obj(env, &ent->release, save->obj_type))
				return BPF_CONFLICT_NO_RELEASE;
			ent->obj_type = save->obj_type;
		}
		if (takes_flags(&ent->release))
			ent->cand[1][ent->nr_cands[1]++] =
				(struct bpf_pad_place){ .loc = BPF_PLACE_IMM };
	} else if (err) {
		return err;
	} else if (!ent_is_saved_kind(sub, ref->saved - 1, ent)) {
		return BPF_CONFLICT_SAVES_DIFFER;
	}
	if (n == BPF_PAD_MAX_CANDS)
		return 0;
	/*
	 * In front of R0-R5, which the calls of a pad clobber: settle_ent() takes the first place
	 * that will do, and such a register does only for the first call of a pad.
	 */
	for (i = 0; i < n && !(cand[i].loc == BPF_PLACE_REG && cand[i].at < BPF_REG_6); i++)
		;
	memmove(&cand[i + 1], &cand[i], (n - i) * sizeof(*cand));
	cand[i] = (struct bpf_pad_place){ .loc = BPF_PLACE_SAVED, .at = ref->saved - 1,
					  .maybe_null = true };
	ent->nr_cands[0]++;
	return 0;
}

/* See ref_ent(). @ref is an iterator or a dynptr, and @slot the first one that it has. */
static int obj_ent(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
		   const struct bpf_reference_state *ref, const struct bpf_stack_state *slot)
{
	if (ref_release(env, ref, &slot->spilled_ptr, slot->slot_type[0] == STACK_ITER, &ent->release))
		return BPF_CONFLICT_NO_RELEASE;
	if (slot->slot_type[0] == STACK_ITER) {
		ent->class = BPF_PAD_ITER;
		ent->rcu = slot->spilled_ptr.type & MEM_RCU;
	} else {
		ent->class = BPF_PAD_DYNPTR;
	}
	return ent_imm(env, ent, &slot->spilled_ptr);
}

/*
 * Make @ent what @ref, one of refs[] of @st, is to a landing pad at @insn_idx: the call that
 * releases it, and the places of the current frame that have the arguments.
 * Returns the reason of a conflict.
 */
static int ref_ent(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
		   const struct bpf_verifier_state *st, int insn_idx,
		   const struct bpf_reference_state *ref)
{
	const struct bpf_stack_state *obj = NULL;
	int class = ref_class(ref), err = 0;

	if (verifier_bug_if(class < 0, env, "no landing pad releases reference type %d", ref->type))
		return -EFAULT;
	memset(ent, 0, sizeof(*ent));
	ent->origin = ref->origin;
	ent->class = class;
	if (class != BPF_PAD_REF)
		ent->release = release_call(class);
	if (class == BPF_PAD_REF || class == BPF_PAD_IRQ)
		ent->nr_cands[0] = find_obj_cands(env, st, insn_idx, ref, ent->cand[0], &obj);
	else
		ent->nr_cands[0] = find_lock_cands(env, st, insn_idx, ref, ent->cand[0]);
	if (class == BPF_PAD_REF && obj)
		err = obj_ent(env, ent, ref, obj);
	else if (class == BPF_PAD_REF)
		err = ptr_ent(env, ent, st, insn_idx, ref);
	/* only a pointer has a save word, see visit_saves() */
	if (class == BPF_PAD_REF && !obj && ref->saved)
		err = saved_ptr_ent(env, ent, st, ref, err);
	if (class == BPF_PAD_RES_LOCK_IRQ) {
		/* The same insn saved irq flags, the next of refs[]: the second argument. */
		if (verifier_bug_if(ref + 1 == st->refs + st->acquired_refs ||
				    ref[1].type != REF_TYPE_IRQ || ref[1].insn_idx != ref->insn_idx,
				    env, "no irq flags after the lock of insn %d", ref->insn_idx))
			return -EFAULT;
		ent->nr_cands[1] = find_obj_cands(env, st, insn_idx, ref + 1, ent->cand[1], &obj);
		if (!ent->nr_cands[1])
			return BPF_CONFLICT_NO_PLACE;
	}
	if (!err && !can_release_under_lock(env, st, st->frame[st->curframe], ent))
		return BPF_CONFLICT_NO_RELEASE;
	if (!err && !ent->nr_cands[0])
		return BPF_CONFLICT_NO_PLACE;
	return err;
}

/*
 * Is @ref irq flags that are saved in the stack of a caller of the current frame of @st? The
 * function got the address in an argument and saved the flags there, like the function that takes
 * a lock for its caller. The compiler keeps the address no longer than the function reads it, so a
 * site behind the last read has no place for it: the hidden slot of the call that saved the flags
 * has the address, see bpf_pad_note_acquire().
 * The object is there: its slots are those of irq flags in every state that is joined with @st,
 * see bpf_same_join_key().
 */
static bool irq_in_caller(const struct bpf_verifier_state *st, const struct bpf_reference_state *ref)
{
	int f, i;

	if (ref->type != REF_TYPE_IRQ)
		return false;
	for (f = st->curframe - 1; f >= 0; f--)
		for (i = 0; i < bpf_stack_nr_slots(st->frame[f]); i++)
			if (slot_is_obj(st->frame[f], i, ref))
				return true;
	return false;
}

/* The entry of @plan that refs[@ref] is on this visit */
static struct bpf_pad_ent *held_ent(const struct bpf_pad_plan *plan, int ref)
{
	int i;

	for (i = 0; i < plan->nr_ents; i++)
		if (plan->ents[i].ref == ref)
			return &plan->ents[i];
	return NULL;
}

/*
 * The entry of @plan that @new is: nothing else is that entry on this visit, the same call releases
 * both, and they have a candidate in common for each of its arguments. @origin: and the origin.
 */
static struct bpf_pad_ent *match_ent(const struct bpf_pad_plan *plan, const struct bpf_pad_ent *new,
				     bool origin)
{
	struct bpf_pad_place cand[BPF_PAD_MAX_CANDS];
	struct bpf_pad_ent *ent;
	int i, arg;

	for (i = 0; i < plan->nr_ents; i++) {
		ent = &plan->ents[i];
		if (ent->ref >= 0 || (origin && ent->origin != new->origin) ||
		    memcmp(&ent->release, &new->release, sizeof(ent->release)) ||
		    ent->obj_type != new->obj_type || ent->rcu != new->rcu)
			continue;
		for (arg = 0; arg < BPF_PAD_MAX_ARGS; arg++)
			if (new->nr_cands[arg] && !common_cands(ent, new, arg, cand))
				break;
		if (arg == BPF_PAD_MAX_ARGS)
			return ent;
	}
	return NULL;
}

/*
 * @new is one more entry of @plan, number @pos. None of the visits so far held it.
 * Returns it, or NULL if there is no memory.
 */
static struct bpf_pad_ent *add_ent(struct bpf_pad_plan *plan, const struct bpf_pad_ent *new,
				   int pos)
{
	struct bpf_pad_ent *ent;
	int i;

	if (!plan->ents)
		plan->ents = kzalloc_objs(*plan->ents, BPF_PAD_MAX_ENTS, BPF_VERIFIER_GFP);
	if (!plan->ents)
		return NULL;
	ent = &plan->ents[pos];
	memmove(ent + 1, ent, (plan->nr_ents++ - pos) * sizeof(*ent));
	*ent = *new;
	ent->always = !plan->visited;
	/* the address of an object in the stack does not tell whether the object is set up */
	if (ent->class == BPF_PAD_IRQ || ent->class >= BPF_PAD_ITER)
		return ent;
	for (i = 0; i < ent->nr_cands[0]; i++)
		ent->cand[0][i].null = place_is_null(&plan->nulls, &ent->cand[0][i]);
	return ent;
}

/*
 * A visit holds the entries @a and @b of @plan, and @a has to stand before @b: the pad releases
 * @b first. Returns false if another visit wants them the other way round, in one step or in
 * several: no order suits both.
 */
static bool put_before(struct bpf_pad_plan *plan, int a, int b)
{
	int i;

	if (plan->before[b] & BIT(a))
		return false;
	for (i = 0; i < plan->nr_ents; i++)
		if (i == a || (plan->before[i] & BIT(a)))
			plan->before[i] |= BIT(b) | plan->before[b];
	return true;
}

/* The calls of a pad clobber it */
static bool place_is_caller_saved(const struct bpf_pad_place *place)
{
	return place->loc == BPF_PLACE_REG && place->at < BPF_REG_6;
}

/*
 * The pad finds the handle of @ent in a register that its calls clobber: the candidate that
 * settle_ent() takes, when all visits are over
 */
static bool ent_is_clobbered(const struct bpf_pad_ent *ent)
{
	int i;

	for (i = 0; i < ent->nr_cands[0] && !ent->always && !ent->cand[0][i].null; i++)
		;
	return i < ent->nr_cands[0] && place_is_caller_saved(&ent->cand[0][i]);
}

/*
 * Does @a stand before @b where no visit says? The pad releases what stands last first, and that
 * has to be the entry whose handle its calls clobber, see released_first(). Else the one that got
 * to the frame at the lower insn stands first.
 */
static bool ent_stands_before(const struct bpf_pad_ent *a, const struct bpf_pad_ent *b)
{
	bool a_clobbered = ent_is_clobbered(a), b_clobbered = ent_is_clobbered(b);

	return a_clobbered != b_clobbered ? b_clobbered : a->origin < b->origin;
}

/*
 * All visits of @plan are over: put its entries in an order that suits each of them, see
 * visit_refs(). There is one, since put_before() refused what would close a cycle. Of the entries
 * that nothing stands before any more the next one is chosen by what the entries are, see
 * ent_stands_before(), so that the order of what no visit held together does not depend on the
 * visits either.
 */
static int order_ents(struct bpf_verifier_env *env, struct bpf_pad_plan *plan)
{
	int i, j, k, n = plan->nr_ents, next;
	u8 row, bit;

	/* the plan of an entry is no plan of a pad: nothing is released, and there is no order */
	if (plan->ordered || plan->kind == BPF_SITE_KENTRY)
		return 0;
	plan->ordered = true;
	for (k = 0; k < n; k++) {
		next = -1;
		for (i = k; i < n; i++) {
			for (j = k; j < n; j++)
				if (plan->before[j] & BIT(i))
					break;
			if (j == n && (next < 0 ||
				       ent_stands_before(&plan->ents[i], &plan->ents[next])))
				next = i;
		}
		/* put_before() keeps a cycle out. A plan that is half in order is no plan. */
		if (verifier_bug_if(next < 0, env, "the entries of a landing pad have no order"))
			return -EFAULT;
		if (next == k)
			continue;
		/* the entries and what is noted about them trade places */
		swap(plan->ents[k], plan->ents[next]);
		swap(plan->before[k], plan->before[next]);
		for (i = 0; i < n; i++) {
			row = plan->before[i];
			bit = (!!(row & BIT(k)) << next) | (!!(row & BIT(next)) << k);
			plan->before[i] = (row & ~(BIT(k) | BIT(next))) | bit;
		}
	}
	return 0;
}

/* refs[@child] of @st was made from the pointer refs[@parent], see invalidate_reference() */
static bool ref_is_child(const struct bpf_verifier_state *st, int child, int parent)
{
	return st->refs[child].type == REF_TYPE_PTR && st->refs[parent].type == REF_TYPE_PTR &&
	       st->refs[child].parent_id == st->refs[parent].id;
}

/*
 * The resources with a handle that the current frame of @st acquired: refs[] from
 * entry_refs on, oldest first. Which entry is one of them? What a pad does with an entry is a call
 * with what it finds at a place, so that is what an entry is, like a variable with a destructor. It
 * does not matter which insn acquired what is there: an iterator that is destroyed and made again
 * is one entry, two nodes that one insn in a loop took off a list are two. Where that leaves a
 * choice the origin decides.
 * An entry need not be held on all visits. What it takes to find out how the pad can tell is noted
 * here, see settle_ent().
 * The pad releases locks and irq flags in the reverse of the order in which a state took them,
 * and what was made from a pointer before the pointer. Only a state that holds two entries says
 * something about their order, and it must not matter which of the states gets here first: the
 * state that holds both has to find them in its own order, not in the order of the visits. So a
 * visit notes the order of the entries that it holds, pair by pair, see put_before(), and
 * order_ents() puts them in an order that suits all visits when they are over. There is none if
 * two states took two locks in two orders: that is the conflict.
 * Returns the reason of a conflict.
 */
static int visit_refs(struct bpf_verifier_env *env, struct bpf_pad_plan *plan,
		      const struct bpf_verifier_state *st, int insn_idx)
{
	const struct bpf_reference_state *ref;
	struct bpf_pad_ent new, *ent, *prev;
	struct bpf_pad_nulls nulls;
	int i, j, arg, pass, pos, err;

	/* the pad of a call runs after the call: what is live at the next insn is there */
	insn_idx += bpf_site_is_call(plan->kind);
	for (i = 0; i < plan->nr_ents; i++)
		plan->ents[i].ref = -1;
	/*
	 * Each of them takes an entry of its own, also a pointer that no place has: its hidden
	 * slot is an entry, see plan_has_room(). So more of them than a pad has entries are a
	 * conflict, whatever the places are, and it is one of this state. A loop that acquires in
	 * each trip and has no way out but this site has no state that fails for what leaks.
	 */
	for (i = st->frame[st->curframe]->entry_refs, pos = 0; i < st->acquired_refs; i++)
		pos += !i || st->refs[i - 1].type != REF_TYPE_RES_LOCK_IRQ;
	if (pos > BPF_PAD_MAX_ENTS)
		return BPF_CONFLICT_TOO_MUCH;
	for (pass = 0; pass < 2; pass++) {
		for (i = st->frame[st->curframe]->entry_refs; i < st->acquired_refs; i++) {
			ref = &st->refs[i];
			/* irq flags that a lock saved are an argument of its entry */
			if (i && ref[-1].type == REF_TYPE_RES_LOCK_IRQ)
				continue;
			if (held_ent(plan, i))
				continue;
			err = ref_ent(env, &new, st, insn_idx, ref);
			/* no entry: a hidden slot may have it, see plan_needs_slots() */
			if (ref->type == REF_TYPE_PTR &&
			    (err == BPF_CONFLICT_NO_PLACE || err == BPF_CONFLICT_CALLER_SAVED)) {
				plan->no_place = err;
				/* nothing here says what releases it: see settle_plan() */
				plan->no_place_atomic |= !pad_can_sleep(st, false);
				continue;
			}
			/* the same for irq flags that a caller has, see irq_in_caller() */
			if (err == BPF_CONFLICT_NO_PLACE && irq_in_caller(st, ref)) {
				plan->no_irq_place = err;
				continue;
			}
			if (err)
				return err;
			ent = match_ent(plan, &new, !pass);
			if (!ent && !pass)
				continue;
			/* no state holds that much: the entries add up over the visits */
			if (!ent && plan->nr_ents == BPF_PAD_MAX_ENTS)
				return BPF_CONFLICT_PLAN_FULL;
			/* the place of an entry is its number until order_ents() */
			if (!ent)
				ent = add_ent(plan, &new, plan->nr_ents);
			if (!ent)
				return -ENOMEM;
			ent->ref = i;
			/* whichever state comes first: the insn that brings it to the frame first */
			ent->origin = min(ent->origin, new.origin);
			for (arg = 0; arg < BPF_PAD_MAX_ARGS; arg++)
				ent->nr_cands[arg] = common_cands(ent, &new, arg, ent->cand[arg]);
		}
	}
	prev = NULL;
	for (i = st->frame[st->curframe]->entry_refs; i < st->acquired_refs; i++) {
		ent = held_ent(plan, i);
		if (!ent || ent->class >= BPF_PAD_REF)
			continue;
		if (prev && !put_before(plan, prev - plan->ents, ent - plan->ents))
			return BPF_CONFLICT_ORDER_DIFFERS;
		prev = ent;
	}
	for (i = 0; i < plan->nr_ents; i++)
		for (j = 0; j < plan->nr_ents; j++)
			if (plan->ents[i].ref >= 0 && plan->ents[j].ref >= 0 &&
			    ref_is_child(st, plan->ents[j].ref, plan->ents[i].ref) &&
			    !put_before(plan, i, j))
				return BPF_CONFLICT_ORDER_DIFFERS;
	find_nulls(st->frame[st->curframe], &nulls);
	for (i = 0; i < plan->nr_ents; i++) {
		ent = &plan->ents[i];
		if (ent->ref >= 0)
			continue;
		ent->always = false;
		for (j = 0; j < ent->nr_cands[0]; j++)
			ent->cand[0][j].null &= place_is_null(&nulls, &ent->cand[0][j]);
	}
	plan->nulls.regs &= nulls.regs;
	plan->nulls.unsaved &= nulls.unsaved;
	bitmap_and(plan->nulls.slots, plan->nulls.slots, nulls.slots, MAX_BPF_STACK_SLOTS);
	return 0;
}

/*
 * The kernel had brought @st into a landing pad of the program when it got here: a frame of it is
 * one that the kernel unwinds, or the first frame of a function that such a frame called and that
 * is verified on its own. See 'forced' of struct bpf_func_state.
 */
static bool state_is_in_kpad(const struct bpf_verifier_state *st)
{
	int i;

	for (i = 0; i <= st->curframe && st->frame[i]; i++)
		if (st->frame[i]->forced)
			return true;
	return false;
}

/*
 * The current frame of @st is about to be unwound at the site of @kind at @insn_idx. Make the plan
 * of the site serve @st too. A visit at which the frame holds nothing is a visit like any other.
 *
 * Sections: the pad leaves as many as the frame has entered, and enters as many as the frame has
 * left of its callers, see frame_sections(). That is a number of calls in the code of the pad, so
 * it has to be the same on all visits, or the function gets hidden slots.
 *
 * A release may sleep: bpf_iter_kmem_cache_destroy(). A frame can hold such a thing in a section
 * of a caller: it left the section, made the iterator and entered the section again. Then the pad
 * leaves the sections of the callers too ahead of the pointers and enters them again behind the
 * pointers: 'outside' of the plan, as many as the frame is in at the site. The frame has been out
 * of each of them since its call, or there is a conflict, see pad_can_sleep(): the pad takes
 * nothing from the callers that the frame has not taken before. The frame need not have been out
 * of all of them at once, so the main pass does to the state what the pad does, see
 * release_frame_resources() in verifier.c: the callers do not trust their RCU pointers behind the
 * call. A state that holds nothing of the kind is not told, and its frame may never have left
 * the sections: 'outside' is 0 for it, and it has to be the same on all visits.
 *
 * Returns the plan. It tells whether there is a conflict.
 */
struct bpf_pad_plan *bpf_pad_visit(struct bpf_verifier_env *env,
				   const struct bpf_verifier_state *st, int insn_idx,
				   enum bpf_site_kind kind)
{
	const struct bpf_pad_ent *ent;
	struct bpf_pad_plan *plan;
	int i, class, nr, out, err;
	bool sleeps = false;

	plan = bpf_pad_plan_get(env, insn_idx, kind);
	if (!plan)
		return ERR_PTR(-ENOMEM);
	/* how the states got to the function, for the log of a conflict: see bpf_pad_log() */
	if (state_is_in_kpad(st))
		plan->from_kpad = true;
	else
		plan->from_normal = true;
	if (plan->conflict)
		return plan;
	err = visit_refs(env, plan, st, insn_idx);
	if (err < 0)
		return ERR_PTR(err);
	plan->conflict = err;
	for (i = 0; !err && i < plan->nr_ents; i++) {
		ent = &plan->ents[i];
		if (ent->ref < 0 || ent->class < BPF_PAD_REF || !call_sleeps(env, &ent->release))
			continue;
		sleeps = true;
		/* an iterator that RCU protects is destroyed ahead of all else, see enum pad_turn */
		if (ent->rcu || !pad_can_sleep(st, true))
			plan->conflict = BPF_CONFLICT_NO_RELEASE;
	}
	for (class = 0; class < BPF_PAD_NR_SECTIONS; class++) {
		nr = frame_sections(st, class);
		out = sleeps ? caller_sections(st, class) : 0;
		if (abs(nr) + 2 * out > BPF_PAD_MAX_SECTIONS)
			plan->conflict = BPF_CONFLICT_TOO_MUCH;
		else if (plan->visited && plan->sections[class] != nr)
			plan->sections_differ |= BIT(class);
		/* no hidden slot tells how many sections of its callers a frame is in */
		if (plan->visited && plan->outside[class] != out && !plan->conflict)
			plan->conflict = BPF_CONFLICT_SECTIONS_DIFFER;
		plan->sections[class] = nr;
		plan->outside[class] = out;
	}
	plan->visited = true;
	return plan;
}

/* Do the entries @a and @b release with the same call? */
static bool same_release(const struct bpf_pad_ent *a, const struct bpf_pad_ent *b)
{
	return a->class == b->class && a->rcu == b->rcu && a->obj_type == b->obj_type &&
	       !memcmp(&a->release, &b->release, sizeof(a->release));
}

/*
 * Keep of the candidates of @ent those that the entry of a landing pad saves from: R6-R9 and
 * stack slots of the program. None if there is no place: @err. Then the landing pad of the program
 * has to release it, or a place has to be there where the frame is left.
 * None either for what is no pointer, see visit_saves().
 */
static void save_cands(struct bpf_pad_ent *ent, int err)
{
	struct bpf_pad_place *cand = ent->cand[0];
	int i, n = 0;

	for (i = 0; !err && ent->class == BPF_PAD_REF && i < ent->nr_cands[0]; i++)
		if (cand[i].loc == BPF_PLACE_SPILL ||
		    (cand[i].loc == BPF_PLACE_REG && cand[i].at >= BPF_REG_6 &&
		     cand[i].at < BPF_REG_FP))
			cand[n++] = cand[i];
	ent->nr_cands[0] = n;
}

/*
 * What the entry of the landing pad behind the call at @call_idx saves, for the current frame of
 * @st, which the kernel begins to unwind there.
 *
 * The frame holds references, locks, objects. The landing pad of the program releases what it
 * wants to, and what is left is for the verifier, where the frame is left: at unwind_exit, or at a
 * site in the pad. Nothing has the pointers there: the program reads a register for the last time
 * where it releases, or never again on that way. So the entry copies each pointer that a register
 * or a stack slot has behind the call into a SAVE WORD, hidden words of the frame like K:
 *
 *	t = bpf_task_from_pid(pid);		   call bpf_task_from_pid
 *	{					   r6 = r0
 *		Guard g;			   ...
 *						   call wait
 *		v = wait();			   unwind_goto pad
 *	}					   kgoto entry
 *	bpf_task_release(t);			   ...
 *					      pad: call ~Guard
 *						   gotol rest
 *					    entry: ax = K
 *						   if ax != 0 goto 1f
 *						   K = 1
 *						   r0 = r6
 *						   *(u64 *)(r10 - 16) = r0
 *						1: r0 = 0
 *						   gotol pad
 *					     rest: ax = K
 *						   if ax == 0 goto 2f
 *						   r1 = *(u64 *)(r10 - 16)
 *						   if r1 == 0 goto 3f
 *						   call bpf_task_release
 *						3: r0 = V
 *						   r2 = 0
 *						   kexit
 *						2: unwind_exit
 *
 * A word has a POINTER, and nothing else: a value that is the handle wherever the frame is left,
 * whatever the pad does to the registers and to the stack. The address of an object in the stack
 * of a caller, irq flags or an iterator, is no such value: the pad can write to the slots, and
 * then nothing releases through the address any more. Nor is the address of a lock that only a
 * register has. What the frame holds of those has to be released by the landing pad of the
 * program, or has to have a place where the frame is left, like an object in the stack of the
 * frame itself and a lock at a constant address. Otherwise the program is rejected.
 *
 * The words go by POSITION: word j is for the j-th of refs[] that the frame holds at the call,
 * whatever that is. The entry of the plan says so, 'word', and from here on 'saved' of the
 * reference does. That is the one number which the entry stores by, see bpf_pad_kentry_insns(),
 * and which the frame is left by: the state has what is still held there, the word is a place
 * like any other, BPF_PLACE_SAVED, and the plan of that site is made as always, see
 * saved_ptr_ent(). No order of the entries of a plan changes it, and bpf_pad_check_saves() looks
 * at what is emitted once more.
 *   - A word that the entry of a frame has put nothing into is 0, 'saved_mask' of the frame has
 *     which. So two calls that hold more and less can share what follows them: the pad tests.
 *   - Where the pad of the program releases on one way only, the word still has the pointer on
 *     that way. No test tells: a conflict at that site, which rejects the program.
 *
 * What releases a pointer follows from its type, and no register has the pointer where the frame
 * is left: states of two calls that are the same but for that type are one state by then. So a
 * word has ONE KIND of thing in all frames of a function, 'saves' of the subprog: the first call
 * that saves there says which, and a call that would save another kind has a conflict.
 *
 * The states that get to the call may not agree: what the frame holds differs between them, in
 * number or in kind, or they have no place in common for a pointer, or a word would get another
 * kind of thing. That is no error. The entry of this call saves nothing then: 'ksave_off'. What
 * its frames hold where they are left has the places that it had without save words, or none,
 * and that rejects the program.
 * Whether they agree is known when all of them have been here, so a run has the answer of the
 * run before it from its start, see settle_entries(). Every state is asked, also where the entry
 * saves nothing: a pass that keeps more apart may have states that agree, and then the entry
 * saves again.
 * Returns why the entry cannot save, 0 if it can.
 */
static int visit_saves(struct bpf_verifier_env *env, struct bpf_pad_plan *plan,
		       const struct bpf_verifier_state *st, int call_idx)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	struct bpf_subprog_info *sub = &env->subprog_info[frame->subprogno];
	int i, j, n, err, nr = st->acquired_refs - frame->entry_refs;
	struct bpf_pad_place cand[BPF_PAD_MAX_CANDS];
	struct bpf_pad_ent new, *ent;
	struct bpf_pad_save *save;

	if (nr > BPF_PAD_MAX_SAVES)
		return BPF_CONFLICT_TOO_MUCH;
	if (plan->saves && plan->nr_ents != nr)
		return BPF_CONFLICT_SAVES_DIFFER;
	if (!plan->ents)
		plan->ents = kzalloc_objs(*plan->ents, BPF_PAD_MAX_ENTS, BPF_VERIFIER_GFP);
	if (!plan->ents)
		return -ENOMEM;
	for (j = 0; j < nr; j++) {
		i = frame->entry_refs + j;
		ent = &plan->ents[j];
		memset(&new, 0, sizeof(new));
		/* what is no pointer has no word, but it has a position */
		if (st->refs[i].type == REF_TYPE_PTR) {
			err = ref_ent(env, &new, st, call_idx + 1, &st->refs[i]);
			if (err < 0)
				return err;
			save_cands(&new, err);
		}
		if (!plan->saves) {
			*ent = new;
			ent->always = true;
		} else if (!ent->nr_cands[0] != !new.nr_cands[0]) {
			return BPF_CONFLICT_SAVES_DIFFER;
		} else if (new.nr_cands[0]) {
			n = common_cands(ent, &new, 0, cand);
			if (!n || !same_release(ent, &new))
				return BPF_CONFLICT_SAVES_DIFFER;
			memcpy(ent->cand[0], cand, n * sizeof(*cand));
			ent->nr_cands[0] = n;
		}
		if (!ent->nr_cands[0])
			continue;
		ent->word = j + 1;
		save = &sub->saves[j];
		if (!save->set)
			*save = (struct bpf_pad_save){ .release = ent->release,
						       .obj_type = ent->obj_type, .set = true };
		if (!ent_is_saved_kind(sub, j, ent))
			return BPF_CONFLICT_SAVES_DIFFER;
	}
	plan->nr_ents = nr;
	plan->saves = true;
	return 0;
}

/*
 * The kernel unwound what the call at @call_idx called, and the current frame of @st goes on in
 * the landing pad that the program has behind the call, see enter_kernel_pad() in verifier.c. The
 * plan of the entry is no plan of a pad: the frame is not left, and nothing is released. It says
 * that the call has an entry, and what the entry does when it is the first one of the frame: it
 * keeps the value of the kernel, and the pointers that the frame holds, see visit_saves(). The
 * references of @st and its frame are marked for what has a save word, with the number that the
 * entry of the plan has for it. Not where the entry saves nothing, 'ksave_off': the state goes on
 * as it is.
 * A frame that the kernel unwinds already keeps what it has: its entry stores nothing.
 * With a conflict the state ends here. bpf_pads_settle() has the pass done again with an entry
 * that saves nothing, or rejects the program: in a program with bpf_throw() the value of the
 * kernel, R0, has to be a number.
 * Returns the plan.
 */
struct bpf_pad_plan *bpf_pad_enter(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
				   int call_idx)
{
	struct bpf_func_state *frame = st->frame[st->curframe];
	struct bpf_pad_plan *plan;
	int j, word, err;

	plan = bpf_pad_plan_get(env, call_idx, BPF_SITE_KENTRY);
	if (!plan)
		return ERR_PTR(-ENOMEM);
	plan->visited = true;
	/* the entry is the second one of this frame, and has to test K: collect_pads() asks */
	plan->forced_visit |= bpf_frame_is_forced(frame);
	if (plan->conflict || bpf_frame_is_forced(frame))
		return plan;
	if (env->has_throw && frame->regs[BPF_REG_0].type != SCALAR_VALUE) {
		plan->conflict = BPF_CONFLICT_NO_VALUE;
		return plan;
	}
	if (!plan->no_saves) {
		err = visit_saves(env, plan, st, call_idx);
		if (err < 0)
			return ERR_PTR(err);
		plan->no_saves = err;
	}
	if (env->insn_aux_data[call_idx + 1].ksave_off)
		return plan;
	err = plan->conflict = plan->no_saves;
	/* entry j is what refs[] has at position j until all visits are over: nothing sorts them */
	for (j = 0; !err && j < plan->nr_ents; j++) {
		word = plan->ents[j].word;
		if (!word)
			continue;
		st->refs[frame->entry_refs + j].saved = word;
		frame->saved_mask |= BIT(word - 1);
	}
	return plan;
}

/* The group of @class */
static int class_group(int class)
{
	if (class < BPF_PAD_NR_SECTIONS)
		return class;
	return class < BPF_PAD_REF ? BPF_PAD_GROUP_LOCKS : BPF_PAD_GROUP_REFS;
}

/* How many of refs[@from] .. refs[@to - 1] of @st are of @group */
static int count_refs(const struct bpf_verifier_state *st, int from, int to, int group)
{
	int i, n = 0;

	for (i = from; i < to; i++)
		n += class_group(ref_class(&st->refs[i])) == group;
	return n;
}

/* NULL if there is no memory */
static struct bpf_pad_note *pad_note_get(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];

	if (!aux->pad_note)
		aux->pad_note = kzalloc_obj(*aux->pad_note, BPF_VERIFIER_GFP);
	return aux->pad_note;
}

/*
 * What the current insn does to a resource of @group concerns a frame that waits in a call, where
 * no store can follow it. It may be the same object that another frame holds once more. So none
 * of the functions on the stack gets hidden slots for @group.
 */
void bpf_pad_no_slots(struct bpf_verifier_env *env, enum bpf_pad_group group)
{
	const struct bpf_verifier_state *st = env->cur_state;
	int f;

	for (f = 0; f <= st->curframe; f++)
		env->subprog_info[st->frame[f]->subprogno].no_slots |= BIT(group);
}

/*
 * The current insn releases a resource of @group that a caller of its frame acquired, or leaves a
 * section that a caller entered. If the kernel had brought the state into a landing pad of the
 * program, that is noted too, for the log of a conflict that hidden slots would have settled, see
 * bpf_pad_log().
 */
static void released_of_caller(struct bpf_verifier_env *env, enum bpf_pad_group group)
{
	const struct bpf_verifier_state *st = env->cur_state;
	int f;

	bpf_pad_no_slots(env, group);
	if (!state_is_in_kpad(st))
		return;
	for (f = 0; f <= st->curframe; f++)
		env->subprog_info[st->frame[f]->subprogno].no_slots_kpad |= BIT(group);
}

/*
 * Make @ent what a hidden slot is to a plan if it has what is in @reg: the handle of @ref, which
 * is one of refs[] of @st, plus a constant. @by_type: no insn of the function acquired @ref.
 * False if there is no such entry.
 */
static bool slot_ent(struct bpf_verifier_env *env, struct bpf_pad_ent *ent,
		     const struct bpf_verifier_state *st, const struct bpf_reference_state *ref,
		     const struct bpf_reg_state *reg, bool by_type)
{
	s64 off = reg->var_off.value;
	int err = 0;

	if (!tnum_is_const(reg->var_off))
		return false;
	memset(ent, 0, sizeof(*ent));
	ent->ref = -1;
	ent->class = ref_class(ref);
	ent->nr_cands[0] = 1;
	ent->cand[0][0] = (struct bpf_pad_place){ .loc = BPF_PLACE_SPILL, .null = true };
	if (ent->class == BPF_PAD_RES_LOCK_IRQ)
		ent->cand[1][ent->nr_cands[1]++] = ent->cand[0][0];
	if (ent->class != BPF_PAD_REF) {
		ent->release = release_call(ent->class);
	} else if (reg->type == PTR_TO_STACK) {
		err = obj_ent(env, ent, ref, bpf_stack_slot(st->frame[reg->frameno],
							    -off / BPF_REG_SIZE - 1));
	} else {
		ent->cand[0][0].delta = off;
		err = by_type ? type_release(env, reg, 0, &ent->release) :
				ref_release(env, ref, reg, false, &ent->release);
		err = err ?: ent_imm(env, ent, reg);
		err = err ?: off != (s16)off;
	}
	return !err;
}

/*
 * The call at @insn_idx, in @sub, brings @ent to a frame that holds @held of the group. R@src goes
 * to the slot. The stores at an insn and the entry of its slots are code: all states that get to
 * the insn have to agree on them. Locks and irq flags are released in the order of the run, which
 * slots don't have: one at a time.
 */
static void note_acquire(struct bpf_verifier_env *env, struct bpf_subprog_info *sub, int insn_idx,
			 const struct bpf_pad_ent *ent, int src, int held)
{
	struct bpf_pad_note *note = pad_note_get(env, insn_idx);
	int group = class_group(ent->class);

	if (!note) {
		sub->no_slots |= BIT(group);
		return;
	}
	if (!note->acquires) {
		note->acquires = true;
		note->src = src;
		note->ent = *ent;
		note->ent.origin = insn_idx;
	}
	if (note->src != src || note->ent.class != ent->class || note->ent.rcu != ent->rcu ||
	    memcmp(&note->ent.release, &ent->release, sizeof(ent->release)) ||
	    note->ent.obj_type != ent->obj_type ||
	    note->ent.cand[0][0].delta != ent->cand[0][0].delta ||
	    held >= BPF_PAD_MAX_ENTS || (held && group == BPF_PAD_GROUP_LOCKS))
		sub->no_slots |= BIT(group) | BIT(class_group(note->ent.class));
	else
		note->held = max_t(int, note->held, held);
}

/*
 * The current insn acquired the youngest of refs[]. @reg has what the release takes: R0, or the
 * argument that is the address of the lock or of the object in the stack.
 * No slot: the argument is in the stack. A reference with a parent, which has to be released
 * first. bpf_map_lookup_elem(): what it returns has to be released if the map has sockets.
 */
void bpf_pad_note_acquire(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	const struct bpf_insn *insn = &env->prog->insnsi[env->insn_idx];
	const struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_reference_state *ref = &st->refs[st->acquired_refs - 1];
	struct bpf_subprog_info *sub = &env->subprog_info[frame->subprogno];
	int group = class_group(ref_class(ref));
	struct bpf_pad_ent ent;

	if (reg < &frame->regs[BPF_REG_0] || reg > &frame->regs[BPF_REG_5] ||
	    (ref->type == REF_TYPE_PTR && ref->parent_id) ||
	    (bpf_helper_call(insn) && insn->imm == BPF_FUNC_map_lookup_elem) ||
	    !slot_ent(env, &ent, st, ref, reg, false) ||
	    !can_release_under_lock(env, st, frame, &ent))
		sub->no_slots |= BIT(group);
	else
		note_acquire(env, sub, env->insn_idx, &ent, reg - frame->regs,
			     count_refs(st, frame->entry_refs, st->acquired_refs - 1, group));
}

/*
 * If @ref is an object in the stack: its first slot, and its address goes to @addr.
 * NULL otherwise.
 */
static const struct bpf_stack_state *find_obj(const struct bpf_verifier_state *st,
					      const struct bpf_reference_state *ref,
					      struct bpf_reg_state *addr)
{
	int f, i;

	for (f = st->curframe; f >= 0 && !(ref->type & REF_TYPE_LOCK_MASK); f--) {
		for (i = 0; i < bpf_stack_nr_slots(st->frame[f]); i++) {
			if (!slot_is_obj(st->frame[f], i, ref))
				continue;
			*addr = st->frame[f]->regs[BPF_REG_FP];
			addr->var_off = tnum_const(-(i + 1) * BPF_REG_SIZE);
			return bpf_stack_slot(st->frame[f], i);
		}
	}
	return NULL;
}

/* The current insn, in @sub, releases a resource of @group. R@reg has the handle plus @delta. */
static void note_release(struct bpf_verifier_env *env, struct bpf_subprog_info *sub, int group,
			 int reg, int delta)
{
	struct bpf_pad_note *note = pad_note_get(env, env->insn_idx);

	if (!note) {
		sub->no_slots |= BIT(group);
		return;
	}
	if (!note->releases) {
		note->releases = true;
		note->group = group;
		note->reg = reg;
		note->delta = delta;
	}
	if (note->group != group || note->reg != reg || note->delta != delta)
		sub->no_slots |= BIT(group) | BIT(note->group);
}

/*
 * The current insn releases refs[@idx] of the current state. The slot that has the handle is found
 * at run time, by the register among R1-R5 that has it too. A register that the insn does not
 * read may have anything in a state that was not looked at.
 */
void bpf_pad_note_release(struct bpf_verifier_env *env, int idx)
{
	const struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_func_state *frame = st->frame[st->curframe];
	const struct bpf_reference_state *ref = &st->refs[idx];
	struct bpf_subprog_info *sub = &env->subprog_info[frame->subprogno];
	int r, nr = 0, group = class_group(ref_class(ref));
	const struct bpf_stack_state *obj;
	struct bpf_pad_place place = {};
	struct bpf_reg_state addr;

	if (env->pad_releases)
		return;
	if (idx < frame->entry_refs) {
		released_of_caller(env, group);
		return;
	}
	obj = find_obj(st, ref, &addr);
	/* irq flags that a lock saved are the second word of its slot */
	if (ref->type == REF_TYPE_IRQ && obj && obj->spilled_ptr.irq.kfunc_class == IRQ_LOCK_KFUNC)
		return;
	for (r = BPF_REG_1; r <= BPF_REG_5 && !nr; r++)
		if (env->insn_aux_data[env->insn_idx].live_regs_before & BIT(r))
			add_cand(&place, &nr, &frame->regs[r], ref, obj ? &addr : NULL,
				 BPF_PLACE_REG, r);
	if (!nr || place.delta != (s16)place.delta)
		sub->no_slots |= BIT(group);
	else
		note_release(env, sub, group, place.at, place.delta);
}

/* The current insn enters a section of @class, or leaves one. It has not changed the state yet. */
void bpf_pad_note_section(struct bpf_verifier_env *env, enum bpf_pad_class class, bool enter)
{
	const struct bpf_verifier_state *st = env->cur_state;
	struct bpf_subprog_info *sub = &env->subprog_info[st->frame[st->curframe]->subprogno];
	struct bpf_pad_ent ent = {
		.ref = -1,
		.class = class,
		.release = release_call(class),
		.nr_cands[0] = 1,
		.cand[0][0] = { .loc = BPF_PLACE_SPILL, .null = true },
	};

	if (enter)
		note_acquire(env, sub, env->insn_idx, &ent, 0, max(frame_sections(st, class), 0));
	else if (frame_sections(st, class) > 0)
		note_release(env, sub, class, 0, 0);
	else
		released_of_caller(env, class_group(class));
}

/*
 * The current frame of @st returns to the call at @call_idx in @caller, with what it acquired and
 * did not release. @plain: with exit, and it is no callback.
 * One pointer that is in R0 is what a kfunc returns: the call acquires it. What releases it follows
 * from its type: states with the same pointer from different insns are the same to the main pass.
 * The store after the call takes R0 as it is, so it has to be 0 when nothing comes with it.
 * Nothing else has a store: it goes past the store if the frame unwinds.
 */
void bpf_pad_note_return(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			 const struct bpf_func_state *caller, int call_idx, bool plain)
{
	const struct bpf_func_state *callee = st->frame[st->curframe];
	const struct bpf_reference_state *ref = &st->refs[callee->entry_refs];
	struct bpf_subprog_info *sub = &env->subprog_info[caller->subprogno];
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[call_idx];
	const struct bpf_reg_state *r0 = &callee->regs[BPF_REG_0];
	int i, nr = st->acquired_refs - callee->entry_refs, in_r0 = 0;
	struct bpf_pad_place place;
	struct bpf_pad_ent ent;

	for (i = 0; i < BPF_PAD_NR_SECTIONS; i++)
		if (frame_sections(st, i))
			sub->no_slots |= BIT(i);
	if (plain && nr == 1 && ref->type == REF_TYPE_PTR && !ref->parent_id)
		add_ref_cand(&place, &in_r0, r0, ref, BPF_PLACE_REG, BPF_REG_0);
	if (in_r0 && slot_ent(env, &ent, st, ref, r0, true) &&
	    can_release_under_lock(env, st, caller, &ent)) {
		note_acquire(env, sub, call_idx, &ent, BPF_REG_0,
			     count_refs(st, caller->entry_refs, callee->entry_refs,
					BPF_PAD_GROUP_REFS));
	} else {
		for (i = 0; i < nr; i++)
			sub->no_slots |= BIT(class_group(ref_class(&ref[i])));
		aux->call_brings_nothing |= plain && !reg_is_null(r0);
	}
	if (aux->call_brings_nothing && aux->pad_note && aux->pad_note->acquires)
		sub->no_slots |= BIT(BPF_PAD_GROUP_REFS);
}

/* The pad finds out by itself whether it has to release @ent: what is at the place may be 0 */
static bool ent_is_tested(const struct bpf_pad_ent *ent)
{
	return !ent->always || ent->cand[0][0].maybe_null;
}

/*
 * R@reg = the handle that is at @place. @test: if there is 0 the entry is not held, the second insn
 * is a jump, and release_ents() knows where to. It comes first: 0 minus the delta is not 0.
 * Returns the number of insns.
 */
static int load_handle(struct bpf_verifier_env *env, struct bpf_insn *buf,
		       struct bpf_insn_aux_data *aux, int reg, const struct bpf_pad_place *place,
		       bool test)
{
	const struct bpf_map *map;
	u64 addr = 0;
	int n = 0;

	switch (place->loc) {
	case BPF_PLACE_REG:
		buf[n++] = BPF_MOV64_REG(reg, place->at);
		break;
	case BPF_PLACE_SPILL:
		buf[n++] = BPF_LDX_MEM(BPF_DW, reg, BPF_REG_FP, place->at);
		break;
	case BPF_PLACE_MAP_VALUE:
		/* what check_and_resolve_insns() makes of such an insn. find_lock_cands() asked. */
		map = env->used_maps[place->at];
		map->ops->map_direct_value_addr(map, &addr, -place->delta);
		addr -= place->delta;
		aux[n].map_index = place->at;
		aux[n].map_off = -place->delta;
		buf[n++] = BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, reg, BPF_PSEUDO_MAP_VALUE, 0,
					(u32)addr);
		buf[n++] = BPF_RAW_INSN(0, 0, 0, 0, addr >> 32);
		return n;
	case BPF_PLACE_IMM:
		buf[n++] = BPF_MOV64_IMM(reg, place->delta);
		return n;
	}
	if (test)
		buf[n++] = BPF_JMP_IMM(BPF_JEQ, reg, 0, 0);
	if (place->delta)
		buf[n++] = BPF_ALU64_IMM(BPF_ADD, reg, -place->delta);
	return n;
}

/*
 * The turns of a pad. Few functions can be called under a lock, and a release may sleep: locks and
 * irq flags go first, then the pad leaves the sections, pointers and objects go last.
 * An iterator that RCU protects goes ahead of them all: a section or irq flags may be what protects
 * it, see in_rcu_cs(). So it goes under the locks of the frame, see can_release_under_lock().
 */
enum pad_turn {
	/* the sections of callers that the frame left are entered behind all three */
	PAD_TURN_RCU_ITERS,
	PAD_TURN_LOCKS,
	PAD_TURN_POINTERS,
};

static enum pad_turn release_turn(const struct bpf_pad_ent *ent)
{
	if (ent->rcu)
		return PAD_TURN_RCU_ITERS;
	return ent->class < BPF_PAD_REF ? PAD_TURN_LOCKS : PAD_TURN_POINTERS;
}

/*
 * How many sections of @class the pad of @plan leaves ahead of the pointers: those that the frame
 * is in beyond the sections of its call, and those of its callers if a release may sleep
 */
static int pad_leaves(const struct bpf_pad_plan *plan, enum bpf_pad_class class)
{
	return max(plan->sections[class], 0) + plan->outside[class];
}

/*
 * How many it enters behind them, so that the frame is unwound in the sections of its call: those
 * of its callers that the frame has left, and those that the pad itself left for the release
 */
static int pad_enters(const struct bpf_pad_plan *plan, enum bpf_pad_class class)
{
	return max(-plan->sections[class], 0) + plan->outside[class];
}

/* The insns that release the entries of @plan whose turn it is, the youngest first */
static int release_ents(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan,
			enum pad_turn turn, struct bpf_insn *buf, struct bpf_insn_aux_data *aux)
{
	const struct bpf_pad_ent *ent;
	int i, arg, first, n = 0;

	for (i = plan->nr_ents - 1; i >= 0; i--) {
		ent = &plan->ents[i];
		if (release_turn(ent) != turn)
			continue;
		first = n;
		for (arg = 0; arg < BPF_PAD_MAX_ARGS && ent->nr_cands[arg]; arg++)
			n += load_handle(env, &buf[n], &aux[n], BPF_REG_1 + arg, &ent->cand[arg][0],
					 !arg && ent_is_tested(ent));
		if (is_obj_drop(&ent->release))
			aux[n].kptr_struct_meta = btf_find_struct_meta(env->prog->aux->btf,
								       ent->obj_type);
		buf[n++] = ent->release;
		if (ent_is_tested(ent))
			buf[first + 1].off = n - first - 2;
	}
	return n;
}

/*
 * The kernel called @subprog, and its pads end the invocation with exit: the main program, whose
 * unwind_exit is exit to the JITs as well, see bpf_prog_can_unwind(), and an async callback that
 * cannot leave unwound, see unwind_exit_insn(). They tell a struct_ops that wants to know, see
 * bpf_prog_report_unwound().
 * An async callback that can leave unwound has callers in the program, or is expected to. It has
 * one pad for all its frames, which ends in kexit, or in unwind_exit for what the program unwinds,
 * and cannot tell who called. kexit can: where the kernel called it finds no landing pad, and
 * tells the struct_ops at run time, see bpf_prog_unwound_to_kernel(). So such a pad tells nobody,
 * and one of the two tells, once. unwind_exit that gets to the kernel tells nobody: the program
 * chose that way out.
 * A pad that ends the invocation tells whatever its site is: also the pad of a call without
 * unwind_goto to which unwind_exit of a callee came back, which is an unwind of the program's own.
 * That tells about more than the kernel has stopped, and it misses nothing that the kernel has: such
 * a pad of the main program calls the exception callback, which the kernel can unwind in turn, and
 * the pads of that callback tell nobody.
 * The exception callback is called by a pad of the main program, which has told already.
 */
static bool pad_reports(const struct bpf_verifier_env *env, int subprog)
{
	const struct bpf_struct_ops *st_ops = env->prog->aux->st_ops;
	const struct bpf_subprog_info *sub = &env->subprog_info[subprog];

	if (!st_ops || !st_ops->unwound || sub->is_exception_cb)
		return false;
	return !subprog || (sub->is_async_cb && !sub->bail_unwinds);
}

/*
 * The landing pad of a site of @kind in @subprog passes R2 on with R0, see bpf_pad_passes_on(): in
 * a subprog that returns two registers. Not out of a global subprog, which passes nothing on: its
 * callers take what comes out for numbers, also where the callee of this frame returns one
 * register and left R2 as it happened to be. R2 is 0 there, as it is at kexit.
 */
bool bpf_pad_passes_r2(struct bpf_verifier_env *env, int subprog, enum bpf_site_kind kind)
{
	return bpf_pad_passes_on(env, subprog, kind) && bpf_ret_reg_pair(env, subprog);
}

/* The calls of the pad of @plan, a site in @subprog, clobber the value that it has to pass on */
static bool plan_saves_value(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan,
			     int subprog)
{
	return (bpf_site_has_value(env, subprog, plan->kind) ||
		bpf_pad_passes_on(env, subprog, plan->kind)) &&
	       (plan->nr_ents || plan->sections[BPF_PAD_RCU] || plan->sections[BPF_PAD_PREEMPT] ||
		pad_reports(env, subprog));
}


/*
 * The insns of the landing pad of @plan, a site in @subprog, but for the last one, which leaves the
 * frame. The passes that follow the emission look up in the aux data of an insn what the main pass
 * notes there. It does not see these insns: what it would note goes to @aux, one per insn.
 * Returns the number of insns, less than BPF_PAD_MAX_INSNS.
 */
int bpf_pad_insns(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan, int subprog,
		  struct bpf_insn *buf, struct bpf_insn_aux_data *aux)
{
	struct bpf_insn ld_aux[2] = { BPF_LD_IMM64(BPF_REG_1, (long)env->prog->aux) };
	int value_off = env->subprog_info[subprog].value_off;
	int src = bpf_site_value_reg(plan->kind), dst = BPF_REG_0;
	bool passes_on = bpf_pad_passes_on(env, subprog, plan->kind);
	bool pair = bpf_pad_passes_r2(env, subprog, plan->kind);
	int class, i, n = 0;

	/* the main program hands the value to the exception callback */
	if (!subprog && env->exception_callback_subprog)
		dst = BPF_REG_1;
	if (plan_saves_value(env, plan, subprog)) {
		buf[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, src, value_off);
		if (pair)
			buf[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_2,
					       value_off + BPF_REG_SIZE);
	}
	n += release_ents(env, plan, PAD_TURN_RCU_ITERS, &buf[n], &aux[n]);
	n += release_ents(env, plan, PAD_TURN_LOCKS, &buf[n], &aux[n]);
	for (class = 0; class < BPF_PAD_NR_SECTIONS; class++)
		for (i = 0; i < pad_leaves(plan, class); i++)
			buf[n++] = release_call(class);
	n += release_ents(env, plan, PAD_TURN_POINTERS, &buf[n], &aux[n]);
	/* the sections of the callers: last, a release of a pointer may sleep */
	for (class = 0; class < BPF_PAD_NR_SECTIONS; class++)
		for (i = 0; i < pad_enters(plan, class); i++)
			buf[n++] = enter_call(class);
	if (pad_reports(env, subprog)) {
		buf[n++] = ld_aux[0];
		buf[n++] = ld_aux[1];
		buf[n++] = BPF_EMIT_KERNEL_CALL(bpf_prog_report_unwound);
	}
	if (bpf_site_is_forced(plan->kind) && env->has_throw) {
		/* what the unwinding of the frame began with: no pad on its way writes the word */
		buf[n++] = BPF_LDX_MEM(BPF_DW, dst, BPF_REG_FP, value_off);
	} else if (plan_saves_value(env, plan, subprog)) {
		buf[n++] = BPF_LDX_MEM(BPF_DW, dst, BPF_REG_FP, value_off);
		if (pair)
			buf[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_FP,
					       value_off + BPF_REG_SIZE);
	} else if (passes_on) {
		/* no call: R0 and R2 are what unwind_exit left */
	} else if (!bpf_site_has_value(env, subprog, plan->kind)) {
		buf[n++] = BPF_MOV64_IMM(dst, bpf_unwound_retval(env));
	} else if (src != dst) {
		buf[n++] = BPF_MOV64_REG(dst, src);
	}
	/*
	 * kexit has 0 in R2: nothing of the frame is left for the pad of kgoto to look at. So has
	 * every other pad of a subprog that returns two registers, unless it passes R2 on.
	 */
	if (bpf_pad_kexits(env, subprog, plan->kind) ||
	    (!pair && bpf_ret_reg_pair(env, subprog)))
		buf[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
	return n;
}

/* Is the first call of the pad of @plan the release of @ent? See bpf_pad_insns(). */
static bool released_first(const struct bpf_pad_plan *plan, const struct bpf_pad_ent *ent)
{
	const struct bpf_pad_ent *other;
	int i;

	for (i = 0; i < plan->nr_ents; i++) {
		other = &plan->ents[i];
		if (release_turn(other) < release_turn(ent) ||
		    (release_turn(other) == release_turn(ent) && other > ent))
			return false;
	}
	/* the sections that the pad enters come behind the pointers, see bpf_pad_insns() */
	return release_turn(ent) != PAD_TURN_POINTERS ||
	       (!pad_leaves(plan, BPF_PAD_RCU) && !pad_leaves(plan, BPF_PAD_PREEMPT));
}

/*
 * How does the pad of @plan tell whether @ent is held? See the comment at the top. The candidate
 * that is emitted goes first. Returns the reason of a conflict.
 */
static int settle_ent(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan,
		      struct bpf_pad_ent *ent)
{
	struct bpf_pad_place *cand = ent->cand[0];
	int i;

	for (i = 0; i < ent->nr_cands[0] && !ent->always && !cand[i].null; i++)
		;
	if (i == ent->nr_cands[0])
		return BPF_CONFLICT_NOT_ALWAYS_HELD;
	swap(cand[0], cand[i]);
	if (place_is_caller_saved(&cand[0]) && !released_first(plan, ent))
		return BPF_CONFLICT_CALLER_SAVED;
	/* R1 is loaded first */
	if (ent->nr_cands[1] && place_is_caller_saved(&ent->cand[1][0]))
		return BPF_CONFLICT_CALLER_SAVED;
	return get_release(env, &ent->release);
}

/* All visits of @plan are over. Returns the reason of a conflict. */
static int settle_plan(struct bpf_verifier_env *env, struct bpf_pad_plan *plan)
{
	struct bpf_insn release;
	int i, class, err = plan->conflict;

	if (!err && plan->sections_differ)
		err = BPF_CONFLICT_SECTIONS_DIFFER;
	err = err ?: plan->no_place;
	err = err ?: plan->no_irq_place;
	for (i = 0; !err && i < plan->nr_ents; i++)
		err = settle_ent(env, plan, &plan->ents[i]);
	/*
	 * A pointer that no place had is released through its hidden slot, whatever it is. A slot
	 * may sleep, and on a visit with such a pointer the pad cannot.
	 */
	for (i = 0; !err && plan->no_place_atomic && i < plan->nr_ents; i++)
		if (plan->ents[i].class >= BPF_PAD_REF && call_sleeps(env, &plan->ents[i].release))
			err = BPF_CONFLICT_NO_RELEASE;
	for (class = 0; !err && class < BPF_PAD_NR_SECTIONS; class++) {
		release = release_call(class);
		if (pad_leaves(plan, class))
			err = get_release(env, &release);
		release = enter_call(class);
		if (!err && pad_enters(plan, class))
			err = get_release(env, &release);
	}
	return err;
}

/*
 * Is the pad the only way out of the site of @plan, whatever the subprog turns out to be? An access
 * to arena that faults can be skipped, and may_goto of the program can jump where the program
 * says, as they do in a subprog that cannot unwind. So can all of them below a call, unless a
 * subprog comes back to the call that is left elsewhere.
 */
bool bpf_pad_must_unwind(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan)
{
	const struct bpf_subprog_info *sub;
	int s;

	/*
	 * The frame was being unwound when it got to the site. What began that is asked: the call
	 * behind which the kernel entered a landing pad of the program, BPF_SITE_KENTRY.
	 */
	if (bpf_site_is_forced(plan->kind))
		return false;
	if (!bpf_site_is_call(plan->kind))
		return plan->kind != BPF_SITE_FAULT && plan->kind != BPF_SITE_MAY_GOTO;
	/* the callees came back to the call in the way of the plan, and that way is asked */
	bpf_pad_for_each_callee(plan, s) {
		sub = &env->subprog_info[s];
		if (bpf_site_is_kernel(plan->kind) ? sub->must_kunwind : sub->must_unwind)
			return true;
	}
	return false;
}

/*
 * What a subprog is left for may be found after its callers were unwound: look at them again.
 * The frame of a call is left in the way in which the callee came back.
 * Callees first: callx and a cycle of calls need more rounds.
 */
int bpf_pads_must_unwind(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *sub;
	const struct bpf_pad_plan *plan;
	bool changed, must, kmust;
	int i, k, err;

	do {
		changed = false;
		err = bpf_add_cost_and_check(env, env->prog->len, BPF_COST_SCAN);
		if (err)
			return err;
		for (k = 0; k < env->subprog_cnt; k++) {
			sub = &env->subprog_info[env->subprog_topo_order[k]];
			must = sub->must_unwind;
			kmust = sub->must_kunwind;
			for (i = sub->start; i < sub[1].start && !(must && kmust); i++) {
				for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next) {
					if (!bpf_site_is_call(plan->kind) ||
					    !bpf_pad_must_unwind(env, plan))
						continue;
					if (bpf_site_is_kernel(plan->kind))
						kmust = true;
					else
						must = true;
				}
			}
			changed |= must != sub->must_unwind || kmust != sub->must_kunwind;
			sub->must_unwind = must;
			sub->must_kunwind = kmust;
		}
	} while (changed);
	return 0;
}

static const char * const site_kind[] = {
	[BPF_SITE_GUARD]		= "may_goto",
	[BPF_SITE_RECURSION]		= "recursion check",
	[BPF_SITE_CALL]			= "call",
	[BPF_SITE_FAULT]		= "arena access",
	[BPF_SITE_THROW]		= "bpf_throw",
	[BPF_SITE_MAY_GOTO]		= "may_goto of the program",
	[BPF_SITE_KCALL]		= "call",
	[BPF_SITE_KENTRY]		= "call",
	[BPF_SITE_REMAINDER]		= "unwind_exit",
};

/* The program has unwind_exit in the subprog. No site: the last bit, far from those of the kinds. */
#define LEFT_AT_UNWIND_EXIT	BIT(15)

/*
 * What comes back to the call of @plan was left at sites of the @kinds of a callee: with kexit
 * at those where the kernel unwinds, with unwind_exit where the program has it.
 */
static u16 kinds_of_plan(const struct bpf_pad_plan *plan, u16 kinds)
{
	return bpf_site_is_kernel(bpf_site_base(plan->kind)) ? kinds & ~LEFT_AT_UNWIND_EXIT
							     : kinds & LEFT_AT_UNWIND_EXIT;
}

/*
 * At which kinds of site does the program leave each subprog? At its own, and at those of what
 * comes back to its calls. Bits by enum bpf_site_kind in 'left_at'. The main pass notes them as
 * the states leave, see bpf_pad_note_left(). This is what is left of that when the pass is over.
 * Callees first: callx and a cycle of calls need more rounds.
 */
static int sites_of_subprogs(struct bpf_verifier_env *env)
{
	const struct bpf_insn_aux_data *aux = env->insn_aux_data;
	const struct bpf_pad_plan *plan;
	struct bpf_subprog_info *sub;
	int i, k, s, c, err;
	bool changed;
	u16 kinds;

	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		sub->left_at = sub->can_unwind && s ? LEFT_AT_UNWIND_EXIT : 0;
	}
	do {
		changed = false;
		err = bpf_add_cost_and_check(env, env->prog->len, BPF_COST_SCAN);
		if (err)
			return err;
		for (k = 0; k < env->subprog_cnt; k++) {
			sub = &env->subprog_info[env->subprog_topo_order[k]];
			kinds = sub->left_at;
			for (i = sub->start; i < sub[1].start; i++) {
				if (aux[i].loop_guard)
					kinds |= BIT(BPF_SITE_GUARD);
				if (aux[i].fault_empty && !aux[i].fault_skips)
					kinds |= BIT(BPF_SITE_FAULT);
				for (plan = aux[i].pad_plans; plan; plan = plan->next) {
					/* the frame is not left at the entry of a pad */
					if (!plan->used || plan->kind == BPF_SITE_KENTRY)
						continue;
					/* a frame that the kernel unwinds: wherever it is left */
					if (bpf_site_is_forced(plan->kind)) {
						kinds |= BIT(BPF_SITE_REMAINDER);
						continue;
					}
					if (!bpf_site_is_call(plan->kind)) {
						kinds |= BIT(plan->kind);
						continue;
					}
					bpf_pad_for_each_callee(plan, c)
						kinds |= kinds_of_plan(plan,
								       env->subprog_info[c].left_at);
				}
			}
			changed |= kinds != sub->left_at;
			sub->left_at = kinds;
		}
	} while (changed);
	return 0;
}

/*
 * The kinds of site that the subprogs which come back to the call of @plan are left at. The main
 * pass asks before sites_of_subprogs() has looked at them: unwind_exit of the program is no site
 * that a state would have noted.
 */
static u16 sites_below(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan)
{
	u16 kinds = 0;
	int s;

	bpf_pad_for_each_callee(plan, s) {
		kinds |= env->subprog_info[s].left_at;
		if (env->subprog_info[s].can_unwind)
			kinds |= LEFT_AT_UNWIND_EXIT;
	}
	return kinds_of_plan(plan, kinds);
}

/*
 * Why the call of @plan at insn @i is a site: where the program leaves what it calls. It goes in
 * front of the conflict, which ends the log.
 */
static void print_sites_below(struct bpf_verifier_env *env, int i, const struct bpf_pad_plan *plan)
{
	u16 kinds;
	int k;

	if (!bpf_site_is_call(plan->kind))
		return;
	kinds = sites_below(env, plan);
	verbose(env, "what the call at %d calls is left at:", i);
	for (k = 0; k <= BPF_SITE_MAY_GOTO; k++)
		if (kinds & BIT(k))
			verbose(env, " %s%s", site_kind[k], kinds >> (k + 1) ? "," : "");
	if (kinds & BIT(BPF_SITE_REMAINDER))
		verbose(env, " a landing pad of the program");
	if (kinds & LEFT_AT_UNWIND_EXIT)
		verbose(env, " unwind_exit");
	verbose(env, "\n");
}

/* The frame of the site of @plan cannot unwind: there is no pad to plan */
static bool plan_is_stuck(const struct bpf_pad_plan *plan)
{
	return plan->conflict == BPF_CONFLICT_CANNOT_UNWIND ||
	       plan->conflict == BPF_CONFLICT_NO_EXIT;
}

/*
 * Is the conflict of @plan an error? It is one at every site: a prog that goes on from a loop that
 * was out of time, or from an access that faulted, was not verified. But not where the frame cannot
 * unwind and the site has another way out, see bpf_pad_must_unwind(): what comes back to a call
 * there is stuck, see bpf_pad_skip_faults().
 * A frame that the kernel unwinds through a landing pad of the program has no other way out,
 * wherever it is left, and neither has the entry of such a pad: the kernel enters the pad, or the
 * program is rejected.
 */
static bool plan_rejects(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan)
{
	if (plan->kind == BPF_SITE_KENTRY || bpf_site_is_forced(plan->kind))
		return plan->conflict;
	return plan->conflict && (bpf_pad_must_unwind(env, plan) || !plan_is_stuck(plan));
}

/*
 * Does an insn of @sub acquire an iterator or a dynptr? If none does, a reference of its frame that
 * no place has is a pointer in every run, and the slot of the call that returned it has it. What
 * comes to the frame in another way is noted in 'no_slots'.
 */
static bool acquires_stack_obj(struct bpf_verifier_env *env, const struct bpf_subprog_info *sub)
{
	const struct bpf_pad_note *note;
	int i;

	for (i = sub->start; i < sub[1].start; i++) {
		note = env->insn_aux_data[i].pad_note;
		if (note && note->acquires && note->ent.class > BPF_PAD_REF)
			return true;
	}
	return false;
}

/*
 * The groups of which @plan has something that its pad cannot tell whether it is held, or where.
 * Slots are stores on the normal path: none for a site that the program does not have.
 * @all_ptrs: no insn of the function acquires an iterator or a dynptr.
 */
static u8 plan_needs_slots(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan,
			   bool all_ptrs)
{
	u8 groups = plan->sections_differ;
	int i, err;

	if (!plan->used || plan->conflict)
		return 0;
	/*
	 * Nor for a frame that the kernel unwinds through a landing pad of the program: the
	 * normal path pays no store for a way that only the kernel takes. Without a plan there
	 * the program is rejected. Its pads do use the slots that the function has for another
	 * site, see plan_take_slots().
	 */
	if (bpf_site_is_forced(plan->kind) || plan->kind == BPF_SITE_KENTRY)
		return 0;
	if (plan->no_place && all_ptrs)
		groups |= BIT(BPF_PAD_GROUP_REFS);
	if (plan->no_irq_place)
		groups |= BIT(BPF_PAD_GROUP_LOCKS);
	for (i = 0; i < plan->nr_ents; i++) {
		err = settle_ent(env, plan, &plan->ents[i]);
		if (err == BPF_CONFLICT_NOT_ALWAYS_HELD || err == BPF_CONFLICT_CALLER_SAVED)
			groups |= BIT(class_group(plan->ents[i].class));
	}
	return groups;
}

/*
 * The groups that the conflict of @plan would not be one with hidden slots for: what the conflict
 * is about, of what @plan asked for when the slots were settled, see settle_slots(), and did not
 * get. A plan that had its conflict by then asked for nothing: a lock that no place has on a visit
 * is not what a slot is for, see visit_refs().
 */
static u8 conflict_groups(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan)
{
	u8 groups = 0;
	int i;

	switch (plan->conflict) {
	case BPF_CONFLICT_SECTIONS_DIFFER:
		groups = plan->sections_differ;
		break;
	case BPF_CONFLICT_NO_PLACE:
		groups = BIT(BPF_PAD_GROUP_REFS);
		if (plan->no_irq_place)
			groups |= BIT(BPF_PAD_GROUP_LOCKS);
		break;
	case BPF_CONFLICT_NOT_ALWAYS_HELD:
	case BPF_CONFLICT_CALLER_SAVED:
		for (i = 0; i < plan->nr_ents; i++)
			if (settle_ent(env, plan, &plan->ents[i]) == plan->conflict)
				groups |= BIT(class_group(plan->ents[i].class));
		/* 'no_place' of the plan can be the same reason, see settle_plan() */
		if (plan->no_place)
			groups |= BIT(BPF_PAD_GROUP_REFS);
		break;
	default:
		break;
	}
	return groups & plan->asked_slots;
}

/* The slot of bpf_res_spin_lock_irqsave() has a word for the second argument of the release */
static int slot_words(const struct bpf_pad_note *note)
{
	return note->ent.class == BPF_PAD_RES_LOCK_IRQ ? 2 : 1;
}

/* Does the pad of @plan run in a frame that has set up its hidden slots? */
static bool plan_has_slots(const struct bpf_pad_plan *plan)
{
	return bpf_site_base(plan->kind) != BPF_SITE_RECURSION &&
	       plan->kind != BPF_SITE_KENTRY && !plan->conflict;
}

/* Has @plan room for @slots entries in place of those that it has of @group? */
static bool plan_has_room(const struct bpf_pad_plan *plan, int group, int slots)
{
	int i;

	for (i = 0; i < plan->nr_ents; i++)
		slots += class_group(plan->ents[i].class) != group;
	return slots <= BPF_PAD_MAX_ENTS;
}

/*
 * The pad of @plan releases what the frame holds of @group through the hidden slots of the @nr
 * calls @notes and in no other way. A slot is an entry that is tested. For the order of a pad, see
 * enum pad_turn, the slots of sections go before all entries, those of references after
 * them, those of locks and irq flags after all entries.
 * @all_ptrs: the slots have all that the frame holds of references.
 */
static int plan_take_slots(struct bpf_pad_plan *plan, int group, struct bpf_pad_note **notes,
			   int nr, bool all_ptrs)
{
	struct bpf_pad_ent new, *ent;
	int i, k, pos = 0;

	for (i = 0, k = 0; i < plan->nr_ents; i++)
		if (class_group(plan->ents[i].class) != group)
			plan->ents[k++] = plan->ents[i];
	plan->nr_ents = k;
	if (group < BPF_PAD_NR_SECTIONS) {
		plan->sections[group] = 0;
		plan->sections_differ &= ~BIT(group);
	}
	if (all_ptrs)
		plan->no_place = 0;
	if (group == BPF_PAD_GROUP_LOCKS) {
		plan->no_irq_place = 0;
		pos = plan->nr_ents;
	}
	while (group == BPF_PAD_GROUP_REFS && pos < plan->nr_ents &&
	       plan->ents[pos].class < BPF_PAD_NR_SECTIONS)
		pos++;
	for (i = 0; i < nr; i++) {
		for (k = 0; k < notes[i]->nr_slots; k++) {
			new = notes[i]->ent;
			new.cand[0][0].at = notes[i]->off - k * BPF_REG_SIZE;
			if (slot_words(notes[i]) == 2)
				new.cand[1][0].at = notes[i]->off - BPF_REG_SIZE;
			ent = add_ent(plan, &new, pos++);
			if (!ent)
				return -ENOMEM;
			ent->always = false;
			ent->cand[0][0].null = true;
		}
	}
	return 0;
}

/*
 * Give subprog @s hidden slots for all that it acquires of @group, below its stack: every access of
 * the program to the frame, also one of a callee through a pointer, has raised stack_depth.
 * A call that is on no cycle runs once per frame: one slot. Any other has one more than the frame
 * holds of the group when it gets there, so that one is free.
 * Returns 0 if that cannot be: a release that the program cannot call, no room in a pad or in the
 * stack.
 */
static int subprog_take_slots(struct bpf_verifier_env *env, int s, int group)
{
	struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_pad_note *note, *notes[BPF_PAD_MAX_ENTS];
	bool all_ptrs = group == BPF_PAD_GROUP_REFS && !acquires_stack_obj(env, sub);
	int i, err, nr = 0, slots = 0, words = 0;
	struct bpf_pad_plan *plan;

	for (i = sub->start; i < sub[1].start; i++) {
		note = aux[i].pad_note;
		if (!note || !note->acquires || class_group(note->ent.class) != group)
			continue;
		err = nr < BPF_PAD_MAX_ENTS ? get_release(env, &note->ent.release) : 1;
		if (err)
			return min(err, 0);
		notes[nr++] = note;
		note->nr_slots = bpf_loop_at_index(env, i) < 0 ? 1 : 1 + note->held;
		note->off = -(int)bpf_stack_depth_with_slots(sub) - (words + 1) * BPF_REG_SIZE;
		slots += note->nr_slots;
		words += note->nr_slots * slot_words(note);
	}
	if (!nr)
		return 0;
	/* a plan of a frame that the kernel unwinds has a conflict instead, see below */
	for (i = sub->start; i < sub[1].start; i++)
		for (plan = aux[i].pad_plans; plan; plan = plan->next)
			if (plan->used && plan_has_slots(plan) &&
			    !bpf_site_is_forced(plan->kind) &&
			    !plan_has_room(plan, group, slots))
				return 0;
	sub->hidden_words += words;
	err = bpf_hidden_slots_fit(env);
	if (err <= 0) {
		sub->hidden_words -= words;
		return err;
	}
	for (i = sub->start; i < sub[1].start; i++) {
		for (plan = aux[i].pad_plans; plan; plan = plan->next) {
			/* the program does not have its site, or the kernel unwinds its frame */
			if (plan_has_slots(plan) && !plan_has_room(plan, group, slots))
				plan->conflict = BPF_CONFLICT_SLOTS_FULL;
			err = plan_has_slots(plan) ?
			      plan_take_slots(plan, group, notes, nr, all_ptrs) : 0;
			if (err)
				return err;
		}
	}
	sub->slots |= BIT(group);
	return 1;
}

/*
 * Hidden slots are the fallback: a subprog gets them for a group of which one of its plans has
 * something that the pad cannot tell otherwise. A slot takes the first call of a pad from an entry
 * that is in R0-R5, so look again. If the subprog cannot have them its plans stay as they are.
 */
static int settle_slots(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_subprog_info *sub;
	struct bpf_pad_plan *plan;
	int i, s, err;
	bool all_ptrs;
	u8 need, asks;

	for (s = 0; s < env->subprog_cnt; s++) {
		env->subprog_info[s].slots = 0;
		env->subprog_info[s].hidden_words = 0;
		env->subprog_info[s].value_off = 0;
		env->subprog_info[s].no_value_word = false;
		env->subprog_info[s].k_off = 0;
		env->subprog_info[s].save_off = 0;
		env->subprog_info[s].save_words = 0;
	}
	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		all_ptrs = !acquires_stack_obj(env, sub);
		do {
			if (bpf_must_abort())
				return -EINTR;
			need = 0;
			for (i = sub->start; i < sub[1].start; i++) {
				for (plan = aux[i].pad_plans; plan; plan = plan->next) {
					asks = plan_needs_slots(env, plan, all_ptrs);
					/* for the log of a conflict, see conflict_groups() */
					plan->asked_slots |= asks;
					need |= asks;
				}
			}
			need &= ~sub->no_slots;
			err = need ? subprog_take_slots(env, s, __ffs(need)) : 0;
			if (err < 0)
				return err;
			if (need && !err)
				sub->no_slots |= BIT(__ffs(need));
		} while (need);
	}
	return 0;
}

static bool note_has_slots(const struct bpf_subprog_info *sub, const struct bpf_pad_note *note)
{
	return note && note->acquires && (sub->slots & BIT(class_group(note->ent.class)));
}

/*
 * The calls of subprog @s that have hidden slots go to @notes, which has room for BPF_PAD_MAX_ENTS.
 * A slot is an entry of each plan of the subprog, so all groups together have no more slots than
 * that, see plan_has_room(), and the insns of the stores are sized for as many, see
 * BPF_PAD_MAX_SLOT_INSNS. Nothing else keeps the calls that few: check it where they are written.
 * Returns how many there are.
 */
int bpf_pad_slot_notes(struct bpf_verifier_env *env, int s, const struct bpf_pad_note **notes)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[s];
	const struct bpf_pad_note *note;
	int i, nr = 0, slots = 0;

	for (i = sub->start; i < sub[1].start; i++) {
		note = env->insn_aux_data[i].pad_note;
		if (!note_has_slots(sub, note))
			continue;
		slots += note->nr_slots;
		if (verifier_bug_if(slots > BPF_PAD_MAX_ENTS, env,
				    "func#%d has %d hidden slots, a landing pad has %d entries",
				    s, slots, BPF_PAD_MAX_ENTS))
			return -EFAULT;
		notes[nr++] = note;
	}
	return nr;
}

/*
 * The entry of a function: all words of its hidden slots are 0. The frame holds nothing of its own,
 * and a pad reads all slots, also at a site that is before the calls that fill them.
 * And in a MIXED function K is 0: the kernel is not unwinding the frame. There an insn is pad code
 * and on the normal path as well, see find_pad_code(), so what tests K can be reached from the
 * first insn of the function with no landing in between that would write the word. Such a
 * function pays one store per call for the landing pads that the kernel enters. Any other function
 * has no store for K here: its stubs and its entries write the word, see kernel/bpf/pads.c.
 */
int bpf_pad_entry_insns(const struct bpf_subprog_info *sub, const struct bpf_pad_note **notes,
			int nr, struct bpf_insn *buf)
{
	int i, k, n = 0;

	for (i = 0; i < nr; i++)
		for (k = 0; k < notes[i]->nr_slots * slot_words(notes[i]); k++)
			buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, notes[i]->off - k * BPF_REG_SIZE,
					      0);
	if (bpf_subprog_clears_k(sub))
		buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, sub->k_off, 0);
	return n;
}

/*
 * The entry of @plan, the plan of an entry, whose pointer goes to save word @word of @sub, see
 * visit_saves(). NULL if the entry of the landing pad puts 0 there.
 */
static const struct bpf_pad_ent *saved_ent(const struct bpf_subprog_info *sub,
					   const struct bpf_pad_plan *plan, int word)
{
	int j;

	/* the function has hidden slots for pointers: every pad releases through them */
	if (sub->slots & BIT(BPF_PAD_GROUP_REFS))
		return NULL;
	for (j = 0; j < plan->nr_ents; j++)
		if (plan->ents[j].word == word + 1)
			return &plan->ents[j];
	return NULL;
}

/*
 * The entry of a landing pad of the program that the kernel enters, see enter_kernel_pad() in
 * verifier.c: kgoto behind the call goes here, and from here the program goes on in its pad. But for
 * the last insn, which is that jump.
 *
 *	ax = K				behind a call in pad code:
 *	if ax != 0 goto 1f		the kernel unwinds the frame already
 *	K = 1
 *	*(u64 *)(r10 - W) = r0		in a program with bpf_throw(): the value
 *	r0 = r6				per save word of the function: the pointer, see
 *	*(u64 *)(r10 - S) = r0		visit_saves(), or 0
 * 1:	r0 = 0
 *
 * The first entry of a frame decides: K stays 1 until the frame is left, and the value that the
 * program ends with is the one that the unwinding began with, whatever unwinds on the way. The
 * pad gets 0 in R0, where unwind_exit of the program leaves what the program threw: the value of
 * the kernel is none of its business, and a pad that takes R0 for an object of the program finds
 * none.
 * Only a call in pad code can be the second entry of a frame: a frame that the kernel unwinds runs
 * nothing else, see bpf_find_kernel_pads(). So only the entry of such a call tests K. Behind any
 * other call the entry is the first one, 'untested' of its plan, and stores without the two insns
 * of the test: it must not read the word, which nothing has written on that way. In a mixed
 * function no call is known to be such a one, every entry tests, and the entry of the function
 * clears K for them.
 * A pointer that the program has not compared with NULL yet can be 0: so is the handle then.
 * The pointer goes through R0, which has the value no longer and is 0 behind the entry. Where the
 * register of the program has more than the handle, the constant that is taken off is one that
 * the program chose: an insn on R0 is blinded like any other, one on AX is not.
 * Returns the number of insns.
 */
int bpf_pad_kentry_insns(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan,
			 int subprog, struct bpf_insn *buf, struct bpf_insn_aux_data *aux)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[subprog];
	const struct bpf_pad_place *place;
	const struct bpf_pad_ent *ent;
	int word, off, first, n = 0;

	if (!plan->untested) {
		buf[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, sub->k_off);
		buf[n++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, 0);
	}
	buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, sub->k_off, 1);
	if (env->has_throw)
		buf[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_0, sub->value_off);
	for (word = 0; word < sub->save_words; word++) {
		off = sub->save_off + word * BPF_REG_SIZE;
		ent = saved_ent(sub, plan, word);
		if (!ent) {
			buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, off, 0);
			continue;
		}
		place = &ent->cand[0][0];
		first = n;
		n += load_handle(env, &buf[n], &aux[n], BPF_REG_0, place, place->delta);
		if (place->delta)
			buf[first + 1].off = 1;
		buf[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_0, off);
	}
	if (!plan->untested)
		buf[1].off = n - 2;
	buf[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
	return n;
}

/*
 * The save words of subprog @s are about to be emitted: stored by the entries of its landing pads,
 * see bpf_pad_kentry_insns(), and read where a frame that the kernel unwinds is left. A reference
 * has one number for both, see visit_saves(). Look at what the plans have made of it:
 *   - An entry stores a pointer into a word that the function has, each into another one, and its
 *     kind is the one of the word.
 *   - A landing pad that reads a word releases that kind, and the plan of an entry has a pointer
 *     for the word. Also one that the program does not have in the end: then every entry stores
 *     0 there. The word is a slot of the stack in its plan, see take_kernel_words().
 * A release of what another reference than its own left in a word must not load.
 */
int bpf_pad_check_saves(struct bpf_verifier_env *env, int s)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[s];
	const struct bpf_insn_aux_data *aux = env->insn_aux_data;
	const struct bpf_pad_place *place;
	const struct bpf_pad_plan *plan;
	const struct bpf_pad_ent *ent;
	u16 stored = 0, words;
	int i, j, word;

	for (i = sub->start; i < sub[1].start; i++) {
		plan = bpf_pad_plan(&aux[i], BPF_SITE_KENTRY);
		words = 0;
		for (j = 0; plan && j < plan->nr_ents; j++) {
			ent = &plan->ents[j];
			word = ent->word - 1;
			if (word < 0)
				continue;
			stored |= BIT(word);
			if (!plan->used || plan->conflict)
				continue;
			if (verifier_bug_if(word >= sub->save_words || (words & BIT(word)) ||
					    !ent->nr_cands[0] || !ent_is_saved_kind(sub, word, ent),
					    env, "the entry at insn %d stores into save word %d",
					    i, word))
				return -EFAULT;
			words |= BIT(word);
		}
	}
	for (i = sub->start; i < sub[1].start; i++) {
		for (plan = aux[i].pad_plans; plan; plan = plan->next) {
			if (!plan->used || plan->conflict || !bpf_site_is_forced(plan->kind))
				continue;
			for (j = 0; j < plan->nr_ents; j++) {
				ent = &plan->ents[j];
				/* the candidate that is emitted: a word is a stack slot by now */
				place = &ent->cand[0][0];
				/* load_handle() has no insn for any other form of it */
				if (verifier_bug_if(ent->nr_cands[0] &&
						    place->loc == BPF_PLACE_SAVED, env,
						    "a save word of the pad of insn %d is no slot",
						    i))
					return -EFAULT;
				if (!ent->nr_cands[0] || place->loc != BPF_PLACE_SPILL ||
				    place->at < sub->save_off)
					continue;
				word = (place->at - sub->save_off) / BPF_REG_SIZE;
				if (word >= sub->save_words)
					continue;
				if (verifier_bug_if(!(stored & BIT(word)) ||
						    !ent_is_saved_kind(sub, word, ent), env,
						    "the landing pad of insn %d reads save word %d",
						    i, word))
					return -EFAULT;
			}
		}
	}
	return 0;
}

/*
 * The call of @note acquires: a slot takes what the release takes, unconditionally. 0 in R0 means
 * that nothing was acquired, and 0 in a slot means the same. A section has no handle: 1.
 * If the call has several slots the first one that is 0 is filled. The frame holds no more than
 * 'held' of the group, so there is one.
 */
static int set_insns(const struct bpf_pad_note *note, struct bpf_insn *buf)
{
	int k, n = 0, nr = note->nr_slots, off = note->off;

	for (k = 0; k < nr; k++, off -= BPF_REG_SIZE) {
		if (nr > 1) {
			buf[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, off);
			buf[n++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, k == nr - 1 ? 1 : 2);
		}
		if (note->ent.class < BPF_PAD_NR_SECTIONS)
			buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, off, 1);
		else
			buf[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, note->src, off);
		if (k < nr - 1)
			buf[n++] = BPF_JMP_A((nr - 1 - k) * 4 - 1);
	}
	/* the irq flags, the next argument: the pad reads the word if the slot is not 0 */
	if (slot_words(note) == 2)
		buf[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, note->src + 1, off);
	return n;
}

/*
 * The call of @rel releases: the slot of the group that has the handle is cleared, whichever call
 * filled it in this run. The first match ends the search: two references to one object are the
 * same handle in two slots, and one of them is released. No match: the call was given NULL.
 * Sections are all alike: the first slot that is not 0.
 */
static int clear_insns(const struct bpf_pad_note **notes, int nr, const struct bpf_pad_note *rel,
		       struct bpf_insn *buf)
{
	int i, k, n = 0, off, delta, reg;

	for (i = 0; i < nr; i++) {
		if (class_group(notes[i]->ent.class) != rel->group)
			continue;
		delta = rel->delta - notes[i]->ent.cand[0][0].delta;
		/*
		 * The delta is made of constants that the program chose, the offsets of a node in
		 * its object. It is added in R0, which a call is about to clobber: there the JIT
		 * blinds it like any other constant of the program. An insn on AX is not blinded.
		 */
		reg = delta ? BPF_REG_0 : BPF_REG_AX;
		for (k = 0; k < notes[i]->nr_slots; k++) {
			off = notes[i]->off - k * BPF_REG_SIZE;
			buf[n++] = BPF_LDX_MEM(BPF_DW, reg, BPF_REG_FP, off);
			if (delta)
				buf[n++] = BPF_ALU64_IMM(BPF_ADD, reg, delta);
			if (rel->group < BPF_PAD_NR_SECTIONS)
				buf[n++] = BPF_JMP_IMM(BPF_JEQ, reg, 0, 2);
			else
				buf[n++] = BPF_JMP_REG(BPF_JNE, reg, rel->reg, 2);
			buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, off, 0);
			buf[n++] = BPF_JMP_A(0);
		}
	}
	/* nothing follows the last slot */
	buf[--n - 2].off = 1;
	for (i = 0; i < n; i++)
		if (buf[i].code == (BPF_JMP | BPF_JA))
			buf[i].off = n - i - 1;
	return n;
}

/* The insns that go before the call of @note in @sub. @notes: the @nr calls with slots. */
int bpf_pad_insns_before(const struct bpf_subprog_info *sub, const struct bpf_pad_note **notes,
			 int nr, const struct bpf_pad_note *note, struct bpf_insn *buf)
{
	int n = 0;

	if (note && note->releases && (sub->slots & BIT(note->group)))
		n = clear_insns(notes, nr, note, buf);
	/* an address that the call takes. The resource is held when the call returns. */
	if (note_has_slots(sub, note) && note->ent.class != BPF_PAD_REF)
		n += set_insns(note, &buf[n]);
	return n;
}

/* The insns that go after the call of @note, which is in @sub */
int bpf_pad_insns_after(const struct bpf_subprog_info *sub, const struct bpf_pad_note *note,
			struct bpf_insn *buf)
{
	int n = 0;

	if (!note_has_slots(sub, note))
		return 0;
	if (note->ent.class == BPF_PAD_REF)
		return set_insns(note, buf);
	/* the lock was not taken. The upper half of an int is not defined. */
	if (note->ent.class == BPF_PAD_RES_LOCK || note->ent.class == BPF_PAD_RES_LOCK_IRQ) {
		buf[n++] = BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 0, 1);
		buf[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, note->off, 0);
	}
	return n;
}

/*
 * Sites whose pads have the same insns share one. But not a pad that frees an object of the
 * program: the same insns free another type at another site, see ent_imm().
 */
bool bpf_pad_can_be_shared(const struct bpf_pad_plan *plan)
{
	int i;

	for (i = 0; i < plan->nr_ents; i++)
		if (is_obj_drop(&plan->ents[i].release))
			return false;
	return true;
}

/*
 * 'spin_lock@5(r6-8)': what insn 5 brought to the frame, the arguments of its release.
 * 'if not 0': the pad tests the first one.
 */
static void print_ent(struct bpf_verifier_env *env, const struct bpf_pad_ent *ent)
{
	static const char * const class[] = {
		[BPF_PAD_RCU]			= "rcu",
		[BPF_PAD_PREEMPT]		= "preempt",
		[BPF_PAD_IRQ]			= "irq",
		[BPF_PAD_RES_LOCK]		= "res_lock",
		[BPF_PAD_RES_LOCK_IRQ]		= "res_lock_irq",
		[BPF_PAD_SPIN_LOCK]		= "spin_lock",
		[BPF_PAD_REF]			= "ref",
		[BPF_PAD_ITER]			= "iter",
		[BPF_PAD_DYNPTR]		= "dynptr",
	};
	const struct bpf_pad_place *place;
	int arg;

	verbose(env, "%s@%d(", class[ent->class], ent->origin);
	for (arg = 0; arg < BPF_PAD_MAX_ARGS && ent->nr_cands[arg]; arg++) {
		place = &ent->cand[arg][0];
		verbose(env, "%s", arg ? ", " : "");
		if (place->loc == BPF_PLACE_SPILL)
			verbose(env, "*fp%d", place->at);
		else if (place->loc == BPF_PLACE_MAP_VALUE)
			verbose(env, "map#%d", place->at);
		else if (place->loc == BPF_PLACE_IMM)
			verbose(env, "%d", place->delta);
		else if (place->loc == BPF_PLACE_SAVED)
			verbose(env, "saved#%d", place->at);
		else if (place->at == BPF_REG_FP)
			verbose(env, "fp");
		else
			verbose(env, "r%d", place->at);
		if (place->delta && place->loc != BPF_PLACE_IMM)
			verbose(env, "%+d", -place->delta);
	}
	verbose(env, ")%s ", ent_is_tested(ent) ? " if not 0" : "");
}

static const char * const conflict_why[] = {
	[BPF_CONFLICT_SECTIONS_DIFFER]	= "the number of sections differs",
	[BPF_CONFLICT_TOO_MUCH]		= "too much is held",
	[BPF_CONFLICT_PLAN_FULL]	=
		"the paths to the site hold more different things than a pad releases",
	[BPF_CONFLICT_SLOTS_FULL]	= "the function has more hidden slots than a pad has entries",
	[BPF_CONFLICT_NO_RELEASE]	= "the program can call nothing that releases a resource",
	[BPF_CONFLICT_NOT_ALWAYS_HELD]	= "a resource is held on some paths only",
	[BPF_CONFLICT_NO_PLACE]		= "no place has the handle on all paths",
	[BPF_CONFLICT_ORDER_DIFFERS]	= "the order of the releases differs",
	[BPF_CONFLICT_CANNOT_UNWIND]	=
		"the JIT or the helper that calls the function cannot unwind it",
	[BPF_CONFLICT_NO_EXIT]		= "the function has no exit",
	[BPF_CONFLICT_NO_PERFMON]	= "the program is loaded without CAP_PERFMON",
	[BPF_CONFLICT_CALLER_SAVED]	= "a handle is in R0-R5 only",
	[BPF_CONFLICT_NO_VALUE]		= "the value of unwind_exit is not a number",
	[BPF_CONFLICT_NO_ROOM]		= "no room in the stack for the value",
	[BPF_CONFLICT_SAVES_DIFFER]	= "what the frames hold at the call differs",
};

/* The plan of the site at insn @i, or why there is none */
static void print_plan(struct bpf_verifier_env *env, int i, const struct bpf_pad_plan *plan)
{
	int j;

	/* no pad of the verifier: the landing pad of the program, with code in front of it */
	if (plan->kind == BPF_SITE_KENTRY) {
		verbose(env, "landing pad of the program behind the call at %d: the kernel enters it",
			i);
		for (j = 0; j < plan->nr_ents; j++) {
			if (!plan->ents[j].nr_cands[0])
				continue;
			verbose(env, ", saves ");
			print_ent(env, &plan->ents[j]);
		}
		verbose(env, "\n");
		return;
	}
	/*
	 * A call has one for what the kernel unwinds, and one for unwind_exit of the program. And
	 * any site one more for the frames that the kernel unwinds already.
	 */
	verbose(env, "landing pad of %s at %d%s%s: ", site_kind[bpf_site_base(plan->kind)], i,
		bpf_site_base(plan->kind) == BPF_SITE_CALL ? " for unwind_exit" : "",
		bpf_site_is_forced(plan->kind) ? " in a frame that the kernel unwinds" : "");
	for (j = plan->nr_ents - 1; !plan->conflict && j >= 0; j--)
		print_ent(env, &plan->ents[j]);
	if (plan->conflict)
		verbose(env, "conflict: %s\n", conflict_why[plan->conflict]);
	else if (plan->outside[BPF_PAD_RCU] || plan->outside[BPF_PAD_PREEMPT])
		verbose(env, "rcu=%d preempt=%d sleeps outside rcu=%d preempt=%d\n",
			plan->sections[BPF_PAD_RCU], plan->sections[BPF_PAD_PREEMPT],
			plan->outside[BPF_PAD_RCU], plan->outside[BPF_PAD_PREEMPT]);
	else
		verbose(env, "rcu=%d preempt=%d\n", plan->sections[BPF_PAD_RCU],
			plan->sections[BPF_PAD_PREEMPT]);
}

/*
 * The insns that get to insn @at over the edges of the control flow graph, @at included: a bitmap
 * of the program. NULL if there is no memory.
 * The walk is for the log and is not charged. So it goes back from @at over each edge of the
 * function once: a walk over the insns until nothing changes takes a round per loop on the way.
 */
static unsigned long *insns_that_reach(struct bpf_verifier_env *env, int at)
{
	const struct bpf_subprog_info *sub = bpf_find_containing_subprog(env, at);
	unsigned long *reach = bitmap_zalloc(env->prog->len, BPF_VERIFIER_GFP);
	/* an edge, and 1 + the edge before it that goes to the same insn */
	struct { u32 from, prev; } *edges = NULL, *edge;
	/* per insn: 1 + the last edge that goes to it. And the insns to walk back from. */
	u32 *last, *todo;
	struct bpf_iarray *succ;
	int i, p, t, nr = 0, top = 0;

	last = kvcalloc(env->prog->len, sizeof(*last), BPF_VERIFIER_GFP);
	todo = kvmalloc_array(env->prog->len, sizeof(*todo), BPF_VERIFIER_GFP);
	if (!reach || !last || !todo)
		goto err;
	for (p = sub->postorder_start; p < sub[1].postorder_start; p++) {
		i = env->cfg.insn_postorder[p];
		succ = bpf_insn_successors(env, i);
		iarray_for_each(t, succ) {
			edge = bpf_table_next(edges, nr);
			if (!edge)
				goto err;
			*edge = (typeof(*edge)){ i, last[t] };
			last[t] = ++nr;
		}
	}
	__set_bit(at, reach);
	todo[top++] = at;
	while (top) {
		t = todo[--top];
		for (p = last[t]; p; p = edges[p - 1].prev) {
			i = edges[p - 1].from;
			if (!__test_and_set_bit(i, reach))
				todo[top++] = i;
		}
	}
out:
	kvfree(edges);
	kvfree(last);
	kvfree(todo);
	return reach;
err:
	bitmap_free(reach);
	reach = NULL;
	goto out;
}

/* The first insn of the landing pad that the program has behind the call at @call_idx */
static int pad_of_call(struct bpf_verifier_env *env, int call_idx)
{
	return call_idx + 2 + bpf_jmp_offset(&env->prog->insnsi[call_idx + 1]);
}

/*
 * The call behind which the kernel enters the first landing pad of the program in @sub, -1 if it
 * enters none. *@more: how many more of them @sub has. With @reach only the pads whose first insn
 * is in that bitmap count, see insns_that_reach().
 * A pass that is over knows the entries that the program has in the end, 'used'. Until then those
 * that a state went through have to do.
 */
static int first_entered_pad(struct bpf_verifier_env *env, const struct bpf_subprog_info *sub,
			     const unsigned long *reach, int *more)
{
	const struct bpf_insn_aux_data *aux = env->insn_aux_data;
	const struct bpf_pad_plan *plan;
	int i, used, first = -1;

	for (used = 1; used >= 0 && first < 0; used--) {
		*more = 0;
		for (i = sub->start; sub->has_kpads && i < sub[1].start; i++) {
			plan = bpf_pad_plan(&aux[i], BPF_SITE_KENTRY);
			if (!plan || !(used ? plan->used : plan->visited))
				continue;
			if (reach && !test_bit(pad_of_call(env, i), reach))
				continue;
			if (first < 0)
				first = i;
			else
				(*more)++;
		}
	}
	return first;
}

/*
 * The log of an error that is one because the kernel enters landing pads of the program in @sub:
 * the start of the line that says so, which names the first of them, of those that count, see
 * first_entered_pad(). False if there is none.
 */
static bool print_entered_pad(struct bpf_verifier_env *env, const struct bpf_subprog_info *sub,
			      const unsigned long *reach)
{
	int more, call = first_entered_pad(env, sub, reach, &more);

	if (call < 0)
		return false;
	verbose(env, "the kernel would enter the landing pad at %d of the call at %d",
		pad_of_call(env, call), call);
	if (more)
		verbose(env, ", and %d more of func#%d", more, (int)(sub - env->subprog_info));
	verbose(env, ": ");
	return true;
}

/*
 * A conflict that a landing pad of the program can make in a frame above its own: its code
 * releases what a caller holds, a lock or a section, on some ways out of its function only, or
 * writes to the stack of a caller, where irq flags or an iterator are. Not a conflict that is
 * there whatever a callee does: one state that holds too much, a release that the program cannot
 * call, a value that is no number, a frame that cannot unwind.
 */
static bool pad_can_cause(enum bpf_pad_conflict conflict)
{
	switch (conflict) {
	case BPF_CONFLICT_SECTIONS_DIFFER:
	case BPF_CONFLICT_PLAN_FULL:
	case BPF_CONFLICT_SLOTS_FULL:
	case BPF_CONFLICT_NOT_ALWAYS_HELD:
	case BPF_CONFLICT_NO_PLACE:
	case BPF_CONFLICT_ORDER_DIFFERS:
	case BPF_CONFLICT_CALLER_SAVED:
		return true;
	default:
		return false;
	}
}

/*
 * The entries of @sub that save nothing, see visit_saves(), of the landing pads whose first insn
 * is in @reach: what their frames still hold has the places that it has without save words.
 */
static void print_saves_nothing(struct bpf_verifier_env *env, const struct bpf_subprog_info *sub,
				const unsigned long *reach)
{
	const struct bpf_insn_aux_data *aux = env->insn_aux_data;
	const struct bpf_pad_plan *plan;
	int i;

	for (i = sub->start; i < sub[1].start - 1; i++) {
		plan = bpf_pad_plan(&aux[i], BPF_SITE_KENTRY);
		if (plan && plan->visited && aux[i + 1].ksave_off &&
		    test_bit(pad_of_call(env, i), reach))
			verbose(env, "the entry of the landing pad of the call at %d saves nothing\n",
				i);
	}
}

/*
 * The conflict of @plan, a site at insn @i, is an error. The kernel enters a landing pad of the
 * program that only resumes or the program is rejected: where such a pad has a part in the
 * conflict the log says so, in front of the line of the conflict. It names a pad only where that
 * pad is known to have the part.
 *   - The plan is that of an entry: it has no value to keep.
 *   - The frame is one that the kernel unwinds through such a pad: it has no plan where the pad
 *     ends, or at a site in pad code. A frame does not know which entry it came through: the
 *     first pad of the function that gets to the insn on the control flow graph is named, and
 *     the others that do are counted. An entry of those that saves nothing is named too.
 *   - States got to the site out of such a pad, in a function that the pad calls. Its frame
 *     does not know the pad. If states of the normal path got there as well, the function is
 *     "also" called from the pad: the conflict may be one without the pad.
 *   - What came back to the call of the plan left a frame below through such a pad, which may
 *     have taken from what the frame of the call holds, or written to its stack. Which pad it
 *     was is not known, and a pad on the way may have done nothing of the kind: the function
 *     that came back is named, the pad is in it or below it.
 *   - Such a pad released what a caller holds, and no function on the stack gets hidden slots
 *     for that, see released_of_caller(): the plan needed them for it.
 */
static void print_kpad_conflict(struct bpf_verifier_env *env, int i, const struct bpf_pad_plan *plan)
{
	const struct bpf_subprog_info *sub = bpf_find_containing_subprog(env, i);
	unsigned long *reach;
	int s, c = -1;

	if (!bpf_verifier_log_needed(&env->log))
		return;
	if (plan->kind == BPF_SITE_KENTRY) {
		verbose(env, "the kernel would enter the landing pad at %d of the call at %d: its entry has no value to keep: %s\n",
			pad_of_call(env, i), i, conflict_why[plan->conflict]);
		return;
	}
	if (bpf_site_is_forced(plan->kind)) {
		reach = insns_that_reach(env, i);
		if (reach && print_entered_pad(env, sub, reach)) {
			if (plan->kind == BPF_SITE_REMAINDER)
				verbose(env, "what the pad leaves at unwind_exit at %d cannot be released\n",
					i);
			else
				verbose(env, "a site in its code has no plan\n");
			print_saves_nothing(env, sub, reach);
		}
		bitmap_free(reach);
		return;
	}
	if (plan->from_kpad)
		verbose(env, "func#%d is %scalled from a landing pad of the program that the kernel would enter\n",
			(int)(sub - env->subprog_info), plan->from_normal ? "also " : "");
	if (!pad_can_cause(plan->conflict))
		return;
	if (bpf_site_is_call(plan->kind) && (sites_below(env, plan) & BIT(BPF_SITE_REMAINDER)))
		bpf_pad_for_each_callee(plan, s)
			if (c < 0 && (env->subprog_info[s].left_at & BIT(BPF_SITE_REMAINDER)))
				c = s;
	if (c >= 0)
		verbose(env, "the kernel would enter a landing pad of the program in or below func#%d: it may release or overwrite what a caller holds at the call at %d\n",
			c, i);
	else if (sub->no_slots_kpad & conflict_groups(env, plan))
		verbose(env, "the kernel would enter a landing pad of the program: what its code releases of a caller may keep func#%d from getting hidden slots\n",
			(int)(sub - env->subprog_info));
}

/* What the landing pad of the site of @plan at @insn_idx releases, or why there is none */
void bpf_pad_log(struct bpf_verifier_env *env, int insn_idx, const struct bpf_pad_plan *plan)
{
	if (plan->conflict) {
		print_sites_below(env, insn_idx, plan);
		print_kpad_conflict(env, insn_idx, plan);
	}
	/* an entry that has a conflict is none: the line above has said why */
	if (plan->kind != BPF_SITE_KENTRY || !plan->conflict)
		print_plan(env, insn_idx, plan);
}

/*
 * A state leaves a frame of @sub at the site of @plan, of @kind: note the kind, for the callers.
 * bpf_pads_settle() notes them again, from the sites that the program has in the end.
 */
void bpf_pad_note_left(struct bpf_verifier_env *env, struct bpf_subprog_info *sub,
		       const struct bpf_pad_plan *plan, enum bpf_site_kind kind)
{
	if (bpf_site_is_forced(kind))
		sub->left_at |= BIT(BPF_SITE_REMAINDER);
	else
		sub->left_at |= bpf_site_is_call(kind) ? sites_below(env, plan) : BIT(kind);
}

/* Did bpf_pad_skip_faults() walk @sub, and has no call in or below it got a new callee since? */
static bool skip_walked(const struct bpf_verifier_env *env, const struct bpf_subprog_info *sub)
{
	return sub->skip_gen && sub->skip_gen == env->pad_skip_gen;
}

/*
 * The frame of the call of @plan cannot unwind, and what comes back to the call was left at
 * accesses to arena and at may_goto of the program only. The accesses are skipped and may_goto jumps
 * where the program says: what came back to the call is stuck, and so is what came back to the
 * calls in there. The main pass sees to most of that where a call is made, see stuck_frame_calls()
 * in verifier.c: this is for a state that left its function before. If it finds a subprog that was
 * not stuck, the pass is done again, and the subprog is stuck from its start, see check_funcs().
 */
int bpf_pad_skip_faults(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan,
			int insn_idx)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i, s, c, err = 0, cnt = env->subprog_cnt;
	struct bpf_subprog_info *sub;
	unsigned long *todo, *done;
	bool walked = true;

	if (verifier_bug_if(!bpf_site_is_call(plan->kind), env,
			    "a site that is no call has a frame that cannot unwind"))
		return -EFAULT;
	/*
	 * Many states can come back to calls of the same subprogs. What was walked is not walked
	 * again while no call in it got a new callee, see plan_add_callee().
	 */
	bpf_pad_for_each_callee(plan, c)
		walked &= skip_walked(env, &env->subprog_info[c]);
	if (walked)
		return 0;
	todo = bitmap_zalloc(cnt, BPF_VERIFIER_GFP);
	done = bitmap_zalloc(cnt, BPF_VERIFIER_GFP);
	if (!todo || !done) {
		bitmap_free(todo);
		bitmap_free(done);
		return -ENOMEM;
	}
	bpf_pad_for_each_callee(plan, c)
		__set_bit(c, todo);
	while ((s = find_first_bit(todo, cnt)) < cnt) {
		__clear_bit(s, todo);
		sub = &env->subprog_info[s];
		if (skip_walked(env, sub) || __test_and_set_bit(s, done))
			continue;
		/* the search in the bitmap, and each insn of the subprog */
		err = bpf_add_cost_and_check(env, cnt / BITS_PER_LONG + sub[1].start - sub->start,
					     BPF_COST_SCAN);
		if (err)
			break;
		env->faults_late |= !sub->stuck;
		/* what came back to a call below the first one is told by that one too */
		bpf_subprog_set_stuck(sub, BPF_STUCK_CAME_BACK, insn_idx);
		for (i = sub->start; i < sub[1].start; i++)
			for (plan = aux[i].pad_plans; plan; plan = plan->next)
				if (bpf_site_is_call(plan->kind))
					bpf_pad_for_each_callee(plan, c)
						__set_bit(c, todo);
	}
	/* a walk that got to its end has all that is below what it walked */
	if (!err)
		for_each_set_bit(s, done, cnt)
			env->subprog_info[s].skip_gen = env->pad_skip_gen;
	bitmap_free(todo);
	bitmap_free(done);
	return err;
}

/*
 * The pads of @sub keep the value over their calls in a hidden word of the frame, below the
 * hidden slots. Nothing else writes it. A subprog whose pads pass on R2 has a second word above
 * it, see bpf_pad_passes_r2(). Returns the reason of a conflict.
 * Every plan of the subprog whose pad keeps the value asks for the word, also behind one that has
 * no room for it, see bpf_pads_settle(), and bpf_hidden_slots_fit() looks at the whole program. So
 * the answer is kept, a no as well: 'no_value_word'. It holds until the next bpf_pads_settle(),
 * since until then the frames get no smaller.
 */
static int take_value_word(struct bpf_verifier_env *env, struct bpf_subprog_info *sub)
{
	int words = 1 + bpf_pad_passes_r2(env, sub - env->subprog_info, BPF_SITE_CALL);
	int err;

	if (sub->value_off)
		return 0;
	if (sub->no_value_word)
		return BPF_CONFLICT_NO_ROOM;
	sub->hidden_words += words;
	err = bpf_hidden_slots_fit(env);
	if (err <= 0) {
		sub->hidden_words -= words;
		sub->no_value_word = !err;
		return err ?: BPF_CONFLICT_NO_ROOM;
	}
	sub->value_off = -(int)bpf_stack_depth_with_slots(sub);
	return 0;
}

/*
 * @sub gets the hidden word K, and in a program with bpf_throw() the word for the value: the entry
 * of a landing pad stores both, see bpf_pad_kentry_insns(). Returns 1 if the stack has no room.
 */
static int take_kernel_words(struct bpf_verifier_env *env, struct bpf_subprog_info *sub)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_pad_place *place;
	struct bpf_pad_plan *plan;
	int i, j, k, err, words = 0;

	/*
	 * As many save words as the entry that saves the most has, see bpf_pad_kentry_insns().
	 * Also one that the program does not have in the end: the states that came through it
	 * went on to the plans of the forced frames, which test the word that it would fill.
	 */
	for (i = sub->start; i < sub[1].start; i++) {
		plan = bpf_pad_plan(&aux[i], BPF_SITE_KENTRY);
		for (j = 0; plan && j < BPF_PAD_MAX_SAVES; j++)
			if (saved_ent(sub, plan, j))
				words = max(words, j + 1);
	}
	sub->hidden_words += 1 + words;
	err = bpf_hidden_slots_fit(env);
	if (err <= 0) {
		sub->hidden_words -= 1 + words;
		return err ?: 1;
	}
	sub->save_words = words;
	sub->save_off = -(int)bpf_stack_depth_with_slots(sub);
	sub->k_off = sub->save_off + words * BPF_REG_SIZE;
	err = env->has_throw ? take_value_word(env, sub) : 0;
	if (err)
		return err < 0 ? err : 1;
	/* the pads of its forced frames read the words: they are slots of the stack like any other */
	for (i = sub->start; i < sub[1].start; i++) {
		for (plan = aux[i].pad_plans; plan; plan = plan->next) {
			if (!bpf_site_is_forced(plan->kind))
				continue;
			for (j = 0; j < plan->nr_ents; j++) {
				for (k = 0; k < plan->ents[j].nr_cands[0]; k++) {
					place = &plan->ents[j].cand[0][k];
					if (place->loc != BPF_PLACE_SAVED)
						continue;
					place->loc = BPF_PLACE_SPILL;
					place->at = sub->save_off + place->at * BPF_REG_SIZE;
				}
			}
		}
	}
	return 0;
}

/*
 * The entries of the landing pads that the kernel enters, ahead of every other plan. What the
 * entry of a call saves is one answer for all states that get to the call, see visit_saves(), and
 * a run has the answer from its start: 'ksave_off' of the call, as the run before left it. Every
 * state was asked whether the answer still holds. Where it does not it changes here, and the pass
 * is done again:
 *   - The entry was to save, and the states do not agree on what the frame holds. The states that
 *     it had marked for a save word went on to the plans of the frames that the kernel unwinds,
 *     and the state that did not agree ended at the entry, see enter_kernel_pad() in verifier.c.
 *     The entry saves nothing from now on. That is no error: what such a frame holds where it is
 *     left has a plan without the save words, or the run that follows has the error.
 *   - The entry saved nothing, and the states agree: this pass keeps apart what the pass that
 *     had the answer did not. The entry saves again. Not in a run that is there because an
 *     answer changed, 'saves_again': such a run only takes away.
 * A run whose answers all hold is not done again: a program with an entry that never saves has
 * one run per pass.
 * So the runs that the entries ask for come to an end: behind a run in which entries save again,
 * each further one takes saving from at least one entry and gives it back to none, which is one
 * run per entry at most. A pass is done again for other reasons too, see pass_needs_restart() in
 * verifier.c: a loop gets its guard late, a global subprog unwinds after all, a subprog is stuck
 * after all. Such a run changed no answer, so the run behind it decides both ways again, and the
 * count starts anew there. Those reruns have bounds of their own, by the loops and the subprogs
 * of the program: what such a run found, the runs behind it know from their start.
 * The plan of an entry that saves nothing has nothing to save from: it is what the emission
 * reads, in the pass that is loaded, and that never looks at the bit of the last run.
 * Any other conflict of an entry is an error like that of a plan, see bpf_pads_settle().
 */
static void settle_entries(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	bool level2 = env->log.level & BPF_LOG_LEVEL2;
	struct bpf_pad_plan *plan;
	int i;

	for (i = 0; i < env->prog->len - 1; i++) {
		plan = bpf_pad_plan(&aux[i], BPF_SITE_KENTRY);
		if (!plan)
			continue;
		if (!aux[i + 1].ksave_off) {
			if (!plan->used || !plan->no_saves)
				continue;
			if (level2)
				verbose(env, "the entry of the landing pad of the call at %d saves nothing: %s\n",
					i, conflict_why[plan->no_saves]);
			aux[i + 1].ksave_off = true;
			env->saves_late = true;
		} else if (plan->used && plan->saves && !plan->no_saves && !plan->conflict &&
			   !env->saves_again) {
			if (level2)
				verbose(env, "the entry of the landing pad of the call at %d saves again\n",
					i);
			aux[i + 1].ksave_off = false;
			env->saves_late = true;
		} else {
			plan->nr_ents = 0;
		}
	}
}

/*
 * The functions in which the kernel enters a landing pad of the program get their hidden words,
 * see take_kernel_words(). They come last: the stack of a function at its limit has no room for
 * them, and they must not take the room of what a program that loads without them needs, the word
 * for the value of a pad of the verifier. Without room the kernel cannot enter the landing pads of
 * the function, and that is an error like any other.
 */
static int take_kpad_words(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_subprog_info *sub;
	struct bpf_pad_plan *plan;
	int i, s, err;
	bool enters;

	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		enters = false;
		for (i = sub->start; sub->has_kpads && !enters && i < sub[1].start; i++) {
			plan = bpf_pad_plan(&aux[i], BPF_SITE_KENTRY);
			enters = plan && plan->used;
		}
		err = enters ? take_kernel_words(env, sub) : 0;
		if (err < 0)
			return err;
		if (!err)
			continue;
		print_entered_pad(env, sub, NULL);
		verbose(env, "no room in the stack for the hidden words of func#%d\n", s);
		return -EINVAL;
	}
	return 0;
}

/*
 * The main pass unwinds at more sites than the program has in the end: pass 0 takes the edge of
 * may_goto in every loop that nothing stops, and a loop that has a trip count gets no may_goto.
 * The states that left a frame there went on to the callers, and visited the plans of the calls.
 * Note the sites at which the program does leave a frame. The caller has dropped the guards and
 * marked the subprogs that unwind, see bpf_mark_subprogs_that_unwind(): the emission asks the
 * same, and what it is going to use is among what is marked here. Only these plans are settled.
 * What a state found at any other site, a conflict or a need for hidden slots, does not count.
 */
void bpf_pads_mark_used(struct bpf_verifier_env *env)
{
	struct bpf_pad_plan *plan;
	int i;

	for (i = 0; i < env->prog->len; i++)
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next)
			plan->used = bpf_site_is_used(env, i, plan);
}

/*
 * A pass that counts is over: all states have visited the plans. A state whose visit made a
 * conflict ended at the site, see unwind_frame(): as an unproven insn if the program has the site
 * for sure. A conflict that shows only now, at a site that the program has, is an error of the
 * pass as well, and its site is an unproven insn for the next one, see
 * bpf_find_unproven_after_pass().
 * That holds for every plan, also for those that are there because the kernel enters landing pads
 * of the program: the entry of such a pad, a site that a frame gets to while the kernel unwinds it
 * through the pad, unwind_exit where the pad ends, and a pad of the verifier in a caller that gets
 * what such a frame left. What the program does in its pad is its own business. What the verifier
 * adds around it has to be right, or the program does not load: no landing pad is passed by
 * because the verifier has no plan, see bpf_pad_log() for what the log says then.
 */
int bpf_pads_settle(struct bpf_verifier_env *env)
{
	const struct bpf_pad_plan *reject = NULL;
	struct bpf_subprog_info *sub;
	struct bpf_pad_plan *plan;
	int i, s, err, at = 0;
	u64 plans = 0;

	err = bpf_pads_must_unwind(env) ?: sites_of_subprogs(env);
	if (err)
		return err;
	/* hidden slots take their places among entries that have theirs */
	for (i = 0; i < env->prog->len; i++) {
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next, plans++) {
			err = order_ents(env, plan);
			if (err)
				return err;
		}
	}
	/* what follows looks at each insn and at the entries of each plan a few times */
	err = bpf_add_cost_and_check(env, env->prog->len + BPF_PAD_MAX_ENTS * plans, BPF_COST_XREG);
	if (err)
		return err;
	err = settle_slots(env);
	if (err)
		return err;
	/* the run that follows is the judge of the plans: it has what each entry saves from its start */
	settle_entries(env);
	if (env->saves_late)
		return 0;
	for (i = 0; i < env->prog->len; i++) {
		if (env->insn_aux_data[i].pad_plans && bpf_must_abort())
			return -EINTR;
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next) {
			if (!plan->used)
				continue;
			sub = bpf_find_containing_subprog(env, i);
			/* the plan of an entry is no plan of a pad: its conflict is what it is */
			if (plan->kind != BPF_SITE_KENTRY) {
				err = settle_plan(env, plan);
				if (!err && plan_saves_value(env, plan, sub - env->subprog_info))
					err = take_value_word(env, sub);
				if (err < 0)
					return err;
				plan->conflict = err;
			}
			if (!plan->conflict)
				continue;
			if (!plan_rejects(env, plan)) {
				/*
				 * The frame cannot unwind and the site has another way out. The
				 * main pass made what came back stuck, and no run that finds a
				 * subprog stuck late gets here. So the program still has the site,
				 * and no pad.
				 */
				err = bpf_pad_skip_faults(env, plan, i);
				if (err)
					return err;
				if (env->faults_late)
					continue;
			}
			/* the first one is the one that the log names */
			if (!reject)
				at = i;
			reject = reject ?: plan;
		}
	}
	/*
	 * The error is raised here, behind all plans: a pass can have several conflicts that show
	 * only now, and each of them is one that the next pass keeps more apart for, see
	 * bpf_find_unproven_after_pass() and bpf_pads_note_causes(). One per pass would be a pass
	 * per conflict.
	 * And behind the question whether the hidden words that the plans rest on fit.
	 */
	if (reject) {
		err = bpf_hidden_slots_settle(env);
		if (err)
			return min(err, 0);
		bpf_pad_log(env, at, reject);
		return -EINVAL;
	}
	if (env->faults_late)
		return 0;
	err = take_kpad_words(env);
	if (err)
		return err;
	err = bpf_hidden_slots_settle(env);
	if (err)
		return min(err, 0);
	/* The main pass is over: the program has no access to its stack that is not known. */
	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		if (sub->hidden_words)
			bpf_stack_take_hidden_words(sub);
	}
	return 0;
}

/*
 * A site at the insn has no landing pad that serves all states and no other way out, see
 * bpf_pads_settle()
 */
bool bpf_pads_conflict(struct bpf_verifier_env *env, const struct bpf_insn_aux_data *aux)
{
	const struct bpf_pad_plan *plan;

	for (plan = aux->pad_plans; plan; plan = plan->next)
		if (plan->used && plan_rejects(env, plan))
			return true;
	return false;
}

/* The loop @l is the loop @h, or a loop inside it */
static bool loop_is_in(struct bpf_verifier_env *env, int l, int h)
{
	return l == h || bpf_is_nested_loop(env, l, h);
}

/*
 * Is @n a conditional jump that leaves the loop @h? From the loop itself, as
 * bpf_insn_leaves_loop() asks, or from a loop inside it: a loop can have its only way out there.
 */
static bool jump_leaves_loop(struct bpf_verifier_env *env, int h, int n)
{
	const struct bpf_insn *insn = &env->prog->insnsi[n];

	if (!bpf_insn_is_cond_jump(insn->code) || BPF_OP(insn->code) == BPF_JCOND ||
	    !loop_is_in(env, bpf_loop_at_index(env, n), h))
		return false;
	return !loop_is_in(env, bpf_loop_at_index(env, n + insn->off + 1), h) ||
	       !loop_is_in(env, bpf_loop_at_index(env, n + 1), h);
}

/*
 * The pass left a frame at the insn of @aux: an access to arena, which has no plan where the frames
 * hold nothing, see check_arena_site(), or may_goto of the program
 */
static bool left_at_insn(const struct bpf_insn_aux_data *aux)
{
	const struct bpf_pad_plan *plan;

	if (aux->fault_skips)
		return false;
	if (aux->fault_empty)
		return true;
	for (plan = aux->pad_plans; plan; plan = plan->next)
		if (plan->visited &&
		    (plan->kind == BPF_SITE_FAULT || plan->kind == BPF_SITE_MAY_GOTO))
			return true;
	return false;
}

/*
 * The landing pad of the call of @plan has a conflict, and that is an error: the kernel unwinds
 * what the call calls. Where it does so at may_goto that the verifier adds, it depends on the
 * values that got to the loop: may_goto is there because a state went around without a trip
 * count. A function is verified for its calls together, and two calls of which each has a trip
 * count can make such a state between them:
 *
 *	static long count(long step, long end)		count(1, 1000000);
 *	{						count(-1, -999993);
 *		long i = 0;
 *							step is 1 or -1, end is one of two
 *		do					numbers: any pair, and no trip count
 *			i += step;
 *		while (i != end);
 *		return i;
 *	}
 *
 * Kept apart no call is left at may_goto, the call is no site, and what its frame holds does not
 * matter. Nothing in the call tells: its arguments are constants. So the jumps that leave such a
 * loop are a cause of the error as well, in each function that came back unwound to the call or
 * to a call below it. What they read decides the trip count, and the next pass keeps it apart,
 * see bpf_note_unproven_cause(), down to the arguments of the function. Such a jump can be in a
 * loop inside the one that has may_goto, see jump_leaves_loop().
 * Only a loop of which the pass knows that it has no trip count counts, see
 * bpf_flow_guard_is_guess().
 *
 * An access to arena that faults leaves a function as well, and so does may_goto of the program.
 * The dependencies of the next pass know exit, unwind_exit and bpf_throw() as the ways out of a
 * function, and none of these stands for such an insn. Where only the calls together get to it,
 * the jumps that can skip it are the cause: the insn is noted, and they are what controls it.
 *
 * Where the kernel enters a landing pad of the program behind a call the frame is not left at the
 * call. What the kernel unwound below it has a part in what follows all the same, and that is not
 * told by a plan: see note_entered().
 */
static void note_causes(struct bpf_verifier_env *env, const struct bpf_pad_plan *plan)
{
	struct bpf_subprog_info *sub = env->subprog_info;
	int s;

	if (bpf_site_base(plan->kind) != BPF_SITE_KCALL)
		return;
	bpf_pad_for_each_callee(plan, s)
		sub[s].below_conflict = true;
}

/*
 * The pass has an error, and the kernel entered landing pads of the program in it: a state went
 * through the entry of a call, 'visited' of its plan, see bpf_pad_enter(). The kernel may have got
 * into such a pad only because calls were verified together: the function of count() above with a
 * landing pad behind its call. Kept apart nothing comes back unwound to that call, no state gets
 * into the pad, and what such a state had a part in is gone. That can be any error, and neither
 * the state nor the plan that has it needs to know of the pad:
 *   - a conflict where the pad ends, at a site in its code, or in a caller that gets what the
 *     pad left;
 *   - an error or a conflict in what its code calls, also in a callback that it only arms;
 *   - a conflict at a call of the normal path, in a function that the code of the pad calls as
 *     well: the numbers that the pad passes take the trip count from its loop, and may_goto is in
 *     the code for every call of the function;
 *   - hidden slots that a function does not get because of what the code of the pad releases,
 *     and hidden words of the function of the pad that have no room, see take_kpad_words().
 * So there is one rule: whatever the error is, every function in which the kernel entered a pad
 * is marked. The calls behind which it did are causes, and so is what makes their callees unwind,
 * see note_causes_below(). The marks say what the next pass keeps apart and nothing else: no
 * verdict rests on them.
 * They are those of this pass, and every pass that has an error makes them again while the
 * kernel still gets into a pad: the causes have to be there for each step of
 * bpf_partition_more() in turn, until the calls are apart. They are no step of their own. A pass
 * after which nothing more is kept apart is the last one with them as without them, and the
 * limit on the cost of a load that is rejected is the same, see do_check_all().
 * A program that is rejected for another reason pays for them: for the dependencies of the calls
 * of the marked functions, in every pass, and where only calls that are verified together get
 * into the pad, for keeping those apart. An error behind such calls depends on the loop of their
 * callee from then on, and costs what an error that reads the result of that loop costs.
 */
static void note_entered(struct bpf_verifier_env *env)
{
	const struct bpf_insn_aux_data *aux = env->insn_aux_data;
	const struct bpf_pad_plan *plan;
	struct bpf_subprog_info *sub;
	int i, s;

	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		if (!sub->has_kpads || sub->below_conflict)
			continue;
		bpf_add_cost(env, sub[1].start - sub->start, BPF_COST_SCAN);
		for (i = sub->start; !sub->below_conflict && i < sub[1].start; i++) {
			plan = bpf_pad_plan(&aux[i], BPF_SITE_KENTRY);
			sub->below_conflict = plan && plan->visited;
		}
	}
}

/*
 * The causes of all conflicts of the pass, see note_causes(), which has marked the functions that
 * came back to their calls. One walk serves them all: what a function has of causes is the same
 * for every conflict above it, a function is scanned once for the jumps that leave its loops, and
 * a pass can have a conflict at every call.
 */
static void note_causes_below(struct bpf_verifier_env *env)
{
	const struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_subprog_info *sub = env->subprog_info;
	int i, n, h, s, c, top = 0, cnt = env->subprog_cnt;
	const struct bpf_pad_plan *below;
	bool guards;
	int *stack;

	for (s = 0; s < cnt && !sub[s].below_conflict; s++)
		;
	if (s == cnt)
		return;
	/* a function is walked once, for its calls: it is on the stack once, when it gets its mark */
	stack = kvmalloc_array(cnt, sizeof(*stack), BPF_VERIFIER_GFP);
	if (!stack) {
		env->no_mem = true;
		return;
	}
	for (; s < cnt; s++)
		if (sub[s].below_conflict)
			stack[top++] = s;
	while (top) {
		s = stack[--top];
		/*
		 * A signal ends the load. The budget of the pass does not: the pass that has the
		 * error can be over it, and the passes behind it need the notes all the same.
		 */
		bpf_add_cost(env, sub[s + 1].start - sub[s].start, BPF_COST_SCAN);
		env->aborted |= bpf_must_abort();
		if (env->aborted)
			break;
		for (i = sub[s].start; i < sub[s + 1].start; i++) {
			for (below = aux[i].pad_plans; below; below = below->next) {
				if ((bpf_site_base(below->kind) != BPF_SITE_KCALL &&
				     below->kind != BPF_SITE_KENTRY) || !below->visited)
					continue;
				/*
				 * The frame is left at this call, or goes on in the landing pad
				 * of the program behind it and is left there, whatever what it
				 * calls was left at: the check of a recursion is no insn to note.
				 * The jumps that can skip the call are a cause.
				 */
				bpf_note_controlled_cause(env, i);
				bpf_pad_for_each_callee(below, c) {
					if (sub[c].below_conflict)
						continue;
					sub[c].below_conflict = true;
					stack[top++] = c;
				}
			}
		}
	}
	kvfree(stack);
	for (s = 0; s < cnt; s++) {
		guards = false;
		for (i = sub[s].start; sub[s].below_conflict && i < sub[s + 1].start; i++) {
			if (left_at_insn(&aux[i]))
				bpf_note_controlled_cause(env, i);
			if (!aux[i].loop_guard || bpf_flow_guard_is_guess(env, i))
				continue;
			h = bpf_loop_at_index(env, i);
			aux[h].loop->guard_is_cause = guards = true;
		}
		if (!guards)
			continue;
		/* a jump is asked about the marked loops that it is in: LOOP_STACK_SIZE at most */
		bpf_add_cost(env, sub[s + 1].start - sub[s].start, BPF_COST_SCAN);
		for (n = sub[s].start; n < sub[s + 1].start; n++) {
			for (h = bpf_loop_at_index(env, n); h >= 0; h = aux[h].loop_header) {
				if (!aux[h].loop->guard_is_cause || !jump_leaves_loop(env, h, n))
					continue;
				bpf_note_unproven_cause(env, n);
				break;
			}
		}
		for (n = sub[s].start; n < sub[s + 1].start; n++)
			if (aux[n].loop)
				aux[n].loop->guard_is_cause = false;
	}
}

/*
 * The pass is over and has an error. Note the causes of the conflicts that are one: those that a
 * state made an error where it visited, see unwind_frame(), and those that bpf_pads_settle() found.
 * And those that any error has where the kernel entered landing pads of the program, see
 * note_entered().
 */
void bpf_pads_note_causes(struct bpf_verifier_env *env)
{
	const struct bpf_pad_plan *plan;
	int i, s;

	for (s = 0; s < env->subprog_cnt; s++)
		env->subprog_info[s].below_conflict = false;
	for (i = 0; i < env->prog->len; i++)
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next)
			if (plan->failed || (plan->used && plan_rejects(env, plan)))
				note_causes(env, plan);
	note_entered(env);
	note_causes_below(env);
	/* the caller looks at the limits before it goes on. This is for a load that is to end. */
	bpf_check_limits(env);
}

/*
 * Subprog @s is stuck, in all its uses, and what told is one call, which the pass that is loaded
 * may not even get to: a pass that keeps less apart found it, and every run after it knows from
 * its start, see check_funcs(). So the line names the insn.
 */
static void print_stuck(struct bpf_verifier_env *env, int s)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[s];
	int by = bpf_find_containing_subprog(env, sub->stuck_insn) - env->subprog_info;

	verbose(env, "func#%d cannot unwind", s);
	switch (sub->stuck_by) {
	case BPF_STUCK_NO_PAD:
		verbose(env, ", the call at %u has no landing pad for it", sub->stuck_insn);
		break;
	case BPF_STUCK_CALLED:
		verbose(env, ", func#%d calls it at %u and cannot unwind", by, sub->stuck_insn);
		break;
	case BPF_STUCK_CAME_BACK:
		verbose(env, ", it came back to the call at %u in func#%d, which cannot unwind",
			sub->stuck_insn, by);
		break;
	default:
		verbose(env, " at %u", sub->stuck_insn);
		break;
	}
	verbose(env, ": its may_goto jumps, its arena accesses are skipped\n");
}

/*
 * The plans of the sites that the program has, the functions that cannot unwind where they could
 * go on instead, and the functions that have hidden slots
 */
void bpf_pads_log(struct bpf_verifier_env *env)
{
	static const char * const group[] = {
		[BPF_PAD_GROUP_RCU]	= "rcu",
		[BPF_PAD_GROUP_PREEMPT]	= "preempt",
		[BPF_PAD_GROUP_LOCKS]	= "locks",
		[BPF_PAD_GROUP_REFS]	= "refs",
	};
	const struct bpf_subprog_info *sub;
	const struct bpf_pad_plan *plan;
	int i, s, g;

	if (!(env->log.level & BPF_LOG_LEVEL2))
		return;
	for (i = 0; i < env->prog->len; i++)
		for (plan = env->insn_aux_data[i].pad_plans; plan; plan = plan->next)
			if (plan->used)
				print_plan(env, i, plan);
	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		if (sub->stuck)
			print_stuck(env, s);
		if (!sub->slots)
			continue;
		verbose(env, "func#%d has hidden slots for:", s);
		for (g = 0; g < BPF_PAD_NR_GROUPS; g++)
			if (sub->slots & BIT(g))
				verbose(env, " %s", group[g]);
		verbose(env, "\n");
	}
}

/*
 * Does @insn leave the frame in a way that goes on with the caller? exit, a tail call that is
 * taken, and LD_ABS or LD_IND that fails. Not unwind_exit: the caller is unwound in turn.
 */
static bool insn_returns(const struct bpf_insn *insn)
{
	if (insn->code == (BPF_JMP | BPF_EXIT))
		return !bpf_is_unwind_exit(insn);
	return bpf_insn_has_hidden_exit(insn);
}

/*
 * The functions that have a landing pad which only resumes, 'kpad' of its unwind_goto: which of
 * their insns can a frame run once the kernel has entered such a pad? Three kinds of code, on the
 * control flow graph:
 *
 *   PAD CODE     What can be reached from the first insn of a pad that only resumes, over every
 *                edge: 'kpad_code'. A frame that the kernel unwinds starts at such an insn, see
 *                enter_kernel_pad() in verifier.c, and goes on over edges of the graph until it is
 *                left. So it runs pad code and nothing else.
 *   NORMAL PATH  What can be reached from the first insn of the function without the jump of
 *                unwind_goto: where a frame is as long as nothing has unwound to it.
 *   the rest     What only the jump of unwind_goto gets to and what is no pad code: the landing
 *                pad of a typed catch, until it returns to the normal path or goes on in the
 *                code that resumes, which it shares with the pads of the destructors. To a frame
 *                that the kernel unwinds it is what the normal path is: such a frame is not there.
 *
 *	call a			normal path
 *	unwind_goto 1f
 *	call b
 *	unwind_goto 2f
 *	exit
 * 2:	if r0 != 7 goto 3f	the rest: a typed catch
 *	r0 = 0
 *	exit
 * 1:	call dtor		pad code
 * 3:	unwind_exit
 *
 * A function is MIXED, 'kpads_mixed', if one of its insns is pad code and on the normal path as
 * well: a pad that the normal path falls into or jumps to, a pad that goes back in front of its
 * call, or to the first insn of its function, any pad of a function that has no exit. In every
 * other function the two share no insn, and a frame gets from the normal path into pad code in
 * two ways only: by the jump of unwind_goto, when a callee left with unwind_exit, and through the
 * entry of a pad, when the kernel unwound the callee.
 *
 * The exit that stands for the return of a tail call or of LD_ABS is no edge here, as it is none
 * where the pads are judged: it can be unwind_exit of the code that resumes, and a tail call on
 * the normal path would make every such function mixed.
 * Nor is the insn behind a call of a subprog that does not return, see bpf_compute_might_return():
 * a function that only throws, static or global. The compiler puts what it likes behind such a
 * call, a cleanup pad too, and nothing falls into that. What comes back to the call is unwound and
 * goes where its unwind_goto says, or leaves the frame. The main pass does not go on behind such a
 * call either, see check_func_call() for a global callee, and the code that a frame of the pass
 * gets to must be the code that is found here.
 * This counts on no unwind being lost at such a call, of a global callee as of a static one: a
 * callee that can leave with unwind_exit or kexit has unwind_goto or kgoto behind each call of it,
 * see insert_unwind_gotos() in fixups.c. A return that found neither would go on behind the call:
 * from the normal path into pad code where a landing pad follows the call, and K is read there. So
 * a trap stands behind such a call wherever the code behind it is dead, see
 * bpf_opt_hard_wire_dead_code_branches().
 */
static int find_pad_code(struct bpf_verifier_env *env)
{
	const struct bpf_insn *insns = env->prog->insnsi, *insn;
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i, p, t, s, cnt, len = env->prog->len, err = 0;
	struct bpf_subprog_info *sub;
	unsigned long *pad, *normal;
	struct bpf_iarray *succ;
	bool changed;

	pad = bitmap_zalloc(len, BPF_VERIFIER_GFP);
	normal = bitmap_zalloc(len, BPF_VERIFIER_GFP);
	if (!pad || !normal) {
		err = -ENOMEM;
		goto out;
	}
	for (s = 0; s < env->subprog_cnt; s++)
		if (env->subprog_info[s].has_kpads)
			__set_bit(env->subprog_info[s].start, normal);
	for (i = 0; i < len; i++)
		if (aux[i].kpad)
			__set_bit(i + 1 + bpf_jmp_offset(&insns[i]), pad);
	/* what an insn gets to comes before it in the postorder: walk that from its end */
	do {
		changed = false;
		err = bpf_add_cost_and_check(env, env->cfg.cur_postorder, BPF_COST_SCAN);
		if (err)
			goto out;
		for (p = env->cfg.cur_postorder - 1; p >= 0; p--) {
			i = env->cfg.insn_postorder[p];
			if (!test_bit(i, pad) && !test_bit(i, normal))
				continue;
			insn = &insns[i];
			s = bpf_pseudo_call(insn) ? bpf_find_subprog(env, i + 1 + insn->imm) : -1;
			if (s >= 0 && !env->subprog_info[s].might_return) {
				/* pad code gets to the landing pad of the call, nothing else */
				t = i + 1 < len && bpf_is_unwind_goto(insn + 1) ?
				    i + 2 + bpf_jmp_offset(insn + 1) : -1;
				if (t >= 0 && test_bit(i, pad) && !__test_and_set_bit(t, pad))
					changed = true;
				continue;
			}
			succ = bpf_insn_successors(env, i);
			cnt = insn_returns(insn) ? min(succ->cnt, 1) : succ->cnt;
			for (t = 0; t < cnt; t++) {
				if (test_bit(i, pad) && !__test_and_set_bit(succ->items[t], pad))
					changed = true;
				/* the second one of unwind_goto is its jump */
				if (test_bit(i, normal) && !(t && bpf_is_unwind_goto(insn)) &&
				    !__test_and_set_bit(succ->items[t], normal))
					changed = true;
			}
		}
	} while (changed);
	for (s = 0; s < env->subprog_cnt; s++) {
		sub = &env->subprog_info[s];
		for (i = sub->start; sub->has_kpads && i < sub[1].start; i++) {
			aux[i].kpad_code = test_bit(i, pad);
			if (sub->kpads_mixed || !test_bit(i, pad) || !test_bit(i, normal))
				continue;
			sub->kpads_mixed = true;
			if (env->log.level & BPF_LOG_LEVEL2)
				verbose(env,
					"insn %d of func#%d is on the normal path and in a landing pad that only resumes\n",
					i, s);
		}
	}
out:
	bitmap_free(pad);
	bitmap_free(normal);
	return err;
}

/*
 * The landing pads that a program has behind its calls are code like any other: a pad can end the
 * unwinding and go on with the program, a catch clause of C++ does. What the kernel unwinds must
 * not be caught. But a pad that only cleans up, a destructor and then unwind_exit, cannot catch
 * anything, and what it does is what the program wants done when a frame is left.
 *
 * Find those pads, on the control flow graph, before any state is looked at. The landing pad of
 * unwind_goto ONLY RESUMES if, from its first insn:
 *   - no path in the function gets to an insn that returns to the caller, see insn_returns(), and
 *   - a path gets to unwind_exit.
 * The second one leaves out the pads that end in a call which never returns: std::terminate().
 * What a pad does on the way is not asked. It can call, loop, fault in arena and call bpf_throw():
 * those are sites of the frame like any other.
 *
 *	~Guard()		try { } catch (...)	noexcept
 *
 *	call foo		call foo		call foo
 *	unwind_goto pad		unwind_goto pad		unwind_goto pad
 *	...			...			...
 * pad:	r6 = r0			call begin_catch	call terminate
 *	call dtor		...			goto -1
 *	r0 = r6			r0 = 0
 *	unwind_exit		exit
 *
 *	only resumes		returns			no unwind_exit
 *
 * A typed catch gets to its handler by a branch on what the personality routine of the program
 * says, which is a value like any other: the pad returns. Pads that share their last insns, as the
 * pads of one function of C++ do, are judged one by one, each from its first insn.
 *
 * What a frame that the kernel unwinds runs from there on is what the pad gets to, and that need
 * not be code of a pad: a pad can jump back in front of its call, or to the first insn of its
 * function, and in a function that has no exit every pad only resumes. Such a frame runs the
 * normal path of the function once more. What holds for it is not that it runs cleanup code only,
 * it is that no insn which it can get to returns to its caller: it is left at unwind_exit or at a
 * site, with kexit, and nowhere else. See enter_kernel_pad() in verifier.c.
 *
 * The answer is a property of the insns, the same in every pass: 'kpad' of unwind_goto. The
 * kernel enters each of these pads when it unwinds what the call in front of it calls, in a
 * function that can unwind, or the program is rejected: see bpf_pads_settle().
 * Dead branches are gone from the graph, see bpf_prune_dead_branches().
 * What such pads get to is found on the same graph, see find_pad_code().
 */
int bpf_find_kernel_pads(struct bpf_verifier_env *env)
{
	const struct bpf_insn *insns = env->prog->insnsi, *insn;
	int i, p, t, pad, cnt, len = env->prog->len, err = 0;
	unsigned long *returns, *resumes;
	struct bpf_iarray *succ;
	bool changed, ret, res, found = false;

	for (i = 0; i < len && !bpf_is_unwind_goto(&insns[i]); i++)
		;
	if (i == len)
		return 0;
	returns = bitmap_zalloc(len, BPF_VERIFIER_GFP);
	resumes = bitmap_zalloc(len, BPF_VERIFIER_GFP);
	if (!returns || !resumes) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < len; i++) {
		if (insn_returns(&insns[i]))
			__set_bit(i, returns);
		if (bpf_is_unwind_exit(&insns[i]))
			__set_bit(i, resumes);
	}
	/* an insn gets to what the insns behind it get to: those come first in the postorder */
	do {
		changed = false;
		err = bpf_add_cost_and_check(env, env->cfg.cur_postorder, BPF_COST_SCAN);
		if (err)
			goto out;
		for (p = 0; p < env->cfg.cur_postorder; p++) {
			i = env->cfg.insn_postorder[p];
			insn = &insns[i];
			ret = test_bit(i, returns);
			res = test_bit(i, resumes);
			succ = bpf_insn_successors(env, i);
			/*
			 * The exit that stands for the return of a tail call or of LD_ABS can be
			 * unwind_exit: the insn returns, whatever that exit is.
			 */
			cnt = insn_returns(insn) ? min(succ->cnt, 1) : succ->cnt;
			for (t = 0; t < cnt; t++) {
				ret |= test_bit(succ->items[t], returns);
				res |= test_bit(succ->items[t], resumes);
			}
			if (ret && !__test_and_set_bit(i, returns))
				changed = true;
			if (res && !__test_and_set_bit(i, resumes))
				changed = true;
		}
	} while (changed);
	for (i = 0; i < len; i++) {
		insn = &insns[i];
		if (!bpf_is_unwind_goto(insn))
			continue;
		pad = i + 1 + bpf_jmp_offset(insn);
		ret = test_bit(pad, returns);
		res = test_bit(pad, resumes);
		env->insn_aux_data[i].kpad = !ret && res;
		if (!ret && res)
			bpf_find_containing_subprog(env, i)->has_kpads = found = true;
		if (!(env->log.level & BPF_LOG_LEVEL2))
			continue;
		verbose(env, "landing pad at %d of the call at %d %s\n", pad, i - 1,
			ret ? "returns" : res ? "only resumes" : "has no unwind_exit");
	}
	err = found ? find_pad_code(env) : 0;
out:
	bitmap_free(returns);
	bitmap_free(resumes);
	return err;
}
