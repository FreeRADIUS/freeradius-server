/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** State machine functions
 *
 * @file src/lib/util/machine.c
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include "machine.h"

typedef struct {
	fr_machine_state_t const *def;		//!< static definition of names, callbacks for this particular state
	fr_dlist_head_t		enter[2];	//!< pre/post enter hooks
	fr_dlist_head_t		process[2];	//!< pre/post process hooks
	fr_dlist_head_t		exit[2];	//!< pre/post exit hooks
	fr_dlist_head_t		signal[2];	//!< pre/post signal hooks
} fr_machine_state_inst_t;

typedef struct {
	int			state;		//!< state transition to defer
	fr_dlist_t		dlist;		//!< linked list of deferred signals
} fr_machine_defer_t;

/** Hooks
 *
 */
struct fr_machine_s {
	fr_machine_def_t const	*def;		//!< static definition of states, names, callbacks for the state machine
	void			*uctx;		//!< to pass to the various handlers
	fr_machine_state_inst_t	*current;	//!< current state we are in
	void const		*in_handler;	//!< which handler we are in

	fr_dlist_head_t		deferred;	//!< list of deferred entries
	int			paused;		//!< are transitions paused?
	bool			dead;		//!< we were asked to exit, but aren't yet done cleaning up

	fr_machine_state_inst_t state[];	//!< all of the state transitions
};

typedef struct {
	void			*uctx;		//!< to pass back to the function
	fr_machine_hook_func_t	func;		//!< function to call for the hook
	bool			oneshot;	//!< is this a one-shot callback?
	fr_dlist_head_t		*head;		//!< where the hook is stored
	fr_dlist_t		dlist;		//!< linked list of hooks
} fr_machine_hook_t;

#undef PRE
#define PRE (0)
#undef POST
#define POST (1)

/** Call the hook with the current state machine, and the hooks context
 *
 *  Note that in most cases, the hook will have saved it's own state
 *  machine in uctx, and will not need the current state machine.
 */
static inline void call_hook(fr_machine_t *m, fr_dlist_head_t *head, int state1, int state2)
{
	fr_machine_hook_t *hook, *next;

	for (hook = fr_dlist_head(head); hook != NULL; hook = next) {
		next = fr_dlist_next(head, hook);

		hook->func(m, state1, state2, hook->uctx);
		if (hook->oneshot) talloc_free(hook);
	}
}

/** Transition from one state to another.
 *
 *  Including calling pre/post hooks.
 *
 *  None of the functions called from here are allowed to perform a
 *  state transition.
 */
static void state_transition(fr_machine_t *m, int state, void *in_handler)
{
	fr_machine_state_inst_t *current = m->current;
	int old;

	fr_assert(current != NULL);

	fr_assert(!m->in_handler);
	m->in_handler = in_handler;

	old = current->def->number;

	/*
	 *	Exit the current state.
	 */
	call_hook(m, &current->exit[PRE], old, state);
	if (current->def->exit) current->def->exit(m, m->uctx);
	call_hook(m, &current->exit[POST], old, state);

	/*
	 *	Reset "current", and enter the new state.
	 */
	current = m->current = &m->state[state];

	call_hook(m, &current->enter[PRE], old, state);
	if (current->def->enter) current->def->enter(m, m->uctx);
	call_hook(m, &current->enter[POST], old, state);

	/*
	 *	We may have transitioned into the "free" state.  If
	 *	so, mark the state machine as dead.
	 */
	m->dead = (state == m->def->free);

	m->in_handler = NULL;
}


/** Free a state machine
 *
 *  When a state machine is freed, it will first transition to the
 *  "free" state.  That state is presumed to do all appropriate
 *  cleanups.
 */
static int _machine_free(fr_machine_t *m)
{
	fr_assert(m);
	fr_assert(m->def);
	fr_assert(m->def->free);

	/*
	 *	Don't transition into the free state multiple times.
	 */
	if (m->current->def->number == m->def->free) return 0;

	fr_assert(m->state[m->def->free].enter != NULL);

	/*
	 *	Exit the current state, and enter the free state.
	 */
	state_transition(m, m->def->free, (void *) _machine_free);

	/*
	 *	Don't call "process" on the free state.  Simply
	 *	entering the free state _should_ clean everything up.
	 *
	 *	Don't check for deferred states.  Once we enter the
	 *	"free" state, we can't do anything else.
	 */

	return 0;
}

/** Instantiate a state machine
 *
 *  @param ctx	the talloc ctx
 *  @param def	the definition of the state machine
 *  @param uctx	the context passed to the callbacks
 *  @return
 *	- NULL on error
 *	- !NULL state machine which can be used.
 */
fr_machine_t *fr_machine_alloc(TALLOC_CTX *ctx, fr_machine_def_t const *def, void *uctx)
{
	int i, j, next;
	fr_machine_t *m;

	/*
	 *	We always reserve 0 for "invalid state".
	 *
	 *	The "max_state" is the maximum allowed state, which is a valid state number.
	 */
	m = (fr_machine_t *) talloc_zero_array(ctx, uint8_t, sizeof(fr_machine_t) + sizeof(m->state[0]) * (def->max_state + 1));
	if (!m) return NULL;

	talloc_set_type(m, fr_machine_t);

	*m = (fr_machine_t) {
		.uctx = uctx,
		.def = def,
	};

	/*
	 *	Initialize the instance structures for each of the
	 *	states.
	 */
	for (i = 1; i <= def->max_state; i++) {
		fr_machine_state_inst_t *state = &m->state[i];

		state->def = &def->state[i];

		for (j = 0; j < 2; j++) {
			fr_dlist_init(&state->enter[j], fr_machine_hook_t, dlist);
			fr_dlist_init(&state->process[j], fr_machine_hook_t, dlist);
			fr_dlist_init(&state->exit[j], fr_machine_hook_t, dlist);
			fr_dlist_init(&state->signal[j], fr_machine_hook_t, dlist);
		}
	}

	fr_dlist_init(&m->deferred, fr_machine_defer_t, dlist);

	/*
	 *	Set the current state to "init".
	 */
	m->current = &m->state[def->init];

#ifdef STATIC_ANALYZER
	if (!m->current || !m->current->def || !m->current->def->process) {
		talloc_free(m);
		return NULL;
	}
#endif

	/*
	 *	We don't transition into the "init" state, as there is
	 *	no previous state.  We just run the "process"
	 *	function, which should transition us into a more
	 *	permanent state.
	 *
	 *	We don't run any pre/post hooks, as the state machine
	 *	is new, and no hooks have been added.
	 *
	 *	The result of the initialization routine can be
	 *	another new state, or 0 for "stay in the current
	 *	state".
	 */
	fr_assert(m->current->def);
	fr_assert(!m->current->def->enter);
	fr_assert(!m->current->def->exit);
	fr_assert(m->current->def->process);

	next = m->current->def->process(m, uctx);
	fr_assert(next >= 0);

	if (def->free) talloc_set_destructor(m, _machine_free);

	if (next) fr_machine_transition(m, next);

	return m;
}

/** Post the new state to the state machine.
 *
 */
static int state_post(fr_machine_t *m, int state)
{
#ifndef NDEBUG
	fr_machine_state_inst_t *current = m->current;
#endif

	/*
	 *	The called function requested that we transition to
	 *	the "free" state.  Don't do that, but instead return
	 *	an error to the caller.  The caller MUST do nothing
	 *	other than free the state machine.
	 */
	if (state == m->def->free) {
		m->dead = true;
		return -1;
	}

	/*
	 *	This is an assertion, because the state machine itself
	 *	shouldn't be broken.
	 */
	fr_assert(current->def->allowed[state]);

	/*
	 *	Transition to the new state, and pause the transition if necessary.
	 */
	fr_machine_transition(m, state);

	return state;
}


/** Process the state machine
 *
 * @param m	The state machine
 * @return
 *	- 0 for "no transition has occured"
 *	- >0 for "we are in a new state".
 *	-<0 for "error, you should tear down the state machine".
 *
 *  This function should be called by the user of the machine.
 *
 *  In general, the caller doesn't really care about the return code
 *  of this function.  The only real utility is >=0 for "continue
 *  calling the state machine as necessary", or <0 for "shut down the
 *  state machine".
 */
int fr_machine_process(fr_machine_t *m)
{
	int state, old;
	fr_machine_state_inst_t *current;

redo:
	current = m->current;

	/*
	 *	Various sanity checks to ensure that the state machine
	 *	implementation isn't doing anything crazy.
	 */

	fr_assert(current != NULL);
	fr_assert(!m->dead);
	fr_assert(!m->paused);
	fr_assert(!m->in_handler);
	fr_assert(fr_dlist_num_elements(&m->deferred) == 0);

	m->in_handler = current;
	old = current->def->number;

	call_hook(m, &current->process[PRE], old, old);

	/*
	 *	Entering this state may, in fact, cause us to switch
	 *	states.  If so, we process the new state, not the old
	 *	one
	 */
	if (fr_dlist_num_elements(&m->deferred) > 0) {
		m->in_handler = NULL;
		fr_machine_resume(m);

		/*
		 *	We do not process dead state machines.
		 */
		if (m->dead) return m->def->free;

		/*
		 *	Start over with the new "pre" process handler.
		 *
		 *	Note that if we have a state transition, we
		 *	skip both "process" and "post-process".
		 */
		goto redo;
	}

	state = current->def->process(m, m->uctx);

	/*
	 *	The "process" function CANNOT do state transitions on
	 *	its own.
	 */
	fr_assert(fr_dlist_num_elements(&m->deferred) == 0);

	call_hook(m, &current->process[POST], old, old);

	m->in_handler = NULL;

	/*
	 *	No changes.
	 */
	if (state == 0) {
		if (fr_dlist_num_elements(&m->deferred) == 0) return 0;

		fr_machine_resume(m);
		return m->current->def->number;
	}

	return state_post(m, state);
}

/** Transition to a new state
 *
 * @param m	The state machine
 * @param state	the state to transition to
 * @return
 *	- <0 for error
 *	- 0 for the transition was made (or deferred)
 *
 *  The transition MAY be deferred.  Note that only one transition at
 *  a time can be deferred.
 *
 *  This function MUST NOT be called from any "hook", or from any
 *  enter/exit/process function.  It should ONLY be called from the
 *  "parent" of the state machine, when it decides that the state
 *  machine needs to change.
 *
 *  i.e. from a timer, or an IO callback
 */
int fr_machine_transition(fr_machine_t *m, int state)
{
	fr_machine_state_inst_t *current = m->current;

	if (m->dead) return -1;

	/*
	 *	Bad states are not allowed.
	 */
	if ((state <= 0) || (state > m->def->max_state)) return -1;

	/*
	 *	If we are not in a state, we cannot transition to
	 *	anything else.
	 */
	if (!current) return -1;

	/*
	 *	Transition to self is "do nothing".
	 */
	if (current->def->number == state) return 0;

	/*
	 *	Check if the transitions are allowed.
	 */
	if (!current->def->allowed[state]) return -1;

	/*
	 *	The caller may be mucking with bits of the state
	 *	machine and/or the code surrounding the state machine.
	 *	In that case, the caller doesn't want transitions to
	 *	occur until it's done those changes.  Otherwise the
	 *	state machine could disappear in the middle of a
	 *	function, which is bad.
	 *
	 *	However, the rest of the code doesn't know what the
	 *	caller wants.  So the caller "pauses" state
	 *	transitions until it's done.  We check for that here,
	 *	and defer transitions until such time as the
	 *	transitions are resumed.
	 */
	if (m->in_handler || m->paused) {
		fr_machine_defer_t *defer = talloc_zero(m, fr_machine_defer_t);

		if (!defer) return -1;

		defer->state = state;
		fr_dlist_insert_tail(&m->deferred, defer);
		return 0;
	}

	/*
	 *	We're allowed to do the transition now, so exit the
	 *	current state, and enter the new one.
	 */
	state_transition(m, state, (void *) fr_machine_transition);

	/*
	 *	Entering a state may cause state transitions to occur.
	 *	Usually due to pre/post callbacks.  If that happens,
	 *	then we immediately process the deferred states.
	 */
	if (fr_dlist_num_elements(&m->deferred) > 0) fr_machine_resume(m);

	return 0;
}

/** Get the current state
 *
 * @param m	The state machine
 * @return
 *	The current state, or 0 for "not in any state"
 */
int fr_machine_current(fr_machine_t *m)
{
	fr_assert(!m->dead);

	if (!m->current) return 0;

	return m->current->def->number;
}

/** Get the name of a particular state
 *
 * @param m	The state machine
 * @param state The state to query
 * @return
 *	the name
 */
char const *fr_machine_state_name(fr_machine_t *m, int state)
{
	fr_assert(!m->dead);

	if ((state < 0) || (state > m->def->max_state)) return "???";

	if (!state) {
		if (m->current) {
			state = m->current->def->number;

		} else {
			return "???";
		}
	}

	return m->def->state[state].name;
}

static int _machine_hook_free(fr_machine_hook_t *hook)
{
	(void) fr_dlist_remove(hook->head, &hook->dlist);

	return 0;
}


/** Add a hook to a state, with an optional talloc_ctx.
 *
 *  The hook is removed when the talloc ctx is freed.
 *
 *  You can also remove the hook by freeing the returned pointer.
 */
void *fr_machine_hook(fr_machine_t *m, TALLOC_CTX *ctx, int state_to_hook, fr_machine_hook_type_t type, fr_machine_hook_sense_t sense,
		      bool oneshot, fr_machine_hook_func_t func, void *uctx)
{
	fr_machine_hook_t *hook;
	fr_dlist_head_t *head;
	fr_machine_state_inst_t *state = &m->state[state_to_hook];

	fr_assert(!m->dead);

	switch (type) {
	case FR_MACHINE_ENTER:
		head = &state->enter[sense];
		break;

	case FR_MACHINE_PROCESS:
		head = &state->process[sense];
		break;

	case FR_MACHINE_EXIT:
		head = &state->exit[sense];
		break;

	case FR_MACHINE_SIGNAL:
		head = &state->signal[sense];
		break;

	default:
		return NULL;
	}

	hook = talloc_zero(ctx, fr_machine_hook_t);
	if (!hook) return NULL;

	*hook = (fr_machine_hook_t) {
		.func = func,
		.head = head,	/* needed for updating num_elements on remove */
		.uctx = uctx,
		.oneshot = oneshot,
	};

	fr_dlist_insert_tail(head, &hook->dlist);

	talloc_set_destructor(hook, _machine_hook_free);

	return hook;
}

/** Pause any transitions.
 *
 */
void fr_machine_pause(fr_machine_t *m)
{
	fr_assert(!m->dead);

	m->paused++;
}

/** Resume transitions.
 *
 */
void fr_machine_resume(fr_machine_t *m)
{
	fr_machine_defer_t *defer, *next;

	fr_assert(!m->dead);
	fr_assert(!m->in_handler);

	if (m->paused > 0) {
		m->paused--;
		if (m->paused > 0) return;
	}

	if (fr_dlist_num_elements(&m->deferred) == 0) return;

	/*
	 *	Process all of the deferred transitions
	 *
	 *	Hopefully this process does not cause new state
	 *	transitions to occur.  Otherwise we might end up in an
	 *	infinite loop.
	 */
	for (defer = fr_dlist_head(&m->deferred); defer != NULL; defer = next) {
		int state = defer->state;

		next = fr_dlist_next(&m->deferred, defer);
		fr_dlist_remove(&m->deferred, defer);
		talloc_free(defer);

		state_transition(m, state, (void *) fr_machine_resume);
	}
}

/** Send an async signal to the state machine.
 *
 * @param m	The state machine
 * @param signal the signal to send to the state machne
 * @return
 *	- 0 for "no transition has occured"
 *	- >0 for "we are in a new state".
 *	-<0 for "error, you should tear down the state machine".
 *
 *  The signal function can return a new state.  i.e. some signals get
 *  ignored, and others cause transitions.
 */
int fr_machine_signal(fr_machine_t *m, int signal)
{
	int old, state;
	fr_machine_state_inst_t *current = m->current;

	if (m->dead) return -1;

	/*
	 *	Bad signals are not allowed.
	 */
	if ((signal <= 0) || (signal > m->def->max_signal)) return -1;

	/*
	 *	Can't send an async signal from within a handler.
	 */
	if (m->in_handler) return -1;

	m->in_handler = (void *) fr_machine_signal;
	old = current->def->number;
	state = 0;

	/*
	 *	Note that the callbacks (for laziness) take the
	 *	_current_ state, and the _signal_.  Not the _new_
	 *	state!
	 */
	call_hook(m, &current->signal[PRE], old, signal);
	if (current->def->signal) state = current->def->signal(m, signal, m->uctx);
	call_hook(m, &current->signal[POST], old, signal);

	m->in_handler = NULL;

	/*
	 *	No changes.  Tell the caller to wait for something
	 *	else to signal a transition.
	 */
	if (state == 0) return 0;

	fr_assert(state != old); /* can't ask us to transition to the current state */

	return state_post(m, state);
}

