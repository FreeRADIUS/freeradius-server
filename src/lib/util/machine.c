#include <freeradius-devel/rad_assert.h>
#include "machine.h"

static int _machine_free(fr_machine_t *m)
{
	fr_machine_edge_t *edge;

	edge = &m->edge[m->state];
	if (!edge) return -1;

	if (!edge->exit) return 0;

	/*
	 *	Ensure that we've exited the current state.
	 */
	return edge->exit(m, ctx);
}

fr_machine_t *fr_machine_alloc(TALLOC_CTX *ctx, int max_state, int max_signal, fr_machine_edge_t const *edge, void *uctx)
{
	fr_machine_t *m;

	m = talloc_zero(ctx, fr_machine_t);
	if (!m) return NULL;

	m->max_state = max_state;
	m->max_signal = max_signal;
	m->edge = edge;
	m->uctx = uctx;

	/*
	 *	The caller can set m->fail if necessary
	 */

	talloc_set_destructor(m, _machine_free);

	return m;
}

int fr_machine_run(fr_machine_t *m, void *ctx)
{
	int next;
	fr_machine_edge_t *edge;

	if (!m) return -1;

	edge = &m->edge[m->state];
	if (!edge) return -1;

	if (!edge->process) return 0; /* we can have states which do nothing */

	/*
	 *	This should return 1..max_state for "next state"
	 */
	next = edge->process(m, ctx);
	if (next <= 0) return next;

	/*
	 *	The process function should return "0" for "do
	 *	nothing".
	 */
	fr_assert(next != m->state);

	return fr_machine_transition(m, ctx, next);
}


int fr_machine_signal(fr_machine_t *m, void *ctx, int signal)
{
	fr_machine_edge_t *edge;

	if (!m) return -1;
	if ((signal <= 0) || (signal > m->max_signal)) return -1;

	edge = &m->edge[m->state];
	if (!edge) return -1;

	if (!edge->signal) return 0; /* we can ignore signals */

	edge->signal(m, ctx, signal); /* signals have no return code */
	return 0;
}

int fr_machine_transition(fr_machine_t *m, void *ctx, int next)
{
	int current;
	fr_machine_edge_t *edge;

	if (!m) return -1;
	if ((next <= 0) || (next > m->max_state)) return -1;

	current = m->state;
	edge = &m->edge[current];

	if (!edge) return -1;

	/*
	 *	Exit the current state.  If this function fails, then
	 *	we presume that it has transitioned from current to a
	 *	*different* state than we were passed.  So stop
	 *	running this state machine, and let the called
	 *	transition override us.
	 *
	 *	Note that we ALWAYS exit the current state, even if
	 *	this transition isn't allowed.  Doing so allows us to
	 *	clean up the current state on error conditions.
	 */
	if (edge->exit && (edge->exit(m, ctx) < 0)) {
		fr_assert(m->state != current);	
		return -1;
	}

	edge = &m->edge[next];

	/*
	 *	The next state doesn't allow transitions from our
	 *	current state.  Die.
	 */
	if ((edge->allowed & (1 << current)) == 0) {
		if (!m->fail) return -1;
		m->state = 0;
		return m->fail(m, crtx);
	}

	/*
	 *	Do any special transitions into the current state,
	 *	from the previous one.
	 */
	if (edge->transition && (edge->transition(m, ctx, current) < 0)) {
		return -1;
	}

	/*
	 *	Enter the new state.
	 */
	if (edge->enter && (edge->enter(m, ctx) < 0)) {
		fr_assert(m->state != current);	
		return -1;
	}

	fr_assert(m->state == current);
	m->state = next;
	return 0;
}
