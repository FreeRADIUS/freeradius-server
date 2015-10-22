/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @brief Multi-packet state handling
 * @file main/state.c
 *
 * @ingroup AVP
 *
 * For each round of a multi-round authentication method such as EAP,
 * or a 2FA method such as OTP, a state entry will be created.  The state
 * entry holds data that should be available during the complete lifecycle
 * of the authentication attempt.
 *
 * When a request is complete, #fr_state_put_vps is called to transfer
 * ownership of the state VALUE_PAIRs and state_ctx (which the VALUE_PAIRs
 * are allocated in) to a #fr_state_entry_t.  This #fr_state_entry_t holds the
 * value of the State attribute, that will be send out in the response.
 *
 * When the next request is received, #fr_state_get_vps is called to transfer
 * the VALUE_PAIRs and state ctx to the new request.
 *
 * The ownership of the state_ctx and state VALUE_PAIRs is transferred as below:
 *
 * @verbatim
   request -> state_entry -> request -> state_entry -> request -> free()
          \-> reply                 \-> reply                 \-> access-reject/access-accept
 * @endverbatim
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/rad_assert.h>

/** Holds a state value, and associated VALUE_PAIRs and data
 *
 */
typedef struct state_entry {
	uint8_t			state[AUTH_VECTOR_LEN];		//!< State value in binary.

	time_t			cleanup;			//!< When this entry should be cleaned up.
	struct state_entry	*prev;				//!< Previous entry in the cleanup list.
	struct state_entry	*next;				//!< Next entry in the cleanup list.

	int			tries;

	TALLOC_CTX		*ctx;
	VALUE_PAIR		*vps;

	void 			*data;
} fr_state_entry_t;

struct fr_state_tree_t {
	int			max_sessions;			//!< Maximum number of sessions we track.
	rbtree_t		*tree;				//!< rbtree used to lookup state value.

	fr_state_entry_t	*head, *tail;			//!< Entries to expire.

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		mutex;				//!< Synchronisation mutex.
#endif
};

static fr_state_tree_t *global_state = NULL;

#ifdef HAVE_PTHREAD_H
#  define PTHREAD_MUTEX_LOCK if (main_config.spawn_workers) pthread_mutex_lock
#  define PTHREAD_MUTEX_UNLOCK if (main_config.spawn_workers) pthread_mutex_unlock
#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#  define PTHREAD_MUTEX_LOCK(_x)
#  define PTHREAD_MUTEX_UNLOCK(_x)
#endif

/** Compare two fr_state_entry_t based on their state value i.e. the value of the attribute
 *
 */
static int state_entry_cmp(void const *one, void const *two)
{
	fr_state_entry_t const *a = one;
	fr_state_entry_t const *b = two;

	return memcmp(a->state, b->state, sizeof(a->state));
}

/** Free a state entry, removing it from the linked lists of states to free
 *
 */
static void state_entry_free(fr_state_tree_t *state, fr_state_entry_t *entry)
{
	fr_state_entry_t *prev, *next;

	prev = entry->prev;
	next = entry->next;

	if (prev) {
		rad_assert(state->head != entry);
		prev->next = next;
	} else if (state->head) {
		rad_assert(state->head == entry);
		state->head = next;
	}

	if (next) {
		rad_assert(state->tail != entry);
		next->prev = prev;
	} else if (state->tail) {
		rad_assert(state->tail == entry);
		state->tail = prev;
	}

	if (entry->data) talloc_free(entry->data);

#ifdef WITH_VERIFY_PTR
	(void) talloc_get_type_abort(entry, fr_state_entry_t);
#endif
	rbtree_deletebydata(state->tree, entry);

	if (entry->ctx) talloc_free(entry->ctx);	/* Should free all VPs associated with the entry */

	talloc_free(entry);
}

/** Walker callback to free all entries in the tree
 *
 */
static int _state_tree_free_entry(void *ctx, void *data)
{
	fr_state_entry_t *entry = talloc_get_type_abort(data, fr_state_entry_t);
	fr_state_tree_t *tree = talloc_get_type_abort(ctx, fr_state_tree_t);

	state_entry_free(tree, entry);

	return 0;
}

/** Free the state tree
 *
 */
static int _state_tree_free(fr_state_tree_t *state)
{
#ifdef HAVE_PTHREAD_H
	if (main_config.spawn_workers) pthread_mutex_destroy(&state->mutex);
#endif

	/*
	 *	Delete all the entries in the tree
	 */
	rbtree_walk(state->tree, RBTREE_DELETE_ORDER, _state_tree_free_entry, state);

	/*
	 *	Ensure we got *all* the entries
	 */
	rad_assert(!state->head);

	/*
	 *	Free the rbtree
	 */
	rbtree_free(state->tree);

	if (state == global_state) global_state = NULL;

	return 0;
}

/** Initialise a new state tree
 *
 * @param ctx to link the lifecycle of the state tree to.
 * @param max_sessions we track state for.
 * @return a new state tree or NULL on failure.
 */
fr_state_tree_t *fr_state_tree_init(TALLOC_CTX *ctx, int max_sessions)
{
	fr_state_tree_t *state;

	/*
	 *	@fixme stupid globals
	 */
	global_state = state = talloc_zero(NULL, fr_state_tree_t);
	if (!state) return 0;

	state->max_sessions = max_sessions;

	/*
	 *	Create a break in the contexts.
	 *	We still want this to be freed at the same time
	 *	as the parent, but we also need it to be thread
	 *	safe, and multiple threads could be using the
	 *	tree.
	 */
	fr_link_talloc_ctx_free(ctx, state);

#ifdef HAVE_PTHREAD_H
	if (main_config.spawn_workers && (pthread_mutex_init(&state->mutex, NULL) != 0)) {
		talloc_free(state);
		return NULL;
	}
#endif

	/*
	 *	We need to do controlled freeing of the
	 *	rbtree, so that all the state entries
	 *	are freed before it's destroyed.  Hence
	 *	it being parented from the NULL ctx.
	 */

	state->tree = rbtree_create(NULL, state_entry_cmp, NULL, 0);
	if (!state->tree) {
		talloc_free(state);
		return NULL;
	}
	talloc_set_destructor(state, _state_tree_free);

	return state;
}

/** Create a new state entry
 *
 * @note Called with the mutex held.
 */
static fr_state_entry_t *state_entry_create(fr_state_tree_t *state, RADIUS_PACKET *packet, fr_state_entry_t *old)
{
	size_t		i;
	uint32_t	x;
	time_t		now = time(NULL);
	VALUE_PAIR	*vp;
	fr_state_entry_t	*entry, *next;

	uint8_t		old_state[AUTH_VECTOR_LEN];
	int		old_tries = 0;

	/*
	 *	Clean up old entries.
	 */
	for (entry = state->head; entry != NULL; entry = next) {
		next = entry->next;

		if (entry == old) continue;

		/*
		 *	Too old, we can delete it.
		 */
		if (entry->cleanup < now) {
			state_entry_free(state, entry);
			continue;
		}

		/*
		 *	Unused.  We can delete it, even if now isn't
		 *	the time to clean it up.
		 */
		if (!entry->ctx && !entry->data) {
			state_entry_free(state, entry);
			continue;
		}

		break;
	}

	if (rbtree_num_elements(state->tree) >= (uint32_t) state->max_sessions) return NULL;

	/*
	 *	Record the information from the old state, we may base the
	 *	new state off the old one.
	 *
	 *	Once we release the mutex, the state of old becomes indeterminate
	 *	so we have to grab the values now.
	 */
	if (old) {
		old_tries = old->tries;

		memcpy(old_state, old->state, sizeof(old_state));

		/*
		 *	The old one isn't used any more, so we can free it.
		 */
		if (!old->data) state_entry_free(state, old);
	}
	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	/*
	 *	Allocation doesn't need to occur inside the critical region
	 *	and would add significantly to contention.
	 *
	 *	We reparent the talloc chunk later (when we hold the mutex again)
	 *	we can't do it now due to thread safety issues with talloc.
	 */
	entry = talloc_zero(NULL, fr_state_entry_t);
	if (!entry) {
		PTHREAD_MUTEX_LOCK(&state->mutex);	/* Caller expects this to be locked */
		return NULL;
	}

	/*
	 *	Limit the lifetime of this entry based on how long the
	 *	server takes to process a request.  Doing it this way
	 *	isn't perfect, but it's reasonable, and it's one less
	 *	thing for an administrator to configure.
	 */
	entry->cleanup = now + main_config.max_request_time * 10;

	/*
	 *	Some modules like rlm_otp create their own magic
	 *	state attributes.  If a state value already exists
	 *	int the reply, we use that in preference to the
	 *	old state.
	 */
	vp = fr_pair_find_by_num(packet->vps, PW_STATE, 0, TAG_ANY);
	if (vp) {
		if (DEBUG_ENABLED && (vp->vp_length > sizeof(entry->state))) {
			WARN("State too long, will be truncated.  Expected <= %zd bytes, got %zu bytes",
			     sizeof(entry->state), vp->vp_length);
		}
		memcpy(entry->state, vp->vp_octets, sizeof(entry->state));
	} else {
		/*
		 *	Base the new state on the old state if we had one.
		 */
		if (old) {
			memcpy(entry->state, old_state, sizeof(entry->state));
			entry->tries = old_tries + 1;
		}

		entry->state[0] = entry->tries;
		entry->state[1] = entry->state[0] ^ entry->tries;
		entry->state[8] = entry->state[2] ^ ((((uint32_t) HEXIFY(RADIUSD_VERSION)) >> 16) & 0xff);
		entry->state[10] = entry->state[2] ^ ((((uint32_t) HEXIFY(RADIUSD_VERSION)) >> 8) & 0xff);
		entry->state[12] = entry->state[2] ^ (((uint32_t) HEXIFY(RADIUSD_VERSION)) & 0xff);

		/*
		 *	16 octets of randomness should be enough to
		 *	have a globally unique state.
		 */
		for (i = 0; i < sizeof(entry->state) / sizeof(x); i++) {
			x = fr_rand();
			memcpy(entry->state + (i * 4), &x, sizeof(x));
		}

		/*
		 *	Allow a portion ofthe State attribute to be set.
		 *
		 *	This allows load-balancing proxies to be much
		 *	less stateful.
		 */
		if (main_config.state_seed < 256) entry->state[3] = main_config.state_seed;

		vp = fr_pair_afrom_num(packet, PW_STATE, 0);
		fr_pair_value_memcpy(vp, entry->state, sizeof(entry->state));
		fr_pair_add(&packet->vps, vp);
	}

	PTHREAD_MUTEX_LOCK(&state->mutex);
	if (rbtree_num_elements(state->tree) >= (uint32_t) state->max_sessions) {
		talloc_free(entry);
		return NULL;
	}

	if (!rbtree_insert(state->tree, entry)) {
		talloc_free(entry);
		return NULL;
	}

	/*
	 *	Link it to the end of the list, which is implicitely
	 *	ordered by cleanup time.
	 */
	if (!state->head) {
		entry->prev = entry->next = NULL;
		state->head = state->tail = entry;
	} else {
		rad_assert(state->tail != NULL);

		entry->prev = state->tail;
		state->tail->next = entry;

		entry->next = NULL;
		state->tail = entry;
	}

	return entry;
}

/** Find the entry, based on the State attribute
 *
 */
static fr_state_entry_t *state_entry_find(fr_state_tree_t *state, RADIUS_PACKET *packet)
{
	VALUE_PAIR *vp;
	fr_state_entry_t *entry, my_entry;

	vp = fr_pair_find_by_num(packet->vps, PW_STATE, 0, TAG_ANY);
	if (!vp) return NULL;

	if (vp->vp_length != sizeof(my_entry.state)) return NULL;

	memcpy(my_entry.state, vp->vp_octets, sizeof(my_entry.state));

	entry = rbtree_finddata(state->tree, &my_entry);

#ifdef WITH_VERIFY_PTR
	if (entry) (void) talloc_get_type_abort(entry, fr_state_entry_t);
#endif

	return entry;
}

/** Called when sending an Access-Reject to discard state information
 *
 */
void fr_state_discard(REQUEST *request, RADIUS_PACKET *original)
{
	fr_state_entry_t *entry;
	fr_state_tree_t *state = global_state;

	fr_pair_list_free(&request->state);
	request->state = NULL;

	PTHREAD_MUTEX_LOCK(&state->mutex);
	entry = state_entry_find(state, original);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state->mutex);
		return;
	}

	state_entry_free(state, entry);
	PTHREAD_MUTEX_UNLOCK(&state->mutex);
	return;
}

/** Copy a pointer to the head of the list of state VALUE_PAIRs (and their ctx) into the request
 *
 * @note Does not copy the actual VALUE_PAIRs.  The VALUE_PAIRs and their context
 *	are transferred between state entries as the conversation progresses.
 */
void fr_state_get_vps(REQUEST *request, RADIUS_PACKET *packet)
{
	fr_state_entry_t *entry;
	fr_state_tree_t *state = global_state;
	TALLOC_CTX *old_ctx = NULL;

	rad_assert(request->state == NULL);

	/*
	 *	No State, don't do anything.
	 */
	if (!fr_pair_find_by_num(request->packet->vps, PW_STATE, 0, TAG_ANY)) {
		RDEBUG3("No &request:State attribute, can't restore &session-state");
		return;
	}

	PTHREAD_MUTEX_LOCK(&state->mutex);
	entry = state_entry_find(state, packet);

	/*
	 *	This has to be done in a mutex lock, because talloc
	 *	isn't thread-safe.
	 */
	if (entry) {
		if (request->state_ctx) old_ctx = request->state_ctx;

		request->state_ctx = entry->ctx;
		request->state = entry->vps;

		entry->ctx = NULL;
		entry->vps = NULL;
	}

	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	if (request->state) {
		RDEBUG2("Restored &session-state");
		rdebug_pair_list(L_DBG_LVL_2, request, request->state, "&session-state:");
	} else {
		RDEBUG3("No &session-state attributes to restore");
	}

	/*
	 *	Free this outside of the mutex for less contention.
	 */
	if (old_ctx) talloc_free(old_ctx);

	VERIFY_REQUEST(request);
	return;
}


/** Transfer ownership of the state VALUE_PAIRs and ctx, back to a state entry
 *
 * Put request->state into the State attribute.  Put the State attribute
 * into the vps list.  Delete the original entry, if it exists
 *
 * Also creates a new state entry.
 */
bool fr_state_put_vps(REQUEST *request, RADIUS_PACKET *original, RADIUS_PACKET *packet)
{
	fr_state_entry_t *entry, *old;
	fr_state_tree_t *state = global_state;

	if (!request->state) {
		RDEBUG3("No &session-state attributes to store");
		return true;
	}

	RDEBUG2("Saving &session-state");
	rdebug_pair_list(L_DBG_LVL_2, request, request->state, "&session-state:");

	PTHREAD_MUTEX_LOCK(&state->mutex);

	old = original ? state_entry_find(state, original) :
			 NULL;

	entry = state_entry_create(state, packet, old);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state->mutex);
		return false;
	}

	rad_assert(entry->ctx == NULL);
	entry->ctx = request->state_ctx;
	entry->vps = request->state;

	request->state_ctx = NULL;
	request->state = NULL;

	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	rad_assert(request->state == NULL);
	VERIFY_REQUEST(request);
	return true;
}

/** Find the opaque data associated with a State attribute
 *
 * Leave the data in the entry.
 */
void *fr_state_find_data(fr_state_tree_t *state, RADIUS_PACKET *packet)
{
	void *data;
	fr_state_entry_t *entry;

	if (!state) return false;

	PTHREAD_MUTEX_LOCK(&state->mutex);
	entry = state_entry_find(state, packet);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state->mutex);
		return NULL;
	}

	data = entry->data;
	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	return data;
}


/** Get the opaque data associated with a State attribute.
 *
 * Then remove the data from the entry.
 */
void *fr_state_get_data(fr_state_tree_t *state, RADIUS_PACKET *packet)
{
	void *data;
	fr_state_entry_t *entry;

	if (!state) return NULL;

	PTHREAD_MUTEX_LOCK(&state->mutex);
	entry = state_entry_find(state, packet);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state->mutex);
		return NULL;
	}

	data = entry->data;
	entry->data = NULL;
	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	return data;
}


/** Get the opaque data associated with a State attribute.
 *
 * Remove the data from the entry.
 */
bool fr_state_put_data(fr_state_tree_t *state, RADIUS_PACKET *original, RADIUS_PACKET *packet, void *data)
{
	fr_state_entry_t *entry, *old;

	if (!state) return false;

	PTHREAD_MUTEX_LOCK(&state->mutex);

	old = original ? state_entry_find(state, original) :
			 NULL;

	entry = state_entry_create(state, packet, old);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state->mutex);
		return false;
	}

	/*
	 *	If we're moving the data, ensure that we delete it
	 *	from the old state.
	 */
	if (old && (old->data == data)) old->data = NULL;

	entry->data = data;

	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	return true;
}
