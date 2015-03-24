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
 * @copyright 2014 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/rad_assert.h>

static rbtree_t *state_tree;

#ifdef HAVE_PTHREAD_H
static pthread_mutex_t state_mutex;

#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock

#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)

#endif

typedef struct state_entry_t {
	uint8_t		state[AUTH_VECTOR_LEN];

	time_t		cleanup;
	struct state_entry_t *prev;
	struct state_entry_t *next;

	int		tries;

	VALUE_PAIR	*vps;

	void 		*opaque;
	void 		(*free_opaque)(void *opaque);
} state_entry_t;

static state_entry_t *state_head = NULL;
static state_entry_t *state_tail = NULL;

/*
 *	rbtree callback.
 */
static int state_entry_cmp(void const *one, void const *two)
{
	state_entry_t const *a = one;
	state_entry_t const *b = two;

	return memcmp(a->state, b->state, sizeof(a->state));
}

/*
 *	When an entry is free'd, it's removed from the linked list of
 *	cleanup times.
 *
 *	Note that
 */
static void state_entry_free(state_entry_t *entry)
{
	state_entry_t *prev, *next;

	/*
	 *	If we're deleting the whole tree, don't bother doing
	 *	all of the fixups.
	 */
	if (!state_tree) return;

	prev = entry->prev;
	next = entry->next;

	if (prev) {
		rad_assert(state_head != entry);
		prev->next = next;
	} else if (state_head) {
		rad_assert(state_head == entry);
		state_head = next;
	}

	if (next) {
		rad_assert(state_tail != entry);
		next->prev = prev;
	} else if (state_tail) {
		rad_assert(state_tail == entry);
		state_tail = prev;
	}

	if (entry->opaque) {
		entry->free_opaque(entry->opaque);
	}

#ifdef WITH_VERIFY_PTR
	(void) talloc_get_type_abort(entry, state_entry_t);
#endif
	rbtree_deletebydata(state_tree, entry);
	talloc_free(entry);
}

bool fr_state_init(void)
{
#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&state_mutex, NULL) != 0) {
		return false;
	}
#endif

	state_tree = rbtree_create(NULL, state_entry_cmp, NULL, 0);
	if (!state_tree) {
		return false;
	}

	return true;
}

void fr_state_delete(void)
{
	rbtree_t *my_tree;

	PTHREAD_MUTEX_LOCK(&state_mutex);

	/*
	 *	Tell the talloc callback to NOT delete the entry from
	 *	the tree.  We're deleting the entire tree.
	 */
	my_tree = state_tree;
	state_tree = NULL;

	rbtree_free(my_tree);
	PTHREAD_MUTEX_UNLOCK(&state_mutex);
}

/*
 *	Create a new entry.  Called with the mutex held.
 */
static state_entry_t *fr_state_create(RADIUS_PACKET *packet, state_entry_t *old)
{
	size_t i;
	uint32_t x;
	time_t now = time(NULL);
	VALUE_PAIR *vp;
	state_entry_t *entry, *next;

	/*
	 *	Clean up old entries.
	 */
	for (entry = state_head; entry != NULL; entry = next) {
		next = entry->next;

		if (entry == old) continue;

		/*
		 *	Too old, we can delete it.
		 */
		if (entry->cleanup < now) {
			state_entry_free(entry);
			continue;
		}

		/*
		 *	Unused.  We can delete it, even if now isn't
		 *	the time to clean it up.
		 */
		if (!entry->vps && !entry->opaque) {
			state_entry_free(entry);
			continue;
		}

		break;
	}

	/*
	 *	Limit the size of the cache based on how many requests
	 *	we can handle at the same time.
	 */
	if (rbtree_num_elements(state_tree) >= main_config.max_requests * 2) {
		return NULL;
	}

	/*
	 *	Allocate a new one.
	 */
	entry = talloc_zero(state_tree, state_entry_t);
	if (!entry) return NULL;

	/*
	 *	Limit the lifetime of this entry based on how long the
	 *	server takes to process a request.  Doing it this way
	 *	isn't perfect, but it's reasonable, and it's one less
	 *	thing for an administrator to configure.
	 */
	entry->cleanup = now + main_config.max_request_time * 10;

	/*
	 *	Hacks for EAP, until we convert EAP to using the state API.
	 *
	 *	The EAP module creates it's own State attribute, so we
	 *	want to use that one in preference to one we create.
	 */
	vp = pairfind(packet->vps, PW_STATE, 0, TAG_ANY);

	/*
	 *	If possible, base the new one off of the old one.
	 */
	if (old) {
		entry->tries = old->tries + 1;

		rad_assert(old->vps == NULL);

		/*
		 *	Track State
		 */
		if (!vp) {
			memcpy(entry->state, old->state, sizeof(entry->state));

			entry->state[1] = entry->state[0] ^ entry->tries;
			entry->state[8] = entry->state[2] ^ ((((uint32_t) HEXIFY(RADIUSD_VERSION)) >> 16) & 0xff);
			entry->state[10] = entry->state[2] ^ ((((uint32_t) HEXIFY(RADIUSD_VERSION)) >> 8) & 0xff);
			entry->state[12] = entry->state[2] ^ (((uint32_t) HEXIFY(RADIUSD_VERSION)) & 0xff);
		}

		/*
		 *	The old one isn't used any more, so we can free it.
		 */
		if (!old->opaque) state_entry_free(old);

	} else if (!vp) {
		/*
		 *	16 octets of randomness should be enough to
		 *	have a globally unique state.
		 */
		for (i = 0; i < sizeof(entry->state) / sizeof(x); i++) {
			x = fr_rand();
			memcpy(entry->state + (i * 4), &x, sizeof(x));
		}
	}

	/*
	 *	If EAP created a State, use that.  Otherwise, use the
	 *	one we created above.
	 */
	if (vp) {
		if (debug_flag && (vp->vp_length > sizeof(entry->state))) {
			WARN("State should be %zd octets!",
			     sizeof(entry->state));
		}
		memcpy(entry->state, vp->vp_octets, sizeof(entry->state));

	} else {
		vp = paircreate(packet, PW_STATE, 0);
		pairmemcpy(vp, entry->state, sizeof(entry->state));
		pairadd(&packet->vps, vp);
	}

	if (!rbtree_insert(state_tree, entry)) {
		talloc_free(entry);
		return NULL;
	}

	/*
	 *	Link it to the end of the list, which is implicitely
	 *	ordered by cleanup time.
	 */
	if (!state_head) {
		entry->prev = entry->next = NULL;
		state_head = state_tail = entry;
	} else {
		rad_assert(state_tail != NULL);

		entry->prev = state_tail;
		state_tail->next = entry;

		entry->next = NULL;
		state_tail = entry;
	}

	return entry;
}


/*
 *	Find the entry, based on the State attribute.
 */
static state_entry_t *fr_state_find(RADIUS_PACKET *packet)
{
	VALUE_PAIR *vp;
	state_entry_t *entry, my_entry;

	vp = pairfind(packet->vps, PW_STATE, 0, TAG_ANY);
	if (!vp) return NULL;

	if (vp->vp_length != sizeof(my_entry.state)) return NULL;

	memcpy(my_entry.state, vp->vp_octets, sizeof(my_entry.state));

	entry = rbtree_finddata(state_tree, &my_entry);

#ifdef WITH_VERIFY_PTR
	if (entry)  (void) talloc_get_type_abort(entry, state_entry_t);
#endif

	return entry;
}

/*
 *	Called when sending Access-Reject, so that all State is
 *	discarded.
 */
void fr_state_discard(REQUEST *request, RADIUS_PACKET *original)
{
	state_entry_t *entry;

	pairfree(&request->state);
	request->state = NULL;

	PTHREAD_MUTEX_LOCK(&state_mutex);
	entry = fr_state_find(original);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state_mutex);
		return;
	}

	state_entry_free(entry);
	PTHREAD_MUTEX_UNLOCK(&state_mutex);
	return;
}

/*
 *	Get the VPS from the state.
 */
void fr_state_get_vps(REQUEST *request, RADIUS_PACKET *packet)
{
	state_entry_t *entry;

	rad_assert(request->state == NULL);

	/*
	 *	No State, don't do anything.
	 */
	if (!pairfind(request->packet->vps, PW_STATE, 0, TAG_ANY)) {
		RDEBUG3("session-state: No State attribute");
		return;
	}

	PTHREAD_MUTEX_LOCK(&state_mutex);
	entry = fr_state_find(packet);

	/*
	 *	This has to be done in a mutex lock, because talloc
	 *	isn't thread-safe.
	 */
	if (entry) {
		pairfilter(request, &request->state, &entry->vps, 0, 0, TAG_ANY);
		RDEBUG2("session-state: Found cached attributes");
		rdebug_pair_list(L_DBG_LVL_1, request, request->state, NULL);

	} else {
		RDEBUG2("session-state: No cached attributes");
	}

	PTHREAD_MUTEX_UNLOCK(&state_mutex);

	VERIFY_REQUEST(request);
	return;
}


/*
 *	Put request->state into the State attribute.  Put the State
 *	attribute into the vps list.  Delete the original entry, if it
 *	exists.
 */
bool fr_state_put_vps(REQUEST *request, RADIUS_PACKET *original, RADIUS_PACKET *packet)
{
	state_entry_t *entry, *old;

	if (!request->state) {
		RDEBUG3("session-state: Nothing to cache");
		return true;
	}

	RDEBUG2("session-state: Saving cached attributes");
	rdebug_pair_list(L_DBG_LVL_1, request, request->state, NULL);

	PTHREAD_MUTEX_LOCK(&state_mutex);

	if (original) {
		old = fr_state_find(original);
	} else {
		old = NULL;
	}

	entry = fr_state_create(packet, old);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state_mutex);
		return false;
	}

	/*
	 *	This has to be done in a mutex lock, because talloc
	 *	isn't thread-safe.
	 */
	pairfilter(entry, &entry->vps, &request->state, 0, 0, TAG_ANY);
	PTHREAD_MUTEX_UNLOCK(&state_mutex);

	rad_assert(request->state == NULL);
	VERIFY_REQUEST(request);
	return true;
}

/*
 *	Find the opaque data associated with a State attribute.
 *	Leave the data in the entry.
 */
void *fr_state_find_data(UNUSED REQUEST *request, RADIUS_PACKET *packet)
{
	void *data;
	state_entry_t *entry;

	PTHREAD_MUTEX_LOCK(&state_mutex);
	entry = fr_state_find(packet);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state_mutex);
		return NULL;
	}

	data = entry->opaque;
	PTHREAD_MUTEX_UNLOCK(&state_mutex);

	return data;
}


/*
 *	Get the opaque data associated with a State attribute.
 *	and remove the data from the entry.
 */
void *fr_state_get_data(UNUSED REQUEST *request, RADIUS_PACKET *packet)
{
	void *data;
	state_entry_t *entry;

	PTHREAD_MUTEX_LOCK(&state_mutex);
	entry = fr_state_find(packet);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state_mutex);
		return NULL;
	}

	data = entry->opaque;
	entry->opaque = NULL;
	PTHREAD_MUTEX_UNLOCK(&state_mutex);

	return data;
}


/*
 *	Get the opaque data associated with a State attribute.
 *	and remove the data from the entry.
 */
bool fr_state_put_data(UNUSED REQUEST *request, RADIUS_PACKET *original, RADIUS_PACKET *packet,
		       void *data, void (*free_data)(void *))
{
	state_entry_t *entry, *old;

	PTHREAD_MUTEX_LOCK(&state_mutex);

	if (original) {
		old = fr_state_find(original);
	} else {
		old = NULL;
	}

	entry = fr_state_create(packet, old);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state_mutex);
		return false;
	}

	/*
	 *	If we're moving the data, ensure that we delete it
	 *	from the old state.
	 */
	if (old && (old->opaque == data)) {
		old->opaque = NULL;
	}

	entry->opaque = data;
	entry->free_opaque = free_data;

	PTHREAD_MUTEX_UNLOCK(&state_mutex);
	return true;
}
