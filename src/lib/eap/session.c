/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file lib/eap/session.h
 * @brief EAP session management.
 *
 * @copyright 2019 The FreeRADIUS server project
 */
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/radius/radius.h>

#include "attrs.h"
#include "compose.h"
#include "session.h"

static int _eap_session_free(eap_session_t *eap_session)
{
	REQUEST *request = eap_session->request;

	if (eap_session->identity) {
		talloc_free(eap_session->identity);
		eap_session->identity = NULL;
	}

#ifdef WITH_VERIFY_PTR
	if (eap_session->prev_round) (void)fr_cond_assert(talloc_parent(eap_session->prev_round) == eap_session);
	if (eap_session->this_round) (void)fr_cond_assert(talloc_parent(eap_session->this_round) == eap_session);
#endif

	/*
	 *	Give helpful debug messages if:
	 *
	 *	we're debugging TLS sessions, which don't finish,
	 *	and which aren't deleted early due to a likely RADIUS
	 *	retransmit which nukes our ID, and therefore our state.
	 */
	if (((request && RDEBUG_ENABLED) || (!request && DEBUG_ENABLED)) &&
	    (eap_session->tls && !eap_session->finished && ((fr_time() - eap_session->updated) > (((fr_time_t) 3) * NSEC)))) {
		ROPTIONAL(RWDEBUG, WARN, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		ROPTIONAL(RWDEBUG, WARN, "!! EAP session %016" PRIxPTR " did not finish!                   !!",
			  (uintptr_t)eap_session);
		ROPTIONAL(RWDEBUG, WARN, "!! See http://wiki.freeradius.org/guide/Certificate_Compatibility !!");
		ROPTIONAL(RWDEBUG, WARN, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	}

	ROPTIONAL(RDEBUG4, DEBUG4, "Freeing eap_session_t %p", eap_session);

	return 0;
}

/** Allocate a new eap_session_t
 *
 * Allocates a new eap_session_t, and inserts it into the REQUEST_DATA_EAP_SESSION index
 * of the request.
 *
 * @note The eap_session_t will remove itself from the #REQUEST_DATA_EAP_SESSION index
 *	if it is freed.  This is to simplify management of the request data entry.
 *
 * @param[in] request That generated this eap_session_t.
 * @return
 *	- A new #eap_session_t on success.
 *	- NULL on failure.
 */
static eap_session_t *eap_session_alloc(REQUEST *request)
{
	eap_session_t	*eap_session;

	eap_session = talloc_zero(NULL, eap_session_t);
	if (!eap_session) {
		ERROR("Failed allocating eap_session");
		return NULL;
	}
	eap_session->request = request;
	eap_session->updated = request->packet->timestamp;

	talloc_set_destructor(eap_session, _eap_session_free);

	return eap_session;
}

/** 'destroy' an EAP session and dissasociate it from the current request
 *
 * @note This could be done in the eap_session_t destructor (and was done previously)
 *	but this made the code too hard to follow, and too fragile.
 *
 * @see eap_session_continue
 * @see eap_session_freeze
 * @see eap_session_thaw
 *
 * @param eap_session to destroy (disassociate and free).
 */
void eap_session_destroy(eap_session_t **eap_session)
{
	if (!*eap_session) return;

	if (!(*eap_session)->request) {
		TALLOC_FREE(*eap_session);
		return;
	}

#ifndef NDEBUG
	{
		eap_session_t *in_request;

		in_request = request_data_get((*eap_session)->request, NULL, REQUEST_DATA_EAP_SESSION);

		/*
		 *	Additional sanity check.  Either there's no eap_session
		 *	associated with the request, or it matches the one we're
		 *	about to free.
		 */
		fr_assert(!in_request || (*eap_session == in_request));
	}
#else
	(void) request_data_get((*eap_session)->request, NULL, REQUEST_DATA_EAP_SESSION);
#endif

	TALLOC_FREE(*eap_session);
}

/** Freeze an #eap_session_t so that it can continue later
 *
 * Sets the request and pointer to the eap_session to NULL. Primarily here to help track
 * the lifecycle of an #eap_session_t.
 *
 * The actual freezing/thawing and management (ensuring it's available during multiple
 * rounds of EAP) of the #eap_session_t associated with REQUEST_DATA_EAP_SESSION, is
 * done by the state API.
 *
 * @note must be called before mod_* functions in rlm_eap return.
 *
 * @see eap_session_continue
 * @see eap_session_thaw
 * @see eap_session_destroy
 *
 * @param eap_session to freeze.
 */
void eap_session_freeze(eap_session_t **eap_session)
{
	if (!*eap_session) return;

	fr_assert((*eap_session)->request);
	(*eap_session)->request = NULL;
	*eap_session = NULL;
}

/** Thaw an eap_session_t so it can be continued
 *
 * Retrieve an #eap_session_t from the request data, and set relevant fields. Primarily
 * here to help track the lifecycle of an #eap_session_t.
 *
 * The actual freezing/thawing and management (ensuring it's available during multiple
 * rounds of EAP) of the #eap_session_t associated with REQUEST_DATA_EAP_SESSION, is
 * done by the state API.
 *
 * @note #eap_session_continue should be used instead if ingesting an #eap_packet_raw_t.
 *
 * @see eap_session_continue
 * @see eap_session_freeze
 * @see eap_session_destroy
 *
 * @param request to retrieve session from.
 * @return
 *	- The #eap_session_t associated with this request.
 *	  MUST be freed with #eap_session_destroy if being disposed of, OR
 *	  MUST be re-frozen with #eap_session_freeze if the authentication session will
 *	  continue when a future request is received.
 *	- NULL if no #eap_session_t associated with this request.
 */
eap_session_t *eap_session_thaw(REQUEST *request)
{
	eap_session_t *eap_session;

	eap_session = request_data_reference(request, NULL, REQUEST_DATA_EAP_SESSION);
	if (!eap_session) return NULL;

	if (!fr_cond_assert(eap_session->inst)) return NULL;

	fr_assert(!eap_session->request);	/* If triggered, something didn't freeze the session */
	eap_session->request = request;
	eap_session->updated = request->packet->timestamp;

	return eap_session;
}

/** Extract the EAP identity from EAP-Identity-Response packets
 *
 * @param[in] request		The current request.
 * @param[in] eap_session	EAP-Session to associate identity with.
 * @param[in] eap_packet	To extract the identity from.
 * @return
 *	- The user's EAP-Identity.
 *	- or NULL on error.
 */
static char *eap_identity(REQUEST *request, eap_session_t *eap_session, eap_packet_raw_t *eap_packet)
{
	uint16_t 	len;

	if (!eap_packet ||
	    (eap_packet->code != FR_EAP_CODE_RESPONSE) ||
	    (eap_packet->data[0] != FR_EAP_METHOD_IDENTITY)) return NULL;

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);

	/*
	 *  Note: The minimum length here is 5.
	 *  Previous versions of FreeRADIUS limited the length to 6 and
	 *  checked for data[0] != \0.
	 *
	 *  This was incorrect, and broke encrypted pseudonyms in EAP-SIM/AKA.
	 *
	 *  RFC 3748 states - If the Identity is unknown, the
	 *  Identity Response field should be zero bytes in length.  The
	 *  Identity Response field MUST NOT be null terminated.  In all
	 *  cases, the length of the Type-Data field is derived from the
	 *  Length field of the Request/Response packet.
	 *
	 *  Code (1) + Identifier (1) + Length (2) + Type (1) = 5.
	 *
	 *  The maximum value is not bounded by the RFC. The eap_validation()
	 *  function called before eap_identity(), checks that the length
	 *  field does not overrun the available data.
	 *
	 *  In some EAP methods, the identity may be encrypted, and padded
	 *  out to the block size of the encryption method.  These identities
	 *  may contain nuls, and made be much larger than humanly readable
	 *  identiies.
	 *
	 *  The identity value *MUST NOT* be artificially limited or truncated
	 *  here.
	 */
	if (len < sizeof(eap_packet_raw_t)) {
		REDEBUG("EAP-Identity length field too short, expected >= 5, got %u", len);
		return NULL;
	}

	/*
	 *	If the length is 5, then a buffer with a length of 1 is
	 *	created with a \0 byte.
	 */
	return talloc_bstrndup(eap_session, (char *)&eap_packet->data[1], len - 5);
}

/** Ingest an eap_packet into a thawed or newly allocated session
 *
 * If eap_packet is an Identity-Response then allocate a new eap_session and fill the identity.
 *
 * If eap_packet is not an identity response, retrieve the pre-existing eap_session_t from request
 * data.
 *
 * If no User-Name attribute is present in the request, one will be created from the
 * Identity-Response received when the eap_session was allocated.
 *
 * @see eap_session_freeze
 * @see eap_session_thaw
 * @see eap_session_destroy
 *
 * @param[in] instance		of rlm_eap that created the session.
 * @param[in] eap_packet_p	extracted from the RADIUS Access-Request.
 *      			Consumed or freed by this function.
 *				Do not access after calling this function.
 *				Is a **so the packet pointer can be
 *				set to NULL.
 * @param[in] request		The current request.
 * @return
 *	- A newly allocated eap_session_t, or the one associated with the current request.
 *	  MUST be freed with #eap_session_destroy if being disposed of, OR
 *	  MUST be re-frozen with #eap_session_freeze if the authentication session will
 *	  continue when a future request is received.
 *	- NULL on error.
 */
eap_session_t *eap_session_continue(void const *instance, eap_packet_raw_t **eap_packet_p, REQUEST *request)
{
	eap_session_t		*eap_session = NULL;
	eap_packet_raw_t	*eap_packet;
	VALUE_PAIR		*user;

	eap_packet = *eap_packet_p;

	/*
	 *	RFC 3579 - Once EAP has been negotiated, the NAS SHOULD
	 *	send an initial EAP-Request message to the authenticating
	 *	peer.  This will typically be an EAP-Request/Identity,
	 *	although it could be an EAP-Request for an authentication
	 *	method (Types 4 and greater).
	 *
	 *	This means that if there is no State attribute, we should
	 *	consider this as the start of a new session.
	 */
	eap_session = eap_session_thaw(request);
	if (!eap_session) {
		eap_session = eap_session_alloc(request);
		if (!eap_session) {
		error_round:
			talloc_free(*eap_packet_p);
			*eap_packet_p = NULL;
			return NULL;
		}
		eap_session->inst = instance;

		if (RDEBUG_ENABLED4) {
			RDEBUG4("New EAP session - eap_session_t %p", eap_session);
		} else {
			RDEBUG2("New EAP session started");
		}

		/*
		 *	All fields in the eap_session are set to zero.
		 */
		switch (eap_packet->data[0]) {
		case FR_EAP_METHOD_IDENTITY:
			eap_session->identity = eap_identity(request, eap_session, eap_packet);
			if (!eap_session->identity) {
				REDEBUG("Invalid identity response");
				goto error_session;
			}

			/*
			 *	Sometimes we need the hex stream to determine where
			 *	random junk is coming from.
			 */
			RHEXDUMP3((uint8_t *const)eap_session->identity,
				 talloc_array_length(eap_session->identity) - 1,
				 "EAP Identity Response - \"%pV\"",
				 fr_box_strvalue_len(eap_session->identity,
						     talloc_array_length(eap_session->identity) - 1));
			break;

		case FR_EAP_METHOD_INVALID:
		case FR_EAP_METHOD_NOTIFICATION:
		case FR_EAP_METHOD_NAK:
			REDEBUG("Initial EAP method %s(%u) invalid",
				eap_type2name(eap_packet->data[0]), eap_packet->data[0]);
			goto error_session;

		/*
		 *	Initialise a zero length identity, as we've
		 *	not been provided with one at the start of the
		 *	EAP method.
		 */
		default:
			eap_session->identity = talloc_bstrndup(eap_session, "", 0);
			break;
		}

		/*
		 *	If the index is removed by something else
		 *	like the state being cleaned up, then we
		 *	still want the eap_session to be freed, which
		 *	is why we set free_opaque to true.
		 *
		 *	We must pass a NULL pointer to associate the
		 *	the EAP_SESSION data with, else we'll break
		 *	tunneled EAP, where the inner EAP module is
		 *	a different instance to the outer one.
		 */
		request_data_talloc_add(request, NULL, REQUEST_DATA_EAP_SESSION, eap_session_t,
					eap_session, true, true, true);

	/*
	 *	Continue a previously started EAP-Session
	 */
	} else {
		if (RDEBUG_ENABLED4) {
			RDEBUG4("Continuing EAP session - eap_session_t %p", eap_session);
		} else {
			RDEBUG2("Continuing EAP session");
		}

		(void) talloc_get_type_abort(eap_session, eap_session_t);
		eap_session->rounds++;
		if (eap_session->rounds >= 50) {
			RERROR("Failing EAP session due to too many round trips");
		error_session:
			eap_session_destroy(&eap_session);
			goto error_round;
		}

		/*
		 *	Even more paranoia.  Without this, some weird
		 *	clients could do crazy things.
		 *
		 *	It's ok to send EAP sub-type NAK in response
		 *	to a request for a particular type, but it's NOT
		 *	OK to blindly return data for another type.
		 */
		if ((eap_packet->data[0] != FR_EAP_METHOD_NAK) &&
		    (eap_packet->data[0] != eap_session->type)) {
			RERROR("Response appears to match a previous request, but the EAP type is wrong");
			RERROR("We expected EAP type %s, but received type %s",
			       eap_type2name(eap_session->type),
			       eap_type2name(eap_packet->data[0]));
			RERROR("Your Supplicant or NAS is probably broken");
			goto error_round;
		}
	}

	/*
	 *	RFC3579 In order to permit non-EAP aware RADIUS proxies to forward the
	 *	Access-Request packet, if the NAS initially sends an
	 *	EAP-Request/Identity message to the peer, the NAS MUST copy the
	 *	contents of the Type-Data field of the EAP-Response/Identity received
	 *	from the peer into the User-Name attribute and MUST include the
	 *	Type-Data field of the EAP-Response/Identity in the User-Name
	 *	attribute in every subsequent Access-Request.
	 */
	user = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
	if (!user) {
		/*
		 *	NAS did not set the User-Name
		 *	attribute, so we set it here and
		 *	prepend it to the beginning of the
		 *	request vps so that autz's work
		 *	correctly
		 */
		RDEBUG2("Broken NAS did not set User-Name, setting from EAP Identity");
		MEM(pair_add_request(&user, attr_user_name) >= 0);
		fr_pair_value_bstrdup_buffer(user, eap_session->identity, true);
	/*
	 *	The RFC 3579 is pretty unambiguous, the main issue is that the EAP Identity Response
	 *	can be significantly longer than 253 bytes (the maximum RADIUS
	 *	attribute length), and the RFC is silent about what happens then.
	 *
	 *	The behaviour seen in the wild, is that the NAS will use the Mac-Address
	 *	of the connecting device as the User-name, and send the Identity in full,
	 *	so if the EAP identity is longer than the max RADIUS attribute length
	 *	then ignore mismatches.
	 */
	} else if ((talloc_array_length(eap_session->identity) - 1) <= RADIUS_MAX_STRING_LENGTH) {
		/*
		 *      A little more paranoia.  If the NAS
		 *      *did* set the User-Name, and it doesn't
		 *      match the identity, (i.e. If they
		 *      change their User-Name part way through
		 *      the EAP transaction), then reject the
		 *      request as the NAS is doing something
		 *      funny.
		 */
		if (talloc_memcmp_bstr(eap_session->identity, user->vp_strvalue) != 0) {
			REDEBUG("Identity from EAP Identity-Response \"%s\" does not match User-Name attribute \"%s\"",
				eap_session->identity, user->vp_strvalue);
			goto error_round;
		}
	}

	eap_session->this_round = eap_round_build(eap_session, eap_packet_p);
	if (!eap_session->this_round) {
		REDEBUG("Failed allocating memory for round");
		goto error_session;
	}

	return eap_session;
}
