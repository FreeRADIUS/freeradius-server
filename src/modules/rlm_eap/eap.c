/*
 * eap.c    rfc2284 & rfc2869 implementation
 *
 * Version:     $Id$
 *
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
 *
 * Copyright 2000-2003,2006  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 */
/*
 *  EAP PACKET FORMAT
 *  --- ------ ------
 *  0		   1		   2		   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |	    Length	     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Data ...
 * +-+-+-+-+
 *
 *
 * EAP Request and Response Packet Format
 * --- ------- --- -------- ------ ------
 *  0		   1		   2		   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |	    Length	     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |  Type-Data ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *
 *
 * EAP Success and Failure Packet Format
 * --- ------- --- ------- ------ ------
 *  0		   1		   2		   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |	    Length	     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
#define LOG_PREFIX "rlm_eap - "
#include <freeradius-devel/modpriv.h>

RCSID("$Id$")

#include "rlm_eap.h"
#include <ctype.h>

static char const *eap_codes[] = {
	 "",				/* 0 is invalid */
	"Request",
	"Response",
	"Success",
	"Failure"
};

static int _eap_module_free(eap_module_t *inst)
{
	/*
	 * Check if handle is still valid. If not, type is referencing freed memory
	 */

	if (!inst->handle) return 0;

	/*
	 *	We have to check inst->type as it's only allocated
	 *	if we loaded the eap method.
	 */
	if (inst->type && inst->type->detach) (inst->type->detach)(inst->instance);

#ifndef NDEBUG
	/*
	 *	Don't dlclose() modules if this is a debug built
	 *	ad it removes the symbols needed by valgrind.
	 */
#else
	dlclose(inst->handle);
#endif

	return 0;
}

/** Load required EAP sub-modules (methods)
 *
 */
int eap_module_instantiate(rlm_eap_t *inst, eap_module_t **m_inst, eap_type_t num, CONF_SECTION *cs)
{
	eap_module_t *method;
	char *mod_name, *p;

	/* Make room for the EAP-Type */
	*m_inst = method = talloc_zero(cs, eap_module_t);
	if (!inst) return -1;

	talloc_set_destructor(method, _eap_module_free);

	/* fill in the structure */
	method->cs = cs;
	method->name = eap_type2name(num);

	/*
	 *	The name of the module were trying to load
	 */
	mod_name = talloc_typed_asprintf(method, "rlm_eap_%s", method->name);

	/*
	 *	dlopen is case sensitive
	 */
	p = mod_name;
	while (*p) {
		*p = tolower(*p);
		p++;
	}

#if defined(HAVE_DLFCN_H) && defined(RTLD_SELF)
	method->type = dlsym(RTLD_SELF, mod_name);
	if (method->type) goto open_self;
#endif

	/*
	 *	Link the loaded EAP-Type
	 */
	method->handle = module_dlopen_by_name(mod_name);
	if (!method->handle) {
		ERROR("Failed to link %s: %s", mod_name, fr_strerror());

		return -1;
	}

	method->type = dlsym(method->handle, mod_name);
	if (!method->type) {
		ERROR("Failed linking to structure in %s: %s", method->name, dlerror());

		return -1;
	}

#if defined(HAVE_DLFCN_H) && defined(RTLD_SELF)
open_self:
#endif
	cf_log_module(cs, "Linked to sub-module %s", mod_name);

	/*
	 *	Call the attach num in the EAP num module
	 */
	if ((method->type->instantiate) && ((method->type->instantiate)(method->cs, &(method->instance)) < 0)) {
		ERROR("Failed to initialise %s", mod_name);

		if (method->instance) {
			(void) talloc_steal(method, method->instance);
		}

		return -1;
	}

	if (method->instance) (void) talloc_steal(method, method->instance);

	return 0;
}

/*
 * Call the appropriate handle with the right eap_method.
 */
static int eap_module_call(eap_module_t *module, eap_session_t *eap_session)
{
	int rcode = 1;
	REQUEST *request = eap_session->request;

	char const *caller = request->module;

	rad_assert(module != NULL);

	RDEBUG2("Calling submodule %s to process data", module->type->name);

	request->module = module->type->name;
	rcode = eap_session->process(module->instance, eap_session);
	request->module = caller;

	return rcode;
}

/** Process NAK data from EAP peer
 *
 */
static eap_type_t eap_process_nak(rlm_eap_t *inst, REQUEST *request,
				    eap_type_t type,
				    eap_type_data_t *nak)
{
	unsigned int i;
	VALUE_PAIR *vp;
	eap_type_t method = PW_EAP_INVALID;

	/*
	 *	The NAK data is the preferred EAP type(s) of
	 *	the client.
	 *
	 *	RFC 3748 says to list one or more proposed
	 *	alternative types, one per octet, or to use
	 *	0 for no alternative.
	 */
	if (!nak->data) {
		REDEBUG("Peer sent empty (invalid) NAK. Can't select method to continue with");

		return PW_EAP_INVALID;
	}

	/*
	 *	Pick one type out of the one they asked for,
	 *	as they may have asked for many.
	 */
	vp = fr_pair_find_by_num(request->control, 0, PW_EAP_TYPE, TAG_ANY);
	for (i = 0; i < nak->length; i++) {
		/*
		 *	Type 0 is valid, and means there are no
		 *	common choices.
		 */
		if (nak->data[i] == 0) {
			RDEBUG("Peer NAK'd indicating it is not willing to continue ");

			return PW_EAP_INVALID;
		}

		/*
		 *	It is invalid to request identity,
		 *	notification & nak in nak.
		 */
		if (nak->data[i] < PW_EAP_MD5) {
			REDEBUG("Peer NAK'd asking for bad type %s (%d)", eap_type2name(nak->data[i]), nak->data[i]);

			return PW_EAP_INVALID;
		}

		if ((nak->data[i] >= PW_EAP_MAX_TYPES) ||
		    !inst->methods[nak->data[i]]) {
			RDEBUG2("Peer NAK'd asking for unsupported EAP type %s (%d), skipping...",
				eap_type2name(nak->data[i]),
				nak->data[i]);

			continue;
		}

		/*
		 *	Prevent a firestorm if the client is confused.
		 */
		if (type == nak->data[i]) {
			char const *type_str = eap_type2name(nak->data[i]);

			RDEBUG2("Peer NAK'd our request for %s (%d) with a request for %s (%d), skipping...",
				type_str, nak->data[i], type_str, nak->data[i]);

			RWARN("!!! We requested to use EAP type %s (%i)", type_str, nak->data[i]);
			RWARN("!!! The supplicant rejected that, and requested to use the same EAP type.");
			RWARN("!!!     i.e. the supplicant said 'I don't like %s, please use %s instead.",
			      type_str, type_str);
			RWARN("!!! The supplicant software is broken and does not work properly.");
			RWARN("!!! Please upgrade it to software that works.");

			continue;
		}

		/*
		 *	Enforce per-user configuration of EAP
		 *	types.
		 */
		if (vp && (vp->vp_integer != nak->data[i])) {
			RDEBUG2("Peer wants %s (%d), while we require %s (%d), skipping",
				eap_type2name(nak->data[i]), nak->data[i],
				eap_type2name(vp->vp_integer), vp->vp_integer);

			continue;
		}

		RDEBUG("Found mutually acceptable type %s (%d)",
		       eap_type2name(nak->data[i]), nak->data[i]);

		method = nak->data[i];

		break;
	}

	if (method == PW_EAP_INVALID) {
		REDEBUG("No mutually acceptable types found");
	}

	return method;
}

/** Select the correct callback based on a response
 *
 * Based on the EAP response from the supplicant, call the appropriate
 * method callback.
 *
 * Default to the configured EAP-Type for all Unsupported EAP-Types.
 *
 * @param inst Configuration data for this instance of rlm_eap.
 * @param eap_session State data that persists over multiple rounds of EAP.
 * @return a status code.
 */
eap_rcode_t eap_method_select(rlm_eap_t *inst, eap_session_t *eap_session)
{
	eap_type_data_t		*type = &eap_session->this_round->response->type;
	REQUEST			*request = eap_session->request;

	eap_type_t		next = inst->default_method;
	VALUE_PAIR		*vp;

	/*
	 *	Don't trust anyone.
	 */
	if ((type->num == 0) || (type->num >= PW_EAP_MAX_TYPES)) {
		REDEBUG("Peer sent EAP type number %d, which is outside known range", type->num);

		return EAP_INVALID;
	}

	/*
	 *	Multiple levels of TLS nesting are invalid.  But if
	 *	the parent has a home_server defined, then this
	 *	request is being processed through a virtual
	 *	server... so that's OK.
	 *
	 *	i.e. we're inside an EAP tunnel, which means we have a
	 *	parent.  If the outer session exists, and doesn't have
	 *	a home server, then it's multiple layers of tunneling.
	 */
	if (eap_session->request->parent &&
	    eap_session->request->parent->parent &&
	    !eap_session->request->parent->parent->home_server) {
		RERROR("Multiple levels of TLS nesting are invalid");

		return EAP_INVALID;
	}

	RDEBUG2("Peer sent packet with EAP method %s (%d)", eap_type2name(type->num), type->num);

	/*
	 *	Figure out what to do.
	 */
	switch (type->num) {
	case PW_EAP_IDENTITY:
		/*
		 *	Allow per-user configuration of EAP types.
		 */
		vp = fr_pair_find_by_num(eap_session->request->control, 0, PW_EAP_TYPE, TAG_ANY);
		if (vp) {
			RDEBUG2("Setting method from &control:EAP-Type");
			next = vp->vp_integer;
		}

		/*
		 *	Ensure it's valid.
		 */
		if ((next < PW_EAP_MD5) || (next >= PW_EAP_MAX_TYPES) || (!inst->methods[next])) {
			REDEBUG2("Tried to start unsupported EAP type %s (%d)",
				 eap_type2name(next), next);
			return EAP_INVALID;
		}

	do_initiate:
		/*
		 *	If any of these fail, we messed badly somewhere
		 */
		rad_assert(next >= PW_EAP_MD5);
		rad_assert(next < PW_EAP_MAX_TYPES);
		rad_assert(inst->methods[next]);

		eap_session->process = inst->methods[next]->type->session_init;
		eap_session->type = next;

		if (eap_module_call(inst->methods[next], eap_session) == 0) {
			REDEBUG2("Failed starting EAP %s (%d) session.  EAP sub-module failed",
				 eap_type2name(next), next);

			return EAP_INVALID;
		}
		break;

	case PW_EAP_NAK:
		/*
		 *	Delete old data, if necessary.  If we called a method
		 *	before, and it initialized itself, we need to free
		 *	the memory it alloced.
		 */
		TALLOC_FREE(eap_session->opaque);
		next = eap_process_nak(inst, eap_session->request, eap_session->type, type);

		/*
		 *	We probably want to return 'fail' here...
		 */
		if (!next) return EAP_INVALID;
		goto do_initiate;

	/*
	 *	Key off of the configured sub-modules.
	 */
	default:
		/*
		 *	We haven't configured it, it doesn't exit.
		 */
		if (!inst->methods[type->num]) {
			REDEBUG2("Client asked for unsupported EAP type %s (%d)", eap_type2name(type->num), type->num);

			return EAP_INVALID;
		}

		eap_session->type = type->num;
		if (eap_module_call(inst->methods[type->num], eap_session) == 0) {
			REDEBUG2("Failed continuing EAP %s (%d) session.  EAP sub-module failed",
				 eap_type2name(type->num), type->num);

			return EAP_INVALID;
		}
		break;
	}

	return EAP_OK;
}


/*
 *	compose EAP reply packet in EAP-Message attr of RADIUS.
 *
 *	Set the RADIUS reply codes based on EAP request codes.  Append
 *	any additonal VPs to RADIUS reply
 */
rlm_rcode_t eap_compose(eap_session_t *eap_session)
{
	VALUE_PAIR *vp;
	eap_packet_raw_t *eap_packet;
	REQUEST *request;
	eap_round_t *eap_round;
	eap_packet_t *reply;
	int rcode;

#ifndef NDEBUG
	eap_session = talloc_get_type_abort(eap_session, eap_session_t);
	request = talloc_get_type_abort(eap_session->request, REQUEST);
	eap_round = talloc_get_type_abort(eap_session->this_round, eap_round_t);
	reply = talloc_get_type_abort(eap_round->request, eap_packet_t);
#else
	request = eap_session->request;
	eap_round = eap_session->this_round;
	reply = eap_round->request;
#endif

	/*
	 *	The Id for the EAP packet to the NAS wasn't set.
	 *	Do so now.
	 *
	 *	LEAP requires the Id to be incremented on EAP-Success
	 *	in Stage 4, so that we can carry on the conversation
	 *	where the client asks us to authenticate ourselves
	 *	in stage 5.
	 */
	if (!eap_round->set_request_id) {
		/*
		 *	Id serves to suppport request/response
		 *	retransmission in the EAP layer and as such
		 *	must be different for 'adjacent' packets
		 *	except in case of success/failure-replies.
		 *
		 *	RFC2716 (EAP-TLS) requires this to be
		 *	incremented, RFC2284 only makes the above-
		 *	mentioned restriction.
		 */
		reply->id = eap_session->this_round->response->id;

		switch (reply->code) {
		/*
		 *	The Id is a simple "ack" for success
		 *	and failure.
		 *
		 *	RFC 3748 section 4.2 says
		 *
		 *	... The Identifier field MUST match
		 *	the Identifier field of the Response
		 *	packet that it is sent in response
		 *	to.
		 */
		case PW_EAP_SUCCESS:
		case PW_EAP_FAILURE:
			break;

		/*
		 *	We've sent a response to their
		 *	request, the Id is incremented.
		 */
		default:
			++reply->id;
		}
	}

	/*
	 *	For Request & Response packets, set the EAP sub-type,
	 *	if the EAP sub-module didn't already set it.
	 *
	 *	This allows the TLS module to be "morphic", and means
	 *	that the TTLS and PEAP modules can call it to do most
	 *	of their dirty work.
	 */
	if (((eap_round->request->code == PW_EAP_REQUEST) ||
	     (eap_round->request->code == PW_EAP_RESPONSE)) &&
	    (eap_round->request->type.num == 0)) {
		rad_assert(eap_session->type >= PW_EAP_MD5);
		rad_assert(eap_session->type < PW_EAP_MAX_TYPES);

		eap_round->request->type.num = eap_session->type;
	}

	if (eap_wireformat(reply) == EAP_INVALID) return RLM_MODULE_INVALID;

	eap_packet = (eap_packet_raw_t *)reply->packet;

	vp = radius_pair_create(request->reply, &request->reply->vps, PW_EAP_MESSAGE, 0);
	if (!vp) return RLM_MODULE_INVALID;

	vp->vp_length = eap_packet->length[0] * 256 + eap_packet->length[1];
	vp->vp_octets = talloc_steal(vp, reply->packet);
	reply->packet = NULL;

	/*
	 *	EAP-Message is always associated with
	 *	Message-Authenticator but not vice-versa.
	 *
	 *	Don't add a Message-Authenticator if
	 *	it's already there.
	 */
	vp = fr_pair_find_by_num(request->reply->vps, 0, PW_MESSAGE_AUTHENTICATOR, TAG_ANY);
	if (!vp) {
		vp = fr_pair_afrom_num(request->reply, 0, PW_MESSAGE_AUTHENTICATOR);
		fr_pair_value_memsteal(vp, talloc_zero_array(vp, uint8_t, AUTH_VECTOR_LEN));
		fr_pair_add(&(request->reply->vps), vp);
	}

	/* Set request reply code, but only if it's not already set. */
	rcode = RLM_MODULE_OK;
	if (!request->reply->code) switch (reply->code) {
	case PW_EAP_RESPONSE:
		request->reply->code = PW_CODE_ACCESS_ACCEPT;
		rcode = RLM_MODULE_HANDLED; /* leap weirdness */
		break;

	case PW_EAP_SUCCESS:
		request->reply->code = PW_CODE_ACCESS_ACCEPT;
		rcode = RLM_MODULE_OK;
		break;

	case PW_EAP_FAILURE:
		request->reply->code = PW_CODE_ACCESS_REJECT;
		rcode = RLM_MODULE_REJECT;
		break;

	case PW_EAP_REQUEST:
		request->reply->code = PW_CODE_ACCESS_CHALLENGE;
		rcode = RLM_MODULE_HANDLED;
		break;

	default:
		/*
		 *	When we're pulling MS-CHAPv2 out of EAP-MS-CHAPv2,
		 *	we do so WITHOUT setting a reply code, as the
		 *	request is being proxied.
		 */
		if (request->options & RAD_REQUEST_OPTION_PROXY_EAP) return RLM_MODULE_HANDLED;

		/* Should never enter here */
		REDEBUG("Reply code %d is unknown, rejecting the request", reply->code);
		request->reply->code = PW_CODE_ACCESS_REJECT;
		reply->code = PW_EAP_FAILURE;
		rcode = RLM_MODULE_REJECT;
		break;
	}

	RDEBUG2("Sending EAP %s (code %i) ID %d length %i",
		eap_codes[eap_packet->code], eap_packet->code, reply->id,
		eap_packet->length[0] * 256 + eap_packet->length[1]);

	return rcode;
}

/*
 * Radius criteria, EAP-Message is invalid without Message-Authenticator
 * For EAP_START, send Access-Challenge with EAP Identity request.
 */
int eap_start(rlm_eap_t *inst, REQUEST *request)
{
	VALUE_PAIR *vp, *proxy;
	VALUE_PAIR *eap_msg;

	eap_msg = fr_pair_find_by_num(request->packet->vps, 0, PW_EAP_MESSAGE, TAG_ANY);
	if (!eap_msg) {
		RDEBUG2("No EAP-Message, not doing EAP");
		return EAP_NOOP;
	}

	/*
	 *	Look for EAP-Type = None (FreeRADIUS specific attribute)
	 *	this allows you to NOT do EAP for some users.
	 */
	vp = fr_pair_find_by_num(request->packet->vps, 0, PW_EAP_TYPE, TAG_ANY);
	if (vp && vp->vp_integer == 0) {
		RDEBUG2("Found EAP-Message, but EAP-Type = None, so we're not doing EAP");
		return EAP_NOOP;
	}

	/*
	 *	http://www.freeradius.org/rfc/rfc2869.html#EAP-Message
	 *
	 *	Checks for Message-Authenticator are handled by fr_radius_recv().
	 */

	/*
	 *	Check for a Proxy-To-Realm.  Don't get excited over LOCAL
	 *	realms (sigh).
	 */
	proxy = fr_pair_find_by_num(request->control, 0, PW_PROXY_TO_REALM, TAG_ANY);
	if (proxy) {
		REALM *realm;

		/*
		 *	If it's a LOCAL realm, then we're not proxying
		 *	to it.
		 */
		realm = realm_find(proxy->vp_strvalue);
		if (!realm || (realm && (!realm->auth_pool))) {
			proxy = NULL;
		}
	}

	/*
	 *	Check the length before de-referencing the contents.
	 *
	 *	Lengths of zero are required by the RFC for EAP-Start,
	 *	but we've never seen them in practice.
	 *
	 *	Lengths of two are what we see in practice as
	 *	EAP-Starts.
	 */
	if ((eap_msg->vp_length == 0) || (eap_msg->vp_length == 2)) {
		uint8_t *p;

		/*
		 *	It's a valid EAP-Start, but the request
		 *	was marked as being proxied.  So we don't
		 *	do EAP, as the home server will do it.
		 */
		if (proxy) {
		do_proxy:
			RDEBUG2("Request is supposed to be proxied to "
				"Realm %s. Not doing EAP.", proxy->vp_strvalue);
			return EAP_NOOP;
		}

		RDEBUG2("Got EAP_START message");
		vp = fr_pair_afrom_num(request->reply, 0, PW_EAP_MESSAGE);
		if (!vp) return EAP_FAIL;
		fr_pair_add(&request->reply->vps, vp);

		/*
		 *	Manually create an EAP Identity request
		 */
		p = talloc_array(vp, uint8_t, 5);
		p[0] = PW_EAP_REQUEST;
		p[1] = 0; /* ID */
		p[2] = 0;
		p[3] = 5; /* length */
		p[4] = PW_EAP_IDENTITY;
		fr_pair_value_memsteal(vp, p);

		return EAP_FOUND;
	} /* end of handling EAP-Start */

	/*
	 *	Supplicants don't usually send EAP-Failures to the
	 *	server, but they're not forbidden from doing so.
	 *	This behaviour was observed with a Spirent Avalanche test server.
	 */
	if ((eap_msg->vp_length == EAP_HEADER_LEN) && (eap_msg->vp_octets[0] == PW_EAP_FAILURE)) {
		REDEBUG("Peer sent EAP %s (code %i) ID %d length %zu",
		        eap_codes[eap_msg->vp_octets[0]],
		        eap_msg->vp_octets[0],
		        eap_msg->vp_octets[1],
		        eap_msg->vp_length);
		return EAP_FAIL;
	/*
	 *	The EAP packet header is 4 bytes, plus one byte of
	 *	EAP sub-type.  Short packets are discarded, unless
	 *	we're proxying.
	 */
	} else if (eap_msg->vp_length < (EAP_HEADER_LEN + 1)) {
		if (proxy) goto do_proxy;

		RDEBUG2("Ignoring EAP-Message which is too short to be meaningful");
		return EAP_FAIL;
	}

	/*
	 *	Create an EAP-Type containing the EAP-type
	 *	from the packet.
	 */
	vp = fr_pair_afrom_num(request->packet, 0, PW_EAP_TYPE);
	if (vp) {
		vp->vp_integer = eap_msg->vp_octets[4];
		fr_pair_add(&(request->packet->vps), vp);
	}

	/*
	 *	If the request was marked to be proxied, do it now.
	 *	This is done after checking for a valid length
	 *	(which may not be good), and after adding the EAP-Type
	 *	attribute.  This lets other modules selectively cancel
	 *	proxying based on EAP-Type.
	 */
	if (proxy) goto do_proxy;

	/*
	 *	From now on, we're supposed to be handling the
	 *	EAP packet.  We better understand it...
	 */

	/*
	 *	We're allowed only a few codes.  Request, Response,
	 *	Success, or Failure.
	 */
	if ((eap_msg->vp_octets[0] == 0) ||
	    (eap_msg->vp_octets[0] >= PW_EAP_MAX_CODES)) {
		RDEBUG2("Peer sent EAP packet with unknown code %i", eap_msg->vp_octets[0]);
	} else {
		RDEBUG2("Peer sent EAP %s (code %i) ID %d length %zu",
		        eap_codes[eap_msg->vp_octets[0]],
		        eap_msg->vp_octets[0],
		        eap_msg->vp_octets[1],
		        eap_msg->vp_length);
	}

	/*
	 *	We handle request and responses.  The only other defined
	 *	codes are success and fail.  The client SHOULD NOT be
	 *	sending success/fail packets to us, as it doesn't make
	 *	sense.
	 */
	if ((eap_msg->vp_octets[0] != PW_EAP_REQUEST) &&
	    (eap_msg->vp_octets[0] != PW_EAP_RESPONSE)) {
		RDEBUG2("Ignoring EAP packet which we don't know how to handle");
		return EAP_FAIL;
	}

	/*
	 *	We've been told to ignore unknown EAP types, AND it's
	 *	an unknown type.  Return "NOOP", which will cause the
	 *	mod_authorize() to return NOOP.
	 *
	 *	EAP-Identity, Notification, and NAK are all handled
	 *	internally, so they never have eap_sessions.
	 */
	if ((eap_msg->vp_octets[4] >= PW_EAP_MD5) &&
	    inst->ignore_unknown_types &&
	    ((eap_msg->vp_octets[4] == 0) ||
	     (eap_msg->vp_octets[4] >= PW_EAP_MAX_TYPES) ||
	     (!inst->methods[eap_msg->vp_octets[4]]))) {
		RDEBUG2("Ignoring Unknown EAP type");
		return EAP_NOOP;
	}

	/*
	 *	They're NAKing the EAP type we wanted to use, and
	 *	asking for one which we don't support.
	 *
	 *	NAK is code + id + length1 + length + NAK
	 *	     + requested EAP type(s).
	 *
	 *	We know at this point that we can't handle the
	 *	request.  We could either return an EAP-Fail here, but
	 *	it's not too critical.
	 *
	 *	By returning "noop", we can ensure that authorize()
	 *	returns NOOP, and another module may choose to proxy
	 *	the request.
	 */
	if ((eap_msg->vp_octets[4] == PW_EAP_NAK) &&
	    (eap_msg->vp_length >= (EAP_HEADER_LEN + 2)) &&
	    inst->ignore_unknown_types &&
	    ((eap_msg->vp_octets[5] == 0) ||
	     (eap_msg->vp_octets[5] >= PW_EAP_MAX_TYPES) ||
	     (!inst->methods[eap_msg->vp_octets[5]]))) {
		RDEBUG2("Ignoring NAK with request for unknown EAP type");
		return EAP_NOOP;
	}

	if ((eap_msg->vp_octets[4] == PW_EAP_TTLS) ||
	    (eap_msg->vp_octets[4] == PW_EAP_PEAP)) {
		RDEBUG2("Continuing tunnel setup");
		return EAP_OK;
	}
	/*
	 * We return ok in response to EAP identity
	 * This means we can write:
	 *
	 * eap {
	 *   ok = return
	 * }
	 * ldap
	 * sql
	 *
	 * ...in the inner-tunnel, to avoid expensive and unnecessary SQL/LDAP lookups
	 */
	if (eap_msg->vp_octets[4] == PW_EAP_IDENTITY) {
		RDEBUG2("Peer sent EAP-Identity.  Returning 'ok' so we can short-circuit the rest of authorize");
		return EAP_OK;
	}

	/*
	 *	Later EAP messages are longer than the 'start'
	 *	message, so if everything is OK, this function returns
	 *	'no start found', so that the rest of the EAP code can
	 *	use the State attribute to match this EAP-Message to
	 *	an ongoing conversation.
	 */
	RDEBUG2("Continuing on-going EAP conversation");

	return EAP_NOTFOUND;
}

/*
 *	compose EAP FAILURE packet in EAP-Message
 */
void eap_fail(eap_session_t *eap_session)
{
	/*
	 *	Delete any previous replies.
	 */
	fr_pair_delete_by_num(&eap_session->request->reply->vps, 0, PW_EAP_MESSAGE, TAG_ANY);
	fr_pair_delete_by_num(&eap_session->request->reply->vps, 0, PW_STATE, TAG_ANY);

	talloc_free(eap_session->this_round->request);
	eap_session->this_round->request = talloc_zero(eap_session->this_round, eap_packet_t);
	eap_session->this_round->request->code = PW_EAP_FAILURE;
	eap_session->finished = true;
	eap_compose(eap_session);
}

/*
 *	compose EAP SUCCESS packet in EAP-Message
 */
void eap_success(eap_session_t *eap_session)
{
	eap_session->this_round->request->code = PW_EAP_SUCCESS;
	eap_session->finished = true;
	eap_compose(eap_session);
}

/*
 * Basic EAP packet verfications & validations
 */
static int eap_validation(REQUEST *request, eap_packet_raw_t **eap_packet_p)
{
	uint16_t len;
	eap_packet_raw_t *eap_packet = *eap_packet_p;

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);

	/*
	 *	High level EAP packet checks
	 */
	if ((len <= EAP_HEADER_LEN) ||
	    ((eap_packet->code != PW_EAP_RESPONSE) &&
	     (eap_packet->code != PW_EAP_REQUEST))) {
		REDEBUG("Badly formatted EAP Message: Ignoring the packet");
		return EAP_INVALID;
	}

	if ((eap_packet->data[0] <= 0) ||
	    (eap_packet->data[0] >= PW_EAP_MAX_TYPES)) {
		/*
		 *	Handle expanded types by smashing them to
		 *	normal types.
		 */
		if (eap_packet->data[0] == PW_EAP_EXPANDED_TYPE) {
			uint8_t *p, *q;

			if (len <= (EAP_HEADER_LEN + 1 + 3 + 4)) {
				REDEBUG("Expanded EAP type is too short: ignoring the packet");
				return EAP_INVALID;
			}

			if ((eap_packet->data[1] != 0) ||
			    (eap_packet->data[2] != 0) ||
			    (eap_packet->data[3] != 0)) {
				REDEBUG("Expanded EAP type has unknown Vendor-ID: ignoring the packet");
				return EAP_INVALID;
			}

			if ((eap_packet->data[4] != 0) ||
			    (eap_packet->data[5] != 0) ||
			    (eap_packet->data[6] != 0)) {
				REDEBUG("Expanded EAP type has unknown Vendor-Type: ignoring the packet");
				return EAP_INVALID;
			}

			if ((eap_packet->data[7] == 0) ||
			    (eap_packet->data[7] >= PW_EAP_MAX_TYPES)) {
				REDEBUG("Unsupported Expanded EAP type %s (%u): ignoring the packet",
					eap_type2name(eap_packet->data[7]), eap_packet->data[7]);
				return EAP_INVALID;
			}

			if (eap_packet->data[7] == PW_EAP_NAK) {
				REDEBUG("Unsupported Expanded EAP-NAK: ignoring the packet");
				return EAP_INVALID;
			}

			/*
			 *	Re-write the EAP packet to NOT have the expanded type.
			 */
			q = (uint8_t *) eap_packet;
			memmove(q + EAP_HEADER_LEN, q + EAP_HEADER_LEN + 7, len - 7 - EAP_HEADER_LEN);

			p = talloc_realloc(talloc_parent(eap_packet), eap_packet, uint8_t, len - 7);
			if (!p) {
				REDEBUG("Unsupported EAP type %s (%u): ignoring the packet",
					eap_type2name(eap_packet->data[0]), eap_packet->data[0]);
				return EAP_INVALID;
			}

			len -= 7;
			p[2] = (len >> 8) & 0xff;
			p[3] = len & 0xff;

			*eap_packet_p = (eap_packet_raw_t *) p;
			RWARN("Converting Expanded EAP to normal EAP.");
			RWARN("Unnecessary use of Expanded EAP types is not recommened.");

			return EAP_VALID;
		}

		REDEBUG("Unsupported EAP type %s (%u): ignoring the packet",
			eap_type2name(eap_packet->data[0]), eap_packet->data[0]);
		return EAP_INVALID;
	}

	/* we don't expect notification, but we send it */
	if (eap_packet->data[0] == PW_EAP_NOTIFICATION) {
		REDEBUG("Got NOTIFICATION, Ignoring the packet");
		return EAP_INVALID;
	}

	return EAP_VALID;
}


/*
 *  Get the user Identity only from EAP-Identity packets
 */
static char *eap_identity(REQUEST *request, eap_session_t *eap_session, eap_packet_raw_t *eap_packet)
{
	int size;
	uint16_t len;
	char *identity;

	if ((!eap_packet) ||
	    (eap_packet->code != PW_EAP_RESPONSE) ||
	    (eap_packet->data[0] != PW_EAP_IDENTITY)) {
		return NULL;
	}

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);

	if ((len <= 5) || (eap_packet->data[1] == 0x00)) {
		RDEBUG("EAP-Identity Unknown");
		return NULL;
	}

	if (len > 1024) {
		RDEBUG("EAP-Identity too long");
		return NULL;
	}

	size = len - 5;
	identity = talloc_array(eap_session, char, size + 1);
	memcpy(identity, &eap_packet->data[1], size);
	identity[size] = '\0';

	return identity;
}


/*
 *	Create our Request-Response data structure with the eap packet
 */
static eap_round_t *eap_round_build(eap_session_t *eap_session, eap_packet_raw_t **eap_packet_p)
{
	eap_round_t		*eap_round = NULL;
	int			typelen;
	eap_packet_raw_t	*eap_packet = *eap_packet_p;
	uint16_t		len;

	eap_round = eap_round_alloc(eap_session);
	if (eap_round == NULL) return NULL;

	eap_round->response->packet = (uint8_t *)eap_packet;
	(void) talloc_steal(eap_round, eap_packet);
	eap_round->response->code = eap_packet->code;
	eap_round->response->id = eap_packet->id;
	eap_round->response->type.num = eap_packet->data[0];

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);
	eap_round->response->length = len;

	/*
	 *	We've eaten the eap packet into the eap_round.
	 */
	*eap_packet_p = NULL;

	/*
	 *	First 5 bytes in eap, are code + id + length(2) + type.
	 *
	 *	The rest is type-specific data.  We skip type while
	 *	getting typedata from data.
	 */
	typelen = len - 5/*code + id + length + type */;
	if (typelen > 0) {
		/*
		 *	Since the packet contains the complete
		 *	eap_packet, typedata will be a ptr in packet
		 *	to its typedata
		 */
		eap_round->response->type.data = eap_round->response->packet + 5/*code+id+length+type*/;
		eap_round->response->type.length = typelen;
	} else {
		eap_round->response->type.length = 0;
		eap_round->response->type.data = NULL;
	}

	return eap_round;
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
		rad_assert(!in_request || (*eap_session == in_request));
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

	rad_assert((*eap_session)->request);
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
	if (!eap_session) {
		/* Either send EAP_Identity or EAP-Fail */
		REDEBUG("No EAP session matching state");
		return NULL;
	}

	if (!rad_cond_assert(eap_session->inst)) return NULL;

	rad_assert(!eap_session->request);	/* If triggered, something didn't freeze the session */
	eap_session->request = request;
	eap_session->updated = request->timestamp.tv_sec;

	return eap_session;
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
 * @param[in] eap_packet_p extracted from the RADIUS Access-Request.  Consumed or freed by this
 *	function.  Do not access after calling this function. Is a **so the packet pointer can be
 *	set to NULL.
 * @param[in] inst of the rlm_eap module.
 * @param[in] request The current request.
 * @return
 *	- A newly allocated eap_session_t, or the one associated with the current request.
 *	  MUST be freed with #eap_session_destroy if being disposed of, OR
 *	  MUST be re-frozen with #eap_session_freeze if the authentication session will
 *	  continue when a future request is received.
 *	- NULL on error.
 */
eap_session_t *eap_session_continue(eap_packet_raw_t **eap_packet_p, rlm_eap_t *inst, REQUEST *request)
{
	eap_session_t	*eap_session = NULL;
	eap_packet_raw_t *eap_packet;
	VALUE_PAIR	*vp;

	/*
	 *	Ensure it's a valid EAP-Request, or EAP-Response.
	 */
	if (eap_validation(request, eap_packet_p) == EAP_INVALID) {
	error:
		talloc_free(*eap_packet_p);
		*eap_packet_p = NULL;
		return NULL;
	}

	eap_packet = *eap_packet_p;

	/*
	 *	eap_session_t MUST be found in the list if it is not
	 *	EAP-Identity response
	 */
	if (eap_packet->data[0] != PW_EAP_IDENTITY) {
		eap_session = eap_session_thaw(request);
		if (!eap_session) {
			vp = fr_pair_find_by_num(request->packet->vps, 0, PW_STATE, TAG_ANY);
			if (!vp) {
				REDEBUG("EAP requires the State attribute to work, but no State exists in the Access-Request packet.");
				REDEBUG("The RADIUS client is broken.  No amount of changing FreeRADIUS will fix the RADIUS client.");
			}

			goto error;
		}

		RDEBUG4("Got eap_session_t %p from request data", eap_session);
#ifdef WITH_VERIFY_PTR
		eap_session = talloc_get_type_abort(eap_session, eap_session_t);
#endif
		eap_session->rounds++;
		if (eap_session->rounds >= 50) {
			RERROR("Failing EAP session due to too many round trips");
		error2:
			eap_session_destroy(&eap_session);
			goto error;
		}

		/*
		 *	Even more paranoia.  Without this, some weird
		 *	clients could do crazy things.
		 *
		 *	It's ok to send EAP sub-type NAK in response
		 *	to a request for a particular type, but it's NOT
		 *	OK to blindly return data for another type.
		 */
		if ((eap_packet->data[0] != PW_EAP_NAK) &&
		    (eap_packet->data[0] != eap_session->type)) {
			RERROR("Response appears to match a previous request, but the EAP type is wrong");
			RERROR("We expected EAP type %s, but received type %s",
			       eap_type2name(eap_session->type),
			       eap_type2name(eap_packet->data[0]));
			RERROR("Your Supplicant or NAS is probably broken");
			goto error;
		}
	/*
	 *	Packet was EAP identity, allocate a new eap_session.
	 */
	} else {
		eap_session = eap_session_alloc(inst, request);
		if (!eap_session) goto error;

		RDEBUG4("New eap_session_t %p", eap_session);

		/*
		 *	All fields in the eap_session are set to zero.
		 */
		eap_session->identity = eap_identity(request, eap_session, eap_packet);
		if (!eap_session->identity) {
			RDEBUG("Identity Unknown, authentication failed");
			goto error2;
		}

		/*
		 *	If the index is removed by something else
		 *	like the state being cleaned up, then we
		 *	still want the eap_session to be freed, which
		 *	is why we set free_opaque to true.
		 *
		 *	We must pass a NULL pointer to associate the
		 *	the EAP_SESSION data with, else we'll break
		 *	tunelled EAP, where the inner EAP module is
		 *	a different instance to the outer one.
		 */
		request_data_add(request, NULL, REQUEST_DATA_EAP_SESSION, eap_session, true, true, true);
	}

	vp = fr_pair_find_by_num(request->packet->vps, 0, PW_USER_NAME, TAG_ANY);
	if (!vp) {
	       /*
		*	NAS did not set the User-Name
		*	attribute, so we set it here and
		*	prepend it to the beginning of the
		*	request vps so that autz's work
		*	correctly
		*/
	       RDEBUG2("Broken NAS did not set User-Name, setting from EAP Identity");
	       vp = fr_pair_make(request->packet, &request->packet->vps,
				 "User-Name", eap_session->identity, T_OP_EQ);
	       if (!vp) {
		       goto error;
	       }
	} else {
	       /*
		*      A little more paranoia.  If the NAS
		*      *did* set the User-Name, and it doesn't
		*      match the identity, (i.e. If they
		*      change their User-Name part way through
		*      the EAP transaction), then reject the
		*      request as the NAS is doing something
		*      funny.
		*/
	       if (strncmp(eap_session->identity, vp->vp_strvalue, FR_MAX_STRING_LEN) != 0) {
		       RDEBUG("Identity does not match User-Name.  Authentication failed");
		       goto error;
	       }
	}

	eap_session->this_round = eap_round_build(eap_session, eap_packet_p);
	if (!eap_session->this_round) {
		REDEBUG("Failed allocating memory for round");
		goto error2;
	}

	return eap_session;
}
