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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000-2003  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 */
/*
 *  EAP PACKET FORMAT
 *  --- ------ ------
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Data ...
 * +-+-+-+-+
 *
 *
 * EAP Request and Response Packet Format 
 * --- ------- --- -------- ------ ------
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |  Type-Data ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *
 *
 * EAP Success and Failure Packet Format 
 * --- ------- --- ------- ------ ------
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#include "rlm_eap.h"

static const char rcsid[] = "$Id$";

static const char *eap_codes[] = {
  "",				/* 0 is invalid */
  "request",
  "response",
  "success",
  "failure"
};

/*
 * Load all the required eap authentication types.
 * Get all the supported EAP-types from config file. 
 */
int eaptype_load(EAP_TYPES **type, int eap_type, CONF_SECTION *cs)
{
	char		buffer[64];
	char		namebuf[64];
	const char	*eaptype_name;
	lt_dlhandle	handle;
	EAP_TYPES	*node;

	eaptype_name = eaptype_type2name(eap_type, namebuf, sizeof(namebuf));
	snprintf(buffer, sizeof(buffer), "rlm_eap_%s", eaptype_name);

	/* Link the loaded EAP-Type */
	handle = lt_dlopenext(buffer);
	if (handle == NULL) {
		radlog(L_ERR, "rlm_eap: Failed to link EAP-Type/%s: %s", 
		       eaptype_name, lt_dlerror());
		return -1;
	}

	/* Make room for the EAP-Type */
	node = (EAP_TYPES *)malloc(sizeof(EAP_TYPES));
	if (node == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return -1;
	}
	memset(node, 0, sizeof(*node));

	/* fill in the structure */
	node->handle = handle;
	node->cs = cs;

	/*
	 *	In general, this is a terrible idea.  It works here
	 *	solely because the eap_type2name function returns a
	 *	'static const char *' pointer sometimes, and we can
	 *	ONLY link to module which are named in that static
	 *	array.
	 */
	node->typename = eaptype_name;
	node->type_data = NULL;
	
	node->type = (EAP_TYPE *)lt_dlsym(node->handle, buffer);
	if (!node->type) {
		radlog(L_ERR, "rlm_eap: Failed linking to %s structure in %s: %s",
				buffer, eaptype_name, lt_dlerror());
		lt_dlclose(node->handle);	/* ignore any errors */
		free(node);
		return -1;
	}
	if ((node->type->attach) && 
	    ((node->type->attach)(node->cs, &(node->type_data)) < 0)) {

		radlog(L_ERR, "rlm_eap: Failed to initialize type %s",
		       eaptype_name);
		lt_dlclose(node->handle);
		free(node);
		return -1;
	}

	DEBUG("rlm_eap: Loaded and initialized type %s", eaptype_name);
	*type = node;
	return 0;
}

/*
 * Call the appropriate handle with the right eap_type.
 */
static int eaptype_call(EAP_TYPES *atype, EAP_HANDLER *handler)
{
	int rcode = 1;

	DEBUG2("  rlm_eap: processing type %s", atype->typename);

	rad_assert(atype != NULL);

	switch (handler->stage) {
	case INITIATE:
		if (!atype->type->initiate(atype->type_data, handler))
			rcode = 0;
		break;

	case AUTHORIZE:
		/*
		 *   The called function updates the EAP reply packet.
		 */
		if (!atype->type->authorize ||
		    !atype->type->authorize(atype->type_data, handler))
			rcode = 0;
		break;

	case AUTHENTICATE:
		/*
		 *   The called function updates the EAP reply packet.
		 */
		if (!atype->type->authenticate ||
		    !atype->type->authenticate(atype->type_data, handler))
			rcode = 0;
		break;

	default:
		/* Should never enter here */
		radlog(L_DBG, "rlm_eap: Invalid operation on eap_type");
		rcode = 0;
		break;
	}

	return rcode;
}

/*
 * Based on TYPE, call the appropriate EAP-type handler
 * Default to the configured EAP-Type 
 * for all Unsupported EAP-Types 
 */
int eaptype_select(rlm_eap_t *inst, EAP_HANDLER *handler)
{
	unsigned int	default_eap_type = inst->default_eap_type;
	eaptype_t	*eaptype;
	VALUE_PAIR	*vp;
	char		namebuf[64];
	const char	*eaptype_name;

	eaptype = &handler->eap_ds->response->type;

	/*
	 *	Don't trust anyone.
	 */
	if ((eaptype->type == 0) ||
	    (eaptype->type > PW_EAP_MAX_TYPES)) {
		DEBUG2(" rlm_eap: Asked to select bad type");
		return EAP_INVALID;
	}

	/*
	 *	Figure out what to do.
	 */
	switch(eaptype->type) {
	case PW_EAP_IDENTITY:
		DEBUG2("  rlm_eap: EAP Identity");
		
		/*
		 *	Allow per-user configuration of EAP types.
		 */
		vp = pairfind(handler->request->config_items,
			      PW_EAP_TYPE);
		if (vp) default_eap_type = vp->lvalue;
		
	do_initiate:
		/*
		 *	Ensure it's valid.
		 */
		if ((default_eap_type < PW_EAP_MD5) ||
		    (default_eap_type > PW_EAP_MAX_TYPES) ||
		    (inst->types[default_eap_type] == NULL)) {
			DEBUG2(" rlm_eap: No such EAP type %s",
			       eaptype_type2name(default_eap_type,
						 namebuf, sizeof(namebuf)));
			return EAP_INVALID;
		}
		
		handler->stage = INITIATE;
		handler->eap_type = default_eap_type;
		
		/*
		 *	Wild & crazy stuff!  For TTLS & PEAP, we
		 *	initiate a TLS session, and then pass that
		 *	session data to TTLS or PEAP for the
		 *	authenticate stage.
		 *
		 *	Handler->eap_type holds the TRUE type.
		 */
		if ((default_eap_type == PW_EAP_TTLS) ||
		    (default_eap_type == PW_EAP_PEAP)) {
			default_eap_type = PW_EAP_TLS;
		}
		
		
		/*
		 *	We don't do TLS inside of TLS, as it's a bad
		 *	idea...
		 */
		if (((handler->request->options & RAD_REQUEST_OPTION_FAKE_REQUEST) != 0) &&
		    (default_eap_type == PW_EAP_TLS)) {
			DEBUG2(" rlm_eap: Unable to tunnel TLS inside of TLS");
			return EAP_INVALID;
		}
		
		if (eaptype_call(inst->types[default_eap_type],
				 handler) == 0) {
			DEBUG2(" rlm_eap: Default EAP type %s failed in initiate", 
			       eaptype_type2name(default_eap_type,
						 namebuf, sizeof(namebuf)));
			return EAP_INVALID;
		}
		break;

	case PW_EAP_NAK:
		/*
		 *	The one byte of NAK data is the preferred EAP type
		 *	of the client.
		 */
		DEBUG2("  rlm_eap: EAP NAK");

		/*
		 *	Delete old data, if necessary.
		 */
		if (handler->opaque && handler->free_opaque) {
			handler->free_opaque(handler->opaque);
			handler->free_opaque = NULL;
			handler->opaque = NULL;
		}

		/*
		 *	It is invalid to request identity,
		 *	notification & nak in nak
		 */
		if (eaptype->data == NULL) {
			DEBUG2(" rlm_eap: Empty NAK packet, cannot decide what EAP type the client wants.");
			return EAP_INVALID;
		}

		if ((eaptype->data[0] < PW_EAP_MD5) ||
		    (eaptype->data[0] > PW_EAP_MAX_TYPES)) {
			DEBUG2(" rlm_eap: NAK asked for bad type %d",
			       eaptype->data[0]);
			return EAP_INVALID;
		}

		default_eap_type = eaptype->data[0];
		eaptype_name = eaptype_type2name(default_eap_type,
						 namebuf, sizeof(namebuf));
		DEBUG2(" rlm_eap: EAP-NAK asked for EAP-Type/%s",
		       eaptype_name);		       

		/*
		 *	Prevent a firestorm if the client is confused.
		 */
		if (handler->eap_type == default_eap_type) {
			DEBUG2(" rlm_eap: ERROR! Our request for %s was NAK'd with a request for %s, what is the client thinking?",
			       eaptype_name, eaptype_name);
			return EAP_INVALID;
		}

		/*
		 *	Enforce per-user configuration of EAP types.
		 */
		vp = pairfind(handler->request->config_items,
			      PW_EAP_TYPE);
		if (vp && (vp->lvalue != default_eap_type)) {
			char	mynamebuf[64];
			DEBUG2("  rlm_eap: Client wants %s, while we require %s, rejecting the user.",
			       eaptype_name,
			       eaptype_type2name(vp->lvalue,
						 mynamebuf,
						 sizeof(mynamebuf)));
			return EAP_INVALID;
		}
		goto do_initiate;
		break;

		/*
		 *	Key off of the configured sub-modules.
		 */
		default:
			eaptype_name = eaptype_type2name(eaptype->type,
							 namebuf,
							 sizeof(namebuf));
			DEBUG2("  rlm_eap: EAP/%s", eaptype_name);
			
			/*
			 *	We haven't configured it, it doesn't exit.
			 */
			if (!inst->types[eaptype->type]) {
				DEBUG2(" rlm_eap: EAP type %d is unsupported",
				       eaptype->type);
				return EAP_INVALID;
			}
			
			rad_assert(handler->stage == AUTHENTICATE);
			handler->eap_type = eaptype->type;
			if (eaptype_call(inst->types[eaptype->type],
					 handler) == 0) {
				DEBUG2(" rlm_eap: Handler failed in EAP/%s",
				       eaptype_name);
				return EAP_INVALID;
			}
		break;
	}

	return EAP_OK;
}


/*
 *	EAP packet format to be sent over the wire
 *
 *	i.e. code+id+length+data where data = null/type+typedata
 *	based on code.
 */
static int eap_wireformat(EAP_PACKET *reply)
{
	eap_packet_t	*hdr;
	uint16_t total_length = 0;

	if (reply == NULL) return EAP_INVALID;

	total_length = EAP_HEADER_LEN;
	if (reply->code < 3) {
		total_length += 1/*EAPtype*/;
		if (reply->type.data && reply->type.length > 0) {
			total_length += reply->type.length;
		}
	}

	reply->packet = (unsigned char *)malloc(total_length);
	hdr = (eap_packet_t *)reply->packet;
	if (!hdr) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return EAP_INVALID;
	}

	hdr->code = (reply->code & 0xFF);
	hdr->id = (reply->id & 0xFF);
	total_length = htons(total_length);
	memcpy(hdr->length, &total_length, sizeof(uint16_t));

	/*
	 *	Request and Response packets are special.
	 */
	if ((reply->code == PW_EAP_REQUEST) ||
	    (reply->code == PW_EAP_RESPONSE)) {
		hdr->data[0] = (reply->type.type & 0xFF);

		/*
		 * Here since we cannot know the typedata format and length
		 *
		 * Type_data is expected to be wired by each EAP-Type
		 *
		 * Zero length/No typedata is supported as long as
		 * type is defined
		 */
		if (reply->type.data && reply->type.length > 0) {
			memcpy(&hdr->data[1], reply->type.data, reply->type.length);
			free(reply->type.data);
			reply->type.data = reply->packet + EAP_HEADER_LEN + 1/*EAPtype*/;
		}
	}

	return EAP_VALID;
}

/*
 *	compose EAP reply packet in EAP-Message attr of RADIUS.  If
 *	EAP exceeds 253, frame it in multiple EAP-Message attrs.
 *
 *	Set the RADIUS reply codes based on EAP request codes.  Append
 *	any additonal VPs to RADIUS reply
 */
int eap_compose(EAP_HANDLER *handler)
{
	uint16_t eap_len, len;
	VALUE_PAIR *eap_msg;
	VALUE_PAIR *vp;
	eap_packet_t *eap_packet;
	unsigned char 	*ptr;
	REQUEST *request = handler->request;
	EAP_DS *eap_ds = handler->eap_ds;
	EAP_PACKET *reply = eap_ds->request;
	int rcode;

	/*
	 *	The Id for the EAP packet to the NAS wasn't set.
	 *	Do so now.
	 *
	 *	LEAP requires the Id to be incremented on EAP-Success
	 *	in Stage 4, so that we can carry on the conversation
	 *	where the client asks us to authenticate ourselves
	 *	in stage 5.
	 */
	if (!eap_ds->set_request_id) {
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
		reply->id = handler->eap_ds->response->id;
		
		switch (reply->code) {
			/*
			 *	The Id is a simple "ack" for success
			 *	and failure.
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
	} else {
		DEBUG2("  rlm_eap: Underlying EAP-Type set EAP ID to %d",
		       reply->id);
	}

	/*
	 *	For Request & Response packets, set the EAP sub-type,
	 *	if the EAP sub-module didn't already set it.
	 *
	 *	This allows the TLS module to be "morphic", and means
	 *	that the TTLS and PEAP modules can call it to do most
	 *	of their dirty work.
	 */
	if (((eap_ds->request->code == PW_EAP_REQUEST) ||
	     (eap_ds->request->code == PW_EAP_RESPONSE)) &&
	    (eap_ds->request->type.type == 0)) {
		rad_assert(handler->eap_type >= PW_EAP_MD5);
		rad_assert(handler->eap_type <= PW_EAP_MAX_TYPES);

		eap_ds->request->type.type = handler->eap_type;
	}
	  

	if (eap_wireformat(reply) == EAP_INVALID) {
		return RLM_MODULE_INVALID;
	}
	eap_packet = (eap_packet_t *)reply->packet;

	memcpy(&eap_len, &(eap_packet->length), sizeof(uint16_t));
	len = eap_len = ntohs(eap_len);
	ptr = (unsigned char *)eap_packet;

	do {
		if (eap_len > 253) {
			len = 253;
			eap_len -= 253;
		} else {
			len = eap_len;
			eap_len = 0;
		}

		/* 
		 * create a value pair & append it to the request reply list
		 * This memory gets freed up when request is freed up
		 */
		eap_msg = paircreate(PW_EAP_MESSAGE, PW_TYPE_OCTETS);
		memcpy(eap_msg->strvalue, ptr, len);
		eap_msg->length = len;
		pairadd(&(request->reply->vps), eap_msg);
		ptr += len;
		eap_msg = NULL;
	} while (eap_len);

	/*
	 *	EAP-Message is always associated with
	 *	Message-Authenticator but not vice-versa.
	 *
	 *	Don't add a Message-Authenticator if it's already
	 *	there.
	 */
	vp = pairfind(request->reply->vps, PW_MESSAGE_AUTHENTICATOR);
	if (!vp) {
		vp = paircreate(PW_MESSAGE_AUTHENTICATOR, PW_TYPE_OCTETS);
		memset(vp->strvalue, 0, AUTH_VECTOR_LEN);
		vp->length = AUTH_VECTOR_LEN;
		pairadd(&(request->reply->vps), vp);
	}

	/* Set request reply code, but only if it's not already set. */
	rcode = RLM_MODULE_OK;
	if (!request->reply->code) switch(reply->code) {
	case PW_EAP_RESPONSE:
		request->reply->code = PW_AUTHENTICATION_ACK;
		rcode = RLM_MODULE_HANDLED; /* leap weirdness */
		break;
	case PW_EAP_SUCCESS:
		request->reply->code = PW_AUTHENTICATION_ACK;
		rcode = RLM_MODULE_OK;
		break;
	case PW_EAP_FAILURE:
		request->reply->code = PW_AUTHENTICATION_REJECT;
		rcode = RLM_MODULE_REJECT;
		break;
	case PW_EAP_REQUEST:
		request->reply->code = PW_ACCESS_CHALLENGE;
		rcode = RLM_MODULE_HANDLED;
		break;
	default:
		/*
		 *	When we're pulling MS-CHAPv2 out of EAP-MS-CHAPv2,
		 *	we do so WITHOUT setting a reply code, as the
		 *	request is being proxied.
		 */
		if (request->options & RAD_REQUEST_OPTION_PROXY_EAP) {
			return RLM_MODULE_HANDLED;
		}

		/* Should never enter here */
		radlog(L_ERR, "rlm_eap: reply code %d is unknown, Rejecting the request.", reply->code);
		request->reply->code = PW_AUTHENTICATION_REJECT;
		rcode = RLM_MODULE_REJECT;
		break;
	}

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
	EAP_DS *eap_ds;
	EAP_HANDLER handler;

	eap_msg = pairfind(request->packet->vps, PW_EAP_MESSAGE);
	if (eap_msg == NULL) {
		DEBUG2("  rlm_eap: No EAP-Message, not doing EAP");
		return EAP_NOOP;
	}

	/*
	 *	Look for EAP-Type = None (FreeRADIUS specific attribute)
	 *	this allows you to NOT do EAP for some users.
	 */
	vp = pairfind(request->packet->vps, PW_EAP_TYPE);
	if (vp && vp->lvalue == 0) {
		DEBUG2("  rlm_eap: Found EAP-Message, but EAP-Type = None, so we're not doing EAP.");
		return EAP_NOOP;
	}

	/*
	 *	http://www.freeradius.org/rfc/rfc2869.html#EAP-Message
	 *
	 *	This is handled by rad_recv().
	 */

	/*
	 *	We're allowed only a few codes.  Request, Response,
	 *	Success, or Failure.
	 */
	if ((eap_msg->strvalue[0] == 0) ||
	    (eap_msg->strvalue[0] > PW_EAP_MAX_CODES)) {
		DEBUG2("  rlm_eap: Unknown EAP packet");
	} else {
		DEBUG2("  rlm_eap: EAP packet type %s id %d length %d",
		       eap_codes[eap_msg->strvalue[0]],
		       eap_msg->strvalue[1],
		       eap_msg->length);
	}

	/*
	 *	Check for a Proxy-To-Realm.  Don't get excited over LOCAL
	 *	realms (sigh).
	 */
	proxy = pairfind(request->config_items, PW_PROXY_TO_REALM);
	if (proxy) {
		REALM *realm;

		/*
		 *	If it's a LOCAL realm, then we're not proxying
		 *	to it.
		 */
		realm = realm_find(proxy->strvalue, 0);
		if (realm && (realm->ipaddr == htonl(INADDR_NONE))) {
			proxy = NULL;
		}
	}

	/*
	 *	Not a start message.  Don't start anything.
	 *
	 *	Later EAP messages are longer than the 'start' message,
	 *	so this function returns 'no start found', so that
	 *	the rest of the EAP code can use the State attribute
	 *	to match this EAP-Message to an ongoing conversation.
	 */
	if (eap_msg->length != EAP_START) {
		DEBUG2("  rlm_eap: No EAP Start, assuming it's an on-going EAP conversation");

		/*
		 *	Add the 'EAP-Type' attribute to the request,
		 *	if it's part of an EAP conversation, and the
		 *	EAP sub-type is in the EAP packet.
		 *
		 *	Store the EAP type in the request, so modules
		 *	outside of EAP can check & use it.
		 */
		if (((eap_msg->strvalue[0] == PW_EAP_REQUEST) ||
		     (eap_msg->strvalue[0] == PW_EAP_RESPONSE)) &&
		    (eap_msg->length >= (EAP_HEADER_LEN + 1))) {
			/*
			 *	Create an EAP-Type of the type which
			 *	was NAK'd, or of the type in the packet.
			 */
			vp = paircreate(PW_EAP_TYPE, PW_TYPE_INTEGER);
			if (vp) {
				vp->lvalue = eap_msg->strvalue[4];
				pairadd(&(request->packet->vps), vp);
			}
			
			/*
			 *	We've been told to ignore unknown EAP
			 *	types, AND it's an unknown type.
			 *	Return "NOOP", which will cause the
			 *	eap_authorize() to return NOOP.
			 *
			 *	EAP-Identity, Notification, and NAK
			 *	are all handled internally, so they
			 *	never have handlers.
			 */
			if ((eap_msg->strvalue[4] >= PW_EAP_MD5) &&
			    inst->ignore_unknown_eap_types &&
			    ((eap_msg->strvalue[4] == 0) ||
			     (eap_msg->strvalue[4] > PW_EAP_MAX_TYPES) ||
			     (inst->types[eap_msg->strvalue[4]] == NULL))) {
				DEBUG2("  rlm_eap:  Ignoring Unknown EAP type");
				return EAP_NOOP;
			}

			/*
			 *	They're NAKing the EAP type we wanted
			 *	to use, and asking for one which we don't
			 *	support.
			 *
			 *	NAK is code + id + length1 + length + NAK
			 *             + requested EAP type.
			 *
			 *	We know at this point that we can't
			 *	handle the request.  We could either
			 *	return an EAP-Fail here, but it's not
			 *	too critical.
			 *
			 *	By returning "noop", we can ensure
			 *	that authorize() returns NOOP, and
			 *	another module may choose to proxy
			 *	the request.
			 */
			if ((eap_msg->strvalue[4] == PW_EAP_NAK) &&
			    (eap_msg->length >= (EAP_HEADER_LEN + 2)) &&
			    inst->ignore_unknown_eap_types &&
			    ((eap_msg->strvalue[5] == 0) ||
			     (eap_msg->strvalue[5] > PW_EAP_MAX_TYPES) ||
			     (inst->types[eap_msg->strvalue[5]] == NULL))) {
				DEBUG2("  rlm_eap: Ignoring NAK with request for unknown EAP type");
				return EAP_NOOP;
			}
		} /* else it's not an EAP-Request or EAP-Response */
 
		/*
		 *	No EAP-Start found.  Proxying: return NOOP.
		 *	Not proxying, return NOTFOUND.
		 */
		if (proxy) goto do_proxy; /* 3 lines below. */
		return EAP_NOTFOUND;

	} else if (proxy) {
	do_proxy:
		/*
		 *	EAP-Start, but proxied.  Don't do EAP.
		 */
		DEBUG2("  rlm_eap: Request is supposed to be proxied to Realm %s.  Not doing EAP.", proxy->strvalue);
		return EAP_NOOP;
	}

	DEBUG2("  rlm_eap: Got EAP_START message");
	if ((eap_ds = eap_ds_alloc()) == NULL) {
		DEBUG2("  rlm_eap: EAP Start failed in allocation");
		return EAP_FAIL;
	}

	/*
	 *	It's an EAP-Start packet.  Tell them to stop wasting
	 *	our time, and give us an EAP-Identity packet.
	 *
	 *	Hmm... we should probably check the contents of the
	 *	EAP-Start packet for something...
	 */
	eap_ds->request->code = PW_EAP_REQUEST;
	eap_ds->request->type.type = PW_EAP_IDENTITY;

	/*
	 *	We don't have a handler, but eap_compose needs one,
	 *	(for various reasons), so we fake it out here.
	 */
	memset(&handler, 0, sizeof(handler));
	handler.request = request;
	handler.eap_ds = eap_ds;

	eap_compose(&handler);

	eap_ds_free(&eap_ds);
	return EAP_FOUND;
}

/*
 *	compose EAP FAILURE packet in EAP-Message
 */
void eap_fail(EAP_HANDLER *handler)
{
	handler->eap_ds->request->code = PW_EAP_FAILURE;
	eap_compose(handler);
}

/*
 *	compose EAP SUCCESS packet in EAP-Message
 */
void eap_success(EAP_HANDLER *handler)
{
	handler->eap_ds->request->code = PW_EAP_SUCCESS;
	eap_compose(handler);
}

/*
 * Basic EAP packet verfications & validations
 */
static int eap_validation(eap_packet_t *eap_packet)
{
	uint16_t len;

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);

	/*
	 *	High level EAP packet checks
	 */
	if ((len <= EAP_HEADER_LEN) ||
 	    ((eap_packet->code != PW_EAP_RESPONSE) &&
 	     (eap_packet->code != PW_EAP_REQUEST)) ||
	    (eap_packet->data[0] <= 0) ||
	    (eap_packet->data[0] > PW_EAP_MAX_TYPES)) {

		radlog(L_AUTH, "rlm_eap: Incorrect EAP Message, "
				"Ignoring the packet");
		return EAP_INVALID;
	}

	/* we don't expect notification, but we send it */
	if (eap_packet->data[0] == PW_EAP_NOTIFICATION) {
		radlog(L_AUTH, "rlm_eap: Got NOTIFICATION, "
				"Ignoring the packet");
		return EAP_INVALID;
	}

	return EAP_VALID;
}


/*
 *  Get the user Identity only from EAP-Identity packets
 */
static char *eap_identity(eap_packet_t *eap_packet)
{
	int size;
	uint16_t len;
	char *identity;

	if ((eap_packet == NULL) ||
	    (eap_packet->code != PW_EAP_RESPONSE) ||
	    (eap_packet->data[0] != PW_EAP_IDENTITY)) {
		return NULL;
	}

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);

	if ((len <= 5) || (eap_packet->data[1] == 0x00)) {
		radlog(L_ERR, "rlm_eap: UserIdentity Unknown ");
		return NULL;
	}

	size = len - 5;
	identity = (char *)malloc(size + 1);
	if (identity == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return NULL;
	}
	memcpy(identity, &eap_packet->data[1], size);
	identity[size] = '\0';

	return identity;
}


/*
 *	Create our Request-Response data structure with the eap packet
 */
static EAP_DS *eap_buildds(eap_packet_t **eap_packet_p)
{
	EAP_DS		*eap_ds = NULL;
	eap_packet_t	*eap_packet = *eap_packet_p;
	int		typelen;
	uint16_t	len;

	if ((eap_ds = eap_ds_alloc()) == NULL) {
		return NULL;
	}

	eap_ds->response->packet = (unsigned char *)eap_packet;
        eap_ds->response->code = eap_packet->code;
        eap_ds->response->id = eap_packet->id;
        eap_ds->response->type.type = eap_packet->data[0];

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);
	eap_ds->response->length = len;

	/*
	 *	We've eaten the eap packet into the eap_ds.
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
		eap_ds->response->type.data = eap_ds->response->packet + 5/*code+id+length+type*/;
		eap_ds->response->type.length = typelen;
	} else {
		eap_ds->response->type.length = 0;
		eap_ds->response->type.data = NULL;
	}

	return eap_ds;
}


/*
 * If identity response then create a fresh handler & fill the identity
 * else handler MUST be in our list, get that.
 * This handler creation cannot fail
 *
 * username contains REQUEST->username which might have been stripped.
 * identity contains the one sent in EAP-Identity response
 */
EAP_HANDLER *eap_handler(rlm_eap_t *inst, eap_packet_t **eap_packet_p,
			 REQUEST *request)
{
	EAP_HANDLER	*handler = NULL;
	eap_packet_t	*eap_packet = *eap_packet_p;
	VALUE_PAIR	*vp;

	/*
	 *	Ensure it's a valid EAP-Request, or EAP-Response.
	 */
	if (eap_validation(eap_packet) == EAP_INVALID) {
		free(*eap_packet_p);
		*eap_packet_p = NULL;
		return NULL;
	}

	/*
	 *	EAP_HANDLER MUST be found in the list if it is not
	 *	EAP-Identity response
	 */
	if (eap_packet->data[0] != PW_EAP_IDENTITY) {
		handler = eaplist_find(inst, request, eap_packet);
		if (handler == NULL) {
			/* Either send EAP_Identity or EAP-Fail */
			radlog(L_ERR, "rlm_eap: Either EAP-request timed out OR"
				" EAP-response to an unknown EAP-request");
			free(*eap_packet_p);
			*eap_packet_p = NULL;
			return NULL;
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
		    (eap_packet->data[0] != handler->eap_type)) {
			radlog(L_ERR, "rlm_eap: Response appears to match, but EAP type is wrong.");
			free(*eap_packet_p);
			*eap_packet_p = NULL;
			return NULL;
		}

               vp = pairfind(request->packet->vps, PW_USER_NAME);
               if (!vp) {
                       /*
                        *	NAS did not set the User-Name
                        *	attribute, so we set it here and
                        *	prepend it to the beginning of the
                        *	request vps so that autz's work
                        *	correctly
			*/
                       radlog(L_INFO, "rlm_eap: Broken NAS did not set User-Name, setting from EAP Identity");
                       vp = pairmake("User-Name", handler->identity, T_OP_EQ);
                       if (vp == NULL) {
                               radlog(L_ERR, "rlm_eap: out of memory");
                               free(*eap_packet_p);
                               *eap_packet_p = NULL;
                               return NULL;
                       }
                       vp->next = request->packet->vps;
                       request->packet->vps = vp;

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
                       if (strncmp(handler->identity, vp->strvalue,
				   MAX_STRING_LEN) != 0) {
                               radlog(L_ERR, "rlm_eap: Identity does not match User-Name.  Authentication failed.");
                               free(*eap_packet_p);
                               *eap_packet_p = NULL;
                               return NULL;
                       }
	       }
	} else {		/* packet was EAP identity */
		handler = eap_handler_alloc();
		if (handler == NULL) {
			radlog(L_ERR, "rlm_eap: out of memory");
			free(*eap_packet_p);
			*eap_packet_p = NULL;
			return NULL;
		}

		/*
		 *	All fields in the handler are set to zero.
		 */
		handler->identity = eap_identity(eap_packet);
		if (handler->identity == NULL) {
			radlog(L_ERR, "rlm_eap: Identity Unknown, authentication failed");
			free(*eap_packet_p);
			*eap_packet_p = NULL;
			eap_handler_free(&handler);
			return NULL;
		}

               vp = pairfind(request->packet->vps, PW_USER_NAME);
               if (!vp) {
                       /*
                        *	NAS did not set the User-Name
                        *	attribute, so we set it here and
                        *	prepend it to the beginning of the
                        *	request vps so that autz's work
                        *	correctly
			*/
                       radlog(L_INFO, "rlm_eap: WARNING NAS did not set User-Name.  Setting it locally from EAP Identity");
                       vp = pairmake("User-Name", handler->identity, T_OP_EQ);
                       if (vp == NULL) {
                               radlog(L_ERR, "rlm_eap: out of memory");
                               free(*eap_packet_p);
                               *eap_packet_p = NULL;
                               return NULL;
                       }
                       vp->next = request->packet->vps;
                       request->packet->vps = vp;
               } else {
                       /*
                        *      Paranoia.  If the NAS *did* set the
                        *      User-Name, and it doesn't match the
                        *      identity, the NAS is doing something
                        *      funny, so reject the request.
			*/
                       if (strncmp(handler->identity, vp->strvalue,
				   MAX_STRING_LEN) != 0) {
                               radlog(L_ERR, "rlm_eap: Identity does not match User-Name, setting from EAP Identity.");
                               free(*eap_packet_p);
                               *eap_packet_p = NULL;
                               eap_handler_free(&handler);
                               return NULL;
                       }
	       }
	}

	handler->eap_ds = eap_buildds(eap_packet_p);
	if (handler->eap_ds == NULL) {
		free(*eap_packet_p);
		*eap_packet_p = NULL;
		eap_handler_free(&handler);
		return NULL;
	}

	handler->timestamp = request->timestamp;
	handler->request = request; /* LEAP needs this */
	return handler;
}
