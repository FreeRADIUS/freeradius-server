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
 * Copyright 2000,2001  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
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

static const char *eap_types[] = {
  "",   
  "identity",
  "notification",
  "nak",			/* NAK */
  "md5",
  "otp",
  "gtc",
  "7",
  "8",
  "9",
  "10",
  "11",
  "12",
  "tls",			/* 13 */
  "14",
  "15",
  "16",
  "leap",			/* 17 */
  "18",
  "19",
  "20",
  "ttls",			/* 21 */
  "22",
  "23",
  "24",
  "peap"			/* 25 */
};

/*
 * Load all the required eap authentication types.
 * Get all the supported EAP-types from config file. 
 */
int eaptype_load(EAP_TYPES **type_list, const char *type_name,
		 CONF_SECTION *cs)
{
	EAP_TYPES **last, *node;
	lt_dlhandle handle;
	char auth_type_name[NAME_LEN];
	int i;

	snprintf(auth_type_name, sizeof(auth_type_name), "rlm_eap_%s", type_name);

	last = type_list;
	/* Go to the end of the EAP-Type list, if it is not already loaded */
	for (node = *type_list; node != NULL; node = node->next) {
		if (strcmp(node->typename, auth_type_name) == 0)
			return 0;
		last = &node->next;
	}

	/* Link the loaded EAP-Type */
	handle = lt_dlopenext(auth_type_name);
	if (handle == NULL) {
		radlog(L_ERR, "rlm_eap: Failed to link EAP-Type/%s: %s", 
				type_name, lt_dlerror());
		return -1;
	}

	/* Make room for the EAP-Type */
	node = (EAP_TYPES *)malloc(sizeof(EAP_TYPES));
	if (node == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return -1;
	}

	/* fill in the structure */
	node->next = NULL;
	node->handle = handle;
	node->cs = cs;
	node->typeid = 0;
	memset(node->typename, 0, NAME_LEN);
	node->type_stuff = NULL;
	strNcpy(node->typename, type_name, sizeof(node->typename));
	for (i = PW_EAP_MAX_TYPES; i > 0; i--) {
		if (!strcmp(type_name, eap_types[i])) {
			node->typeid = i;
			break;
		}
	}

	if (node->typeid == 0) {
		radlog(L_ERR, "rlm_eap: Invalid type name %s cannot be linked", type_name);
		free(node);
		return -1;
	}
	
	node->type = (EAP_TYPE *)lt_dlsym(node->handle, auth_type_name);
	if (!node->type) {
		radlog(L_ERR, "rlm_eap: Failed linking to %s structure in %s: %s",
				auth_type_name, type_name, lt_dlerror());
		lt_dlclose(node->handle);	/* ignore any errors */
		free(node);
		return -1;
	}
	if ((node->type->attach) && 
		((node->type->attach)(node->cs, &(node->type_stuff)) < 0)) {

		radlog(L_ERR, "rlm_eap: Failed to initialize the type %s", type_name);
		lt_dlclose(node->handle);
		free(node);
		return -1;
	}

	DEBUG("rlm_eap: Loaded and initialized the type %s", type_name);
	*last = node;
	return 0;
}

/*
 * Get the handle for the requested authentication type, 
 * if supported.
 */
EAP_TYPES *eaptype_byid(EAP_TYPES **list, int type)
{
	EAP_TYPES *node;
	for(node = *list; node != NULL; node = node->next) {
		if (node->typeid == type)
			return node;
	}
	return NULL;
}

EAP_TYPES *eaptype_byname(EAP_TYPES **list, const char *name)
{
	EAP_TYPES *node;
	for(node = *list; node != NULL; node = node->next) {
		if (strcmp(node->typename, name) == 0)
			return node;
	}
	return NULL;
}

/*
 * Call the appropriate handle with the right eap_type.
 */
int eaptype_call(int eap_type, operation_t action, 
	EAP_TYPES *type_list, EAP_HANDLER *handler)
{
	EAP_TYPES *atype;

	atype = eaptype_byid(&type_list, eap_type);
	if (!atype) {
		radlog(L_ERR, "rlm_eap: Unsupported EAP_TYPE %d",
			handler->eap_ds->response->type.type);
		return 0;
	}

	DEBUG2("  rlm_eap: processing type %s", atype->typename);

	switch (action) {
	case INITIATE:
		if (!atype->type->initiate(atype->type_stuff, handler))
			return 0;
		break;
	case AUTHENTICATE:
		/*
		 * when it returns, eap_ds->reply is expected to have complete info
		 */
		if (!atype->type->authenticate(atype->type_stuff, handler))
			return 0;
		break;
	default:
		/* Should never enter here */
		radlog(L_DBG, "rlm_eap: Invalid operation  on eap_type");
		break;
	}
	return 1;
}

/*
 * Based on TYPE, call the appropriate EAP-type handler
 * Default to the configured EAP-Type 
 * for all Unsupported EAP-Types 
 */
int eaptype_select(EAP_TYPES *type_list, EAP_HANDLER *handler, char *conftype)
{
	int type = 0, i;
	eaptype_t *eaptype;

	for (i = PW_EAP_MAX_TYPES; i > 0; i--) {
		if (strcmp(conftype, eap_types[i]) == 0) {
			type = i;
			break;
		}
	}

	if (type == 0) {
		radlog(L_ERR, "rlm_eap: Configured  EAP_TYPE is not supported");
	}

	eaptype = &handler->eap_ds->response->type;
	switch(eaptype->type) {
	case PW_EAP_IDENTITY:
		DEBUG2("  rlm_eap: EAP Identity");
		if (eaptype_call(type, INITIATE, type_list, handler) == 0)
			return EAP_INVALID;
			break;

	case PW_EAP_NAK:
		DEBUG2("  rlm_eap: EAP NAK");
		/*
		 * It is invalid to request identity, notification & nak in nak
		 */
		if ((eaptype->data != NULL) &&
			(eaptype->data[0] < PW_EAP_MD5)) {
			return EAP_INVALID;
		}

		/*
		 *	The one byte of NAK data is the preferred EAP type
		 *	of the client.
		 */
		switch (eaptype->data[0]) {
		case PW_EAP_MD5:
		case PW_EAP_TLS:
		case PW_EAP_LEAP:
			/*
			 * eap-type specified in typdata is supported
			 */
			if (eaptype_call(eaptype->data[0],
				INITIATE, type_list, handler) == 0)
				return EAP_INVALID;
			break;
		default :
			DEBUG2("  rlm_eap: Unknown EAP type %d, reverting to default_eap_type",
			       eaptype->data[0]);
			/*
			 * Unsupported type, default to configured one.
			 * or rather reject it
			 */
			/* handler->eap_ds->request->code = PW_EAP_FAILURE; */
			if (eaptype_call(type, INITIATE, type_list, handler) == 0)
				return EAP_INVALID;
			break;
		}
		break;
		case PW_EAP_MD5:
		case PW_EAP_OTP:
		case PW_EAP_GTC:
		case PW_EAP_TLS:
		case PW_EAP_LEAP:
		default:
			DEBUG2("  rlm_eap: EAP_TYPE - %s",
				eap_types[eaptype->type]);
			if (eaptype_call(eaptype->type, AUTHENTICATE,
				type_list, handler) == 0) {
				return EAP_INVALID;
		}
		break;
	}
	return EAP_OK;
}

/*
 * Handles multiple EAP-Message attrs
 * ie concatenates all to get the complete EAP packet
 *
 * NOTE: Sometimes Framed-MTU might contain the length of EAP-Message,
 *      refer fragmentation in rfc2869.
 */
eap_packet_t *eap_attribute(VALUE_PAIR *vps)
{
	VALUE_PAIR *first, *vp;
	eap_packet_t *eap_packet;
	unsigned char *ptr;
	uint16_t len;
	int total_len;

	/*
	 *	Get only EAP-Message attribute list
	 */
	first = pairfind(vps, PW_EAP_MESSAGE);
	if (first == NULL) {
		radlog(L_ERR, "rlm_eap: EAP-Message not found");
		return NULL;
	}

	/*
	 *	Sanity check the length before doing anything.
	 */
	if (first->length < 4) {
		radlog(L_ERR, "rlm_eap: EAP packet is too short.");
		return NULL;
	}

	/*
	 *	Get the Actual length from the EAP packet
	 *	First EAP-Message contains the EAP packet header
	 */
	memcpy(&len, first->strvalue + 2, sizeof(len));
	len = ntohs(len);

	/*
	 *	Take out even more weird things.
	 */
	if (len < 4) {
		radlog(L_ERR, "rlm_eap: EAP packet has invalid length.");
		return NULL;
	}

	/*
	 *	Sanity check the length, BEFORE malloc'ing memory.
	 */
	total_len = 0;
	for (vp = first; vp; vp = pairfind(vp->next, PW_EAP_MESSAGE)) {
		total_len += vp->length;
		
		if (total_len > len) {
			radlog(L_ERR, "rlm_eap: Malformed EAP packet.  Length in packet header does not match actual length");
			return NULL;
		}
	}

	/*
	 *	If the length is SMALLER, die, too.
	 */
	if (total_len < len) {
		radlog(L_ERR, "rlm_eap: Malformed EAP packet.  Length in packet header does not match actual length");
		return NULL;
	}

	/*
	 *	Now that we know the lengths are OK, allocate memory.
	 */
	eap_packet = (eap_packet_t *) malloc(len);
	if (eap_packet == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return NULL;
	}

	/*
	 *	Copy the data from EAP-Message's over to out EAP packet.
	 */
	ptr = (unsigned char *)eap_packet;

	/* RADIUS ensures order of attrs, so just concatenate all */
	for (vp = first; vp; vp = pairfind(vp->next, PW_EAP_MESSAGE)) {
		memcpy(ptr, vp->strvalue, vp->length);
		ptr += vp->length;
	}

	return eap_packet;
}

/*
 * EAP packet format to be sent over the wire
 * ie code+id+length+data where data = null/type+typedata
 * based on code.
 */
int eap_wireformat(EAP_PACKET *reply)
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

	if (reply->code < 3) {
		hdr->data[0] = (reply->type.type & 0xFF);

		/*
		 * Here since we cannot know the typedata format and length
		 * Type_data is expected to be wired by each EAP-Type
		 * Zero length/No typedata is supported as long as type is defined
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
 * compose EAP reply packet in EAP-Message attr of RADIUS.
 * If EAP exceeds 253, frame it in multiple EAP-Message attrs.
 * Set the RADIUS reply codes based on EAP request codes
 * Append any additonal VPs to RADIUS reply
 */
int eap_compose(REQUEST *request, EAP_DS *eap_ds)
{
	uint16_t eap_len, len;
	VALUE_PAIR *eap_msg;
	EAP_PACKET *rq;
	VALUE_PAIR *vp;
	eap_packet_t *eap_packet;
	unsigned char 	*ptr;
	EAP_PACKET *reply = eap_ds->request;

	/*
	 * ID serves to suppport request/response
	 * retransmission in the EAP layer and as
	 * such must be different for 'adjacent'
	 * packets except in case of success/failure-replies.
	 *
	 * RFC2716 (EAP_TLS) requires this to be
	 * incremented, RFC2284 only makes the above-
	 * mentioned restriction.
	 */
	eap_msg = pairfind(request->packet->vps, PW_EAP_MESSAGE);
	rq = (EAP_PACKET *)eap_msg->strvalue;

	/*
	 *	The ID for the EAP packet to the NAS wasn't set.
	 *	Do so now.
	 */
	if (!eap_ds->set_request_id) {
		reply->id = rq->id;
		
		switch (reply->code) {
		case PW_EAP_SUCCESS:
		case PW_EAP_FAILURE:
	    		break;
			
		default:
	    		++reply->id;
		}
	} else {
		DEBUG2("  rlm_eap: Underlying EAP-Type set EAP ID to %d",
		       reply->id);
	}

	if (eap_wireformat(reply) == EAP_INVALID) {
		return EAP_INVALID;
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

	/*
	 * Generate State, only if it not Identity request
	 */ 
	if ((eap_packet->code == PW_EAP_REQUEST) &&
	    (eap_packet->data[0] >= PW_EAP_MD5)) {
		vp = generate_state();
		pairadd(&(request->reply->vps), vp);
	}
		
	/* Set request reply code, but only if it's not already set. */
	if (!request->reply->code) switch(reply->code) {
	case PW_EAP_RESPONSE:
	case PW_EAP_SUCCESS:
		request->reply->code = PW_AUTHENTICATION_ACK;
		break;
	case PW_EAP_FAILURE:
		request->reply->code = PW_AUTHENTICATION_REJECT;
		break;
	case PW_EAP_REQUEST:
		request->reply->code = PW_ACCESS_CHALLENGE;
		break;
	default:
		/* Should never enter here */
		radlog(L_ERR, "rlm_eap: reply code %d is unknown, Rejecting the request.", reply->code);
		request->reply->code = PW_AUTHENTICATION_REJECT;
		break;
	}
	return 0;
}

/*
 * Radius criteria, EAP-Message is invalid without Message-Authenticator
 * For EAP_START, send Access-Challenge with EAP Identity request.
 */
int eap_start(REQUEST *request)
{
	VALUE_PAIR *vp;
	VALUE_PAIR *eap_msg;
	EAP_DS *eapstart;

	eap_msg = pairfind(request->packet->vps, PW_EAP_MESSAGE);
	if (eap_msg == NULL) {
		return EAP_NOOP;
	}

	/*
	 *  http://www.freeradius.org/rfc/rfc2869.html#EAP-Message
	 */
	vp = pairfind(request->packet->vps, PW_MESSAGE_AUTHENTICATOR);
	if (!vp) {
		radlog(L_ERR, "rlm_eap: EAP-Message without Message-Authenticator: Ignoring the request due to RFC 2869 Section 5.13 requirements");
		return EAP_NOOP;
	}

	if ((eap_msg->strvalue[0] == 0) ||
	    (eap_msg->strvalue[0] > PW_EAP_MAX_TYPES)) {
		DEBUG2("  rlm_eap: Unknown EAP packet");
	} else {
		DEBUG2("  rlm_eap: EAP packet type %s id %d length %d",
		       eap_types[eap_msg->strvalue[0]],
		       eap_msg->strvalue[1],
		       (eap_msg->strvalue[2] << 8) | eap_msg->strvalue[3]);
	}

	/*
	 *	If we've been configured to proxy, do nothing.
	 *
	 *	Note that we don't check if the realm is local.
	 *	We figure that anyone bright enough to add
	 *	Proxy-To-Realm is bright enough to NOT do so
	 *	when it's a local realm.
	 */
	if (pairfind(request->config_items, PW_PROXY_TO_REALM) != NULL) {
	  	return EAP_NOOP;
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
		DEBUG2("  rlm_eap: EAP Start not found");
		return EAP_NOTFOUND;
	}

	DEBUG2("  rlm_eap: Got EAP_START message");
	if ((eapstart = eap_ds_alloc()) == NULL) {
		DEBUG2("  rlm_eap: EAP Start failed in allocation");
		return EAP_FAIL;
	}

	/*
	 *	Hmm... why isn't this taken from the eap_msg?
	 */
	eapstart->request->code = PW_EAP_REQUEST;
	eapstart->request->type.type = PW_EAP_IDENTITY;

	eap_compose(request, eapstart);

	eap_ds_free(&eapstart);
	return EAP_FOUND;
}

/*
 * compose EAP FAILURE packet in EAP-Message
 */
void eap_fail(REQUEST *request, EAP_DS *eap_ds)
{
	eap_ds->request->code = PW_EAP_FAILURE;
	eap_compose(request, eap_ds);
}

/*
 * compose EAP SUCCESS packet in EAP-Message
 */
void eap_success(REQUEST *request, EAP_DS *eap_ds)
{
	eap_ds->request->code = PW_EAP_SUCCESS;
	eap_compose(request, eap_ds);
}

/*
 * Basic EAP packet verfications & validations
 */
int eap_validation(eap_packet_t *eap_packet)
{
	uint16_t len;

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);

	/* High level EAP packet checks */
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
 *  Get the user Identity if at all it is available with us.
 */
VALUE_PAIR *eap_useridentity(EAP_HANDLER *list, eap_packet_t *eap_packet, unsigned char id[])
{
	char *un;
	VALUE_PAIR *username;
	EAP_HANDLER *handler;

	if ((un = eap_identity(eap_packet)) != NULL) {
		username = pairmake("User-Name", un, T_OP_EQ);
		free(un);
		return username;
	}

	/* Get the handler from the list, if present */
	handler = eaplist_findhandler(list, id);
	if (handler)
		return pairmake("User-Name", handler->identity, T_OP_EQ);
	return NULL;
}


/*
 *  Get the user Identity only from EAP-Identity packets
 */
char *eap_identity(eap_packet_t *eap_packet)
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
 * Create our Request-Response data structure with the eap packet
 */
static EAP_DS *eap_buildds(eap_packet_t **eap_packet_p)
{
	EAP_DS *eap_ds = NULL;
	eap_packet_t	*eap_packet = NULL;
	int typelen;
	uint16_t len;

	eap_packet = *eap_packet_p;
	if (eap_packet == NULL) {
		return NULL;
	}

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

	/* First byte in eap_packet->data is *EAP-Type* */
	/*
	 * First 5 bytes, in eap, are code+id+length(2)+type
	 * The rest is TypeData
	 * skip *type* while getting typedata from data
	 */
	typelen = len - 5/*code+id+length+type*/;
	if (typelen > 0) {
		/*
		 * Since packet contians the complete eap_packet, 
		 * typedata will be a ptr in packet to its typedata
		 */
		eap_ds->response->type.data = eap_ds->response->packet + 5/*code+id+length+type*/;
		eap_ds->response->type.length = typelen;
	} else {
		eap_ds->response->type.length = 0;
		eap_ds->response->type.data = NULL;
	}

	*eap_packet_p = NULL;
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
EAP_HANDLER *eap_handler(EAP_HANDLER **list, eap_packet_t **eap_packet_p, REQUEST *request)
{
	EAP_HANDLER	*handler = NULL;
	unsigned char	*unique;
	eap_packet_t	*eap_packet = NULL;

	eap_packet = *eap_packet_p;
	if (eap_validation(eap_packet) == EAP_INVALID) {
		return NULL;
	}

	/*
	 * EAP_HANDLER MUST be found in the list if it is not EAP-Identity response
	 */
	if (eap_packet->data[0] != PW_EAP_IDENTITY) {
		unique = eap_regenerateid(request, eap_packet->id);
		if (unique == NULL) {
			return NULL;
		}

		handler = eaplist_isreply(list, unique);
		free(unique);
		unique = NULL;
		if (handler == NULL) {
			/* Either send EAP_Identity or EAP-Fail */
			radlog(L_ERR, "rlm_eap: Either EAP-request timed out OR"
				" EAP-response to an unknown EAP-request");
			return NULL;
		}
	} else {
		handler = eap_handler_alloc();
		if (handler == NULL) {
			radlog(L_ERR, "rlm_eap: out of memory");
			return NULL;
		}

		handler->id = NULL;
		handler->prev_eapds = NULL;
		handler->eap_ds = NULL;
		handler->configured = NULL;
		handler->opaque = NULL;
		handler->free_opaque = NULL;
		handler->next = NULL;

		handler->identity = eap_identity(eap_packet);
		if (handler->identity == NULL) {
			radlog(L_ERR, "rlm_eap: Identity Unknown, authentication failed");
			eap_handler_free(&handler);
			return NULL;
		}

		/* Get the User-Name */
		if (request->username == NULL) {
			handler->username = pairmake("User-Name", handler->identity, T_OP_EQ);
		} else {
			handler->username = paircopy(request->username);
		}

		/* No User-Name, No authentication */
		/*
		if (handler->username == NULL) {
			radlog(L_ERR, "rlm_eap: Unknown User, authentication failed");
			eap_handler_free(&handler);
			return NULL;
		}
		*/

		/*
		 * Always get the configured values, for each user.
		 * to pass it to the specific EAP-Type
		 *
		 * No Configured information found for a user, means
		 * there is no such user in the database.
		 *
		 * Every user should have, atleast, one item configured
		 * This is required for Authentication purpose.
		 */
		handler->configured = paircopy(request->config_items);
		if (handler->configured == NULL) {
			DEBUG2("  rlm_eap: No configured information for this user");

			/*
			 * FIXME: If there is no config info then
			 * config_items should provide the same username
			 * if the user is present in the database.
			 */
			/*
			eap_handler_free(&handler);
			return NULL;
			*/
		}
	}

	handler->eap_ds = eap_buildds(eap_packet_p);
	if (handler->eap_ds == NULL) {
		eap_handler_free(&handler);
		return NULL;
	}

	handler->timestamp = time(NULL);
	handler->reply_vps = &(request->reply->vps);
	handler->request = request; /* LEAP needs this */
	return handler;
}


/*
 * Regenerate the ID to match the ID stored in the list.
 * This ID is created based on the NAS, State & EAP-Response
 */
unsigned char *eap_regenerateid(REQUEST *request, unsigned char response_id)
{
	VALUE_PAIR 	*state = NULL;
	unsigned char	*id = NULL;

	state = pairfind(request->packet->vps, PW_STATE);
	if (state == NULL) {
		DEBUG2("  rlm_eap: NO State Attribute found: Cannot match EAP packet to any existing conversation.");
		return NULL;
	}
	if (verify_state(state) != 0) {
		radlog(L_ERR, "rlm_eap: State verification failed.");
		return NULL;
	}

	id = (unsigned char *)malloc(1/*Length*/ + 1/*Id*/ + state->length + sizeof(request->packet->src_ipaddr));
	if (id == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return NULL;
	}

	/*
	 * Generate unique-id to check for the reply 
	 * id = Length + ID + State + Client IP Address
	 *
	 *  Note that we do NOT use NAS-IP-Address, or NAS-Identifier,
	 *  as they may lie to us!
	 */
	id[0] = (1 + 1 + state->length + sizeof(request->packet->src_ipaddr)) & 0xFF;
	memcpy(id+1, &response_id, sizeof(unsigned char));
	memcpy(id+2, state->strvalue, state->length);
	memcpy(id+2+state->length, &request->packet->src_ipaddr,
	       sizeof(request->packet->src_ipaddr));

	return id;
}

/*
 * Generate the ID that is used as the search criteria in the list.
 * This ID is created based on the NAS, State & EAP-Request
 */
unsigned char *eap_generateid(REQUEST *request, unsigned char response_id)
{
	VALUE_PAIR 	*state = NULL;
	unsigned char	*id = NULL;

	state = pairfind(request->reply->vps, PW_STATE);
	if (state == NULL) {
		DEBUG2("  rlm_eap: NO State Attribute found.  Cannot match the EAP packet to any existing conversation.");
		return NULL;
	}

	id = (unsigned char *)malloc(1/*Length*/ + 1/*Id*/ + state->length + sizeof(request->packet->src_ipaddr));
	if (id == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return NULL;
	}

	/*
	 * Generate unique-id to check for the reply 
	 * id = Length + ID + State + Client IP Address
	 *
	 *  Note that we do NOT use NAS-IP-Address, or NAS-Identifier,
	 *  as they may lie to us!
	 */
	id[0] = (1 + 1 + state->length + sizeof(request->packet->src_ipaddr)) & 0xFF;
	memcpy(id+1, &response_id, sizeof(unsigned char));
	memcpy(id+2, state->strvalue, state->length);
	memcpy(id+2+state->length, &request->packet->src_ipaddr,
               sizeof(request->packet->src_ipaddr));

	return id;
}
