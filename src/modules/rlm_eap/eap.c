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

#include <stdio.h>
#include "eap.h"

static const char *eap_types[] = {
  "",   
  "identity",
  "notification",
  "nak",
  "md5",
  "otp",
  "gtc",
  "",
  "",
  "",
  "",
  "",
  "",
  "tls"
};

/*
 * Load all the required eap authentication types.
 * Get all the supported EAP-types from config file. 
 */
void load_type(EAP_TYPES **type_list, const char *type_name, CONF_SECTION *cs)
{
	EAP_TYPES **last, *node;
	lt_dlhandle *handle;
	char auth_type_name[NAME_LEN];
	int i;

	memset(auth_type_name, 0, NAME_LEN);
	snprintf(auth_type_name, sizeof(auth_type_name), "rlm_eap_%s", type_name);

	last = type_list;
	for (node = *type_list; node != NULL; node = node->next) {
		if (strcmp(node->typename, auth_type_name) == 0)
			return;
		last = &node->next;
	}

	handle = lt_dlopenext(auth_type_name);
	if (handle == NULL) {
		radlog(L_ERR, "rlm_eap: Failed to link to type %s: %s\n", type_name, lt_dlerror());
		return;
	}

	/* make room for auth type */
	node = (EAP_TYPES *) malloc(sizeof(EAP_TYPES));
	if (node == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return;
	}

	/* fill in the structure */
	node->next = NULL;
	node->handle = handle;
	node->cs = cs;
	node->typeid = 0;
	memset(node->typename, 0, NAME_LEN);
	node->type_stuff = NULL;
	snprintf(node->typename, sizeof(type_name), "%s", type_name);
	for (i = PW_EAP_MAX_TYPES; i > 0; i--) {
		if (!strcmp(type_name, eap_types[i])) {
			node->typeid = i;
			break;
		}
	}

	if (node->typeid == 0) {
		radlog(L_ERR, "rlm_eap: Invalid type name %s cannot be linked", type_name);
		free(node);
		return;
	}
	
	node->type = (EAP_TYPE *) lt_dlsym(node->handle, auth_type_name);
	if (!node->type) {
		radlog(L_ERR, "rlm_eap: Failed linking to %s structure in %s: %s",
				auth_type_name, type_name, lt_dlerror());
		lt_dlclose(node->handle);	/* ignore any errors */
		free(node);
		return;
	}
	if ((node->type->attach) && ((node->type->attach)(node->cs,
					&(node->type_stuff)) < 0)) {
		radlog(L_ERR, "rlm_eap: Failed to initialize the type %s", type_name);
		lt_dlclose(node->handle);
		free(node);
		return;
	}

	radlog(L_INFO, "rlm_eap: Loaded and initialized the type %s", type_name);
	*last = node;
	return;
}

/*
 * Get the handle for the requested authentication type, 
 * if supported.
 */
EAP_TYPES *find_type(EAP_TYPES **list, int type)
{
	EAP_TYPES *node;
	for(node = *list; node != NULL; node = node->next) {
		if (node->typeid == type)
			return node;
	}
	return NULL;
}

EAP_TYPES *find_typename(EAP_TYPES **list, const char *name)
{
	EAP_TYPES *node;
	for(node = *list; node != NULL; node = node->next) {
		if (strcmp(node->typename, name) == 0)
			return node;
	}
	return NULL;
}

/*
 * Here we also handle multiple PW_EAP_MESSAGE
 * Basically concatenate all of them and process as one EAP Message
 * Similarly while sending eap, check if it exceeds 254, if so
 * separate into multiple PW_EAP_MESSAGE
 *
 * NOTE: Sometimes Framed-MTU might contain the length of EAP-Message, see fragmentation
 */
eap_packet_t *get_eapmsg_attr(VALUE_PAIR *vps)
{
	VALUE_PAIR *vp_list, *i;
	eap_packet_t *eap_msg;
	uint8_t *ptr;
	int len;

        vp_list = paircopy2(vps, PW_EAP_MESSAGE);
        if (vp_list == NULL) {
		radlog(L_ERR, "rlm_eap: EAP_Message not found");
                return NULL;
	}

	/* 
	 * Get the Actual length from the EAP packet
	 */
        memcpy(&len, vp_list->strvalue+2, sizeof(u_short));
        len = ntohs(len);

	eap_msg = malloc(len);
	memcpy(eap_msg, vp_list->strvalue, vp_list->length);
	ptr = (uint8_t *)(eap_msg + vp_list->length);

	/*
	 * TODO: This check can also be based on Framed-MTU
	if (len < MAX_STRING_LEN)
		return eap_msg;
	 */

        if (vp_list->next != NULL) {
		radlog(L_INFO, "rlm_eap: Multiple EAP_Message attributes found");

		/* TODO: Check for the order of attributes too */
		for (i = vp_list->next; i; i = i->next) {
			if (((int)(ptr + i->length) - (int)eap_msg) >= len) {
				radlog(L_ERR, "rlm_eap: CRITICAL EAP_Message lengths doesnot match");
			}
			memcpy(ptr, i->strvalue, i->length);
			ptr += i->length;
		}
	}
	pairfree(&vp_list);
	return eap_msg;
}

/*
 * Get the user name from the EAP Identity message
 */
VALUE_PAIR *get_username(eap_packet_t *eap_msg)
{
	char 		*un;
	VALUE_PAIR 	*username = NULL;
	uint8_t		*ptr;
	int		len;

	if (eap_msg == NULL)
		return NULL;

	ptr = (uint8_t *)eap_msg;
	if ((ptr[0] != PW_EAP_RESPONSE) || (ptr[4] != PW_EAP_IDENTITY)) {
		return NULL;
	}

	memcpy(&len, ptr+1, sizeof(u_short));
	len = ntohs(len);

	if ((len == 5) || (ptr[5] == '\0')) {
		/* either send notification or discard */
		radlog(L_ERR, "rlm_eap: UserIdentity Unknown ");
		return NULL;
	}

	if (len > 5) {
		un = malloc(len-5);
		memcpy(un, ptr+5, len-5);
		username = pairmake("User-Name", un, T_OP_EQ);
		free(un);
	}
	return username;
}

/*
 * Extract EAP packet from EAP-Message attribute of RADIUS packet.
 * After performing some validations, like,
 * We are the Auth server, we expect only EAP_RESPONSE for 
 * which EAP_REQUEST, EAP_SUCCESS or EAP_FAILURE is sent back.
 */
EAP_DS *extract(eap_packet_t *eap_msg)
{
        eap_packet_t    *hdr;
        EAP_DS        	*eap_ds;
        uint16_t        len;

        hdr = (eap_packet_t *)eap_msg;
        memcpy(&len, hdr->length, sizeof(u_short));
        len = ntohs(len);

	/* 
	 * High level checks
	 */
        if ((len <= EAP_HEADER_LEN) ||
		(hdr->code != PW_EAP_RESPONSE) ||
		(hdr->data[0] <= 0) ||
		(hdr->data[0] > PW_EAP_MAX_TYPES)) {
		radlog(L_AUTH, "rlm_eap: Incorrect EAP Message, Ignoring the packet");
                return NULL;
        }

	/* 
	 * we don't expect notification, but we send it
	 */
	if (hdr->data[0] == PW_EAP_NOTIFICATION) {
		radlog(L_AUTH, "rlm_eap: Got NOTIFICATION, Ignoring the packet");
                return NULL;
	}

        /*
	 * Frame EAP Packet
	 */
	if ((eap_ds = eap_ds_alloc()) == NULL) {
		return NULL;
	}
        eap_ds->response->code = hdr->code;
        eap_ds->response->id = hdr->id;
        eap_ds->response->length = len;
        eap_ds->response->rad_vps = NULL;

	/*
	 * Usually, first byte in eap_packet->data is *type*
	 */
        eap_ds->response->type = hdr->data[0];

	/*
	 * First 5 bytes, in eap, are code+id+length(2)+type
	 */
	if ((eap_ds->response->typedata = malloc(len - 5)) == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		eap_ds_free(&eap_ds);
		return NULL;
	}

	/*
	 * skip *type* while getting typedata from data
	 */
	memcpy(eap_ds->response->typedata, hdr->data + 1, len - 5);

	return eap_ds;
}

/*
 * EAP packet format to be sent over the wire
 * ie code+id+length+data where data = null/type+typedata
 * based on code.
 */
eap_packet_t *wire_format(EAP_PACKET *packet)
{
	eap_packet_t	*hdr;
	int		total_length = 0;

	if (!packet) return NULL;
	hdr = (eap_packet_t *) malloc(PACKET_DATA_LEN);
	if (!hdr) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return NULL;
	}
	hdr->code = (packet->code & 0xFF);
	hdr->id = (packet->id & 0xFF);
	if (packet->code < 3) {
		hdr->data[0] = (packet->type & 0xFF);
		total_length = EAP_HEADER_LEN + 1;

		/*
		 * Here since we cannot know the typedata format and length
		 * Type_data is expected to be wired by each eap_type and type_len also.
		 */
		memcpy(&hdr->data[1], packet->typedata, packet->type_len);
		total_length += packet->type_len;
	} else {
		hdr->data[0] = 0x00;
		total_length = EAP_HEADER_LEN;
	}
	total_length = htons(total_length);
	memcpy(hdr->length, &total_length, sizeof(u_short));

	return hdr;
}

/*
 * Assumption: reply eap packet is filled with all the required information.
 * 
 * compose the whole reply packet in the EAP_MESSAGE attribute of RADIUS reply packet.
 * check to see if it exceeds more than 254.
 *
 * Based on the eap_ds->request->code REQUEST-reply->code is
 * Access-Accept, Access-Reject, Access-Challenge
 * 
 * if any rad_vps then append them to REQUEST->reply->vps
 * if we have to keep track of the ids that we have sent then store
 * them in *instance and call a timer
 * 
 */
int compose(REQUEST *request, EAP_PACKET *reply)
{
	int eap_len, len;
	int allowed;
	VALUE_PAIR *eap_msg;
	VALUE_PAIR *msg_auth;
	eap_packet_t *eap_packet, *ptr;

	allowed = MAX_STRING_LEN;
	eap_len = reply->type_len + EAP_HEADER_LEN + 1;
	len = eap_len;

	/*
	 * Either use unique id or we can use the below to get id
	 * good way is to use uniqe id, and not depend on any thing else 
	 */
	reply->id = request->packet->id;
	eap_packet = wire_format(reply);
	ptr = eap_packet;

	do {
		if (eap_len > allowed) {
			len = allowed;
			eap_len -= allowed;
		} else {
			len = eap_len;
			eap_len = 0;
		}

		/* 
		 * create a value pair & append it to the request reply list
		 * This memory gets freed up when request is freed up
		 */
		eap_msg = paircreate(PW_EAP_MESSAGE, PW_TYPE_STRING);
		memcpy(eap_msg->strvalue, ptr, len);
		eap_msg->length = len;
		pairadd(&(request->reply->vps), eap_msg);
		ptr += len;
		eap_msg = NULL;
	} while (eap_len);

	/*
	 * EAP-Message is always associated with Message-Authenticator
	 * but not viceversa.
	 */
	msg_auth = paircreate(PW_MESSAGE_AUTHENTICATOR, PW_TYPE_STRING);
	memset(msg_auth->strvalue, 0, AUTH_VECTOR_LEN);
	msg_auth->length = AUTH_VECTOR_LEN;
	pairadd(&(request->reply->vps), msg_auth);

	/* add any rad_vps to request */
	if (reply->rad_vps) {
		pairadd(&(request->reply->vps), reply->rad_vps);
		reply->rad_vps = NULL;
	}

	/* Set request reply code */
	switch(reply->code) {
		case PW_EAP_SUCCESS:
			request->reply->code = PW_AUTHENTICATION_ACK;
			break;
		case PW_EAP_FAILURE:
			request->reply->code = PW_AUTHENTICATION_REJECT;
			break;
		case PW_EAP_REQUEST:
			request->reply->code = PW_ACCESS_CHALLENGE;
			break;
		case PW_EAP_RESPONSE:
		default:
			/* Should never enter here */
			radlog(L_DBG, "rlm_eap: reply code is wrong");
	}
	if (eap_packet) free(eap_packet);
	return 0;
}

/*
 * Radius criteria, EAP-Message is invalid without Message-Authenticator
 * For EAP_START, send Access-Challenge with EAP Identity request.
 */
int eap_start(REQUEST *request)
{
	VALUE_PAIR *eap_msg;
	EAP_DS *eapstart;

        eap_msg = pairfind(request->packet->vps, PW_EAP_MESSAGE);
        if (eap_msg == NULL) {
		radlog(L_ERR, "rlm_eap: EAP-Message not found");
		return EAP_NOOP;
	}

	/*
	 * FIXME: This check is now not required here, as the main code handles this
        if (pairfind(request->packet->vps, PW_MESSAGE_AUTHENTICATOR) == NULL) {
		radlog(L_ERR, "rlm_eap: EAP-Message without Message-Authenticator is Invalid");
		return EAP_NOOP;
	}
	 */
	
        if (eap_msg->length != EAP_START) {
		return EAP_NOTFOUND;
	}

	radlog(L_INFO, "rlm_eap: Got EAP_START message");
	if ((eapstart = eap_ds_alloc()) == NULL) {
		return EAP_FAIL;
	}
	eapstart->request->code = PW_EAP_REQUEST;
	eapstart->request->type = PW_EAP_IDENTITY;

	compose(request, eapstart->request);

	eap_ds_free(&eapstart);
	return EAP_FOUND;
}

/*
 * compose EAP FAILURE packet in EAP-Message
 */
void eap_fail(REQUEST *request, EAP_PACKET *reply)
{

	reply->code = PW_EAP_FAILURE;
	compose(request, reply);
}

/*
 * compose EAP SUCCESS packet in EAP-Message
 */
void eap_success(REQUEST *request, EAP_PACKET *reply)
{

	reply->code = PW_EAP_SUCCESS;
	compose(request, reply);
}

/*
 * Call the appropriate handle with the right eap_type.
 */
int eap_type_handle(int eap_type, operation_t action, EAP_TYPES *type_list, EAP_DS *eap_ds, EAP_DS *req)
{
	EAP_TYPES *atype;

	atype = find_type(&type_list, eap_type);
	if (!atype) {
		radlog(L_INFO, "rlm_eap: Unsupported EAP_TYPE %d", 
			eap_ds->response->type);
		return 0;
	}

	radlog(L_INFO, "rlm_eap: processing type %s", atype->typename);

	switch (action) {
	case INITIATE:
		if (!atype->type->initiate(atype->type_stuff, eap_ds))
			return 0;
		break;
	case AUTHENTICATE:
		/*
		 * when it returns, eap_ds->reply is expected to have complete info
		 */
		if (!atype->type->authenticate(atype->type_stuff, eap_ds, (void *)req))
			return 0;
		break;
	default:
		/* Should never enter here */
		radlog(L_DBG, "rlm_eap: Invalid operation  on eap_type");
		break;
	}
	return 1;
}

int process_eap(EAP_TYPES *type_list, EAP_DS *eap_ds, EAP_DS *req)
{
	EAP_TYPES *atype;
	atype = find_type(&type_list, eap_ds->response->type);
	if (!atype) {
		radlog(L_INFO, "rlm_eap: Unsupported EAP_TYPE %d", 
			eap_ds->response->type);
		return 0;
	}

	radlog(L_INFO, "rlm_eap: processing type %s", atype->typename);
	if (!atype->type->authenticate(atype->type_stuff, eap_ds, (void *)req))
		return 0;

	return 1;
}

/*
 * Based on TYPE, call the appropriate EAP-type handler
 * currently it defaults to MD5-type
 */
int select_eap_type(EAP_LIST **list, EAP_TYPES *type_list, EAP_DS *eap_ds, char *conftype)
{
	EAP_LIST *item = NULL;
	int eaptype, i;

	eaptype = 0;
	for (i = PW_EAP_MAX_TYPES; i > 0; i--) {
		if (!strcmp(conftype, eap_types[i])) {
			eaptype = i;
			break;
		}
	}
	if (eaptype == 0) {
		radlog(L_ERR, "rlm_eap: Configured EAP_TYPE is not supported");
	}

        switch(eap_ds->response->type) {
        case PW_EAP_IDENTITY:
		if (eap_type_handle(eaptype, INITIATE, type_list, eap_ds, NULL) == 0)
			return EAP_INVALID;
                break;

        case PW_EAP_NAK:
                /*
		 * It is invalid to request identity, notification & nak in nak
		 */
                if ((eap_ds->response->typedata != NULL) &&
                        (eap_ds->response->typedata[0] < PW_EAP_MD5)) {
                        return EAP_INVALID;
                }
		switch (eap_ds->response->typedata[0]) {
		case PW_EAP_MD5:
		case PW_EAP_TLS:
			/*
			 * eap-type specified in typdata is supported
			 */
			if (eap_type_handle(eap_ds->response->typedata[0],
				INITIATE, type_list, eap_ds, NULL) == 0)
				return EAP_INVALID;
			break;
		default :
			/*
			 * Unsupported type, default to configured one.
			 * or rather reject it
			eap_ds->request->code = PW_EAP_FAILURE;
			 */
			if (eap_type_handle(eaptype, INITIATE, type_list, eap_ds, NULL) == 0)
				return EAP_INVALID;
			break;
		}
		break;
        case PW_EAP_MD5:
        case PW_EAP_OTP:
        case PW_EAP_GTC:
        case PW_EAP_TLS:
        default:
		radlog(L_INFO, "rlm_eap: EAP_TYPE - %s",
			eap_types[eap_ds->response->type]);
		item = is_reply(*list, eap_ds);
                if (eap_type_handle(eap_ds->response->type, AUTHENTICATE, 
			type_list, eap_ds, (item?item->eap_ds:NULL)) == 0) {
                        return EAP_INVALID;
                }
		if (item) remove_item(list, item);
		break;
        }
	return EAP_OK;
}

/*
 * Radius handles retransmissions and duplicates
 * so just figure out if we got a reply or not
 * We send EAP-Request and receive EAP-response,
 * so we expect back the same id that we sent in EAP-request

 * HELP: Proxy "State" attribute can also be used to 
 * identify the reply when sent in challenge 
 * to overcome the limitation of 256.
 */
EAP_LIST *is_reply(EAP_LIST *list, EAP_DS *eap_ds)
{
	EAP_LIST *node;
	node = list;
	
        while (node) {
                /*
                 * Reply is identified by same IDs and Usernames.
                 */
                if ((node->eap_ds->request->id == eap_ds->response->id) &&
                        (memcmp(node->eap_ds->username->strvalue,
                                eap_ds->username->strvalue,
                                eap_ds->username->length) == 0)) {
                         if ((eap_ds->response->code == PW_EAP_RESPONSE) &&
                                (node->eap_ds->request->code == PW_EAP_REQUEST)) {
                                radlog(L_INFO, "rlm_eap: Received response to previous request sent");
				return node;
			}
		}
                node = node->next;
	}
	return NULL;
}

/*
 * Radius handles retransmissions and duplicates
 * if needed, we can use this function

 * probably we need a finished flag in auth and should 
 * not delete after processing the response.
 */
int is_duplicate(EAP_LIST *list, EAP_DS *eap_ds)
{
	EAP_LIST *node;
	node = list;
	
        while (node) {
                /*
                 * Duplicates are identified by the same IDs and Usernames.
                 */
                if ((node->eap_ds->request->id == eap_ds->response->id) &&
                        (memcmp(node->eap_ds->username->strvalue,
                                eap_ds->username->strvalue,
                                eap_ds->username->length) == 0)) {
                        radlog(L_INFO, "rlm_eap: Received duplicate packet discard it");
			return TRUE;
		}
                node = node->next;
	}
	return FALSE;
}
