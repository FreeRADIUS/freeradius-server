/*
 * peap.c  contains the interfaces that are called from eap
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
 *   Copyright 2003 Alan DeKok <aland@freeradius.org>
 */
#include "eap_tls.h"
#include "eap_peap.h"

/*
 *	Send protected EAP-Failure
 *
 *       Result-TLV = Failure
 */
static int eappeap_failure(EAP_HANDLER *handler, tls_session_t *tls_session)
{
	uint8_t tlv_packet[11];

	DEBUG2("  rlm_eap_peap: FAILURE");

	tlv_packet[0] = PW_EAP_REQUEST;
	tlv_packet[1] = handler->eap_ds->response->id +1;
	tlv_packet[2] = 0;
	tlv_packet[3] = 11;	/* length of this packet */
	tlv_packet[4] = PW_EAP_TLV;
	tlv_packet[5] = 0x80;
	tlv_packet[6] = EAP_TLV_ACK_RESULT;
	tlv_packet[7] = 0;
	tlv_packet[8] = 2;	/* length of the data portion */
	tlv_packet[9] = 0;
	tlv_packet[10] = EAP_TLV_FAILURE;

	record_plus(&tls_session->clean_in, tlv_packet, 11);

	/*
	 *	FIXME: Check the return code.
	 */
	tls_handshake_send(tls_session);
	record_init(&tls_session->clean_in);

	return 1;
}


/*
 *	Send protected EAP-Success
 *
 *       Result-TLV = Success
 */
static int eappeap_success(EAP_HANDLER *handler, tls_session_t *tls_session)
{
	uint8_t tlv_packet[11];

	DEBUG2("  rlm_eap_peap: SUCCESS");

	tlv_packet[0] = PW_EAP_REQUEST;
	tlv_packet[1] = handler->eap_ds->response->id +1;
	tlv_packet[2] = 0;
	tlv_packet[3] = 11;	/* length of this packet */
	tlv_packet[4] = PW_EAP_TLV;
	tlv_packet[5] = 0x80;	/* mandatory AVP */
	tlv_packet[6] = EAP_TLV_ACK_RESULT;
	tlv_packet[7] = 0;
	tlv_packet[8] = 2;	/* length of the data portion */
	tlv_packet[9] = 0;
	tlv_packet[10] = EAP_TLV_SUCCESS;

	record_plus(&tls_session->clean_in, tlv_packet, 11);

	/*
	 *	FIXME: Check the return code.
	 */
	tls_handshake_send(tls_session);
	record_init(&tls_session->clean_in);

	return 1;
}


/*
 *	Verify the tunneled EAP message.
 */
static int eapmessage_verify(const uint8_t *data, unsigned int data_len)
{
	const eap_packet_t *eap_packet = (const eap_packet_t *) data;
	uint8_t eap_type;
	char identity[256];

	if (!data || (data_len <= 1)) {
		return 0;
	}

	eap_type = *data;
	switch (eap_type) {
	case PW_EAP_IDENTITY:
		memcpy(identity, data + 1, data_len - 1);
		identity[data_len - 1] = '\0';
		DEBUG2("  rlm_eap_peap: Identity - %s", identity);
		return 1;
		break;
		
		/*
		 *	If the first byte of the packet is
		 *	EAP-Response, and the EAP data is a TLV,
		 *	then it looks OK...
		 */
	case PW_EAP_RESPONSE:
		if (eap_packet->data[0] == PW_EAP_TLV) {
			DEBUG2("  rlm_eap_peap: Received EAP-TLV response.");
			return 1;
		}
		DEBUG2("  rlm_eap_peap: Got something weird.");
		break;


		/*
		 *	We normally do Microsoft MS-CHAPv2 (26), versus
		 *	Cisco MS-CHAPv2 (29).
		 */
	case PW_EAP_MSCHAPV2:
	default:
		DEBUG2("  rlm_eap_peap: EAP type %d", eap_type);
		return 1;
		break;
	}

	return 0;
}

/*
 *	Convert a pseudo-EAP packet to a list of VALUE_PAIR's.
 */
static VALUE_PAIR *eap2vp(EAP_DS *eap_ds,
			  const uint8_t *data, unsigned int data_len)
{
	VALUE_PAIR *vp = NULL;

	/*
	 *	Sanity check this...
	 */
	if (data_len + EAP_HEADER_LEN > MAX_STRING_LEN) {
		radlog(L_ERR, "rlm_eap_peap: EAP Response packet is too large.  Code must be fixed to handle this.");
		return NULL;
	}

	vp = paircreate(PW_EAP_MESSAGE, PW_TYPE_OCTETS);
	if (!vp) {
		DEBUG2("  rlm_eap_peap: Failure in creating VP");
		return NULL;
	}

	/*
	 *	Hand-build an EAP packet from the crap in PEAP version 0.
	 */
	vp->strvalue[0] = PW_EAP_RESPONSE;
	vp->strvalue[1] = eap_ds->response->id;
	vp->strvalue[2] = 0;
	vp->strvalue[3] = EAP_HEADER_LEN + data_len;

	memcpy(vp->strvalue + EAP_HEADER_LEN, data, data_len);
	vp->length = EAP_HEADER_LEN + data_len;

	return vp;
}


/*
 *	Convert a list of VALUE_PAIR's to an EAP packet, through the
 *	simple expedient of dumping the EAP message
 */
static int vp2eap(tls_session_t *tls_session, VALUE_PAIR *vp)
{
	if (vp->next != NULL) {
		radlog(L_ERR, "rlm_eap_peap: EAP Request packet is too large.  Code must be fixed to handle this.");
		return 0;
	}

	/*
	 *	Skip the id, code, and length.  Just write the EAP
	 *	type & data to the client.
	 */
#ifndef NDEBUG
	if (debug_flag > 2) {
		int i;
		int total = vp->length - 4;
		
		if (debug_flag > 0) for (i = 0; i < total; i++) {
			if ((i & 0x0f) == 0) printf("  PEAP tunnel data out %04x: ", i);
			
			printf("%02x ", vp->strvalue[i + 4]);
			
			if ((i & 0x0f) == 0x0f) printf("\n");
		}
		if ((total & 0x0f) != 0) printf("\n");
	}
#endif

	/*
	 *	Send the EAP data, WITHOUT the header.
	 */
#if 1
	record_plus(&tls_session->clean_in, vp->strvalue + EAP_HEADER_LEN,
		vp->length - EAP_HEADER_LEN);
#else
	record_plus(&tls_session->clean_in, vp->strvalue, vp->length);
#endif
	tls_handshake_send(tls_session);
	record_init(&tls_session->clean_in);

	return 1;
}


/*
 *	See if there's a TLV in the response.
 */
static int eappeap_check_tlv(const uint8_t *data)
{
	const eap_packet_t *eap_packet = (const eap_packet_t *) data;

	/*
	 *	Look for success or failure.
	 */
	if ((eap_packet->code == PW_EAP_RESPONSE) &&
	    (eap_packet->data[0] == PW_EAP_TLV)) {
		if (data[10] == EAP_TLV_SUCCESS) {
			return 1;
		}

		if (data[10] == EAP_TLV_FAILURE) {
			DEBUG2("  rlm_eap_peap: Client rejected our response.  The password is probably incorrect.");
			return 0;
		}
	}

	return 0;
}

/*
 *	Process the pseudo-EAP contents of the tunneled data.
 */
int eappeap_process(EAP_HANDLER *handler, tls_session_t *tls_session)
{
	int err;
	peap_tunnel_t *t = tls_session->opaque;
	REQUEST *fake;
	VALUE_PAIR *vp;
	int rcode = RLM_MODULE_REJECT;
	const uint8_t *data;
	unsigned int data_len;
	unsigned char buffer[1024];
#ifndef NDEBUG
	int i;
#endif

	REQUEST *request = handler->request;
	EAP_DS *eap_ds = handler->eap_ds;

	/*
	 *	Grab the dirty data, and copy it to our buffer.
	 *
	 *	I *really* don't like these 'record_t' things...
	 */
	data_len = record_minus(&tls_session->dirty_in, buffer, sizeof(buffer));
	data = buffer;

	/*
	 *	Write the data from the dirty buffer (i.e. packet
	 *	data) into the buffer which we will give to SSL for
	 *	decoding.
	 *
	 *	Some of this code COULD technically go into the TLS
	 *	module, in eaptls_process(), where it returns EAPTLS_OK.
	 *
	 *	Similarly, the writing of data to the SSL context could
	 *	go there, too...
	 */
	BIO_write(tls_session->into_ssl, buffer, data_len);
	record_init(&tls_session->clean_out);

	/*
	 *	Read (and decrypt) the tunneled data from the SSL session,
	 *	and put it into the decrypted data buffer.
	 */
	err = SSL_read(tls_session->ssl, tls_session->clean_out.data,
		       sizeof(tls_session->clean_out.data));
	if (err < 0) {
		/*
		 *	FIXME: Call SSL_get_error() to see what went
		 *	wrong.
		 */
		radlog(L_INFO, "rlm_eap_peap: SSL_read Error");
		return RLM_MODULE_REJECT;
	}

	/*
	 *	If there's no data, maybe this is an ACK to an
	 *	MS-CHAP2-Success.
	 */	
	if (err == 0) {
		/*
		 *	FIXME: Call SSL_get_error() to see what went
		 *	wrong.
		 */
		radlog(L_INFO, "rlm_eap_peap: No data inside of the tunnel.");
		return RLM_MODULE_REJECT;
	}
 
	data_len = tls_session->clean_out.used = err;
	data = tls_session->clean_out.data;

#ifndef NDEBUG
	if (debug_flag > 2) for (i = 0; i < data_len; i++) {
		if ((i & 0x0f) == 0) printf("  PEAP tunnel data in %04x: ", i);
		
		printf("%02x ", data[i]);
		
		if ((i & 0x0f) == 0x0f) printf("\n");
	}
	if ((data_len & 0x0f) != 0) printf("\n");
#endif

	if (!eapmessage_verify(data, data_len)) {
		return RLM_MODULE_REJECT;
	}

	DEBUG2("  rlm_eap_peap: Tunneled data is valid.");

	/*
	 *	If we authenticated the user, then it's OK.
	 */
	if (t->status == PEAP_STATUS_SENT_TLV_SUCCESS) {
		if (eappeap_check_tlv(data)) {
			DEBUG2("  rlm_eap_peap: Success");
			return RLM_MODULE_OK;
		}

		return RLM_MODULE_REJECT;

	} else if (t->status == PEAP_STATUS_SENT_TLV_FAILURE) {
		DEBUG2("  rlm_eap_peap:  Had sent TLV failure, rejecting.");
		return RLM_MODULE_REJECT;
	}

	fake = request_alloc_fake(request);

	rad_assert(fake->packet->vps == NULL);

	fake->packet->vps = eap2vp(eap_ds, data, data_len);
	if (!fake->packet->vps) {
		DEBUG2("  rlm_eap_peap: Unable to convert tunneled EAP packet to internal server data structures");
		return PW_AUTHENTICATION_REJECT;
	}

#ifndef NDEBUG
	if (debug_flag > 0) {
	  printf("  PEAP: Got tunneled EAP-Message\n");

	  for (vp = fake->packet->vps; vp != NULL; vp = vp->next) {
	    putchar('\t');vp_print(stdout, vp);putchar('\n');
	  }
	}
#endif

	/*
	 *	Tell the request that it's a fake one.
	 */
	vp = pairmake("Freeradius-Proxied-To", "127.0.0.1", T_OP_EQ);
	if (vp) {
		pairadd(&fake->packet->vps, vp);
	}

	/*
	 *	Update other items in the REQUEST data structure.
	 */
	if (!t->username) {
		if ((data[0] == PW_EAP_IDENTITY) && (data_len > 1)) {
			t->username = pairmake("User-Name", "", T_OP_EQ);
			rad_assert(t->username != NULL);
				
			memcpy(t->username->strvalue, data+1, data_len - 1);
			t->username->length = data_len -1;
			t->username->strvalue[t->username->length] = 0;
			DEBUG2("  PEAP: Got tunneled identity of %s", t->username->strvalue);

			/*
			 *	If there's a default EAP type,
			 *	set it here.
			 */
			if (t->default_eap_type != 0) {
			  DEBUG2("  PEAP: Setting default EAP type for tunneled EAP session.");
			  vp = pairmake("EAP-Type", "0", T_OP_EQ);
			  vp->lvalue = t->default_eap_type;
			  pairadd(&fake->config_items, vp);
			}
		}
	} /* else there WAS a t->username */

	if (t->username) {
		vp = paircopy(t->username);
		pairadd(&fake->packet->vps, vp);
		fake->username = pairfind(fake->packet->vps, PW_USER_NAME);
	}

	/*
	 *	Add the State attribute, too, if it exists.
	 */
	if (t->state) {
		DEBUG2("  PEAP: Adding old state with %02x %02x",
		       t->state->strvalue[0], t->state->strvalue[1]);
		vp = paircopy(t->state);
		if (vp) pairadd(&fake->packet->vps, vp);
	}

	/*
	 *	If this is set, we copy SOME of the request attributes
	 *	from outside of the tunnel to inside of the tunnel.
	 *
	 *	We copy ONLY those attributes which do NOT already
	 *	exist in the tunneled request.
	 *
	 *	This code is copied from ../rlm_eap_ttls/ttls.c
	 */
	if (t->copy_request_to_tunnel) {
		VALUE_PAIR *copy;

		for (vp = request->packet->vps; vp != NULL; vp = vp->next) {
			/*
			 *	The attribute is a server-side thingy,
			 *	don't copy it.
			 */
			if ((vp->attribute > 255) &&
			    (((vp->attribute >> 16) & 0xffff) == 0)) {
				continue;
			}

			/*
			 *	The outside attribute is already in the
			 *	tunnel, don't copy it.
			 *
			 *	This works for BOTH attributes which
			 *	are originally in the tunneled request,
			 *	AND attributes which are copied there
			 *	from below.
			 */
			if (pairfind(fake->packet->vps, vp->attribute)) {
				continue;
			}

			/*
			 *	Some attributes are handled specially.
			 */
			switch (vp->attribute) {
				/*
				 *	NEVER copy Message-Authenticator,
				 *	EAP-Message, or State.  They're
				 *	only for outside of the tunnel.
				 */
			case PW_USER_NAME:
			case PW_USER_PASSWORD:
			case PW_CHAP_PASSWORD:
			case PW_CHAP_CHALLENGE:
			case PW_PROXY_STATE:
			case PW_MESSAGE_AUTHENTICATOR:
			case PW_EAP_MESSAGE:
			case PW_STATE:
				continue;
				break;

				/*
				 *	By default, copy it over.
				 */
			default:
				break;
			}

			/*
			 *	Don't copy from the head, we've already
			 *	checked it.
			 */
			copy = paircopy2(vp, vp->attribute);
			pairadd(&fake->packet->vps, copy);
		}
	}

#ifndef NDEBUG
	if (debug_flag > 0) {
		printf("  PEAP: Sending tunneled request\n");
		
		for (vp = fake->packet->vps; vp != NULL; vp = vp->next) {
			putchar('\t');vp_print(stdout, vp);putchar('\n');
		}
	}
#endif

	/*
	 *	Call authentication recursively, which will
	 *	do PAP, CHAP, MS-CHAP, etc.
	 */
	rad_authenticate(fake);

	/*
	 *	Note that we don't do *anything* with the reply
	 *	attributes.
	 */
#ifndef NDEBUG
	if (debug_flag > 0) {
		printf("  PEAP: Got tunneled reply RADIUS code %d\n",
		 fake->reply->code);
		
		for (vp = fake->reply->vps; vp != NULL; vp = vp->next) {
			putchar('\t');vp_print(stdout, vp);putchar('\n');
		}
	}
#endif

	switch (fake->reply->code) {
	case PW_AUTHENTICATION_ACK:
		DEBUG2("  PEAP: Tunneled authentication was successful.");
		t->status = PEAP_STATUS_SENT_TLV_SUCCESS;
		eappeap_success(handler, tls_session);
		rcode = RLM_MODULE_HANDLED;
		
		/*
		 *	If we've been told to use the attributes from
		 *	the reply, then do so.
		 *
		 *	WARNING: This may leak information about the
		 *	tunneled user!
		 */
		if (t->use_tunneled_reply) {
			pairadd(&request->reply->vps, fake->reply->vps);
			fake->reply->vps = NULL;
		}
		break;

	case PW_AUTHENTICATION_REJECT:
		DEBUG2("  PEAP: Tunneled authentication was rejected.");
		t->status = PEAP_STATUS_SENT_TLV_FAILURE;
		eappeap_failure(handler, tls_session);
		rcode = RLM_MODULE_HANDLED;
		break;

	case PW_ACCESS_CHALLENGE:
		DEBUG2("  PEAP: Got tunneled Access-Challenge");

		/*
		 *	Keep the State attribute, if necessary.
		 *
		 *	Get rid of the old State, too.
		 */
		pairfree(&t->state);
		pairmove2(&t->state, &fake->reply->vps, PW_STATE);

		/*
		 *	We should really be a bit smarter about this,
		 *	and move over only those attributes which
		 *	are relevant to the authentication request,
		 *	but that's a lot more work, and this "dumb"
		 *	method works in 99.9% of the situations.
		 */
		vp = NULL;
		pairmove2(&vp, &fake->reply->vps, PW_EAP_MESSAGE);

		/*
		 *	There MUST be a Reply-Message in the challenge,
		 *	which we tunnel back to the client.
		 *
		 *	If there isn't one in the reply VP's, then
		 *	we MUST create one, with an empty string as
		 *	it's value.
		 */
		pairmove2(&vp, &fake->reply->vps, PW_REPLY_MESSAGE);

		/*
		 *	Handle the ACK, by tunneling any necessary reply
		 *	VP's back to the client.
		 */
		if (vp) {
			vp2eap(tls_session, vp);
			pairfree(&vp);
		}
		rcode = RLM_MODULE_HANDLED;
		break;


	default:
		DEBUG2("  PEAP: Unknown RADIUS packet type %d: rejecting tunneled user", fake->reply->code);
		rcode = RLM_MODULE_REJECT;
		break;
	}
	
	request_free(&fake);
	
	return rcode;
}

