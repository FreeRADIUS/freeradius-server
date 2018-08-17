/*
 * rlm_eap_ttls.c  contains the interfaces that are called from eap
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
 *   @copyright 2003 Alan DeKok <aland@freeradius.org>
 *   @copyright 2006 The FreeRADIUS server project
 */

RCSID("$Id$")

#include "eap_ttls.h"
#include "eap_chbind.h"


#define FR_DIAMETER_AVP_FLAG_VENDOR	0x80
#define FR_DIAMETER_AVP_FLAG_MANDATORY	0x40
/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           AVP Code                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |V M r r r r r r|                  AVP Length                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                        Vendor-ID (opt)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Data ...
 *   +-+-+-+-+-+-+-+-+
 */

/*
 *	Verify that the diameter packet is valid.
 */
static int diameter_verify(REQUEST *request, uint8_t const *data, unsigned int data_len)
{
	uint32_t attr;
	uint32_t length;
	unsigned int hdr_len;
	unsigned int remaining = data_len;

	while (remaining > 0) {
		hdr_len = 12;

		if (remaining < hdr_len) {
		  RDEBUG2("Diameter attribute is too small (%u) to contain a Diameter header", remaining);
			return 0;
		}

		memcpy(&attr, data, sizeof(attr));
		attr = ntohl(attr);
		memcpy(&length, data + 4, sizeof(length));
		length = ntohl(length);

		if ((data[4] & 0x80) != 0) {
			if (remaining < 16) {
				RDEBUG2("Diameter attribute is too small to contain a Diameter header with Vendor-Id");
				return 0;
			}

			hdr_len = 16;
		}

		/*
		 *	Get the length.  If it's too big, die.
		 */
		length &= 0x00ffffff;

		/*
		 *	Too short or too long is bad.
		 */
		if (length <= (hdr_len - 4)) {
			RDEBUG2("Tunneled attribute %u is too short (%u < %u) to contain anything useful.", attr,
				length, hdr_len);
			return 0;
		}

		if (length > remaining) {
			RDEBUG2("Tunneled attribute %u is longer than room remaining in the packet (%u > %u).", attr,
				length, remaining);
			return 0;
		}

		/*
		 *	Check for broken implementations, which don't
		 *	pad the AVP to a 4-octet boundary.
		 */
		if (remaining == length) break;

		/*
		 *	The length does NOT include the padding, so
		 *	we've got to account for it here by rounding up
		 *	to the nearest 4-byte boundary.
		 */
		length += 0x03;
		length &= ~0x03;

		/*
		 *	If the rest of the diameter packet is larger than
		 *	this attribute, continue.
		 *
		 *	Otherwise, if the attribute over-flows the end
		 *	of the packet, die.
		 */
		if (remaining < length) {
			REDEBUG2("Diameter attribute overflows packet!");
			return 0;
		}

		/*
		 *	remaining > length, continue.
		 */
		remaining -= length;
		data += length;
	}

	/*
	 *	We got this far.  It looks OK.
	 */
	return 1;
}


/*
 *	Convert diameter attributes to our VALUE_PAIR's
 */
static ssize_t eap_ttls_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *parent,
				    uint8_t const *data, size_t data_len,
				    void *decoder_ctx)
{
	uint8_t const		*p = data, *end = p + data_len;

	VALUE_PAIR		*vp = NULL;
	SSL			*ssl = decoder_ctx;

	while (p < end) {
		ssize_t			ret;
		uint32_t		attr, vendor, length, value_len;
		uint8_t			flags;
		fr_dict_attr_t const	*our_parent = parent;

		if ((end - p) < 8) {
			fr_strerror_printf("Malformed diameter VPs.  Needed at least 8 bytes, got %zu bytes", end - p);
		error:
			fr_cursor_free_list(cursor);
			return -1;
		}

		attr = fr_ntoh32_bin(p);
		p += 4;

		flags = p[0];
		p++;

		value_len = length = fr_ntoh24_bin(p);	/* Yes, that is a 24 bit length field */
		p += 3;

		value_len -= 8;	/* -= 8 for AVP code (4), flags (1), AVP length (3) */

		MEM(vp = fr_pair_alloc(ctx));

		/*
		 *	Do we have a vendor field?
		 */
		if (flags & FR_DIAMETER_AVP_FLAG_VENDOR) {
			vendor = fr_ntoh32_bin(p);
			p += 4;
			value_len -= 4;	/* -= 4 for the vendor ID field */

			our_parent = fr_dict_vendor_attr_by_num(attr_vendor_specific, vendor);
			if (!our_parent) {
				if (flags & FR_DIAMETER_AVP_FLAG_MANDATORY) {
					fr_strerror_printf("Mandatory bit set and no vendor %u found", vendor);
					talloc_free(vp);
					goto error;
				}

				MEM(vp->da = fr_dict_unknown_afrom_fields(vp, attr_vendor_specific, vendor, attr));
				goto do_value;
			}
		} else {
			our_parent = fr_dict_root(fr_dict_internal);
		}

		/*
		 *	Is the attribute known?
		 */
		vp->da = fr_dict_attr_child_by_num(our_parent, attr);
		if (!vp->da) {
			if (flags & FR_DIAMETER_AVP_FLAG_MANDATORY) {
				fr_strerror_printf("Mandatory bit set and no attribute %u defined", attr);
				talloc_free(vp);
				goto error;
			}
			MEM(vp->da = fr_dict_unknown_afrom_fields(vp, parent, 0, attr));
		}

do_value:
		ret = fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, p, value_len, true);
		if (ret < 0) {
			/*
			 *	Mandatory bit is set, and the attribute
			 *	is malformed. Fail.
			 */
			if (flags & FR_DIAMETER_AVP_FLAG_MANDATORY) {
				fr_strerror_printf("Mandatory bit is set and attribute is malformed");
				talloc_free(vp);
				goto error;
			}

			fr_pair_to_unknown(vp);
			fr_pair_value_memcpy(vp, p, value_len);
		}

		/*
		 *	The length does NOT include the padding, so
		 *	we've got to account for it here by rounding up
		 *	to the nearest 4-byte boundary.
		 */
		p += (value_len + 0x03) & ~0x03;
		fr_cursor_append(cursor, vp);

		if (vp->da->flags.is_unknown) continue;

		/*
		 *	Ensure that the client is using the correct challenge.
		 *
		 *	This weirdness is to protect against against replay
		 *	attacks, where anyone observing the CHAP exchange could
		 *	pose as that user, by simply choosing to use the same
		 *	challenge.
		 *	By using a challenge based on information from the
		 *	current session, we can guarantee that the client is
		 *	not *choosing* a challenge. We're a little forgiving in
		 *	that we have loose checks on the length, and we do NOT
		 *	check the Id (first octet of the response to the
		 *	challenge) But if the client gets the challenge correct,
		 *	we're not too worried about the Id.
		 */
		if ((vp->da == attr_chap_challenge) || (vp->da == attr_ms_chap_challenge)) {
			uint8_t	challenge[16];
			uint8_t	scratch[16];

			if ((vp->vp_length < 8) || (vp->vp_length > 16)) {
				fr_strerror_printf("Tunneled challenge has invalid length");
				goto error;
			}

			eap_tls_gen_challenge(ssl, challenge, scratch,
					      sizeof(challenge), "ttls challenge");

			if (memcmp(challenge, vp->vp_octets, vp->vp_length) != 0) {
				fr_strerror_printf("Tunneled challenge is incorrect");
				goto error;
			}
		}

		/*
		 *	Diameter pads strings (i.e. User-Password) with trailing zeros.
		 */
		if (vp->vp_type == FR_TYPE_STRING) fr_pair_value_strcpy(vp, vp->vp_strvalue);
	}

	/*
	 *	We got this far.  It looks OK.
	 */
	return p - data;
}

/*
 *	Convert VALUE_PAIR's to diameter attributes, and write them
 *	to an SSL session.
 *
 *	The ONLY VALUE_PAIR's which may be passed to this function
 *	are ones which can go inside of a RADIUS (i.e. diameter)
 *	packet.  So no server-configuration attributes, or the like.
 */
static int vp2diameter(REQUEST *request, tls_session_t *tls_session, VALUE_PAIR *first)
{
	/*
	 *	RADIUS packets are no more than 4k in size, so if
	 *	we've got more than 4k of data to write, it's very
	 *	bad.
	 */
	uint8_t		buffer[4096];
	uint8_t		*p;
	uint32_t	attr;
	uint32_t	length;
	uint32_t	vendor;
	size_t		total;
	uint64_t	attr64;
	VALUE_PAIR	*vp;
	fr_cursor_t	cursor;

	p = buffer;
	total = 0;

	for (vp = fr_cursor_init(&cursor, &first);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	Too much data: die.
		 */
		if ((total + vp->vp_length + 12) >= sizeof(buffer)) {
			RDEBUG2("output buffer is full!");
			return 0;
		}

		/*
		 *	Hmm... we don't group multiple EAP-Messages
		 *	together.  Maybe we should...
		 */

		length = vp->vp_length;
		vendor = fr_dict_vendor_num_by_da(vp->da);
		if (vendor != 0) {
			attr = vp->da->attr & 0xffff;
			length |= ((uint32_t)1 << 31);
		} else {
			attr = vp->da->attr;
		}

		/*
		 *	Hmm... set the M bit for all attributes?
		 */
		length |= (1 << 30);

		attr = ntohl(attr);

		memcpy(p, &attr, sizeof(attr));
		p += 4;
		total += 4;

		length += 8;	/* includes 8 bytes of attr & length */

		if (vendor != 0) {
			length += 4; /* include 4 bytes of vendor */

			length = ntohl(length);
			memcpy(p, &length, sizeof(length));
			p += 4;
			total += 4;

			vendor = ntohl(vendor);
			memcpy(p, &vendor, sizeof(vendor));
			p += 4;
			total += 4;
		} else {
			length = ntohl(length);
			memcpy(p, &length, sizeof(length));
			p += 4;
			total += 4;
		}

		switch (vp->vp_type) {
		case FR_TYPE_UINT32:
		case FR_TYPE_DATE:
			attr = htonl(vp->vp_uint32); /* stored in host order */
			memcpy(p, &attr, sizeof(attr));
			length = 4;
			break;

		case FR_TYPE_UINT64:
			attr64 = htonll(vp->vp_uint64); /* stored in host order */
			memcpy(p, &attr64, sizeof(attr64));
			length = 8;
			break;

		case FR_TYPE_IPV4_ADDR:
			memcpy(p, &vp->vp_ipv4addr, 4); /* network order */
			length = 4;
			break;

		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
		default:
			memcpy(p, vp->vp_strvalue, vp->vp_length);
			length = vp->vp_length;
			break;
		}

		/*
		 *	Skip to the end of the data.
		 */
		p += length;
		total += length;

		/*
		 *	Align the data to a multiple of 4 bytes.
		 */
		if ((total & 0x03) != 0) {
			size_t i;

			length = 4 - (total & 0x03);
			for (i = 0; i < length; i++) {
				*p = '\0';
				p++;
				total++;
			}
		}
	} /* loop over the VP's to write. */

	/*
	 *	Write the data in the buffer to the SSL session.
	 */
	if (total > 0) {
		(tls_session->record_from_buff)(&tls_session->clean_in, buffer, total);

		/*
		 *	FIXME: Check the return code.
		 */
		tls_session_send(request, tls_session);
	}

	/*
	 *	Everything's OK.
	 */
	return 1;
}

/*
 *	Use a reply packet to determine what to do.
 */
static rlm_rcode_t CC_HINT(nonnull) process_reply(NDEBUG_UNUSED eap_session_t *eap_session, tls_session_t *tls_session,
						  REQUEST *request, RADIUS_PACKET *reply)
{
	rlm_rcode_t	rcode = RLM_MODULE_REJECT;
	VALUE_PAIR	*vp, *tunnel_vps = NULL;
	fr_cursor_t	cursor;
	fr_cursor_t	to_tunnel;

	ttls_tunnel_t	*t = tls_session->opaque;

	rad_assert(eap_session->request == request);

	/*
	 *	If the response packet was Access-Accept, then
	 *	we're OK.  If not, die horribly.
	 *
	 *	FIXME: Take MS-CHAP2-Success attribute, and
	 *	tunnel it back to the client, to authenticate
	 *	ourselves to the client.
	 *
	 *	FIXME: If we have an Access-Challenge, then
	 *	the Reply-Message is tunneled back to the client.
	 *
	 *	FIXME: If we have an EAP-Message, then that message
	 *	must be tunneled back to the client.
	 *
	 *	FIXME: If we have an Access-Challenge with a State
	 *	attribute, then do we tunnel that to the client, or
	 *	keep track of it ourselves?
	 *
	 *	FIXME: EAP-Messages can only start with 'identity',
	 *	NOT 'eap start', so we should check for that....
	 */
	switch (reply->code) {
	case FR_CODE_ACCESS_ACCEPT:
	{
		RDEBUG("Got tunneled Access-Accept");

		fr_cursor_init(&to_tunnel, &tunnel_vps);
		rcode = RLM_MODULE_OK;

		/*
		 *	Copy what we need into the TTLS tunnel and leave
		 *	the rest to be cleaned up.
		 */
		for (vp = fr_cursor_init(&cursor, &reply->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			if (vp->da == attr_ms_chap2_success) {
				RDEBUG("Got MS-CHAP2-Success, tunneling it to the client in a challenge");

				rcode = RLM_MODULE_HANDLED;
				t->authenticated = true;
				fr_cursor_prepend(&to_tunnel, fr_pair_copy(tls_session, vp));
			} else if (vp->da == attr_eap_channel_binding_message) {
				rcode = RLM_MODULE_HANDLED;
				t->authenticated = true;
				fr_cursor_prepend(&to_tunnel, fr_pair_copy(tls_session, vp));
			}
		}
	}
		break;

	case FR_CODE_ACCESS_REJECT:
		RDEBUG("Got tunneled Access-Reject");
		rcode = RLM_MODULE_REJECT;
		break;

	/*
	 *	Handle Access-Challenge, but only if we
	 *	send tunneled reply data.  This is because
	 *	an Access-Challenge means that we MUST tunnel
	 *	a Reply-Message to the client.
	 */
	case FR_CODE_ACCESS_CHALLENGE:
		RDEBUG("Got tunneled Access-Challenge");

		fr_cursor_init(&to_tunnel, &tunnel_vps);

		/*
		 *	Copy what we need into the TTLS tunnel and leave
		 *	the rest to be cleaned up.
		 */
		for (vp = fr_cursor_init(&cursor, &reply->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
		     	if ((vp->da == attr_eap_message) || (vp->da == attr_reply_message)) {
		     		fr_cursor_prepend(&to_tunnel, fr_pair_copy(tls_session, vp));
		     	} else if (vp->da == attr_eap_channel_binding_message) {
				fr_cursor_prepend(&to_tunnel, fr_pair_copy(tls_session, vp));
		     	}
		}
		rcode = RLM_MODULE_HANDLED;
		break;

	default:
		RDEBUG("Unknown RADIUS packet type %d: rejecting tunneled user", reply->code);
		rcode = RLM_MODULE_INVALID;
		break;
	}


	/*
	 *	Pack any tunneled VPs and send them back
	 *	to the supplicant.
	 */
	if (tunnel_vps) {
		RDEBUG("Sending tunneled reply attributes");
		log_request_pair_list(L_DBG_LVL_2, request, tunnel_vps, NULL);

		vp2diameter(request, tls_session, tunnel_vps);
		fr_pair_list_free(&tunnel_vps);
	}

	return rcode;
}


#ifdef WITH_PROXY
/*
 *	Do post-proxy processing,
 */
static int CC_HINT(nonnull) eap_ttls_postproxy(eap_session_t *eap_session, void *data)
{
	int rcode;
	tls_session_t *tls_session = talloc_get_type_abort(data, tls_session_t);
	REQUEST *fake, *request = eap_session->request;

	RDEBUG("Passing reply from proxy back into the tunnel");

	/*
	 *	If there was a fake request associated with the proxied
	 *	request, do more processing of it.
	 */
	fake = (REQUEST *) request_data_get(eap_session->request,
					    eap_session->request->proxy,
					    REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK);

	/*
	 *	Do the callback, if it exists, and if it was a success.
	 */
	if (fake && (eap_session->request->proxy->reply->code == FR_CODE_ACCESS_ACCEPT)) {
		/*
		 *	Terrible hacks.
		 */
		rad_assert(!fake->packet);
		fake->packet = talloc_steal(fake, request->proxy->packet);
		fake->packet->src_ipaddr = request->packet->src_ipaddr;
		request->proxy->packet = NULL;

		rad_assert(!fake->reply);
		fake->reply = talloc_steal(fake, request->proxy->reply);
		request->proxy->reply = NULL;

		if ((rad_debug_lvl > 0) && fr_log_fp) {
			fprintf(fr_log_fp, "server %s {\n", cf_section_name2(fake->server_cs));
		}

		/*
		 *	Perform a post-auth stage for the tunneled
		 *	session.
		 */
		fake->options &= ~RAD_REQUEST_OPTION_PROXY_EAP;
		rcode = rad_postauth(fake);
		RDEBUG2("post-auth returns %d", rcode);

		if ((rad_debug_lvl > 0) && fr_log_fp) {
			fprintf(fr_log_fp, "} # server %s\n", cf_section_name2(fake->server_cs));

			RDEBUG("Final reply from tunneled session code %d", fake->reply->code);
			log_request_pair_list(L_DBG_LVL_1, request, fake->reply->vps, NULL);
		}

		/*
		 *	Terrible hacks.
		 */
		request->proxy->packet = talloc_steal(request->proxy, fake->packet);
		fake->packet = NULL;
		request->proxy->reply = talloc_steal(request->proxy, fake->reply);
		fake->reply = NULL;

		/*
		 *	And we're done with this request.
		 */

		switch (rcode) {
		case RLM_MODULE_FAIL:
			talloc_free(fake);
			eap_tls_fail(eap_session);
			return 0;

		default:  /* Don't Do Anything */
			RDEBUG2("Got reply %d",
			       request->proxy->reply->code);
			break;
		}
	}
	talloc_free(fake);	/* robust if !fake */

	/*
	 *	Process the reply from the home server.
	 */
	rcode = process_reply(eap_session, tls_session, eap_session->request, eap_session->request->proxy->reply);

	/*
	 *	The proxy code uses the reply from the home server as
	 *	the basis for the reply to the NAS.  We don't want that,
	 *	so we toss it, after we've had our way with it.
	 */
	fr_pair_list_free(&eap_session->request->proxy->reply->vps);

	switch (rcode) {
	case RLM_MODULE_REJECT:
		RDEBUG("Reply was rejected");
		break;

	case RLM_MODULE_HANDLED:
		RDEBUG("Reply was handled");
		eap_tls_request(eap_session);
		request->proxy->reply->code = FR_CODE_ACCESS_CHALLENGE;
		return 1;

	case RLM_MODULE_OK:
		RDEBUG("Reply was OK");

		/*
		 *	Success: Automatically return MPPE keys.
		 */
		if (eap_tls_success(eap_session) < 0) return 0;
		return 1;

	default:
		RDEBUG("Reply was unknown");
		break;
	}

	eap_tls_fail(eap_session);
	return 0;
}

#endif	/* WITH_PROXY */

/*
 *	Process the "diameter" contents of the tunneled data.
 */
FR_CODE eap_ttls_process(eap_session_t *eap_session, tls_session_t *tls_session)
{
	FR_CODE			code = FR_CODE_ACCESS_REJECT;
	rlm_rcode_t		rcode;
	REQUEST			*fake = NULL;
	VALUE_PAIR		*vp = NULL;
	fr_cursor_t		cursor;
	ttls_tunnel_t		*t;
	uint8_t			const *data;
	size_t			data_len;
	REQUEST			*request = eap_session->request;
	chbind_packet_t		*chbind;

	/*
	 *	Just look at the buffer directly, without doing
	 *	record_to_buff.
	 */
	data_len = tls_session->clean_out.used;
	tls_session->clean_out.used = 0;
	data = tls_session->clean_out.data;

	t = (ttls_tunnel_t *) tls_session->opaque;

	/*
	 *	If there's no data, maybe this is an ACK to an
	 *	MS-CHAP2-Success.
	 */
	if (data_len == 0) {
		if (t->authenticated) {
			RDEBUG("Got ACK, and the user was already authenticated");
			code = FR_CODE_ACCESS_ACCEPT;
			goto finish;
		} /* else no session, no data, die. */

		/*
		 *	FIXME: Call SSL_get_error() to see what went
		 *	wrong.
		 */
		RDEBUG2("SSL_read Error");
		code = FR_CODE_ACCESS_REJECT;
		goto finish;
	}

	if (!diameter_verify(request, data, data_len)) {
		code = FR_CODE_ACCESS_REJECT;
		goto finish;
	}

	/*
	 *	Allocate a fake REQUEST structure.
	 */
	fake = request_alloc_fake(request);

	rad_assert(!fake->packet->vps);

	/*
	 *	Add the tunneled attributes to the fake request.
	 */
	fr_cursor_init(&cursor, &fake->packet->vps);
	if (eap_ttls_decode_pair(fake->packet, &cursor, fr_dict_root(fr_dict_internal),
				 data, data_len, tls_session->ssl) < 0) {
		RPEDEBUG("Decoding TTLS TLVs failed");
		code = FR_CODE_ACCESS_REJECT;
		goto finish;
	}

	/*
	 *	Tell the request that it's a fake one.
	 */
	MEM(fr_pair_add_by_da(fake->packet, &vp, &fake->packet->vps, attr_freeradius_proxied_to) >= 0);
	fr_pair_value_from_str(vp, "127.0.0.1", sizeof("127.0.0.1"), '\0', false);

	RDEBUG("Got tunneled request");
	log_request_pair_list(L_DBG_LVL_1, request, fake->packet->vps, NULL);

	/*
	 *	Update other items in the REQUEST data structure.
	 */
	fake->username = fr_pair_find_by_da(fake->packet->vps, attr_user_name, TAG_ANY);
	fake->password = fr_pair_find_by_da(fake->packet->vps, attr_user_password, TAG_ANY);

	/*
	 *	No User-Name, try to create one from stored data.
	 */
	if (!fake->username) {
		/*
		 *	No User-Name in the stored data, look for
		 *	an EAP-Identity, and pull it out of there.
		 */
		if (!t->username) {
			vp = fr_pair_find_by_da(fake->packet->vps, attr_eap_message, TAG_ANY);
			if (vp &&
			    (vp->vp_length >= EAP_HEADER_LEN + 2) &&
			    (vp->vp_strvalue[0] == FR_EAP_CODE_RESPONSE) &&
			    (vp->vp_strvalue[EAP_HEADER_LEN] == FR_EAP_IDENTITY) &&
			    (vp->vp_strvalue[EAP_HEADER_LEN + 1] != 0)) {
				/*
				 *	Create & remember a User-Name
				 */
				t->username = fr_pair_afrom_da(t, attr_user_name);
				rad_assert(t->username != NULL);
				t->username->vp_tainted = true;

				fr_pair_value_bstrncpy(t->username, vp->vp_octets + 5, vp->vp_length - 5);

				RDEBUG("Got tunneled identity of %pV", &t->username->data);
			} else {
				/*
				 *	Don't reject the request outright,
				 *	as it's permitted to do EAP without
				 *	user-name.
				 */
				RWDEBUG2("No EAP-Identity found to start EAP conversation");
			}
		} /* else there WAS a t->username */

		if (t->username) {
			vp = fr_pair_copy(fake->packet, t->username);
			fr_pair_add(&fake->packet->vps, vp);
			fake->username = vp;
		}
	} /* else the request ALREADY had a User-Name */

	/*
	 *	Process channel binding.
	 */
	chbind = eap_chbind_vp2packet(fake, fake->packet->vps);
	if (chbind) {
		FR_CODE chbind_code;
		CHBIND_REQ *req = talloc_zero(fake, CHBIND_REQ);

		RDEBUG("received chbind request");
		req->request = chbind;
		if (fake->username) {
			req->username = fake->username;
		} else {
			req->username = NULL;
		}
		chbind_code = chbind_process(request, req);

		/* encapsulate response here */
		if (req->response) {
			RDEBUG("sending chbind response");
			fr_pair_add(&fake->reply->vps,
				    eap_chbind_packet2vp(fake->reply, req->response));
		} else {
			RDEBUG("no chbind response");
		}

		/* clean up chbind req */
		talloc_free(req);

		if (chbind_code != FR_CODE_ACCESS_ACCEPT) {
			code = chbind_code;
			goto finish;
		}
	}

	/*
	 *	Call authentication recursively, which will
	 *	do PAP, CHAP, MS-CHAP, etc.
	 */
	eap_virtual_server(request, fake, eap_session, t->virtual_server);

	/*
	 *	Decide what to do with the reply.
	 */
	switch (fake->reply->code) {
	case 0:			/* No reply code, must be proxied... */
#ifdef WITH_PROXY
		vp = fr_pair_find_by_da(fake->control, attr_proxy_to_realm, TAG_ANY);
		if (vp) {
			int			ret;
			eap_tunnel_data_t	*tunnel;

			RDEBUG("Tunneled authentication will be proxied to %pV", &vp->data);

			/*
			 *	Tell the original request that it's going
			 *	to be proxied.
			 */
			fr_pair_list_copy_by_da(request, &request->control, fake->control, attr_proxy_to_realm);

			/*
			 *	Seed the proxy packet with the
			 *	tunneled request.
			 */
			rad_assert(!request->proxy);

			request->proxy = request_alloc_proxy(request);

			request->proxy->packet = talloc_steal(request->proxy, fake->packet);
			memset(&request->proxy->packet->src_ipaddr, 0, sizeof(request->proxy->packet->src_ipaddr));
			memset(&request->proxy->packet->src_ipaddr, 0, sizeof(request->proxy->packet->src_ipaddr));
			request->proxy->packet->src_port = 0;
			request->proxy->packet->dst_port = 0;
			fake->packet = NULL;
			fr_radius_packet_free(&fake->reply);
			fake->reply = NULL;

			/*
			 *	Set up the callbacks for the tunnel
			 */
			tunnel = talloc_zero(request, eap_tunnel_data_t);
			tunnel->tls_session = tls_session;
			tunnel->callback = eap_ttls_postproxy;

			/*
			 *	Associate the callback with the request.
			 */
			ret = request_data_add(request, request->proxy, REQUEST_DATA_EAP_TUNNEL_CALLBACK,
					       tunnel, false, false, false);
			fr_cond_assert(ret == 0);

			/*
			 *	rlm_eap.c has taken care of associating
			 *	the eap_session with the fake request.
			 *
			 *	So we associate the fake request with
			 *	this request.
			 */
			ret = request_data_add(request, request->proxy, REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK,
					       fake, true, false, false);
			fr_cond_assert(ret == 0);

			fake = NULL;

			/*
			 *	Didn't authenticate the packet, but
			 *	we're proxying it.
			 */
			code = FR_CODE_STATUS_CLIENT;

		} else
#endif	/* WITH_PROXY */
		  {
			RDEBUG("No tunneled reply was found for request %" PRIu64 ", and the request was not "
			       "proxied: rejecting the user", request->number);
			code = FR_CODE_ACCESS_REJECT;
		}
		break;

	default:
		/*
		 *	Returns RLM_MODULE_FOO, and we want to return FR_FOO
		 */
		rcode = process_reply(eap_session, tls_session, request, fake->reply);
		switch (rcode) {
		case RLM_MODULE_REJECT:
			code = FR_CODE_ACCESS_REJECT;
			break;

		case RLM_MODULE_HANDLED:
			code = FR_CODE_ACCESS_CHALLENGE;
			break;

		case RLM_MODULE_OK:
			code = FR_CODE_ACCESS_ACCEPT;
			break;

		default:
			code = FR_CODE_ACCESS_REJECT;
			break;
		}
		break;
	}

finish:
	talloc_free(fake);

	return code;
}
