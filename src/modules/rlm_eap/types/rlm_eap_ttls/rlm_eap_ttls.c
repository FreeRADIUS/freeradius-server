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
 * @file rlm_eap_ttls.c
 * @brief EAP-TTLS as defined by RFC 5281
 *
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/eap/tls.h>
#include <freeradius-devel/eap/chbind.h>
#include <freeradius-devel/tls/strerror.h>

typedef struct {
	SSL_CTX		*ssl_ctx;		//!< Thread local SSL_CTX.
} rlm_eap_ttls_thread_t;

typedef struct {
	/*
	 *	TLS configuration
	 */
	char const		*tls_conf_name;
	fr_tls_conf_t		*tls_conf;

	/*
	 *	RFC 5281 (TTLS) says that the length field MUST NOT be
	 *	in fragments after the first one.  However, we've done
	 *	it that way for years, and no one has complained.
	 *
	 *	In the interests of allowing the server to follow the
	 *	RFC, we add the option here.  If set to "no", it sends
	 *	the length field in ONLY the first fragment.
	 */
	bool			include_length;

	/*
	 *	Virtual server for inner tunnel session.
	 */
	virtual_server_t	*virtual_server;
	CONF_SECTION		*server_cs;

	/*
	 * 	Do we do require a client cert?
	 */
	bool			req_client_cert;
} rlm_eap_ttls_t;

typedef struct {
	fr_pair_t	*username;
	bool		authenticated;
} ttls_tunnel_t;

static conf_parser_t submodule_config[] = {
	{ FR_CONF_OFFSET("tls", rlm_eap_ttls_t, tls_conf_name) },
	{ FR_CONF_DEPRECATED("copy_request_to_tunnel", rlm_eap_ttls_t, NULL), .dflt = "no" },
	{ FR_CONF_DEPRECATED("use_tunneled_reply", rlm_eap_ttls_t, NULL), .dflt = "no" },
	{ FR_CONF_OFFSET_TYPE_FLAGS("virtual_server", FR_TYPE_VOID, CONF_FLAG_REQUIRED | CONF_FLAG_NOT_EMPTY, rlm_eap_ttls_t, virtual_server),
				    .func = virtual_server_cf_parse,
				    .uctx = &(virtual_server_cf_parse_uctx_t){ .process_module_name = "radius"} },
	{ FR_CONF_OFFSET("include_length", rlm_eap_ttls_t, include_length), .dflt = "yes" },
	{ FR_CONF_OFFSET("require_client_cert", rlm_eap_ttls_t, req_client_cert), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_eap_ttls_dict[];
fr_dict_autoload_t rlm_eap_ttls_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_eap_tls_require_client_cert;

static fr_dict_attr_t const *attr_chap_challenge;
static fr_dict_attr_t const *attr_ms_chap2_success;
static fr_dict_attr_t const *attr_eap_message;
static fr_dict_attr_t const *attr_ms_chap_challenge;
static fr_dict_attr_t const *attr_reply_message;
static fr_dict_attr_t const *attr_eap_channel_binding_message;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;
static fr_dict_attr_t const *attr_vendor_specific;

extern fr_dict_attr_autoload_t rlm_eap_ttls_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_ttls_dict_attr[] = {
	{ .out = &attr_eap_tls_require_client_cert, .name = "EAP-TLS-Require-Client-Cert", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_chap_challenge, .name = "CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap_challenge, .name = "Vendor-Specific.Microsoft.CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap2_success, .name = "Vendor-Specific.Microsoft.CHAP2-Success", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_reply_message, .name = "Reply-Message", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_eap_channel_binding_message, .name = "Vendor-Specific.UKERNA.EAP-Channel-Binding-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_vendor_specific, .name = "Vendor-Specific", .type = FR_TYPE_VSA, .dict = &dict_radius },
	DICT_AUTOLOAD_TERMINATOR
};


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
static int diameter_verify(request_t *request, uint8_t const *data, unsigned int data_len)
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
 *	Convert diameter attributes to our fr_pair_t's
 */
static ssize_t eap_ttls_decode_pair(request_t *request, TALLOC_CTX *ctx, fr_pair_list_t *out,
				    fr_dict_attr_t const *parent,
				    uint8_t const *data, size_t data_len,
				    void *decode_ctx)
{
	uint8_t const		*p = data, *end = p + data_len;

	fr_pair_t		*vp = NULL;
	SSL			*ssl = decode_ctx;
	fr_dict_attr_t const   	*attr_radius;
	fr_dict_attr_t const	*da;
	TALLOC_CTX		*tmp_ctx = NULL;

	attr_radius = fr_dict_root(dict_radius);

	while (p < end) {
		ssize_t			ret;
		uint32_t		attr, vendor;
		uint64_t		value_len;
		uint8_t			flags;
		fr_dict_attr_t const	*our_parent = parent;

		if ((end - p) < 8) {
			fr_strerror_printf("Malformed diameter attribute at offset %zu.  Needed at least 8 bytes, got %zu bytes",
					   p - data, end - p);
		error:
			talloc_free(tmp_ctx);
			fr_pair_list_free(out);
			return -1;
		}

		RDEBUG3("%04zu %02x%02x%02x%02x %02x%02x%02x%02x ...", p - data,
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

		attr = fr_nbo_to_uint32(p);
		p += 4;

		flags = p[0];
		p++;

		value_len = fr_nbo_to_uint64v(p, 3);	/* Yes, that is a 24 bit length field */
		p += 3;

		if (value_len < 8) {
			fr_strerror_printf("Malformed diameter attribute at offset %zu.  Needed at least length of 8, got %u",
					   p - data, (unsigned int) value_len);
			goto error;
		}

		/*
		 *	Account for the 8 bytes we've already read from the packet.
		 */
		if ((p + ((value_len + 0x03) & ~0x03)) - 8 > end) {
			fr_strerror_printf("Malformed diameter attribute at offset %zu.  Value length %u overflows input",
					   p - data, (unsigned int) value_len);
			goto error;
		}

		value_len -= 8;	/* -= 8 for AVP code (4), flags (1), AVP length (3) */

		/*
		 *	Do we have a vendor field?
		 */
		if (flags & FR_DIAMETER_AVP_FLAG_VENDOR) {
			vendor = fr_nbo_to_uint32(p);
			p += 4;
			value_len -= 4;	/* -= 4 for the vendor ID field */

			our_parent = fr_dict_vendor_da_by_num(attr_vendor_specific, vendor);
			if (!our_parent) {
				if (flags & FR_DIAMETER_AVP_FLAG_MANDATORY) {
					fr_strerror_printf("Mandatory bit set and no vendor %u found", vendor);
					goto error;
				}

				if (!tmp_ctx) {
					fr_dict_attr_t *n;

					MEM(our_parent = n = fr_dict_attr_unknown_vendor_afrom_num(ctx, parent, vendor));
					tmp_ctx = n;
				} else {
					MEM(our_parent = fr_dict_attr_unknown_vendor_afrom_num(tmp_ctx, parent, vendor));
				}
			}
		} else {
			our_parent = attr_radius;
		}

		/*
		 *	Is the attribute known?
		 */
		da = fr_dict_attr_child_by_num(our_parent, attr);
		if (!da) {
			if (flags & FR_DIAMETER_AVP_FLAG_MANDATORY) {
				fr_strerror_printf("Mandatory bit set and no attribute %u defined for parent %s", attr, parent->name);
				goto error;
			}

			MEM(da = fr_dict_attr_unknown_raw_afrom_num(vp, our_parent, attr));
		}

		MEM(vp =fr_pair_afrom_da_nested(ctx, out, da));

		ret = fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da,
						&FR_DBUFF_TMP(p, (size_t)value_len), value_len, true);
		if (ret < 0) {
			/*
			 *	Mandatory bit is set, and the attribute
			 *	is malformed. Fail.
			 */
			if (flags & FR_DIAMETER_AVP_FLAG_MANDATORY) {
				fr_strerror_const("Mandatory bit is set and attribute is malformed");
				goto error;
			}

			fr_pair_raw_afrom_pair(vp, p, value_len);
		}

		/*
		 *	The length does NOT include the padding, so
		 *	we've got to account for it here by rounding up
		 *	to the nearest 4-byte boundary.
		 */
		p += (value_len + 0x03) & ~0x03;

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
			uint8_t	challenge[17];
			static const char label[] = "ttls challenge";

			if ((vp->vp_length < 8) || (vp->vp_length > 16)) {
				fr_strerror_const("Tunneled challenge has invalid length");
				goto error;
			}

			/*
			 *	TLSv1.3 exports a different key depending on the length
			 *	requested so ask for *exactly* what the spec requires
			 */
			if (SSL_export_keying_material(ssl, challenge, vp->vp_length + 1,
						       label, sizeof(label) - 1, NULL, 0, 0) != 1) {
				fr_tls_strerror_printf("Failed generating phase2 challenge");
				goto error;
			}

			if (memcmp(challenge, vp->vp_octets, vp->vp_length) != 0) {
				fr_strerror_const("Tunneled challenge is incorrect");
				goto error;
			}
		}

		/*
		 *	Diameter pads strings (i.e. User-Password) with trailing zeros.
		 */
		if (vp->vp_type == FR_TYPE_STRING) fr_pair_value_strtrim(vp);
	}

	/*
	 *	We got this far.  It looks OK.
	 */
	talloc_free(tmp_ctx);
	return p - data;
}

/*
 *	Convert fr_pair_t's to diameter attributes, and write them
 *	to an SSL session.
 *
 *	The ONLY fr_pair_t's which may be passed to this function
 *	are ones which can go inside of a RADIUS (i.e. diameter)
 *	packet.  So no server-configuration attributes, or the like.
 */
static int vp2diameter(request_t *request, fr_tls_session_t *tls_session, fr_pair_list_t *list)
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
	fr_pair_t	*vp;

	p = buffer;
	total = 0;

	for (vp = fr_pair_list_head(list);
	     vp;
	     vp = fr_pair_list_next(list, vp)) {
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
		case FR_TYPE_DATE:
			attr = htonl(fr_unix_time_to_sec(vp->vp_date)); /* stored in host order */
			memcpy(p, &attr, sizeof(attr));
			length = 4;
			break;

		case FR_TYPE_UINT32:
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
		fr_tls_session_send(request, tls_session);
	}

	/*
	 *	Everything's OK.
	 */
	return 1;
}


static unlang_action_t eap_ttls_success(unlang_result_t *p_result, request_t *request, eap_session_t *eap_session)
{
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;
	eap_tls_prf_label_t prf_label;

	eap_crypto_prf_label_init(&prf_label, eap_session,
				  "ttls keying material",
				  sizeof("ttls keying material") - 1);
	/*
	 *	Success: Automatically return MPPE keys.
	 */
	if (eap_tls_success(request, eap_session, &prf_label) < 0) RETURN_UNLANG_FAIL;

	/*
	 *	Result is always OK, even if we fail to persist the
	 *	session data.
	 */
	p_result->rcode = RLM_MODULE_OK;

	/*
	 *	Write the session to the session cache
	 *
	 *	We do this here (instead of relying on OpenSSL to call the
	 *	session caching callback), because we only want to write
	 *	session data to the cache if all phases were successful.
	 *
	 *	If we wrote out the cache data earlier, and the server
	 *	exited whilst the session was in progress, the supplicant
	 *	could resume the session (and get access) even if phase2
	 *	never completed.
	 */
	return fr_tls_cache_pending_push(request, tls_session);
}


/*
 *	Use a reply packet to determine what to do.
 */
static unlang_action_t process_reply(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t		*eap_session = talloc_get_type_abort(mctx->rctx, eap_session_t);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;
	fr_pair_t		*vp = NULL;
	fr_pair_list_t		tunnel_vps;
	ttls_tunnel_t		*t = tls_session->opaque;
	fr_packet_t		*reply = request->reply;

	fr_pair_list_init(&tunnel_vps);
	fr_assert(eap_session->request == request->parent);

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
	case FR_RADIUS_CODE_ACCESS_ACCEPT:
		RDEBUG2("Got tunneled Access-Accept");

		/*
		 *	Copy what we need into the TTLS tunnel and leave
		 *	the rest to be cleaned up.
		 */
		if ((vp = fr_pair_find_by_da_nested(&request->reply_pairs, NULL, attr_ms_chap2_success))) {
			RDEBUG2("Got MS-CHAP2-Success, tunneling it to the client in a challenge");
		} else {
			vp = fr_pair_find_by_da_nested(&request->reply_pairs, NULL, attr_eap_channel_binding_message);
		}
		if (vp) {
			t->authenticated = true;
			fr_pair_prepend(&tunnel_vps, fr_pair_copy(tls_session, vp));
			reply->code = FR_RADIUS_CODE_ACCESS_CHALLENGE;
			break;
		}

		/*
		 *	Success: Automatically return MPPE keys.
		 */
		return eap_ttls_success(p_result, request, eap_session);

	case FR_RADIUS_CODE_ACCESS_REJECT:
		REDEBUG("Got tunneled Access-Reject");
		eap_tls_fail(request, eap_session);
		RETURN_UNLANG_REJECT;

	/*
	 *	Handle Access-Challenge, but only if we
	 *	send tunneled reply data.  This is because
	 *	an Access-Challenge means that we MUST tunnel
	 *	a Reply-Message to the client.
	 */
	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
		RDEBUG2("Got tunneled Access-Challenge");

		/*
		 *	Copy what we need into the TTLS tunnel and leave
		 *	the rest to be cleaned up.
		 */
		vp = NULL;
		while ((vp = fr_pair_list_next(&request->reply_pairs, vp))) {
		     	if ((vp->da == attr_eap_message) || (vp->da == attr_reply_message)) {
				fr_pair_prepend(&tunnel_vps, fr_pair_copy(tls_session, vp));
		     	} else if (vp->da == attr_eap_channel_binding_message) {
				fr_pair_prepend(&tunnel_vps, fr_pair_copy(tls_session, vp));
		     	}
		}
		break;

	default:
		REDEBUG("Unknown RADIUS packet type %d: rejecting tunneled user", reply->code);
		eap_tls_fail(request, eap_session);
		RETURN_UNLANG_INVALID;
	}


	/*
	 *	Pack any tunneled VPs and send them back
	 *	to the supplicant.
	 */
	if (!fr_pair_list_empty(&tunnel_vps)) {
		RDEBUG2("Sending tunneled reply attributes");
		log_request_pair_list(L_DBG_LVL_2, request, NULL, &tunnel_vps, NULL);

		vp2diameter(request, tls_session, &tunnel_vps);
		fr_pair_list_free(&tunnel_vps);
	}

	eap_tls_request(request, eap_session);
	RETURN_UNLANG_OK;
}

/*
 *	Process the "diameter" contents of the tunneled data.
 */
static unlang_action_t eap_ttls_process(unlang_result_t *p_result, module_ctx_t const *mctx,
					request_t *request, eap_session_t *eap_session, fr_tls_session_t *tls_session)
{
	fr_pair_t		*vp = NULL;
	ttls_tunnel_t		*t;
	uint8_t			const *data;
	size_t			data_len;
	chbind_packet_t		*chbind;
	fr_pair_t		*username;
	rlm_eap_ttls_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_ttls_t);

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
			RDEBUG2("Got ACK, and the user was already authenticated");
			return eap_ttls_success(p_result, request, eap_session);
		} /* else no session, no data, die. */

		/*
		 *	FIXME: Call SSL_get_error() to see what went
		 *	wrong.
		 */
		RDEBUG2("SSL_read Error");
		return UNLANG_ACTION_FAIL;
	}

	if (!diameter_verify(request, data, data_len)) return UNLANG_ACTION_FAIL;

	/*
	 *	Add the tunneled attributes to the request request.
	 */
	if (eap_ttls_decode_pair(request, request->request_ctx, &request->request_pairs, fr_dict_root(fr_dict_internal()),
				 data, data_len, tls_session->ssl) < 0) {
		RPEDEBUG("Decoding TTLS TLVs failed");
		return UNLANG_ACTION_FAIL;
	}

	/*
	 *	Update other items in the request_t data structure.
	 */

	/*
	 *	No User-Name, try to create one from stored data.
	 */
	username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	if (!username) {
		/*
		 *	No User-Name in the stored data, look for
		 *	an EAP-Identity, and pull it out of there.
		 */
		if (!t->username) {
			vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_eap_message);
			if (vp &&
			    (vp->vp_length >= EAP_HEADER_LEN + 2) &&
			    (vp->vp_strvalue[0] == FR_EAP_CODE_RESPONSE) &&
			    (vp->vp_strvalue[EAP_HEADER_LEN] == FR_EAP_METHOD_IDENTITY) &&
			    (vp->vp_strvalue[EAP_HEADER_LEN + 1] != 0)) {
				/*
				 *	Create & remember a User-Name
				 */
				MEM(t->username = fr_pair_afrom_da(t, attr_user_name));
				t->username->vp_tainted = true;

				fr_pair_value_bstrndup(t->username,
						       (char const *)vp->vp_octets + 5, vp->vp_length - 5, true);

				RDEBUG2("Got tunneled identity of %pV", &t->username->data);
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
			vp = fr_pair_copy(request->request_ctx, t->username);
			fr_pair_append(&request->request_pairs, vp);
		}
	} /* else the request ALREADY had a User-Name */

	/*
	 *	Process channel binding.
	 */
	chbind = eap_chbind_vp2packet(request, &request->request_pairs);
	if (chbind) {
		fr_radius_packet_code_t chbind_code;
		CHBIND_REQ *req = talloc_zero(request, CHBIND_REQ);

		RDEBUG2("received chbind request");
		req->request = chbind;
		if (username) {
			req->username = username;
		} else {
			req->username = NULL;
		}
		chbind_code = chbind_process(request, req);

		/* encapsulate response here */
		if (req->response) {
			RDEBUG2("sending chbind response");
			fr_pair_append(&request->reply_pairs,
				    eap_chbind_packet2vp(request->reply_ctx, req->response));
		} else {
			RDEBUG2("no chbind response");
		}

		/* clean up chbind req */
		talloc_free(req);

		if (chbind_code != FR_RADIUS_CODE_ACCESS_ACCEPT) return UNLANG_ACTION_FAIL;
	}

	/*
	 *	For this round, when the virtual server returns
	 *	we run the process reply function.
	 */
	if (unlikely(unlang_module_yield(request, process_reply, NULL, 0, eap_session) != UNLANG_ACTION_YIELD)) {
		return UNLANG_ACTION_FAIL;
	}

	/*
	 *	Call authentication recursively, which will
	 *	do PAP, CHAP, MS-CHAP, etc.
	 */
	return eap_virtual_server(request, eap_session, inst->virtual_server);
}

/*
 *	Allocate the TTLS per-session data
 */
static ttls_tunnel_t *ttls_alloc(TALLOC_CTX *ctx)
{
	ttls_tunnel_t *t;

	t = talloc_zero(ctx, ttls_tunnel_t);

	return t;
}

static unlang_action_t mod_handshake_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t		*eap_session = talloc_get_type_abort(mctx->rctx, eap_session_t);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;

	ttls_tunnel_t		*tunnel = talloc_get_type_abort(tls_session->opaque, ttls_tunnel_t);

	if ((eap_tls_session->state == EAP_TLS_INVALID) || (eap_tls_session->state == EAP_TLS_FAIL)) {
		REDEBUG("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, eap_tls_session->state, "<INVALID>"));
	} else {
		RDEBUG2("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, eap_tls_session->state, "<INVALID>"));
	}

	switch (eap_tls_session->state) {
	/*
	 *	EAP-TLS handshake was successful, tell the
	 *	client to keep talking.
	 *
	 *	If this was EAP-TLS, we would just return
	 *	an EAP-TLS-Success packet here.
	 */
	case EAP_TLS_ESTABLISHED:
		if (SSL_session_reused(tls_session->ssl)) {
			RDEBUG2("Skipping Phase2 due to session resumption");
			return eap_ttls_success(p_result, request, eap_session);
		}

		if (tunnel && tunnel->authenticated) return eap_ttls_success(p_result, request, eap_session);

		eap_tls_request(request, eap_session);
		RETURN_UNLANG_OK;

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case EAP_TLS_HANDLED:
		RETURN_UNLANG_HANDLED;

	/*
	 *	Handshake is done, proceed with decoding tunneled
	 *	data.
	 */
	case EAP_TLS_RECORD_RECV_COMPLETE:
		break;

	/*
	 *	Anything else: fail.
	 */
	default:
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Decoding Diameter attributes");

	/*
	 *	Process the TTLS portion of the request.
	 */
	return eap_ttls_process(p_result, mctx, request, eap_session, tls_session);
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static unlang_action_t mod_handshake_process(UNUSED unlang_result_t *p_result, UNUSED module_ctx_t const *mctx,
					     request_t *request)
{
	eap_session_t		*eap_session = eap_session_get(request->parent);

	/*
	 *	Setup the resumption frame to process the result
	 */
	(void)unlang_module_yield(request, mod_handshake_resume, NULL, 0, eap_session);

	/*
	 *	Process TLS layer until done.
	 */
	return eap_tls_process(request, eap_session);
}

static unlang_action_t mod_session_init_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_ttls_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_ttls_t);
	rlm_eap_ttls_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_ttls_thread_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	eap_tls_session_t	*eap_tls_session;
	fr_tls_session_t	*tls_session;
	fr_pair_t		*vp;
	bool			client_cert;

	/*
	 *	EAP-TLS-Require-Client-Cert attribute will override
	 *	the require_client_cert configuration option.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_eap_tls_require_client_cert);
	if (vp) {
		client_cert = vp->vp_uint32 ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}

	eap_session->opaque = eap_tls_session = eap_tls_session_init(request, eap_session, t->ssl_ctx, client_cert);
	if (!eap_tls_session) RETURN_UNLANG_FAIL;
	tls_session = eap_tls_session->tls_session;

	eap_tls_session->include_length = inst->include_length;

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	if (eap_tls_start(request, eap_session) < 0) {
		talloc_free(eap_tls_session);
		RETURN_UNLANG_FAIL;
	}

	tls_session->opaque = ttls_alloc(tls_session);

	eap_session->process = mod_handshake_process;

	RETURN_UNLANG_OK;
}

/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static unlang_action_t mod_session_init(UNUSED unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_ttls_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_ttls_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	eap_session->tls = true;

	(void) unlang_module_yield(request, mod_session_init_resume, NULL, 0, NULL);

	if (inst->tls_conf->new_session) return fr_tls_new_session_push(request, inst->tls_conf);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_eap_ttls_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_ttls_t);
	rlm_eap_ttls_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_ttls_thread_t);

	t->ssl_ctx = fr_tls_ctx_alloc(inst->tls_conf, false);
	if (!t->ssl_ctx) return -1;

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_eap_ttls_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_ttls_thread_t);

	if (likely(t->ssl_ctx != NULL)) SSL_CTX_free(t->ssl_ctx);
	t->ssl_ctx = NULL;

	return 0;
}

/*
 *	Attach the module.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_eap_ttls_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_ttls_t);
	CONF_SECTION 	*conf = mctx->mi->conf;

	inst->server_cs = virtual_server_cs(inst->virtual_server);

	/*
	 *	Read tls configuration, either from group given by 'tls'
	 *	option, or from the eap-tls configuration.
	 */
	inst->tls_conf = eap_tls_conf_parse(conf);
	if (!inst->tls_conf) {
		cf_log_err(conf, "Failed initializing SSL context");
		return -1;
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_ttls;
rlm_eap_submodule_t rlm_eap_ttls = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "eap_ttls",

		.inst_size		= sizeof(rlm_eap_ttls_t),
		.config			= submodule_config,
		.instantiate		= mod_instantiate,	/* Create new submodule instance */

		.thread_inst_size	= sizeof(rlm_eap_ttls_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	},
	.provides		= { FR_EAP_METHOD_TTLS },
	.session_init		= mod_session_init,	/* Initialise a new EAP session */
};
