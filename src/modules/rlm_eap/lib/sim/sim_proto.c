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
 * @file rlm_eap/lib/sim/sim_proto.c
 * @brief Code common to EAP-SIM/AKA/AKA' clients and servers.
 *
 * The development of the EAP-SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * @copyright 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * @copyright 2003-2016 The FreeRADIUS server project
 */

/*
 *  EAP-SIM/AKA/AKA' PACKET FORMAT
 *  ---------------- ------ ------
 *
 * EAP Request and Response Packet Format
 * --- ------- --- -------- ------ ------
 *  0		   1		   2		   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |	    Length	     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    AT-Type    |   AT-Length   |     value ... |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * With AT-Type/AT-Length/Value... repeating. Length is in units
 * of 32 bits, and includes the Type/Length fields.
 */
RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/sha1.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>

#include "eap_types.h"
#include "eap_sim_common.h"
#include "sim_proto.h"

/*
 * definitions changed to take a buffer for unknowns
 * as this is more thread safe.
 */
char const *fr_sim_session_to_name(char *out, size_t outlen, eap_sim_client_states_t state)
{
	static char const *sim_states[] = { "init", "start", NULL };

	if (state >= EAP_SIM_CLIENT_MAX_STATES) {
		snprintf(out, outlen, "eapstate:%d", state);
		return out;
	}

	return sim_states[state];
}

char const *fr_sim_subtype_to_name(char *out, size_t outlen, eap_sim_subtype_t subtype)
{
	static char const *subtypes[] = { "subtype0", "subtype1", "subtype2", "subtype3",
					   "subtype4", "subtype5", "subtype6", "subtype7",
					   "subtype8", "subtype9",
					   "start",
					   "challenge",
					   "notification",
					   "reauth",
					   "client-error",
					   NULL };

	if (subtype >= EAP_SIM_MAX_SUBTYPE) {
		snprintf(out, outlen, "illegal-subtype:%d", subtype);
		return out;
	}

	return subtypes[subtype];
}

/** Decode SIM/AKA/AKA' attributes
 *
 * @param[in] ctx		to allocate attributes in.
 * @param[in] cursor		where to insert the attributes.
 * @param[in] parent		root attribute for the SIM dialect (SIM/AKA/AKA') we're parsing.
 * @param[in] data		data to parse.
 * @param[in] data_len		length of data.
 * @param[in] decoder_ctx	extra context to pass to the decoder(unused).
 * @return
 *	- The number of bytes parsed.
 *	- -1 on error.
 */
static ssize_t fr_sim_decode_pair(TALLOC_CTX *ctx, vp_cursor_t *cursor, fr_dict_attr_t const *parent,
				  uint8_t const *data, size_t data_len,
				  UNUSED void *decoder_ctx)
{
	int		sim_at;
	uint32_t	sim_at_len;

	uint8_t const	*p = data;
	uint8_t const	*end = p + data_len;

	/*
	 *	Move the cursor to the end, so we know if
	 *	any additional attributes were added.
	 */
	fr_cursor_end(cursor);

	/*
	 *	Loop over all the attributes decoding
	 *	them into the appropriate attributes
	 *	in the SIM/AKA/AKA' dict.
	 */
	while (p < end) {
		fr_dict_attr_t const	*da;
		VALUE_PAIR		*vp;

		if ((end - p) < 2) break;

		sim_at = p[0];
		sim_at_len = p[1] * sizeof(uint32_t);

		if ((p + sim_at_len) > end) {
			fr_strerror_printf("Malformed attribute %d: Length longer than data (%u > %zu)",
					   sim_at, sim_at_len, end - p);
		error:
			fr_cursor_free(cursor);
			return -1;
		}

		if (sim_at_len == 0) {
			fr_strerror_printf("Malformed attribute %d: Length field is zero", sim_at);
			goto error;
		}

		da = fr_dict_attr_child_by_num(parent, sim_at);
		if (!da) {
			/*
			 *	Encountered none skippable attribute
			 *
			 *	RFC says we need to die on these if we don't
			 *	understand them.  non-skippables are < 128.
			 */
			if (sim_at < 128) {
				fr_strerror_printf("Unknown (non-skippable) attribute %i", sim_at);
				goto error;
			}

			/*
			 *	@fixme We should create unknowns....
			 */
			fr_strerror_printf("Skipping unknown attribute %i", sim_at);
			goto next;
		}

		vp = fr_pair_afrom_da(ctx, da);
		if (!vp) goto error;
		fr_pair_value_memcpy(vp, &p[2], sim_at_len - 2);
		fr_cursor_append(cursor, vp);

	next:
		/* advance pointers, decrement length */
		p += sim_at_len;
	}

	return p - data;
}

/** Decode SIM/AKA/AKA' specific packet data
 *
 * @note data should point to the subtype field in the EAP packet.
 *
 * Extracts the SUBTYPE and adds it an attribute, then decodes any TLVs in the
 * SIM/AKA/AKA' packet.
 *
 * @param[in] request		the current request.
 * @param[in] parent		the root of the dictionary.
 * @param[in] decoded		where to write decoded attributes.
 * @param[in] data		to convert to pairs.
 * @param[in] data_len		length of data to convert.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_sim_decode(REQUEST *request, fr_dict_attr_t const *parent,
		  vp_cursor_t *decoded, uint8_t const *data, size_t data_len)
{
	ssize_t		slen;
	uint8_t	const	*p = data;
	uint8_t const	*end = p + data_len;

	FR_PROTO_HEX_DUMP(NULL, data, data_len);

	fr_strerror();

	/*
	 *	Check if we have enough data for a single attribute
	 *	Minimum attribute size is 4 bytes, then + 3 for
	 *	subtype and the reserved bytes.
	 */
	if (data_len < (3 + sizeof(uint32_t))) {
		REDEBUG("Packet data too small: %zu < %zu" , data_len, 3 + sizeof(uint32_t));
		return -1;
	}
	p += 3;

	slen = fr_sim_decode_pair(request->packet, decoded, parent, p, end - p, NULL);
	if (slen < 0) {
		REDEBUG("%s", fr_strerror());
		return -1;
	}
	p += slen;
	rad_assert(p <= end);

	if (p != end) {
		REDEBUG("Got %zu bytes of trailing garbage", end - p);
		RHEXDUMP(L_DBG_LVL_2, p, end - p, "");
	error:
		fr_cursor_free(decoded);	/* Free any attributes we added */
		return -1;
	}

	/*
	 *	No point in doing this until we known the rest
	 *	of the data is OK!
	 */
	{
		VALUE_PAIR *vp;

		vp = fr_pair_afrom_child_num(request->packet, parent, PW_SIM_SUBTYPE);
		if (!vp) {
			REDEBUG("Failed allocating subtype attribute");
			goto error;
		}
		vp->vp_integer = data[0];
		vp->vp_length = 1;
		fr_cursor_append(decoded, vp);
	}

	return 0;
}

int fr_sim_encode(REQUEST *request, fr_dict_attr_t const *parent,
		  VALUE_PAIR *to_encode, eap_packet_t *ep)
{
	VALUE_PAIR		*vp;
	int			encoded_size;
	uint8_t			*encoded_msg, *attr;
	unsigned int		id, eap_code;
	uint8_t			*mac_space;
	uint8_t const		*append;
	int			append_len;
	unsigned char		subtype;
	vp_cursor_t		cursor;

	fr_dict_attr_t const	*da;

	mac_space = NULL;
	append = NULL;
	append_len = 0;

	da = fr_dict_attr_child_by_num(parent, PW_SIM_SUBTYPE);
	if (!da) {
		REDEBUG("Missing definition for subtype attribute");
		return -1;
	}

	/*
	 *	Encoded_msg is now an EAP-SIM message.
	 *	It might be too big for putting into an
	 *	EAP packet.
	 */
	vp = fr_pair_find_by_da(to_encode, da, TAG_ANY);
	subtype = vp ? vp->vp_integer : EAP_SIM_START;

	vp = fr_pair_find_by_num(to_encode, 0, PW_EAP_ID, TAG_ANY);
	id = vp ? vp->vp_integer : ((int)getpid() & 0xff);

	vp = fr_pair_find_by_num(to_encode, 0, PW_EAP_CODE, TAG_ANY);
	eap_code = vp ? vp->vp_integer : PW_EAP_REQUEST;

	/*
	 *	take a walk through the attribute list to
	 *	see how much space that we need to encode
	 *	all of this.
	 */
	encoded_size = 0;

	(void)fr_cursor_init(&cursor, &to_encode);
	while ((vp = fr_cursor_next_by_ancestor(&cursor, parent, TAG_ANY))) {
		int rounded_len;
		int vp_len;

		if (vp->da->attr > UINT8_MAX) continue;	/* Skip non-protocol attributes */

		vp_len = vp->vp_length;

		/*
		 * the AT_MAC attribute is a bit different, when we get to this
		 * attribute, we pull the contents out, save it for later
		 * processing, set the size to 16 bytes (plus 2 bytes padding).
		 *
		 * At this point, we only care about the size.
		 */
		if (vp->da->attr == PW_SIM_MAC) vp_len = 18;


		/*
		 * Round up to next multiple of 4, after taking in
		 * account the type and length bytes.
		 */
		rounded_len = (vp_len + 2 + 3) & ~3;
		encoded_size += rounded_len;
	}

	if (ep->code != PW_EAP_SUCCESS) ep->code = eap_code;

	ep->id = (id & 0xff);
	ep->type.num = PW_EAP_SIM;

	/*
	 *	If no attributes were found, do very little.
	 */
	if (encoded_size == 0) {
		MEM(encoded_msg = talloc_array(ep, uint8_t, 3));

		encoded_msg[0] = subtype;
		encoded_msg[1] = 0;
		encoded_msg[2] = 0;

		ep->type.length = 3;
		ep->type.data = encoded_msg;

		return 0;
	}

	/*
	 *	Figured out the length, so allocate some space for the results.
	 *
	 *	Note that we do not bother going through an "EAP" stage, which
	 * 	is a bit strange compared to the unmap, which expects to see
	 *	an EAP-SIM virtual attributes.
	 *
	 *	EAP is 1-code, 1-identifier, 2-length, 1-type = 5 overhead.
	 *
	 *	SIM code adds a subtype, and 2 bytes of reserved = 3.
	 *
	 */
	encoded_size += 3;
	encoded_msg = talloc_array(ep, uint8_t, encoded_size);
	if (!encoded_msg) return 0;

	memset(encoded_msg, 0, encoded_size);

	/*
	 *	Now walk the attributes again, encoding.
	 *
	 *	we go three bytes into the encoded message, because there are two
	 *	bytes of reserved, and we will fill the "subtype" in later.
	 *
	 */
	attr = encoded_msg + 3;

	(void)fr_cursor_first(&cursor);
	while ((vp = fr_cursor_next_by_ancestor(&cursor, parent, TAG_ANY))) {
		int rounded_len;

		if (vp->da->attr > UINT8_MAX) continue;	/* Skip non-protocol attributes */

		/*
		 *	The AT_MAC attribute is a bit different, when we get to this
		 *	attribute, we pull the contents out, save it for later
		 *	processing, set the size to 16 bytes (plus 2 bytes padding).
		 *
		 *	At this point, we put in zeros, and remember where the
		 *	sixteen bytes go.
		 */
		if (vp->da->attr == PW_EAP_SIM_MAC) {
			rounded_len = 20;
			memset(&attr[2], 0, 18);
			mac_space = &attr[4];
			append = vp->vp_octets;
			append_len = vp->vp_length;
		} else {
			rounded_len = (vp->vp_length + 2 + 3) & ~3;
			memset(attr, 0, rounded_len);
			memcpy(&attr[2], vp->vp_strvalue, vp->vp_length);
		}
		attr[0] = vp->da->attr;
		attr[1] = rounded_len >> 2;

		attr += rounded_len;
	}

	encoded_msg[0] = subtype;

	ep->type.length = encoded_size;
	ep->type.data = encoded_msg;

	/*
	 *	If mac_space was set and we have a key,
	 * 	then we should calculate the HMAC-SHA1 of the resulting EAP-SIM
	 * 	packet, appended with the value of append.
	 */
	da = fr_dict_attr_child_by_num(parent, PW_SIM_KEY);
	if (!da) {
		REDEBUG("Missing definition for key attribute");
		return -1;
	}

	vp = fr_pair_find_by_da(to_encode, da, TAG_ANY);
	if ((mac_space != NULL) && (vp != NULL)) {
		unsigned char		*buffer;
		eap_packet_raw_t	*hdr;
		uint16_t		hmac_len, total_length = 0;
		unsigned char		sha1digest[20];

		total_length = EAP_HEADER_LEN + 1 + encoded_size;
		hmac_len = total_length + append_len;
		buffer = talloc_array(to_encode, uint8_t, hmac_len);
		hdr = (eap_packet_raw_t *) buffer;
		if (!hdr) {
			talloc_free(encoded_msg);
			return 0;
		}

		hdr->code = eap_code & 0xff;
		hdr->id = (id & 0xff);
		total_length = htons(total_length);
		memcpy(hdr->length, &total_length, sizeof(total_length));

		hdr->data[0] = PW_EAP_SIM;

		/* copy the data */
		memcpy(&hdr->data[1], encoded_msg, encoded_size);

		/* copy the nonce */
		memcpy(&hdr->data[encoded_size+1], append, append_len);

		/* HMAC it! */
		fr_hmac_sha1(sha1digest, buffer, hmac_len, vp->vp_octets, vp->vp_length);

		talloc_free(buffer);

		/* now copy the digest to where it belongs in the AT_MAC */
		/* note that it is truncated to 128-bits */
		memcpy(mac_space, sha1digest, 16);
	}

	/* if we had an AT_MAC and no key, then fail */
	if ((mac_space != NULL) && !vp) {
		if (encoded_msg != NULL) {
			talloc_free(encoded_msg);
		}

		return 0;
	}

	return 1;
}

