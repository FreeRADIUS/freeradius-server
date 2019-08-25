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
 * @file src/lib/sim/xlat.c
 * @brief EAP-SIM/EAP-AKA identity detection, creation, and decyption.
 *
 * @copyright 2017 The FreeRADIUS server project
 */

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.eap.h>
#include "base.h"
#include "attrs.h"

static int sim_xlat_refs = 0;


/** Returns the SIM method EAP-SIM or EAP-AKA hinted at by the user identifier
 *
 *	%{sim_id_method:&id_attr}
 */
static ssize_t sim_xlat_id_method(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
				  UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				  REQUEST *request, char const *fmt)
{
	vp_tmpl_t		*vpt;
	TALLOC_CTX		*our_ctx = talloc_init("sim_xlat");
	ssize_t			slen, id_len;
	char const		*p = fmt, *id, *method;
	fr_sim_id_type_t	type_hint;
	fr_sim_method_hint_t	method_hint;

	/*
	 *  Trim whitespace
	 */
	fr_skip_spaces(p);

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &vpt, p, -1,
				      &(vp_tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = VP_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid attribute reference");
	error:
		talloc_free(our_ctx);
		return -1;
	}

	if (tmpl_aexpand(our_ctx, &id, request, vpt, NULL, NULL) < 0) {
		RPEDEBUG2("Failing expanding ID attribute");
		goto error;
	}

	id_len = talloc_array_length(id) - 1;
	if (fr_sim_id_type(&type_hint, &method_hint, id, id_len) < 0) {
		RPEDEBUG2("SIM ID \"%pV\" has unrecognised format", fr_box_strvalue_len(id, id_len));
		goto error;
	}

	method = fr_dict_enum_alias_by_value(attr_sim_method_hint, fr_box_uint32(method_hint));
	if (!method) {
		REDEBUG("Missing Sim-Method-Hint value");
		goto error;
	}
	*out = talloc_typed_strdup(ctx, method);
	talloc_free(our_ctx);

	return talloc_array_length(*out) - 1;
}

/** Returns the type of identity used
 *
 *	%{sim_id_type:&id_attr}
 */
static ssize_t sim_xlat_id_type(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
				UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				REQUEST *request, char const *fmt)
{
	vp_tmpl_t		*vpt;
	TALLOC_CTX		*our_ctx = talloc_init("sim_xlat");
	ssize_t			slen, id_len;
	char const		*p = fmt, *id, *method;
	fr_sim_id_type_t	type_hint;
	fr_sim_method_hint_t	method_hint;

	/*
	 *  Trim whitespace
	 */
	fr_skip_spaces(p);

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &vpt, p, -1,
				      &(vp_tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = VP_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid attribute reference");
	error:
		talloc_free(our_ctx);
		return -1;
	}

	if (tmpl_aexpand(our_ctx, &id, request, vpt, NULL, NULL) < 0) {
		RPEDEBUG2("Failing expanding ID attribute");
		goto error;
	}

	id_len = talloc_array_length(id) - 1;
	if (fr_sim_id_type(&type_hint, &method_hint, id, id_len) < 0) {
		RPEDEBUG2("SIM ID \"%pV\" has unrecognised format", fr_box_strvalue_len(id, id_len));
		goto error;
	}

	method = fr_dict_enum_alias_by_value(attr_sim_identity_type, fr_box_uint32(type_hint));
	if (!method) {
		REDEBUG("Missing Sim-Method-Hint value");
		goto error;
	}
	*out = talloc_typed_strdup(ctx, method);
	talloc_free(our_ctx);

	return talloc_array_length(*out) - 1;
}

/** Returns the key index from a 3gpp pseudonym
 *
 *	%{sim_id_3gpp_pseudonym_key_index:&id_attr}
 *
 */
static ssize_t sim_xlat_3gpp_pseudonym_key_index(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
						 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
						 REQUEST *request, char const *fmt)
{
	vp_tmpl_t	*vpt;
	TALLOC_CTX	*our_ctx = talloc_init("sim_xlat");
	ssize_t		slen, id_len;
	char const	*p = fmt, *id;

	/*
	 *  Trim whitespace
	 */
	fr_skip_spaces(p);

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &vpt, p, -1,
				      &(vp_tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = VP_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid attribute reference");
	error:
		talloc_free(our_ctx);
		return -1;
	}

	if (tmpl_aexpand(our_ctx, &id, request, vpt, NULL, NULL) < 0) {
		RPEDEBUG2("Failing expanding ID attribute");
		goto error;
	}

	id_len = talloc_array_length(id) - 1;
	if (id_len != SIM_3GPP_PSEUDONYM_LEN) {
		REDEBUG2("3gpp pseudonym incorrect length, expected %i bytes, got %zu bytes",
			 SIM_3GPP_PSEUDONYM_LEN, id_len);
		goto error;
	}

	MEM(*out = talloc_typed_asprintf(ctx, "%i", fr_sim_id_3gpp_pseudonym_tag(id)));
	talloc_free(our_ctx);

	return talloc_array_length(*out) - 1;
}

static ssize_t sim_xlat_3gpp_pseudonym_decrypt(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
					       UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
					       REQUEST *request, char const *fmt)
{
	vp_tmpl_t	*id_vpt, *key_vpt;
	TALLOC_CTX	*our_ctx = talloc_init("sim_xlat");
	ssize_t		slen, id_len, key_len;
	uint8_t		tag;
	char		out_tag;
	uint8_t		*key;
	char		decrypted[SIM_IMSI_MAX_LEN + 1];
	char const	*p = fmt, *id;

	/*
	 *  Trim whitespace
	 */
	fr_skip_spaces(p);

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &id_vpt, p, -1,
				      &(vp_tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = VP_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid ID attribute reference");
	error:
		talloc_free(our_ctx);
		return -1;
	}

	p += slen;
	if (*p != ' ') {
		REDEBUG2("Missing key argument");
		goto error;
	}
	p++;

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &key_vpt, p, -1,
				      &(vp_tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = VP_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid key attribute reference");
		goto error;
	}

	if (tmpl_aexpand(our_ctx, &id, request, id_vpt, NULL, NULL) < 0) {
		RPEDEBUG2("Failing expanding ID attribute");
		goto error;
	}


	if (tmpl_aexpand(our_ctx, &key, request, key_vpt, NULL, NULL) < 0) {
		RPEDEBUG2("Failing expanding Key attribute");
		goto error;
	}

	id_len = talloc_array_length(id);
	if (id_len != (SIM_3GPP_PSEUDONYM_LEN + 1)) {
		REDEBUG2("3gpp pseudonym incorrect length, expected %i bytes, got %zu bytes",
			 SIM_3GPP_PSEUDONYM_LEN + 1, id_len);
		goto error;
	}

	key_len = talloc_array_length(key);
	if (key_len != 16) {
		REDEBUG2("Decryption key incorrect length, expected %i bytes, got %zu bytes", 16, key_len);
		goto error;
	}

	tag = fr_sim_id_3gpp_pseudonym_tag(id);
	switch (tag) {
	case SIM_ID_TAG_PSEUDONYM_SIM_B64:
		out_tag = SIM_ID_TAG_PERMANENT_SIM;
		break;

	case SIM_ID_TAG_PSEUDONYM_AKA_B64:
		out_tag = SIM_ID_TAG_PERMANENT_AKA;
		break;

	case SIM_ID_TAG_PSEUDONYM_AKA_PRIME_B64:
		out_tag = SIM_ID_TAG_PERMANENT_AKA_PRIME;
		break;

	default:
		REDEBUG2("Unexpected tag value (%u) in SIM ID \"%pV\"", tag, fr_box_strvalue_len(id, id_len));
		goto error;
	}

	RDEBUG2("Decrypting \"%pV\"", fr_box_strvalue_len(id, id_len));
	if (fr_sim_id_3gpp_pseudonym_decrypt(decrypted, id, key) < 0) {
		RPEDEBUG2("Failed decrypting SIM ID");
		goto error;
	}

	/*
	 *	Recombine unencrypted IMSI with tag
	 */
	MEM(*out = talloc_typed_asprintf(ctx, "%c%s", out_tag, decrypted));
	talloc_free(our_ctx);

	return talloc_array_length(*out) - 1;
}

/** Encrypts a 3gpp pseudonym
 *
 *	%{sim_id_3gpp_pseudonym_encrypt:&id_attr &key_attr key_index}
 *
 */
static ssize_t sim_xlat_3gpp_pseudonym_encrypt(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
					       UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
					       REQUEST *request, char const *fmt)
{
	vp_tmpl_t		*id_vpt, *key_vpt;
	TALLOC_CTX		*our_ctx = talloc_init("sim_xlat");
	ssize_t			slen, id_len, key_len;
	uint8_t			*key, tag = 0;
	unsigned long		key_index;
	char			encrypted[SIM_3GPP_PSEUDONYM_LEN + 1];
	char const		*p = fmt, *id;
	char const		*id_p, *id_end;
	fr_sim_id_type_t	type_hint;
	fr_sim_method_hint_t	method_hint;

	/*
	 *  Trim whitespace
	 */
	fr_skip_spaces(p);

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &id_vpt, p, -1,
				      &(vp_tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = VP_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid ID attribute reference");
	error:
		talloc_free(our_ctx);
		return -1;
	}

	p += slen;
	if (*p != ' ') {
		REDEBUG2("Missing key argument");
		goto error;
	}
	p++;

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &key_vpt, p, -1,
				      &(vp_tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = VP_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid key attribute reference");
		goto error;
	}
	p += slen;

	if (*p != ' ') {
		REDEBUG2("Missing key index");
		goto error;
	}
	p++;

	/*
	 *	Get the key index
	 */
	key_index = strtoul(p, NULL, 10);
	if (key_index > 15) {
		REDEBUG2("Key index must be between 0-15");
		goto error;
	}

	/*
	 *	Get the ID
	 */
	if (tmpl_aexpand(our_ctx, &id, request, id_vpt, NULL, NULL) < 0) {
		RPEDEBUG2("Failing expanding ID attribute");
		goto error;
	}

	/*
	 *	Get the key
	 */
	if (tmpl_aexpand(our_ctx, &key, request, key_vpt, NULL, NULL) < 0) {
		RPEDEBUG2("Failing expanding Key attribute");
		goto error;
	}

	key_len = talloc_array_length(key);
	if (key_len != 16) {
		REDEBUG2("Encryption key incorrect length, expected %i bytes, got %zu bytes", 16, key_len);
		goto error;
	}

	/*
	 *	Determine what type/method hints are in the current ID.
	 */
	id_len = talloc_array_length(id) - 1;
	if (id_len == (SIM_IMSI_MAX_LEN + 1)) {	/* +1 for ID tag */
		if (fr_sim_id_type(&type_hint, &method_hint, id, id_len) < 0) {
			RPEDEBUG2("SIM ID \"%pV\" has unrecognised format", fr_box_strvalue_len(id, id_len));
			goto error;
		}

		if (type_hint != SIM_ID_TYPE_PERMANENT) {
			REDEBUG2("SIM ID \"%pV\" is not a permanent identity (IMSI)", fr_box_strvalue_len(id, id_len));
			goto error;
		}

		switch (method_hint) {
		case SIM_METHOD_HINT_SIM:
			tag = SIM_ID_TAG_PSEUDONYM_SIM_B64;
			break;

		case SIM_METHOD_HINT_AKA:
			tag = SIM_ID_TAG_PSEUDONYM_AKA_B64;
			break;

		case SIM_METHOD_HINT_AKA_PRIME:
			tag = SIM_ID_TAG_PSEUDONYM_AKA_PRIME_B64;
			break;

		case SIM_METHOD_HINT_UNKNOWN:
			REDEBUG2("SIM ID \"%pV\" does not contain a method hint", fr_box_strvalue_len(id, id_len));
			goto error;
		}

		id_p = id + 1;
		id_end = (id_p + id_len) - 1;
	/*
	 *	ID lacks a hint byte, figure it out from &control:EAP-Type
	 */
	} else if ((id_len >= SIM_IMSI_MIN_LEN) && (id_len <= SIM_IMSI_MAX_LEN)) {
		VALUE_PAIR *eap_type;

		eap_type = fr_pair_find_by_da(request->control, attr_eap_type, TAG_ANY);
		if (!eap_type) {
			REDEBUG("SIM ID does not contain method hint, and no &control:EAP-Type found.  "
				"Don't know what tag to prepend to encrypted identity");
			goto error;
		}

		switch (eap_type->vp_uint32) {
		case FR_EAP_TYPE_VALUE_SIM:
			tag = SIM_ID_TAG_PSEUDONYM_SIM_B64;
			break;

		case FR_EAP_TYPE_VALUE_AKA:
			tag = SIM_ID_TAG_PSEUDONYM_AKA_B64;
			break;

		case FR_EAP_TYPE_VALUE_AKA_PRIME:
			tag = SIM_ID_TAG_PSEUDONYM_AKA_PRIME_B64;
			break;

		default:
			REDEBUG("&control:EAP-Type does not match a SIM based EAP-Type (SIM, AKA, AKA-Prime)");
			break;
		}

		id_p = id;
		id_end = id_p + id_len;
	} else {
		REDEBUG2("IMSI incorrect length, expected %i bytes, got %zu bytes", SIM_IMSI_MAX_LEN + 1,
			 id_len);
		goto error;

	}

	/*
	 *	Encrypt the IMSI
	 *
	 *	Strip existing tag from the permanent id
	 */
	if (fr_sim_id_3gpp_pseudonym_encrypt(encrypted, id_p, id_end - id_p, tag, (uint8_t)key_index, key) < 0) {
		RPEDEBUG2("Failed encrypting SIM ID \"%pV\"", fr_box_strvalue_len(id, id_len));
		return -1;
	}

	MEM(*out = talloc_typed_asprintf(ctx, "%s", encrypted));
	talloc_free(our_ctx);

	return talloc_array_length(*out) - 1;
}

void sim_xlat_register(void)
{
	if (sim_xlat_refs) {
		sim_xlat_refs++;
		return;
	}

	xlat_register(NULL, "sim_id_method", sim_xlat_id_method, NULL, NULL, 0, 0, true);
	xlat_register(NULL, "sim_id_type", sim_xlat_id_type, NULL, NULL, 0, 0, true);
	xlat_register(NULL, "3gpp_pseudonym_key_index",
		      sim_xlat_3gpp_pseudonym_key_index, NULL, NULL, 0, 0, true);
	xlat_register(NULL, "3gpp_pseudonym_decrypt",
		      sim_xlat_3gpp_pseudonym_decrypt, NULL, NULL, 0, 0, true);
	xlat_register(NULL, "3gpp_pseudonym_encrypt",
		      sim_xlat_3gpp_pseudonym_encrypt, NULL, NULL, 0, 0, true);
	sim_xlat_refs = 1;
}

void sim_xlat_unregister(void)
{
	if (sim_xlat_refs > 1) {
		sim_xlat_refs--;
		return;
	}

	xlat_unregister("sim_id_method");
	xlat_unregister("sim_id_type");
	xlat_unregister("3gpp_pseudonym_key_index");
	xlat_unregister("3gpp_pseudonym_decrypt");
	xlat_unregister("3gpp_pseudonym_encrypt");
	sim_xlat_refs = 0;
}
