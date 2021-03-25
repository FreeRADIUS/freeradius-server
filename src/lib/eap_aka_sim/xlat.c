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
 * @file src/lib/eap_aka_sim/xlat.c
 * @brief EAP-SIM/EAP-AKA identity detection, creation, and decyption.
 *
 * @copyright 2017 The FreeRADIUS server project
 */

#include <freeradius-devel/server/base.h>
#include "base.h"
#include "attrs.h"

static int aka_sim_xlat_refs = 0;


static xlat_arg_parser_t const aka_sim_xlat_id_method_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Returns the SIM method EAP-SIM or EAP-AKA hinted at by the user identifier
 *
@verbatim
%(aka_sim_id_method:%{id_attr})
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t aka_sim_xlat_id_method_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
						 UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
						 fr_value_box_list_t *in)
{
	char const			*method;
	fr_aka_sim_id_type_t		type_hint;
	fr_aka_sim_method_hint_t	method_hint;
	fr_value_box_t			*id = fr_dlist_head(in);
	fr_value_box_t			*vb;

	if (fr_aka_sim_id_type(&type_hint, &method_hint, id->vb_strvalue, id->vb_length) < 0) {
		RPEDEBUG2("AKA/SIM Id \"%pV\" has unrecognised format", id);
		return XLAT_ACTION_FAIL;
	}

	switch (method_hint) {
	default:
	case AKA_SIM_METHOD_HINT_UNKNOWN:
		return XLAT_ACTION_DONE;

	case AKA_SIM_METHOD_HINT_SIM:
		method = fr_dict_enum_name_by_value(attr_eap_aka_sim_method_hint,
						     fr_box_uint32(FR_METHOD_HINT_VALUE_SIM));
		break;

	case AKA_SIM_METHOD_HINT_AKA:
		method = fr_dict_enum_name_by_value(attr_eap_aka_sim_method_hint,
						     fr_box_uint32(FR_METHOD_HINT_VALUE_AKA));
		break;

	case AKA_SIM_METHOD_HINT_AKA_PRIME:
		method = fr_dict_enum_name_by_value(attr_eap_aka_sim_method_hint,
						     fr_box_uint32(FR_METHOD_HINT_VALUE_AKA_PRIME));
		break;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrndup(ctx, vb, NULL, method, strlen(method), false);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const aka_sim_xlat_id_type_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Returns the type of identity used
 *
@verbatim
%(aka_sim_id_type:%{id_attr})
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t aka_sim_xlat_id_type_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
					       UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					       fr_value_box_list_t *in)
{
	char const			*type;
	fr_aka_sim_id_type_t		type_hint;
	fr_aka_sim_method_hint_t	method_hint;
	fr_value_box_t			*id = fr_dlist_head(in);
	fr_value_box_t			*vb;

	if (fr_aka_sim_id_type(&type_hint, &method_hint, id->vb_strvalue, id->vb_length) < 0) {
		RPEDEBUG2("AKA/AKA/SIM Id \"%pV\" has unrecognised format", id);
		return XLAT_ACTION_FAIL;
	}

	switch (type_hint) {
	default:
	case AKA_SIM_ID_TYPE_UNKNOWN:
		return XLAT_ACTION_DONE;

	case AKA_SIM_ID_TYPE_PERMANENT:
		type = fr_dict_enum_name_by_value(attr_eap_aka_sim_identity_type,
						   fr_box_uint32(FR_IDENTITY_TYPE_VALUE_PERMANENT));
		break;

	case AKA_SIM_ID_TYPE_PSEUDONYM:
		type = fr_dict_enum_name_by_value(attr_eap_aka_sim_identity_type,
						   fr_box_uint32(FR_IDENTITY_TYPE_VALUE_PSEUDONYM));
		break;

	case AKA_SIM_ID_TYPE_FASTAUTH:
		type = fr_dict_enum_name_by_value(attr_eap_aka_sim_identity_type,
						   fr_box_uint32(FR_IDENTITY_TYPE_VALUE_FASTAUTH));
		break;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrndup(ctx, vb, NULL, type, strlen(type), false);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const aka_sim_id_3gpp_pseudonym_key_index_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Returns the key index from a 3gpp pseudonym
 *
@verbatim
%(3gpp_pseudonym_key_index:%{id_attr})
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t aka_sim_id_3gpp_pseudonym_key_index_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
							      UNUSED void const *xlat_inst,
							      UNUSED void *xlat_thread_inst, fr_value_box_list_t *in)
{
	fr_value_box_t	*id = fr_dlist_head(in);
	fr_value_box_t	*vb;

	if (id->vb_length != AKA_SIM_3GPP_PSEUDONYM_LEN) {
		REDEBUG2("3gpp pseudonym incorrect length, expected %i bytes, got %zu bytes",
			 AKA_SIM_3GPP_PSEUDONYM_LEN, id->vb_length);
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
	vb->vb_uint8 = fr_aka_sim_id_3gpp_pseudonym_tag(id->vb_strvalue);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Decrypt a 3gpp pseudonym
 *
@verbatim
%(3gpp_pseudonym_decrypt:&id_attr &key_attr)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t aka_sim_3gpp_pseudonym_decrypt_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
							 UNUSED void const *xlat_inst,
							 UNUSED void *xlat_thread_inst, fr_value_box_list_t *in)
{
	tmpl_t	*id_vpt, *key_vpt;
	TALLOC_CTX	*our_ctx = talloc_init_const("aka_sim_xlat");
	ssize_t		slen, id_len, key_len;
	uint8_t		tag;
	char		out_tag, *buff;
	uint8_t		*key;
	char		decrypted[AKA_SIM_IMSI_MAX_LEN + 1];
	char const	*id;
	fr_value_box_t	*id_vb = fr_dlist_head(in);
	fr_value_box_t	*key_vb = fr_dlist_next(in, id_vb);
	fr_value_box_t	*vb;

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &id_vpt, &FR_SBUFF_IN(id_vb->vb_strvalue, id_vb->vb_length),
				      NULL,
				      &(tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid ID attribute reference");
	error:
		talloc_free(our_ctx);
		return XLAT_ACTION_FAIL;
	}

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &key_vpt, &FR_SBUFF_IN(key_vb->vb_strvalue, key_vb->vb_length),
				      NULL,
				      &(tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = TMPL_ATTR_REF_PREFIX_AUTO
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
	if (id_len != (AKA_SIM_3GPP_PSEUDONYM_LEN + 1)) {
		REDEBUG2("3gpp pseudonym incorrect length, expected %i bytes, got %zu bytes",
			 AKA_SIM_3GPP_PSEUDONYM_LEN + 1, id_len);
		goto error;
	}

	key_len = talloc_array_length(key);
	if (key_len != 16) {
		REDEBUG2("Decryption key incorrect length, expected %i bytes, got %zu bytes", 16, key_len);
		goto error;
	}

	tag = fr_aka_sim_id_3gpp_pseudonym_tag(id);
	switch (tag) {
	case ID_TAG_SIM_PSEUDONYM_B64:
		out_tag = ID_TAG_SIM_PERMANENT;
		break;

	case ID_TAG_AKA_PSEUDONYM_B64:
		out_tag = ID_TAG_AKA_PERMANENT;
		break;

	case ID_TAG_AKA_PRIME_PSEUDONYM_B64:
		out_tag = ID_TAG_AKA_PRIME_PERMANENT;
		break;

	default:
		REDEBUG2("Unexpected tag value (%u) in AKA/SIM Id \"%pV\"", tag, fr_box_strvalue_len(id, id_len));
		goto error;
	}

	RDEBUG2("Decrypting \"%pV\"", fr_box_strvalue_len(id, id_len));
	if (fr_aka_sim_id_3gpp_pseudonym_decrypt(decrypted, id, key) < 0) {
		RPEDEBUG2("Failed decrypting AKA/SIM Id");
		goto error;
	}

	/*
	 *	Recombine unencrypted IMSI with tag
	 */
	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_bstr_alloc(ctx, &buff, vb, NULL, AKA_SIM_IMSI_MAX_LEN + 1, false);
	*buff = out_tag;
	strncpy(buff+1, decrypted, AKA_SIM_IMSI_MAX_LEN + 1);
	fr_dcursor_append(out, vb);
	talloc_free(our_ctx);

	return XLAT_ACTION_DONE;
}

extern xlat_arg_parser_t aka_sim_3gpp_pseudonym_decrypt_xlat_args[];
xlat_arg_parser_t aka_sim_3gpp_pseudonym_decrypt_xlat_args[] = {
	{ .required = true, .concat = true, .single = false, .variadic = false, .type = FR_TYPE_STRING,
	  .func = NULL, .uctx = NULL },
	{ .required = true, .concat = true, .single = false, .variadic = false, .type = FR_TYPE_STRING,
	  .func = NULL, .uctx = NULL },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Encrypts a 3gpp pseudonym
 *
@verbatim
%(3gpp_pseudonym_encrypt:&id_attr &key_attr key_index)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t aka_sim_3gpp_pseudonym_encrypt_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
							 UNUSED void const *xlat_inst,
							 UNUSED void *xlat_thread_inst, fr_value_box_list_t *in)
{
	tmpl_t				*id_vpt, *key_vpt;
	TALLOC_CTX			*our_ctx = talloc_init_const("aka_sim_xlat");
	ssize_t				slen, id_len, key_len;
	uint8_t				*key, tag = 0;
	unsigned long			key_index;
	char				encrypted[AKA_SIM_3GPP_PSEUDONYM_LEN + 1];
	char const			*id;
	char const			*id_p, *id_end;
	fr_aka_sim_id_type_t		type_hint;
	fr_aka_sim_method_hint_t	method_hint;
	fr_value_box_t			*id_vb = fr_dlist_head(in);
	fr_value_box_t			*attr_vb = fr_dlist_next(in, id_vb);
	fr_value_box_t			*index_vb = fr_dlist_next(in, attr_vb);
	fr_value_box_t			*vb;

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &id_vpt, &FR_SBUFF_IN(id_vb->vb_strvalue, id_vb->vb_length),
				      NULL,
				      &(tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid ID attribute reference");
	error:
		talloc_free(our_ctx);
		return XLAT_ACTION_FAIL;
	}

	slen = tmpl_afrom_attr_substr(our_ctx, NULL, &key_vpt, &FR_SBUFF_IN(attr_vb->vb_strvalue, attr_vb->vb_length),
				      NULL,
				      &(tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid key attribute reference");
		goto error;
	}

	/*
	 *	Get the key index
	 */
	key_index = index_vb->vb_uint8;
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
	if (id_len == (AKA_SIM_IMSI_MAX_LEN + 1)) {	/* +1 for ID tag */
		if (fr_aka_sim_id_type(&type_hint, &method_hint, id, id_len) < 0) {
			RPEDEBUG2("SIM ID \"%pV\" has unrecognised format", fr_box_strvalue_len(id, id_len));
			goto error;
		}

		if (type_hint != AKA_SIM_ID_TYPE_PERMANENT) {
			REDEBUG2("SIM ID \"%pV\" is not a permanent identity (IMSI)", fr_box_strvalue_len(id, id_len));
			goto error;
		}

		switch (method_hint) {
		case AKA_SIM_METHOD_HINT_SIM:
			tag = ID_TAG_SIM_PSEUDONYM_B64;
			break;

		case AKA_SIM_METHOD_HINT_AKA:
			tag = ID_TAG_AKA_PSEUDONYM_B64;
			break;

		case AKA_SIM_METHOD_HINT_AKA_PRIME:
			tag = ID_TAG_AKA_PRIME_PSEUDONYM_B64;
			break;

		case AKA_SIM_METHOD_HINT_UNKNOWN:
		case AKA_SIM_METHOD_HINT_MAX:
			REDEBUG2("AKA/SIM ID \"%pV\" does not contain a method hint", fr_box_strvalue_len(id, id_len));
			goto error;
		}

		id_p = id + 1;
		id_end = (id_p + id_len) - 1;
	/*
	 *	ID lacks a hint byte, figure it out from &control.EAP-Type
	 */
	} else if ((id_len >= AKA_SIM_IMSI_MIN_LEN) && (id_len <= AKA_SIM_IMSI_MAX_LEN)) {
		fr_pair_t *eap_type;

		eap_type = fr_pair_find_by_da(&request->control_pairs, attr_eap_type);
		if (!eap_type) {
			REDEBUG("SIM ID does not contain method hint, and no &control.EAP-Type found.  "
				"Don't know what tag to prepend to encrypted identity");
			goto error;
		}

		if (eap_type->vp_uint32 == enum_eap_type_sim->vb_uint32) {
			tag = ID_TAG_SIM_PSEUDONYM_B64;
		} else if (eap_type->vp_uint32 == enum_eap_type_aka->vb_uint32) {
			tag = ID_TAG_AKA_PSEUDONYM_B64;
		} else if (eap_type->vp_uint32 == enum_eap_type_aka_prime->vb_uint32) {
			tag = ID_TAG_AKA_PRIME_PSEUDONYM_B64;
		} else {
			REDEBUG("&control.EAP-Type does not match a SIM based EAP-Type (SIM, AKA, AKA-Prime)");
		}

		id_p = id;
		id_end = id_p + id_len;
	} else {
		REDEBUG2("IMSI incorrect length, expected %i bytes, got %zu bytes", AKA_SIM_IMSI_MAX_LEN + 1,
			 id_len);
		goto error;

	}

	/*
	 *	Encrypt the IMSI
	 *
	 *	Strip existing tag from the permanent id
	 */
	if (fr_aka_sim_id_3gpp_pseudonym_encrypt(encrypted, id_p, id_end - id_p, tag, (uint8_t)key_index, key) < 0) {
		RPEDEBUG2("Failed encrypting SIM ID \"%pV\"", fr_box_strvalue_len(id, id_len));
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrndup(ctx, vb, NULL, encrypted, strlen(encrypted), false);
	fr_dcursor_append(out, vb);
	talloc_free(our_ctx);

	return XLAT_ACTION_DONE;
}

extern xlat_arg_parser_t aka_sim_3gpp_pseudonym_encrypt_xlat_args[];
xlat_arg_parser_t aka_sim_3gpp_pseudonym_encrypt_xlat_args[] = {
	{ .required = true, .concat = true, .single = false, .variadic = false, .type = FR_TYPE_STRING,
	  .func = NULL, .uctx = NULL },
	{ .required = true, .concat = true, .single = false, .variadic = false, .type = FR_TYPE_STRING,
	  .func = NULL, .uctx = NULL },
	{ .required = true, .concat = false, .single = true, .variadic = false, .type = FR_TYPE_UINT8,
	  .func = NULL, .uctx = NULL },
	XLAT_ARG_PARSER_TERMINATOR
};

void fr_aka_sim_xlat_register(void)
{
	xlat_t	*xlat;

	if (aka_sim_xlat_refs) {
		aka_sim_xlat_refs++;
		return;
	}

	xlat = xlat_register(NULL, "aka_sim_id_method", aka_sim_xlat_id_method_xlat, false);
	xlat_func_args(xlat, aka_sim_xlat_id_method_xlat_args);
	xlat = xlat_register(NULL, "aka_sim_id_type", aka_sim_xlat_id_type_xlat, false);
	xlat_func_args(xlat, aka_sim_xlat_id_type_xlat_args);
	xlat = xlat_register(NULL, "3gpp_pseudonym_key_index", aka_sim_id_3gpp_pseudonym_key_index_xlat, false);
	xlat_func_args(xlat, aka_sim_id_3gpp_pseudonym_key_index_xlat_args);
	xlat = xlat_register(NULL, "3gpp_pseudonym_decrypt", aka_sim_3gpp_pseudonym_decrypt_xlat, false);
	xlat_func_args(xlat, aka_sim_3gpp_pseudonym_decrypt_xlat_args);
	xlat = xlat_register(NULL, "3gpp_pseudonym_encrypt", aka_sim_3gpp_pseudonym_encrypt_xlat, false);
	xlat_func_args(xlat, aka_sim_3gpp_pseudonym_encrypt_xlat_args);
	aka_sim_xlat_refs = 1;
}

void fr_aka_sim_xlat_unregister(void)
{
	if (aka_sim_xlat_refs > 1) {
		aka_sim_xlat_refs--;
		return;
	}

	xlat_unregister("aka_sim_id_method");
	xlat_unregister("aka_sim_id_type");
	xlat_unregister("3gpp_pseudonym_key_index");
	xlat_unregister("3gpp_pseudonym_decrypt");
	xlat_unregister("3gpp_pseudonym_encrypt");
	aka_sim_xlat_refs = 0;
}
