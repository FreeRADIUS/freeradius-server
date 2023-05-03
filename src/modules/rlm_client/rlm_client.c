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
 * @file rlm_client.c
 * @brief Reads client definitions from flat files as required.
 *
 * @copyright 2008 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include "lib/server/cf_util.h"
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/unlang/xlat_func.h>

/** Client field
 *
 */
typedef struct {
	CONF_SECTION	*cs;		//!< Client's CONF_SECTION.
	CONF_PAIR	*cp;		//!< First instance of the field in the client's CONF_SECTION.
	char const	*field;		//!< Field name.
} client_get_vp_ctx_t;

static int _map_proc_client_get_vp(TALLOC_CTX *ctx, fr_pair_list_t *out, request_t *request,
				   map_t const *map, void *uctx)
{
	client_get_vp_ctx_t	*client = uctx;
	fr_pair_list_t		head;
	fr_pair_t		*vp;
	fr_dict_attr_t const	*da;
	CONF_PAIR const		*cp;

	fr_assert(ctx != NULL);

	fr_pair_list_init(&head);

	/*
	 *	FIXME: allow multiple entries.
	 */
	if (tmpl_is_attr(map->lhs)) {
		da = tmpl_attr_tail_da(map->lhs);
	} else {
		char *attr;

		if (tmpl_aexpand(ctx, &attr, request, map->lhs, NULL, NULL) <= 0) {
			RWDEBUG("Failed expanding string");
		error:
			fr_pair_list_free(&head);
			return -1;
		}

		da = fr_dict_attr_by_name(NULL, fr_dict_root(request->dict), attr);
		if (!da) {
			RWDEBUG("No such attribute '%s'", attr);
			talloc_free(attr);
			goto error;
		}

		talloc_free(attr);
	}

	for (cp = client->cp;
	     cp;
	     cp = cf_pair_find_next(client->cs, cp, client->field)) {
		char const *value = cf_pair_value(cp);

		MEM(vp = fr_pair_afrom_da(ctx, da));
		if (fr_pair_value_from_str(vp, value, talloc_array_length(value) - 1, NULL, false) < 0) {
			RWDEBUG("Failed parsing value \"%pV\" for attribute %s: %s", fr_box_strvalue(value),
				tmpl_attr_tail_da(map->lhs)->name, fr_strerror());
			talloc_free(vp);
			goto error;
		}

		fr_pair_append(&head, vp);

		if (map->op != T_OP_ADD_EQ) break;	/* Create multiple attribute for multiple CONF_PAIRs */
	}

	fr_pair_list_append(out, &head);

	return 0;
}

/** Map multiple attributes from a client into the request
 *
 * @param[out] p_result		Result of applying the map:
 *				- #RLM_MODULE_NOOP no rows were returned.
 *				- #RLM_MODULE_UPDATED if one or more #fr_pair_t were added to the #request_t.
 *				- #RLM_MODULE_FAIL if an error occurred.
 * @param[in] mod_inst		NULL.
 * @param[in] proc_inst		NULL.
 * @param[in] request		The current request.
 * @param[in] client_override	If NULL, use the current client, else use the client matching
 *				the ip given.
 * @param[in] maps		Head of the map list.
 * @return UNLANG_ACTION_CALCULATE_RESULT
 */
static unlang_action_t map_proc_client(rlm_rcode_t *p_result, UNUSED void *mod_inst, UNUSED void *proc_inst,
				       request_t *request, fr_value_box_list_t *client_override, map_list_t const *maps)
{
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	map_t const		*map = NULL;
	fr_client_t		*client;
	client_get_vp_ctx_t	uctx;

	if (!fr_value_box_list_empty(client_override)) {
		fr_ipaddr_t	ip;
		char const	*client_str;
		fr_value_box_t	*client_override_head = fr_value_box_list_head(client_override);

		/*
		 *	Concat don't asprint, as this becomes a noop
		 *	in the vast majority of cases.
		 */
		if (fr_value_box_list_concat_in_place(request,
						      client_override_head, client_override, FR_TYPE_STRING,
						      FR_VALUE_BOX_LIST_FREE, true,
						      SIZE_MAX) < 0) {
			REDEBUG("Failed concatenating input data");
			RETURN_MODULE_FAIL;
		}
		client_str = client_override_head->vb_strvalue;

		if (fr_inet_pton(&ip, client_str, -1, AF_UNSPEC, false, true) < 0) {
			REDEBUG("\"%s\" is not a valid IPv4 or IPv6 address", client_str);
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		client = client_find(NULL, &ip, IPPROTO_IP);
		if (!client) {
			RDEBUG("No client found with IP \"%s\"", client_str);
			rcode = RLM_MODULE_NOTFOUND;
			goto finish;
		}

		if (client->cs) {
			char const *filename;
			int line;

			filename = cf_filename(client->cs);
			line = cf_lineno(client->cs);

			if (filename) {
				RDEBUG2("Found client matching \"%s\".  Defined in \"%s\" line %i",
					client_str, filename, line);
			} else {
				RDEBUG2("Found client matching \"%s\"", client_str);
			}
		}
	} else {
		client = client_from_request(request);
		if (!client) {
			REDEBUG("No client associated with this request");
			RETURN_MODULE_FAIL;
		}
	}
	uctx.cs = client->cs;

	RINDENT();
	while ((map = map_list_next(maps, map))) {
		char	*field = NULL;

		if (tmpl_aexpand(request, &field, request, map->rhs, NULL, NULL) < 0) {
			REDEBUG("Failed expanding RHS at %s", map->lhs->name);
			rcode = RLM_MODULE_FAIL;
			talloc_free(field);
			break;
		}

		uctx.cp = cf_pair_find(client->cs, field);
		if (!uctx.cp) {
			RDEBUG3("No matching client property \"%s\", skipping...", field);
			goto next;			/* No matching CONF_PAIR found */
		}
		uctx.field = field;

		/*
		 *	Pass the raw data to the callback, which will
		 *	create the VP and add it to the map.
		 */
		if (map_to_request(request, map, _map_proc_client_get_vp, &uctx) < 0) {
			rcode = RLM_MODULE_FAIL;
			talloc_free(field);
			break;
		}
		rcode = RLM_MODULE_UPDATED;

	next:
		talloc_free(field);
	}
	REXDENT();

finish:
	RETURN_MODULE_RCODE(rcode);
}

static xlat_arg_parser_t const xlat_client_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	{ .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** xlat to get client config data
 *
 * Example:
@verbatim
%(client:foo [<ipaddr>])
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_client(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 UNUSED xlat_ctx_t const *xctx,
				 request_t *request, fr_value_box_list_t *in)
{
	char const	*value = NULL;
	fr_ipaddr_t	ip;
	CONF_PAIR	*cp;
	fr_client_t	*client = NULL;
	fr_value_box_t	*field = fr_value_box_list_head(in);
	fr_value_box_t	*client_ip = fr_value_box_list_next(in, field);
	fr_value_box_t	*vb;

	if (client_ip) {
		if (fr_inet_pton(&ip, client_ip->vb_strvalue, -1, AF_UNSPEC, false, true) < 0) {
			RDEBUG("Invalid client IP address \"%s\"", client_ip->vb_strvalue);
			return XLAT_ACTION_FAIL;
		}

		client = client_find(NULL, &ip, IPPROTO_IP);
		if (!client) {
			RDEBUG("No client found with IP \"%s\"", client_ip->vb_strvalue);
			return XLAT_ACTION_FAIL;
		}
	} else {
		client = client_from_request(request);
		if (!client) {
			REDEBUG("No client associated with this request");
			return XLAT_ACTION_FAIL;
		}
	}

	cp = cf_pair_find(client->cs, field->vb_strvalue);
	if (!cp || !(value = cf_pair_value(cp))) {
		if (strcmp(field->vb_strvalue, "shortname") == 0 && client->shortname) {
			value = client->shortname;
		}
		else if (strcmp(field->vb_strvalue, "nas_type") == 0 && client->nas_type) {
			value = client->nas_type;
		}
		if (!value) return XLAT_ACTION_DONE;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));

	if (fr_value_box_strdup(ctx, vb, NULL, value, false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}


/*
 *	Find the client definition.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	size_t		length;
	char const	*value;
	CONF_PAIR	*cp;
	char		buffer[2048];
	fr_client_t	*client;

	/*
	 *	Ensure we're only being called from the main thread,
	 *	with fake packets.
	 */
	if ((request->packet->socket.inet.src_port != 0) || (!fr_pair_list_empty(&request->request_pairs)) ||
	    (request->parent != NULL)) {
		REDEBUG("Improper configuration");
		RETURN_MODULE_NOOP;
	}

	client = client_from_request(request);
	if (!client || !client->cs) {
		REDEBUG("Unknown client definition");
		RETURN_MODULE_NOOP;
	}

	cp = cf_pair_find(client->cs, "directory");
	if (!cp) {
		REDEBUG("No directory configuration in the client");
		RETURN_MODULE_NOOP;
	}

	value = cf_pair_value(cp);
	if (!value) {
		REDEBUG("No value given for the directory entry in the client");
		RETURN_MODULE_NOOP;
	}

	length = strlen(value);
	if (length > (sizeof(buffer) - 256)) {
		REDEBUG("Directory name too long");
		RETURN_MODULE_NOOP;
	}

	memcpy(buffer, value, length + 1);
	fr_inet_ntoh(&request->packet->socket.inet.src_ipaddr, buffer + length, sizeof(buffer) - length - 1);

	/*
	 *	Read the buffer and generate the client.
	 */
	if (!client->server) RETURN_MODULE_FAIL;

	client = client_read(buffer, client->server_cs, true);
	if (!client) RETURN_MODULE_FAIL;

	/*
	 *	Replace the client.  This is more than a bit of a
	 *	hack.
	 */
	request->client = client;

	RETURN_MODULE_OK;
}

static int mod_load(void)
{
	xlat_t	*xlat;

	if (unlikely((xlat = xlat_func_register(NULL, "client", xlat_client, FR_TYPE_STRING)) == NULL)) return -1;
	xlat_func_args_set(xlat, xlat_client_args);

	map_proc_register(NULL, "client", map_proc_client, NULL, 0);

	return 0;
}

static void mod_unload(void)
{
	xlat_func_unregister("client");
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_client;
module_rlm_t rlm_client = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "dynamic_clients",
		.type		= MODULE_TYPE_THREAD_SAFE,		/* type */
		.onload		= mod_load,
		.unload		= mod_unload
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = CF_IDENT_ANY, .name2 = CF_IDENT_ANY,		.method = mod_authorize   },
		MODULE_NAME_TERMINATOR
	}
};
