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
 * @copyright 2008  The FreeRADIUS server project
 * @copyright 2008  Alan DeKok <aland@deployingradius.com>
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/rad_assert.h>

/** Client field
 *
 */
typedef struct {
	CONF_SECTION	*cs;		//!< Client's CONF_SECTION.
	CONF_PAIR	*cp;		//!< First instance of the field in the client's CONF_SECTION.
	char const	*field;		//!< Field name.
} client_get_vp_ctx_t;

static int _map_proc_client_get_vp(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request,
				   vp_map_t const *map, void *uctx)
{
	client_get_vp_ctx_t	*client = uctx;
	VALUE_PAIR		*head = NULL, *vp;
	fr_cursor_t		cursor;
	fr_dict_attr_t const	*da;
	CONF_PAIR const		*cp;

	rad_assert(ctx != NULL);

	fr_cursor_init(&cursor, &head);

	/*
	 *	FIXME: allow multiple entries.
	 */
	if (map->lhs->type == TMPL_TYPE_ATTR) {
		da = map->lhs->tmpl_da;
	} else {
		char *attr;

		if (tmpl_aexpand(ctx, &attr, request, map->lhs, NULL, NULL) <= 0) {
			RWDEBUG("Failed expanding string");
			return -1;
		}

		da = fr_dict_attr_by_name(request->dict, attr);
		if (!da) {
			RWDEBUG("No such attribute '%s'", attr);
			return -1;
		}

		talloc_free(attr);
	}

	for (cp = client->cp;
	     cp;
	     cp = cf_pair_find_next(client->cs, cp, client->field)) {
		char const *value = cf_pair_value(cp);

		MEM(vp = fr_pair_afrom_da(ctx, da));
		if (fr_pair_value_from_str(vp, value, talloc_array_length(value) - 1, '\0', false) < 0) {
			RWDEBUG("Failed parsing value \"%pV\" for attribute %s: %s", fr_box_strvalue(value),
				map->lhs->tmpl_da->name, fr_strerror());
			fr_pair_list_free(&head);
			talloc_free(vp);
			return -1;
		}

		vp->op = map->op;
		fr_cursor_append(&cursor, vp);

		if (map->op != T_OP_ADD) break;	/* Create multiple attribute for multiple CONF_PAIRs */
	}

	*out = head;

	return 0;
}

/** Map multiple attributes from a client into the request
 *
 * @param[in] mod_inst		NULL.
 * @param[in] proc_inst		NULL.
 * @param[in] request		The current request.
 * @param[in] client_override	If NULL, use the current client, else use the client matching
 *				the ip given.
 * @param[in] maps		Head of the map list.
 * @return
 *	- #RLM_MODULE_NOOP no rows were returned.
 *	- #RLM_MODULE_UPDATED if one or more #VALUE_PAIR were added to the #REQUEST.
 *	- #RLM_MODULE_FAIL if an error occurred.
 */
static rlm_rcode_t map_proc_client(UNUSED void *mod_inst, UNUSED void *proc_inst, REQUEST *request,
				   fr_value_box_t **client_override, vp_map_t const *maps)
{
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	vp_map_t const		*map;
	RADCLIENT		*client;
	client_get_vp_ctx_t	uctx;

	if (*client_override) {
		fr_ipaddr_t	ip;
		char const	*client_str;

		/*
		 *	Concat don't asprint, as this becomes a noop
		 *	in the vast majority of cases.
		 */
		if (fr_value_box_list_concat(request, *client_override, client_override, FR_TYPE_STRING, true) < 0) {
			REDEBUG("Failed concatenating input data");
			return RLM_MODULE_FAIL;
		}
		client_str = (*client_override)->vb_strvalue;

		if (fr_inet_pton(&ip, client_str, -1, AF_UNSPEC, false, true) < 0) {
			REDEBUG("\"%s\" is not a valid IPv4 or IPv6 address", client_str);
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		client = client_find(NULL, &ip, IPPROTO_IP);
		if (!client) {
			RDEBUG("No client found with IP \"%s\"", client_str);
			return 0;
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
		client = request->client;
	}
	uctx.cs = client->cs;

	RINDENT();
	for (map = maps;
	     map != NULL;
	     map = map->next) {
		char	*field = NULL;

		if (tmpl_aexpand(request, &field, request, map->rhs, NULL, NULL) < 0) {
			RDEBUG("Failed expanding RHS at %s", map->lhs->name);
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
	return rcode;
}

/*
 *	Xlat for %{client:[<ipaddr>.]foo}
 */
static ssize_t xlat_client(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	char const	*value = NULL;
	char		buffer[INET6_ADDRSTRLEN], *q;
	char const	*p = fmt;
	fr_ipaddr_t	ip;
	CONF_PAIR	*cp;
	RADCLIENT	*client = NULL;

	*out = NULL;

	q = strrchr(p, '.');
	if (q) {
		strlcpy(buffer, p, (q + 1) - p);
		if (fr_inet_pton(&ip, buffer, -1, AF_UNSPEC, false, true) < 0) goto request_client;

		p = q + 1;

		client = client_find(NULL, &ip, IPPROTO_IP);
		if (!client) {
			RDEBUG("No client found with IP \"%s\"", buffer);
			return 0;
		}
	} else {
	request_client:
		client = request->client;
		if (!client) {
			RERROR("No client associated with this request");

			return -1;
		}
	}

	cp = cf_pair_find(client->cs, p);
	if (!cp || !(value = cf_pair_value(cp))) {
		if (strcmp(fmt, "shortname") == 0 && request->client->shortname) {
			value = request->client->shortname;
		}
		else if (strcmp(fmt, "nas_type") == 0 && request->client->nas_type) {
			value = request->client->nas_type;
		}
		if (!value) return 0;
	}

	*out = talloc_typed_strdup(ctx, value);
	return talloc_array_length(*out) - 1;
}


/*
 *	Find the client definition.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, UNUSED void *thread, REQUEST *request)
{
	size_t length;
	char const *value;
	CONF_PAIR *cp;
	RADCLIENT *c;
	CONF_SECTION *server_cs;
	char buffer[2048];

	/*
	 *	Ensure we're only being called from the main thread,
	 *	with fake packets.
	 */
	if ((request->packet->src_port != 0) || (request->packet->vps != NULL) ||
	    (request->parent != NULL)) {
		RDEBUG("Improper configuration");
		return RLM_MODULE_NOOP;
	}

	if (!request->client || !request->client->cs) {
		RDEBUG("Unknown client definition");
		return RLM_MODULE_NOOP;
	}

	cp = cf_pair_find(request->client->cs, "directory");
	if (!cp) {
		RDEBUG("No directory configuration in the client");
		return RLM_MODULE_NOOP;
	}

	value = cf_pair_value(cp);
	if (!value) {
		RDEBUG("No value given for the directory entry in the client");
		return RLM_MODULE_NOOP;
	}

	length = strlen(value);
	if (length > (sizeof(buffer) - 256)) {
		RDEBUG("Directory name too long");
		return RLM_MODULE_NOOP;
	}

	memcpy(buffer, value, length + 1);
	fr_inet_ntoh(&request->packet->src_ipaddr, buffer + length, sizeof(buffer) - length - 1);

	/*
	 *	Read the buffer and generate the client.
	 */
	if (request->client->server) {
		server_cs = request->client->server_cs;

	} else if (request->listener) {
		server_cs = request->listener->server_cs;
	} else {
		return RLM_MODULE_FAIL;
	}

	c = client_read(buffer, server_cs, true);
	if (!c) return RLM_MODULE_FAIL;

	/*
	 *	Replace the client.  This is more than a bit of a
	 *	hack.
	 */
	request->client = c;

	return RLM_MODULE_OK;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_bootstrap(void *instance, UNUSED CONF_SECTION *conf)
{
	xlat_register(instance, "client", xlat_client, NULL, NULL, 0, 0, true);
	map_proc_register(instance, "client", map_proc_client, NULL, 0);

	return 0;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern rad_module_t rlm_client;
rad_module_t rlm_client = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dynamic_clients",
	.type		= RLM_TYPE_THREAD_SAFE,		/* type */
	.bootstrap	= mod_bootstrap,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize
	},
};
