/*
 * @file xlat.c
 * @brief String expansion ("translation"). Implements %Attribute -> value
 *
 * Version:	$Id$
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/rad_assert.h>
#include	<freeradius-devel/base64.h>

#include	<ctype.h>

typedef struct xlat_t {
	char		module[MAX_STRING_LEN];
	int		length;
	void		*instance;
	RAD_XLAT_FUNC	do_xlat;
	int		internal;	/* not allowed to re-define these */
} xlat_t;

static rbtree_t *xlat_root = NULL;

/*
 *	Define all xlat's in the structure.
 */
static const char * const internal_xlat[] = {"check",
					     "request",
					     "reply",
					     "proxy-request",
					     "proxy-reply",
					     "outer.request",
					     "outer.reply",
					     "outer.control",
					     NULL};
#ifdef WITH_UNLANG
static const char * const xlat_foreach_names[] = {"Foreach-Variable-0",
						  "Foreach-Variable-1",
						  "Foreach-Variable-2",
						  "Foreach-Variable-3",
						  "Foreach-Variable-4",
						  "Foreach-Variable-5",
						  "Foreach-Variable-6",
						  "Foreach-Variable-7",
						  "Foreach-Variable-8",
						  "Foreach-Variable-9",
						  NULL};
#endif

#if REQUEST_MAX_REGEX > 8
#error Please fix the following line
#endif
static int xlat_inst[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };	/* up to 8 for regex */

/**
 * @brief Convert the value on a VALUE_PAIR to string
 */
static int valuepair2str(char * out,int outlen,VALUE_PAIR * pair, int type)
{
	if (pair != NULL) {
		vp_prints_value(out, outlen, pair, -1);
		return strlen(out);
	}

	switch (type) {
	case PW_TYPE_STRING :
		strlcpy(out,"_",outlen);
		break;
	case PW_TYPE_INTEGER64:
	case PW_TYPE_SIGNED:
	case PW_TYPE_INTEGER:
		strlcpy(out,"0",outlen);
		break;
	case PW_TYPE_IPADDR :
		strlcpy(out,"?.?.?.?",outlen);
		break;
	case PW_TYPE_IPV6ADDR :
		strlcpy(out,":?:",outlen);
		break;
	case PW_TYPE_DATE :
		strlcpy(out,"0",outlen);
		break;
	default :
		strlcpy(out,"unknown_type",outlen);
	}
	return strlen(out);
}

static VALUE_PAIR *pairfind_tag(VALUE_PAIR *vps, const DICT_ATTR *da, int tag)
{
	VALUE_PAIR *vp = vps;

redo:
	vp = pairfind(vp, da->attr, da->vendor);
	if (!tag) return vp;

	if (!vp) return NULL;

	if (!vp->flags.has_tag) return NULL;

	if (vp->flags.tag == tag) return vp;
	
	vp = vp->next;
	goto redo;
}

/*
 *	Dynamically translate for check:, request:, reply:, etc.
 */
static size_t xlat_packet(void *instance, REQUEST *request,
			  const char *fmt, char *out, size_t outlen)
{
	DICT_ATTR	*da;
	VALUE_PAIR	*vp;
	VALUE_PAIR	*vps = NULL;
	RADIUS_PACKET	*packet = NULL;

	switch (*(int*) instance) {
	case 0:
		vps = request->config_items;
		break;

	case 1:
		vps = request->packet->vps;
		packet = request->packet;
		break;

	case 2:
		vps = request->reply->vps;
		packet = request->reply;
		break;

	case 3:
#ifdef WITH_PROXY
		if (request->proxy) vps = request->proxy->vps;
		packet = request->proxy;
#endif
		break;

	case 4:
#ifdef WITH_PROXY
		if (request->proxy_reply) vps = request->proxy_reply->vps;
		packet = request->proxy_reply;
#endif
		break;

	case 5:
		if (request->parent) {
			vps = request->parent->packet->vps;
			packet = request->parent->packet;
		}
		break;
			
	case 6:
		if (request->parent && request->parent->reply) {
			vps = request->parent->reply->vps;
			packet = request->parent->reply;
		}
		break;
			
	case 7:
		if (request->parent) {
			vps = request->parent->config_items;
		}
		break;
			
	default:		/* WTF? */
		return 0;
	}

	/*
	 *	The "format" string is the attribute name.
	 */
	da = dict_attrbyname(fmt);
	if (!da) {
		int do_number = FALSE;
		int do_array = FALSE;
		int do_count = FALSE;
		int do_all = FALSE;
		int tag = 0;
		size_t count = 0, total;
		char *p;
		char buffer[256];

		if (strlen(fmt) > sizeof(buffer)) return 0;

		strlcpy(buffer, fmt, sizeof(buffer));

		/*
		 *	%{Attribute-name#} - print integer version of it.
		 */
		p = buffer + strlen(buffer) - 1;
		if (*p == '#') {
			*p = '\0';
			do_number = TRUE;
		}

		/*
		 *	%{Attribute-Name:tag} - get the name with the specified
		 *	value of the tag.
		 */
		p = strchr(buffer, ':');
		if (p) {
			tag = atoi(p + 1);
			*p = '\0';
			p++;

		} else {
			/*
			 *	Allow %{Attribute-Name:tag[...]}
			 */
			p = buffer;
		}

		/*
		 *	%{Attribute-Name[...] does more stuff
		 */
		p = strchr(p, '[');
		if (p) {
			*p = '\0';
			do_array = TRUE;
			if (p[1] == '#') {
				do_count = TRUE;
			} else if (p[1] == '*') {
				do_all = TRUE;
			} else {
				count = atoi(p + 1);
				p += 1 + strspn(p + 1, "0123456789");
				if (*p != ']') {
					RDEBUG2("xlat: Invalid array reference in string at %s %s",
						fmt, p);
					return 0;
				}
			}
		}

		/*
		 *	We COULD argue about %{Attribute-Name[#]#} etc.
		 *	But that looks like more work than it's worth.
		 */

		da = dict_attrbyname(buffer);
		if (!da) return 0;

		/*
		 *	No array, print the tagged attribute.
		 */
		if (!do_array) {
			vp = pairfind_tag(vps, da, tag);
			goto just_print;
		}

		total = 0;

		/*
		 *	Array[#] - return the total
		 */
		if (do_count) {
			for (vp = pairfind_tag(vps, da, tag);
			     vp != NULL;
			     vp = pairfind_tag(vp->next, da, tag)) {
				total++;
			}

			snprintf(out, outlen, "%d", (int) total);
			return strlen(out);
		}

		/*
		 *	%{Attribute-Name[*]} returns ALL of the
		 *	the attributes, separated by a newline.
		 */
		if (do_all) {
			for (vp = pairfind_tag(vps, da, tag);
			     vp != NULL;
			     vp = pairfind_tag(vp->next, da, tag)) {
				count = valuepair2str(out, outlen - 1, vp, da->type);
				rad_assert(count <= outlen);
				total += count + 1;
				outlen -= (count + 1);
				out += count;

				*(out++) = '\n';

				if (outlen <= 1) break;
			}

			*out = '\0';
			return total;
		}

		/*
		 *	Find the N'th value.
		 */
		for (vp = pairfind_tag(vps, da, tag);
		     vp != NULL;
		     vp = pairfind_tag(vp->next, da, tag)) {
			if (total == count) break;
			total++;
			if (total > count) {
				vp = NULL;
				break;
			}
		}

		/*
		 *	Non-existent array reference.
		 */
	just_print:
		if (!vp) return 0;

		if (do_number) {
			if ((vp->type != PW_TYPE_IPADDR) &&
			    (vp->type != PW_TYPE_INTEGER) &&
			    (vp->type != PW_TYPE_SHORT) &&
			    (vp->type != PW_TYPE_BYTE) &&
			    (vp->type != PW_TYPE_DATE)) {
				*out = '\0';
				return 0;
			}
			
			return snprintf(out, outlen, "%u", vp->vp_integer);
		}

		return valuepair2str(out, outlen, vp, da->type);
	}

	vp = pairfind(vps, da->attr, da->vendor);
	if (!vp) {
		/*
		 *	Some "magic" handlers, which are never in VP's, but
		 *	which are in the packet.
		 *
		 *	@bug FIXME: We should really do this in a more
		 *	intelligent way...
		 */
		if (packet) {
			VALUE_PAIR localvp;

			memset(&localvp, 0, sizeof(localvp));

			switch (da->attr) {
			case PW_PACKET_TYPE:
			{
				DICT_VALUE *dval;

				dval = dict_valbyattr(da->attr, da->vendor, packet->code);
				if (dval) {
					snprintf(out, outlen, "%s", dval->name);
				} else {
					snprintf(out, outlen, "%d", packet->code);
				}
				return strlen(out);
			}
			break;

			case PW_CLIENT_SHORTNAME:
				if (request->client && request->client->shortname) {
					strlcpy(out, request->client->shortname, outlen);
				} else {
					strlcpy(out, "<UNKNOWN-CLIENT>", outlen);
				}
				return strlen(out);

			case PW_CLIENT_IP_ADDRESS: /* the same as below */
			case PW_PACKET_SRC_IP_ADDRESS:
				if (packet->src_ipaddr.af != AF_INET) {
					return 0;
				}
				localvp.attribute = da->attr;
				localvp.vp_ipaddr = packet->src_ipaddr.ipaddr.ip4addr.s_addr;
				break;

			case PW_PACKET_DST_IP_ADDRESS:
				if (packet->dst_ipaddr.af != AF_INET) {
					return 0;
				}
				localvp.attribute = da->attr;
				localvp.vp_ipaddr = packet->dst_ipaddr.ipaddr.ip4addr.s_addr;
				break;

			case PW_PACKET_SRC_PORT:
				localvp.attribute = da->attr;
				localvp.vp_integer = packet->src_port;
				break;

			case PW_PACKET_DST_PORT:
				localvp.attribute = da->attr;
				localvp.vp_integer = packet->dst_port;
				break;

			case PW_PACKET_AUTHENTICATION_VECTOR:
				localvp.attribute = da->attr;
				memcpy(localvp.vp_strvalue, packet->vector,
				       sizeof(packet->vector));
				localvp.length = sizeof(packet->vector);
				break;

				/*
				 *	Authorization, accounting, etc.
				 */
			case PW_REQUEST_PROCESSING_STAGE:
				if (request->component) {
					strlcpy(out, request->component, outlen);
				} else {
					strlcpy(out, "server_core", outlen);
				}
				return strlen(out);

			case PW_PACKET_SRC_IPV6_ADDRESS:
				if (packet->src_ipaddr.af != AF_INET6) {
					return 0;
				}
				localvp.attribute = da->attr;
				memcpy(localvp.vp_strvalue,
				       &packet->src_ipaddr.ipaddr.ip6addr,
				       sizeof(packet->src_ipaddr.ipaddr.ip6addr));
				break;

			case PW_PACKET_DST_IPV6_ADDRESS:
				if (packet->dst_ipaddr.af != AF_INET6) {
					return 0;
				}
				localvp.attribute = da->attr;
				memcpy(localvp.vp_strvalue,
				       &packet->dst_ipaddr.ipaddr.ip6addr,
				       sizeof(packet->dst_ipaddr.ipaddr.ip6addr));
				break;

			case PW_VIRTUAL_SERVER:
				if (!request->server) return 0;

				snprintf(out, outlen, "%s", request->server);
				return strlen(out);
				break;

			case PW_MODULE_RETURN_CODE:
				localvp.attribute = da->attr;

				/*
				 *	See modcall.c for a bit of a hack.
				 */
				localvp.vp_integer = request->simul_max;
				break;

			default:
				return 0; /* not found */
				break;
			}

			localvp.type = da->type;
			return valuepair2str(out, outlen, &localvp, da->type);
		}

		/*
		 *	Not found, die.
		 */
		return 0;
	}

	if (!vps) return 0;	/* silently fail */

	/*
	 *	Convert the VP to a string, and return it.
	 */
	return valuepair2str(out, outlen, vp, da->type);
}

/**
 * @brief Print data as integer, not as VALUE.
 */
static size_t xlat_integer(UNUSED void *instance, REQUEST *request,
			   const char *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(request, fmt, &vp) < 0) || !vp) {
		*out = '\0';
		return 0;
	}

	if ((vp->type != PW_TYPE_IPADDR) &&
	    (vp->type != PW_TYPE_INTEGER) &&
	    (vp->type != PW_TYPE_INTEGER64) &&
	    (vp->type != PW_TYPE_SHORT) &&
	    (vp->type != PW_TYPE_BYTE) &&
	    (vp->type != PW_TYPE_DATE)) {
		*out = '\0';
		return 0;
	}

	if (vp->type == PW_TYPE_INTEGER64) {
		return snprintf(out, outlen, "%llu", vp->vp_integer64);
	}

	return snprintf(out, outlen, "%u", vp->vp_integer);
}

/**
 * @brief Print data as hex, not as VALUE.
 */
static size_t xlat_hex(UNUSED void *instance, REQUEST *request,
		       const char *fmt, char *out, size_t outlen)
{
	size_t i;
	VALUE_PAIR *vp;
	uint8_t	buffer[MAX_STRING_LEN];
	ssize_t	ret;
	size_t	len;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(request, fmt, &vp) < 0) || !vp) {
		*out = '\0';
		return 0;
	}
	
	ret = rad_vp2data(vp, buffer, sizeof(buffer));
	len = (size_t) ret;
	
	/*
	 *	Don't truncate the data.
	 */
	if ((ret < 0 ) || (outlen < (len * 2))) {
		*out = 0;
		return 0;
	}

	for (i = 0; i < len; i++) {
		snprintf(out + 2*i, 3, "%02x", buffer[i]);
	}

	return len * 2;
}

/**
 * @brief Print data as base64, not as VALUE
 */
static size_t xlat_base64(UNUSED void *instance, REQUEST *request,
			  const char *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;
	uint8_t buffer[MAX_STRING_LEN];
	ssize_t	ret;
	size_t	len;
	size_t	enc;
	
	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(request, fmt, &vp) < 0) || !vp) {
		*out = '\0';
		return 0;
	}
	
	ret = rad_vp2data(vp, buffer, sizeof(buffer));
	if (ret < 0) {
		*out = 0;
		return 0;
	}
	
	len = (size_t) ret;
	
	enc = FR_BASE64_ENC_LENGTH(len);
	
	/*
	 *	Don't truncate the data.
	 */
	if (outlen < (enc + 1)) {
		*out = 0;
		return 0;
	}
	
	fr_base64_encode(buffer, len, out, outlen);

	return enc;
}

/**
 * @brief Prints the current module processing the request
 */
static size_t xlat_module(UNUSED void *instance, REQUEST *request,
			  UNUSED const char *fmt, char *out, size_t outlen)
{
	strlcpy(out, request->module, outlen);

	return strlen(out);
}

#ifdef WITH_UNLANG
/**
 * @brief Implements the Foreach-Variable-X
 *
 * @see modcall()
 */
static size_t xlat_foreach(void *instance, REQUEST *request,
			   UNUSED const char *fmt, char *out, size_t outlen)
{
	VALUE_PAIR	**pvp;

	/*
	 *	See modcall, "FOREACH" for how this works.
	 */
	pvp = (VALUE_PAIR **) request_data_reference(request, radius_get_vp,
						     *(int*) instance);
	if (!pvp || !*pvp) {
		*out = '\0';
		return 0;
	}

	return valuepair2str(out, outlen, (*pvp), (*pvp)->type);
}
#endif

/**
 * @brief Print data as string, if possible.
 *
 * If attribute "Foo" is defined as "octets" it will normally
 * be printed as 0x0a0a0a. The xlat "%{string:Foo}" will instead
 * expand to "\n\n\n"
 */
static size_t xlat_string(UNUSED void *instance, REQUEST *request,
			  const char *fmt, char *out, size_t outlen)
{
	int len;
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if (outlen < 3) {
	nothing:
		*out = '\0';
		return 0;
	}

	if (radius_get_vp(request, fmt, &vp) < 0) goto nothing;

	if (!vp) goto nothing;

	if (vp->type != PW_TYPE_OCTETS) goto nothing;

	len = fr_print_string(vp->vp_strvalue, vp->length, out, outlen);
	out[len] = '\0';

	return len;
}

#ifdef HAVE_REGEX_H
/*
 * @brief Expand regexp matches %{0} to %{8}
 */
static size_t xlat_regex(void *instance, REQUEST *request,
			 const char *fmt, char *out, size_t outlen)
{
	char *regex;

	/*
	 *	We cheat: fmt is "0" to "8", but those numbers
	 *	are already in the "instance".
	 */
	fmt = fmt;		/* -Wunused */

	regex = request_data_reference(request, request,
				 REQUEST_DATA_REGEX | *(int *)instance);
	if (!regex) return 0;

	/*
	 *	Copy UP TO "freespace" bytes, including
	 *	a zero byte.
	 */
	strlcpy(out, regex, outlen);
	return strlen(out);
}
#endif				/* HAVE_REGEX_H */

/**
 * @brief Dynamically change the debugging level for the current request
 *
 * Example %{debug:3}
 */
static size_t xlat_debug(UNUSED void *instance, REQUEST *request,
			 const char *fmt, char *out, size_t outlen)
{
	int level = 0;
	
	/* 
	 *  Expand to previous (or current) level
	 */
	snprintf(out, outlen, "%d", request->options & RAD_REQUEST_OPTION_DEBUG4);

	/* 
	 *  Assume we just want to get the current value and NOT set it to 0
	 */
	if (!*fmt)
		goto done;
		
	level = atoi(fmt);
	if (level == 0) {
		request->options = RAD_REQUEST_OPTION_NONE;
		request->radlog = NULL;
	} else {
		if (level > 4) level = 4;

		request->options = level;
		request->radlog = radlog_request;
	}
	
	done:
	return strlen(out);
}

/*
 *	Compare two xlat_t structs, based ONLY on the module name.
 */
static int xlat_cmp(const void *a, const void *b)
{
	if (((const xlat_t *)a)->length != ((const xlat_t *)b)->length) {
		return ((const xlat_t *)a)->length - ((const xlat_t *)b)->length;
	}

	return memcmp(((const xlat_t *)a)->module,
		      ((const xlat_t *)b)->module,
		      ((const xlat_t *)a)->length);
}


/*
 *	find the appropriate registered xlat function.
 */
static xlat_t *xlat_find(const char *module)
{
	xlat_t my_xlat;

	strlcpy(my_xlat.module, module, sizeof(my_xlat.module));
	my_xlat.length = strlen(my_xlat.module);

	return rbtree_finddata(xlat_root, &my_xlat);
}


/**
 * @brief Register an xlat function.
 *
 * @param module xlat name
 * @param func xlat function to be called
 * @param instance argument to xlat function
 * @return 0 on success, -1 on failure
 */
int xlat_register(const char *module, RAD_XLAT_FUNC func, void *instance)
{
	xlat_t	*c;
	xlat_t	my_xlat;

	if (!module || !*module) {
		DEBUG("xlat_register: Invalid module name");
		return -1;
	}

	/*
	 *	First time around, build up the tree...
	 *
	 *	FIXME: This code should be hoisted out of this function,
	 *	and into a global "initialization".  But it isn't critical...
	 */
	if (!xlat_root) {
		int i;
#ifdef HAVE_REGEX_H
		char buffer[2];
#endif

		xlat_root = rbtree_create(xlat_cmp, free, 0);
		if (!xlat_root) {
			DEBUG("xlat_register: Failed to create tree.");
			return -1;
		}

		/*
		 *	Register the internal packet xlat's.
		 */
		for (i = 0; internal_xlat[i] != NULL; i++) {
			xlat_register(internal_xlat[i], xlat_packet, &xlat_inst[i]);
			c = xlat_find(internal_xlat[i]);
			rad_assert(c != NULL);
			c->internal = TRUE;
		}

#ifdef WITH_UNLANG
		for (i = 0; xlat_foreach_names[i] != NULL; i++) {
			xlat_register(xlat_foreach_names[i],
				      xlat_foreach, &xlat_inst[i]);
			c = xlat_find(xlat_foreach_names[i]);
			rad_assert(c != NULL);
			c->internal = TRUE;
		}
#endif

		/*
		 *	New name: "control"
		 */
		xlat_register("control", xlat_packet, &xlat_inst[0]);
		c = xlat_find("control");
		rad_assert(c != NULL);
		c->internal = TRUE;

#define XLAT_REGISTER(_x) xlat_register(Stringify(_x), xlat_ ## _x, NULL); \
		c = xlat_find(Stringify(_x)); \
		rad_assert(c != NULL); \
		c->internal = TRUE

		XLAT_REGISTER(integer);
		XLAT_REGISTER(hex);
		XLAT_REGISTER(base64);
		XLAT_REGISTER(string);
		XLAT_REGISTER(module);

#ifdef HAVE_REGEX_H
		/*
		 *	Register xlat's for regexes.
		 */
		buffer[1] = '\0';
		for (i = 0; i <= REQUEST_MAX_REGEX; i++) {
			buffer[0] = '0' + i;
			xlat_register(buffer, xlat_regex, &xlat_inst[i]);
			c = xlat_find(buffer);
			rad_assert(c != NULL);
			c->internal = TRUE;
		}
#endif /* HAVE_REGEX_H */


		xlat_register("debug", xlat_debug, &xlat_inst[0]);
		c = xlat_find("debug");
		rad_assert(c != NULL);
		c->internal = TRUE;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	strlcpy(my_xlat.module, module, sizeof(my_xlat.module));
	my_xlat.length = strlen(my_xlat.module);
	c = rbtree_finddata(xlat_root, &my_xlat);
	if (c) {
		if (c->internal) {
			DEBUG("xlat_register: Cannot re-define internal xlat");
			return -1;
		}

		c->do_xlat = func;
		c->instance = instance;
		return 0;
	}

	/*
	 *	Doesn't exist.  Create it.
	 */
	c = rad_malloc(sizeof(*c));
	memset(c, 0, sizeof(*c));

	c->do_xlat = func;
	strlcpy(c->module, module, sizeof(c->module));
	c->length = strlen(c->module);
	c->instance = instance;

	rbtree_insert(xlat_root, c);

	return 0;
}

/**
 * @brief Unregister an xlat function.
 *
 *	We can only have one function to call per name, so the
 *	passing of "func" here is extraneous.
 *
 * @param module xlat to unregister
 * @param func Unused
 * @return Void.
 */
void xlat_unregister(const char *module, RAD_XLAT_FUNC func, void *instance)
{
	xlat_t	*c;
	xlat_t		my_xlat;

	func = func;		/* -Wunused */

	if (!module) return;

	strlcpy(my_xlat.module, module, sizeof(my_xlat.module));
	my_xlat.length = strlen(my_xlat.module);

	c = rbtree_finddata(xlat_root, &my_xlat);
	if (!c) return;

	if (c->instance != instance) return;

	rbtree_deletebydata(xlat_root, c);
}

/**
 * @brief De-register all xlat functions, used mainly for debugging.
 */
void xlat_free(void)
{
	rbtree_free(xlat_root);
}


/**
 * @brief Decode an attribute name into a string.
 *
 * This expands the various formats:
 * - %{Name}
 * - %{xlat:name}
 * - %{Name:-Other}
 *
 * calls radius_xlat() to do most of the work
 *
 * @param from string to expand
 * @param to buffer for output
 * @param freespace space remaining in output buffer
 * @param request current server request
 * @param func optional function to escape output; passed to radius_xlat()
 * @return 0 on success, -1 on failure
 */
static int decode_attribute(const char **from, char **to, int freespace,
			     REQUEST *request,
			     RADIUS_ESCAPE_STRING func, void *funcarg)
{
	int	do_length = 0;
	const char *module_name, *xlat_str;
	char *p, *q, *l, *next = NULL;
	int retlen=0;
	const xlat_t *c;
	int varlen;
	char buffer[8192];

	q = *to;

	*q = '\0';

	/*
	 *	Copy the input string to an intermediate buffer where
	 *	we can mangle it.
	 */
	varlen = rad_copy_variable(buffer, *from);
	if (varlen < 0) {
		RDEBUG2("ERROR: Badly formatted variable: %s", *from);
		return -1;
	}
	*from += varlen;

	/*
	 *	Kill the %{} around the data we are looking for.
	 */
	p = buffer;
	p[varlen - 1] = '\0';	/*  */
	p += 2;
	if (*p == '#') {
		p++;
		do_length = 1;
	}

	/*
	 *	Handle %{%{foo}:-%{bar}}, which is useful, too.
	 *
	 *	Did I mention that this parser is garbage?
	 */
	if ((p[0] == '%') && (p[1] == '{')) {
		int len1, len2;
		int expand2 = FALSE;

		/*
		 *	'p' is after the start of 'buffer', so we can
		 *	safely do this.
		 */
		len1 = rad_copy_variable(buffer, p);
		if (len1 < 0) {
			RDEBUG2("ERROR: Badly formatted variable: %s", p);
			return -1;
		}

		/*
		 *	They did %{%{foo}}, which is stupid, but allowed.
		 */
		if (!p[len1]) {
			RDEBUG2("Improperly nested variable; %%{%s}", p);
			return -1;
		}

		/*
		 *	It SHOULD be %{%{foo}:-%{bar}}.  If not, it's
		 *	an error.
		 */
		if ((p[len1] != ':') || (p[len1 + 1] != '-')) {
			RDEBUG2("No trailing :- after variable at %s", p);
			return -1;
		}

		/*
		 *	Parse the second bit.  The second bit can be
		 *	either %{foo}, or a string "foo", or a string
		 *	'foo', or just a bare word: foo
		 */
		p += len1 + 2;
		l = buffer + len1 + 1;

		if ((p[0] == '%') && (p[1] == '{')) {
			len2 = rad_copy_variable(l, p);

			if (len2 < 0) {
				RDEBUG2("ERROR: Invalid text after :- at %s", p);
				return -1;
			}
			p += len2;
			expand2 = TRUE;

		} else if ((p[0] == '"') || p[0] == '\'') {
		  getstring((const char **) &p, l, strlen(l));

		} else {
			l = p;
		}

		/*
		 *	Expand the first one.  If we did, exit the
		 *	conditional.
		 */
		retlen = radius_xlat(q, freespace, buffer, request, func, funcarg);
		if (retlen) {
			q += retlen;
			goto done;
		}

		RDEBUG2("\t... expanding second conditional");
		/*
		 *	Expand / copy the second string if required.
		 */
		if (expand2) {
			retlen = radius_xlat(q, freespace, l,
					    request, func, funcarg);
			if (retlen) {
				q += retlen;
			}
		} else {
			strlcpy(q, l, freespace);
			q += strlen(q);
		}

		/*
		 *	Else the output is an empty string.
		 */
		goto done;
	}

	/*
	 *	See if we're supposed to expand a module name.
	 */
	module_name = NULL;
	for (l = p; *l != '\0'; l++) {
		/*
		 *	module:string
		 */
		if (*l == ':') {
			module_name = p; /* start of name */
			*l = '\0';
			p = l + 1;
			break;
		}

		/*
		 *	Module names can't have spaces.
		 */
		if ((*l == ' ') || (*l == '\t')) break;
	}

	/*
	 *	%{name} is a simple attribute reference,
	 *	or regex reference.
	 */
	if (!module_name) {
		if (isdigit(*p) && !p[1]) { /* regex 0..8 */
			module_name = xlat_str = p;
		} else {
			xlat_str = p;
		}
		goto do_xlat;
	}

	/*
	 *	Maybe it's the old-style %{foo:-bar}
	 */
	if (*p == '-') {
		RDEBUG2("WARNING: Deprecated conditional expansion \":-\".  See \"man unlang\" for details");
		p++;

		xlat_str = module_name;
		next = p;
		goto do_xlat;
	}

	/*
	 *	FIXME: For backwards "WTF" compatibility, check for
	 *	{...}, (after the :), and copy that, too.
	 */

	/* module name, followed by (possibly) per-module string */
	xlat_str = p;
	
do_xlat:
	/*
	 *	Just "foo".  Maybe it's a magic attr, which doesn't
	 *	really exist.
	 *
	 *	If we can't find that, then assume it's a dictionary
	 *	attribute in the request.
	 *
	 *	Else if it's module:foo, look for module, and pass it "foo".
	 */
	if (!module_name) {
		c = xlat_find(xlat_str);
		if (!c) c = xlat_find("request");
	} else {
		c = xlat_find(module_name);
	}
	if (!c) {
		if (!module_name) {
			RDEBUG2("WARNING: Unknown Attribute \"%s\" in string expansion \"%%%s\"", xlat_str, *from);
		} else {
			RDEBUG2("WARNING: Unknown module \"%s\" in string expansion \"%%%s\"", module_name, *from);
		}
		return -1;
	}

	if (!c->internal) RDEBUG3("radius_xlat: Running registered xlat function of module %s for string \'%s\'",
				  c->module, xlat_str);
	if (func) {
		/* xlat to a temporary buffer, then escape */
		char tmpbuf[8192];
		retlen = c->do_xlat(c->instance, request, xlat_str, tmpbuf, sizeof(tmpbuf));
		if (retlen > 0) {
			retlen = func(request, q, freespace, tmpbuf, funcarg);
			if (retlen > 0) {
				RDEBUG2("string escaped from \'%s\' to \'%s\'", tmpbuf, q);
			} else if (retlen < 0) {
				RDEBUG2("string escape failed");
			}
		}
	} else {
		retlen = c->do_xlat(c->instance, request, xlat_str, q, freespace);
	}
	if (retlen > 0) {
		if (do_length) {
			snprintf(q, freespace, "%d", retlen);
			retlen = strlen(q);
		}
		
	} else if (next) {
		/*
		 *	Expand the second bit.
		 */
		RDEBUG2("\t... expanding second conditional");
		retlen = radius_xlat(q, freespace, next, request, func, funcarg);
	}
	q += retlen;

done:
	*to = q;
	return 0;
}

/**
 * @brief Replace %whatever in a string.
 *
 *	See 'doc/variables.txt' for more information.
 *
 * @param out output buffer
 * @param outlen size of output buffer
 * @param fmt string to expand
 * @param request current request
 * @param func function to escape final value e.g. SQL quoting
 * @return length of string written @bug should really have -1 for failure
 */
int radius_xlat(char *out, int outlen, const char *fmt,
		REQUEST *request,
		RADIUS_ESCAPE_STRING func, void *funcarg)
{
	int c, len, freespace;
	const char *p;
	char *q;
	char *nl;
	VALUE_PAIR *tmp;
	struct tm *TM, s_TM;
	char tmpdt[40]; /* For temporary storing of dates */

	/*
	 *	Catch bad modules.
	 */
	if (!fmt || !out || !request) return 0;

       	q = out;
	p = fmt;
	while (*p) {
		/* Calculate freespace in output */
		freespace = outlen - (q - out);
		if (freespace <= 1)
			break;
		c = *p;

		if ((c != '%') && (c != '$') && (c != '\\')) {
			/*
			 * We check if we're inside an open brace.  If we are
			 * then we assume this brace is NOT literal, but is
			 * a closing brace and apply it
			 */
			*q++ = *p++;
			continue;
		}

		/*
		 *	There's nothing after this character, copy
		 *	the last '%' or "$' or '\\' over to the output
		 *	buffer, and exit.
		 */
		if (*++p == '\0') {
			*q++ = c;
			break;
		}

		if (c == '\\') {
			switch(*p) {
			case '\\':
				*q++ = *p;
				break;
			case 't':
				*q++ = '\t';
				break;
			case 'n':
				*q++ = '\n';
				break;
			default:
				*q++ = c;
				*q++ = *p;
				break;
			}
			p++;

		} else if (c == '%') switch(*p) {
			case '{':
				p--;
				if (decode_attribute(&p, &q, freespace, request, func, funcarg) < 0) return 0;
				break;

			case '%':
				*q++ = *p++;
				break;
			case 'd': /* request day */
				TM = localtime_r(&request->timestamp, &s_TM);
				len = strftime(tmpdt, sizeof(tmpdt), "%d", TM);
				if (len > 0) {
					strlcpy(q, tmpdt, freespace);
					q += strlen(q);
				}
				p++;
				break;
			case 'l': /* request timestamp */
				snprintf(tmpdt, sizeof(tmpdt), "%lu",
					 (unsigned long) request->timestamp);
				strlcpy(q,tmpdt,freespace);
				q += strlen(q);
				p++;
				break;
			case 'm': /* request month */
				TM = localtime_r(&request->timestamp, &s_TM);
				len = strftime(tmpdt, sizeof(tmpdt), "%m", TM);
				if (len > 0) {
					strlcpy(q, tmpdt, freespace);
					q += strlen(q);
				}
				p++;
				break;
			case 't': /* request timestamp */
				CTIME_R(&request->timestamp, tmpdt, sizeof(tmpdt));
				nl = strchr(tmpdt, '\n');
				if (nl) *nl = '\0';
				strlcpy(q, tmpdt, freespace);
				q += strlen(q);
				p++;
				break;
			case 'C': /* ClientName */
				strlcpy(q,request->client->shortname,freespace);
				q += strlen(q);
				p++;
				break;
			case 'D': /* request date */
				TM = localtime_r(&request->timestamp, &s_TM);
				len = strftime(tmpdt, sizeof(tmpdt), "%Y%m%d", TM);
				if (len > 0) {
					strlcpy(q, tmpdt, freespace);
					q += strlen(q);
				}
				p++;
				break;
			case 'G': /* request minute */
				TM = localtime_r(&request->timestamp, &s_TM);
				len = strftime(tmpdt, sizeof(tmpdt), "%M", TM);
				if (len > 0) {
					strlcpy(q, tmpdt, freespace);
					q += strlen(q);
				}
				p++;
				break;
			case 'H': /* request hour */
				TM = localtime_r(&request->timestamp, &s_TM);
				len = strftime(tmpdt, sizeof(tmpdt), "%H", TM);
				if (len > 0) {
					strlcpy(q, tmpdt, freespace);
					q += strlen(q);
				}
				p++;
				break;
			case 'I': /* Request ID */
				snprintf(tmpdt, sizeof(tmpdt), "%i", request->packet->id);
				strlcpy(q, tmpdt, freespace);
				q += strlen(q);
				p++;
				break;
			case 'S': /* request timestamp in SQL format*/
				TM = localtime_r(&request->timestamp, &s_TM);
				len = strftime(tmpdt, sizeof(tmpdt), "%Y-%m-%d %H:%M:%S", TM);
				if (len > 0) {
					strlcpy(q, tmpdt, freespace);
					q += strlen(q);
				}
				p++;
				break;
			case 'T': /* request timestamp */
				TM = localtime_r(&request->timestamp, &s_TM);
				len = strftime(tmpdt, sizeof(tmpdt), "%Y-%m-%d-%H.%M.%S.000000", TM);
				if (len > 0) {
					strlcpy(q, tmpdt, freespace);
					q += strlen(q);
				}
				p++;
				break;
			case 'V': /* Request-Authenticator */
				strlcpy(q,"Verified",freespace);
				q += strlen(q);
				p++;
				break;
			case 'Y': /* request year */
				TM = localtime_r(&request->timestamp, &s_TM);
				len = strftime(tmpdt, sizeof(tmpdt), "%Y", TM);
				if (len > 0) {
					strlcpy(q, tmpdt, freespace);
					q += strlen(q);
				}
				p++;
				break;
			case 'Z': /* Full request pairs except password */
				tmp = request->packet->vps;
				while (tmp && (freespace > 3)) {
					if (tmp->attribute != PW_USER_PASSWORD) {
						*q++ = '\t';
						len = vp_prints(q, freespace - 2, tmp);
						q += len;
						freespace -= (len + 2);
						*q++ = '\n';
					}
					tmp = tmp->next;
				}
				p++;
				break;
			default:
				RDEBUG2("WARNING: Unknown variable '%%%c': See 'doc/variables.txt'", *p);
				if (freespace > 2) {
					*q++ = '%';
					*q++ = *p++;
				}
				break;
		}
	}
	*q = '\0';

	RDEBUG2("\texpand: %s -> %s", fmt, out);

	return strlen(out);
}
