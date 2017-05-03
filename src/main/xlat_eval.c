/*
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
 */

/**
 * $Id$
 *
 * @file xlat_eval.c
 * @brief String expansion ("translation").  Evaluation of pre-parsed xlat epxansions.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>
#include "xlat.h"

static size_t xlat_process(TALLOC_CTX *ctx, char **out, REQUEST *request, xlat_exp_t const * const head,
			   xlat_escape_t escape, void  const *escape_ctx);


static char *xlat_getvp(TALLOC_CTX *ctx, REQUEST *request, vp_tmpl_t const *vpt,
			bool escape, bool return_null)
{
	VALUE_PAIR *vp = NULL, *virtual = NULL;
	RADIUS_PACKET *packet = NULL;
	fr_dict_enum_t *dv;
	char *ret = NULL;

	vp_cursor_t cursor;
	char quote = escape ? '"' : '\0';

	rad_assert((vpt->type == TMPL_TYPE_ATTR) || (vpt->type == TMPL_TYPE_LIST));

	/*
	 *	We only support count and concatenate operations on lists.
	 */
	if (vpt->type == TMPL_TYPE_LIST) {
		vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
		goto do_print;
	}

	/*
	 *	See if we're dealing with an attribute in the request
	 *
	 *	This allows users to manipulate virtual attributes as if
	 *	they were real ones.
	 */
	vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	if (vp) goto do_print;

	/*
	 *	We didn't find the VP in a list.
	 *	If it's not a virtual one, and we're not meant to
	 *	be counting it, return.
	 */
	if (!vpt->tmpl_da->flags.virtual) {
		if (vpt->tmpl_num == NUM_COUNT) goto do_print;
		return NULL;
	}

	/*
	 *	Switch out the request to the one specified by the template
	 */
	if (radius_request(&request, vpt->tmpl_request) < 0) return NULL;

	/*
	 *	Some non-packet expansions
	 */
	switch (vpt->tmpl_da->attr) {
	default:
		break;		/* ignore them */

	case PW_CLIENT_SHORTNAME:
		if (vpt->tmpl_num == NUM_COUNT) goto count_virtual;
		if (request->client && request->client->shortname) {
			return talloc_typed_strdup(ctx, request->client->shortname);
		}
		return talloc_typed_strdup(ctx, "<UNKNOWN-CLIENT>");

	case PW_REQUEST_PROCESSING_STAGE:
		if (vpt->tmpl_num == NUM_COUNT) goto count_virtual;
		if (request->component) return talloc_typed_strdup(ctx, request->component);
		return talloc_typed_strdup(ctx, "server_core");

	case PW_VIRTUAL_SERVER:
		if (vpt->tmpl_num == NUM_COUNT) goto count_virtual;
		if (!request->server) return NULL;
		return talloc_typed_strdup(ctx, request->server);

	case PW_MODULE_RETURN_CODE:
		if (vpt->tmpl_num == NUM_COUNT) goto count_virtual;
		if (!request->rcode) return NULL;
		return talloc_typed_strdup(ctx, fr_int2str(modreturn_table, request->rcode, ""));
	}

	/*
	 *	All of the attributes must now refer to a packet.
	 *	If there's no packet, we can't print any attribute
	 *	referencing it.
	 */
	packet = radius_packet(request, vpt->tmpl_list);
	if (!packet) {
		if (return_null) return NULL;
		return fr_pair_type_asprint(ctx, vpt->tmpl_da->type);
	}

	vp = NULL;
	switch (vpt->tmpl_da->attr) {
	default:
		break;

	case PW_PACKET_TYPE:
		if (packet->code > 0) {
			dv = fr_dict_enum_by_da(NULL, vpt->tmpl_da, packet->code);
			if (dv) return talloc_typed_strdup(ctx, dv->name);
			return talloc_typed_asprintf(ctx, "%d", packet->code);
		}

		/*
		 *	If there's no code set then we return an empty string (not zero).
		 */
		return talloc_strdup(ctx, "");

	case PW_RESPONSE_PACKET_TYPE:
	{
		int code = 0;

#ifdef WITH_PROXY
		/*
		 *	This code is probably wrong.  Why automatically get the proxy reply code?
		 */
		if (request->proxy && request->proxy->reply && (!request->reply || !request->reply->code)) {
			code = request->proxy->reply->code;
		} else
#endif
		if (request->reply) {
			code = request->reply->code;
		}

		if (code > 0) return talloc_typed_strdup(ctx, fr_packet_codes[code]);

		/*
		 *	If there's no code set then we return an empty string (not zero).
		 */
		return talloc_strdup(ctx, "");
	}

	/*
	 *	Virtual attributes which require a temporary VALUE_PAIR
	 *	to be allocated. We can't use stack allocated memory
	 *	because of the talloc checks sprinkled throughout the
	 *	various VP functions.
	 */
	case PW_PACKET_AUTHENTICATION_VECTOR:
		virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
		fr_pair_value_memcpy(virtual, packet->vector, sizeof(packet->vector));
		vp = virtual;
		break;

	case PW_CLIENT_IP_ADDRESS:
	case PW_PACKET_SRC_IP_ADDRESS:
		if (packet->src_ipaddr.af == AF_INET) {
			virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
			virtual->vp_ipv4addr = packet->src_ipaddr.addr.v4.s_addr;
			vp = virtual;
		}
		break;

	case PW_PACKET_DST_IP_ADDRESS:
		if (packet->dst_ipaddr.af == AF_INET) {
			virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
			virtual->vp_ipv4addr = packet->dst_ipaddr.addr.v4.s_addr;
			vp = virtual;
		}
		break;

	case PW_PACKET_SRC_IPV6_ADDRESS:
		if (packet->src_ipaddr.af == AF_INET6) {
			virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
			memcpy(&virtual->vp_ipv6addr,
			       &packet->src_ipaddr.addr.v6,
			       sizeof(packet->src_ipaddr.addr.v6));
			vp = virtual;
		}
		break;

	case PW_PACKET_DST_IPV6_ADDRESS:
		if (packet->dst_ipaddr.af == AF_INET6) {
			virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
			memcpy(&virtual->vp_ipv6addr,
			       &packet->dst_ipaddr.addr.v6,
			       sizeof(packet->dst_ipaddr.addr.v6));
			vp = virtual;
		}
		break;

	case PW_PACKET_SRC_PORT:
		virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
		virtual->vp_integer = packet->src_port;
		vp = virtual;
		break;

	case PW_PACKET_DST_PORT:
		virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
		virtual->vp_integer = packet->dst_port;
		vp = virtual;
		break;
	}

	/*
	 *	Fake various operations for virtual attributes.
	 */
	if (virtual) {
		if (vpt->tmpl_num != NUM_ANY) switch (vpt->tmpl_num) {
		/*
		 *	[n] is NULL (we only have [0])
		 */
		default:
			goto finish;
		/*
		 *	[*] means only one.
		 */
		case NUM_ALL:
			break;

		/*
		 *	[#] means 1 (as there's only one)
		 */
		case NUM_COUNT:
		count_virtual:
			ret = talloc_strdup(ctx, "1");
			goto finish;

		/*
		 *	[0] is fine (get the first instance)
		 */
		case 0:
			break;
		}
		goto print;
	}

do_print:
	switch (vpt->tmpl_num) {
	/*
	 *	Return a count of the VPs.
	 */
	case NUM_COUNT:
	{
		int count = 0;

		for (vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
		     vp;
		     vp = tmpl_cursor_next(&cursor, vpt)) count++;

		return talloc_typed_asprintf(ctx, "%d", count);
	}


	/*
	 *	Concatenate all values together,
	 *	separated by commas.
	 */
	case NUM_ALL:
	{
		char *p, *q;

		if (!fr_pair_cursor_current(&cursor)) return NULL;
		p = fr_pair_value_asprint(ctx, vp, quote);
		if (!p) return NULL;

		while ((vp = tmpl_cursor_next(&cursor, vpt)) != NULL) {
			q = fr_pair_value_asprint(ctx, vp, quote);
			if (!q) return NULL;
			p = talloc_strdup_append(p, ",");
			p = talloc_strdup_append(p, q);
		}

		return p;
	}

	default:
		/*
		 *	The cursor was set to the correct
		 *	position above by tmpl_cursor_init.
		 */
		vp = fr_pair_cursor_current(&cursor);
		break;
	}

	if (!vp) {
		if (return_null) return NULL;
		return fr_pair_type_asprint(ctx, vpt->tmpl_da->type);
	}

print:
	ret = fr_pair_value_asprint(ctx, vp, quote);

finish:
	talloc_free(virtual);
	return ret;
}

#ifdef DEBUG_XLAT
static const char xlat_spaces[] = "                                                                                                                                                                                                                                                                ";
#endif

static char *xlat_aprint(TALLOC_CTX *ctx, REQUEST *request, xlat_exp_t const * const node,
			 xlat_escape_t escape, void const *escape_ctx, int lvl)
{
	ssize_t rcode;
	char *str = NULL, *child;
	char const *p;

	XLAT_DEBUG("%.*sxlat aprint %d %s", lvl, xlat_spaces, node->type, node->fmt);

	switch (node->type) {
		/*
		 *	Don't escape this.
		 */
	case XLAT_LITERAL:
		XLAT_DEBUG("%.*sxlat_aprint LITERAL", lvl, xlat_spaces);
		return talloc_typed_strdup(ctx, node->fmt);

		/*
		 *	Do a one-character expansion.
		 */
	case XLAT_PERCENT:
	{
		char *nl;
		size_t freespace = 256;
		struct tm ts;
		time_t when;
		long int microseconds;

		XLAT_DEBUG("%.*sxlat_aprint PERCENT", lvl, xlat_spaces);

		str = talloc_array(ctx, char, freespace); /* @todo do better allocation */
		p = node->fmt;

		when = request->packet->timestamp.tv_sec;
		microseconds = request->packet->timestamp.tv_usec;

		switch (*p) {
		case '%':
			str[0] = '%';
			str[1] = '\0';
			break;

		case 'd': /* request day */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%d", &ts);
			break;

		case 'l': /* request timestamp */
			snprintf(str, freespace, "%lu",
				 (unsigned long) when);
			break;

		case 'm': /* request month */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%m", &ts);
			break;

		case 'n': /* Request Number*/
			snprintf(str, freespace, "%" PRIu64 , request->number);
			break;

		case 's': /* First request in this sequence */
			snprintf(str, freespace, "%" PRIu64 , request->seq_start);
			break;

		case 'e': /* Request second */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%S", &ts);
			break;

		case 't': /* request timestamp */
			CTIME_R(&when, str, freespace);
			nl = strchr(str, '\n');
			if (nl) *nl = '\0';
			break;

		case 'D': /* request date */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%Y%m%d", &ts);
			break;

		case 'G': /* request minute */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%M", &ts);
			break;

		case 'H': /* request hour */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%H", &ts);
			break;

		case 'I': /* Request ID */
			rad_assert(request != NULL);
			snprintf(str, freespace, "%i", request->packet->id);
			break;

		case 'M': /* Request microsecond */
			snprintf(str, freespace, "%06ld", microseconds);
			break;

		case 'S': /* request timestamp in SQL format*/
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%Y-%m-%d %H:%M:%S", &ts);
			break;

		case 'T': /* request timestamp */
			if (!localtime_r(&when, &ts)) goto error;
			nl = str + strftime(str, freespace, "%Y-%m-%d-%H.%M.%S", &ts);
			rad_assert(((str + freespace) - nl) >= 8);
			snprintf(nl, (str + freespace) - nl, ".%06d",  (int) microseconds);
			break;

		case 'Y': /* request year */
			if (!localtime_r(&when, &ts)) {
				error:
				REDEBUG("Failed converting packet timestamp to localtime: %s", fr_syserror(errno));
				talloc_free(str);
				return NULL;
			}
			strftime(str, freespace, "%Y", &ts);
			break;

		case 'v': /* Version of code */
			RWDEBUG("%%v is deprecated and will be removed.  Use ${version.freeradius-server}");
			snprintf(str, freespace, "%s", radiusd_version_short);
			break;

		default:
			rad_assert(0 == 1);
			break;
		}
	}
		break;

	case XLAT_ATTRIBUTE:
		XLAT_DEBUG("%.*sxlat_aprint ATTRIBUTE", lvl, xlat_spaces);

		/*
		 *	Some attributes are virtual <sigh>
		 */
		str = xlat_getvp(ctx, request, node->attr, escape ? false : true, true);
		if (str) {
			XLAT_DEBUG("%.*sEXPAND attr %s", lvl, xlat_spaces, node->attr->tmpl_da->name);
			XLAT_DEBUG("%.*s       ---> %s", lvl ,xlat_spaces, str);
		}
		break;

	case XLAT_VIRTUAL:
		XLAT_DEBUG("xlat_aprint VIRTUAL");

		if (node->xlat->buf_len > 0) {
			str = talloc_array(ctx, char, node->xlat->buf_len);
			str[0] = '\0';	/* Be sure the string is \0 terminated */
		}
		rcode = node->xlat->func(ctx, &str, node->xlat->buf_len, node->xlat->mod_inst, NULL, request, NULL);
		if (rcode < 0) {
			talloc_free(str);
			return NULL;
		}
		RDEBUG2("EXPAND X %s", node->xlat->name);
		RDEBUG2("   --> %s", str);
		break;

	case XLAT_MODULE:
		XLAT_DEBUG("xlat_aprint MODULE");

		if (node->child) {
			if (xlat_process(ctx, &child, request,
					 node->child, node->xlat->escape, node->xlat->mod_inst) == 0) {
				return NULL;
			}

			XLAT_DEBUG("%.*sEXPAND mod %s %s", lvl, xlat_spaces, node->fmt, node->child->fmt);
		} else {
			XLAT_DEBUG("%.*sEXPAND mod %s", lvl, xlat_spaces, node->fmt);
			child = talloc_typed_strdup(ctx, "");
		}

		XLAT_DEBUG("%.*s      ---> %s", lvl, xlat_spaces, child);

		/*
		 *	Smash \n --> CR.
		 *
		 *	The OUTPUT of xlat is a "raw" string.  The INPUT is a printable string.
		 *
		 *	This is really the reverse of fr_snprint().
		 */
		if (*child) {
			PW_TYPE type;
			value_box_t data;

			type = PW_TYPE_STRING;
			if (value_box_from_str(ctx, &data, &type, NULL, child,
						talloc_array_length(child) - 1, '"') < 0) {
				talloc_free(child);
				return NULL;
			}

			talloc_free(child);
			child = data.datum.ptr;

		} else {
			char *q;

			p = q = child;
			while (*p) {
				if (*p == '\\') switch (p[1]) {
					default:
						*(q++) = p[1];
						p += 2;
						continue;

					case 'n':
						*(q++) = '\n';
						p += 2;
						continue;

					case 't':
						*(q++) = '\t';
						p += 2;
						continue;
					}

				*(q++) = *(p++);
			}
			*q = '\0';
		}

		if (node->xlat->buf_len > 0) {
			str = talloc_array(ctx, char, node->xlat->buf_len);
			str[0] = '\0';	/* Be sure the string is \0 terminated */
		}
		rcode = node->xlat->func(ctx, &str, node->xlat->buf_len, node->xlat->mod_inst, NULL, request, child);
		talloc_free(child);
		if (rcode < 0) {
			talloc_free(str);
			return NULL;
		}
		break;

#ifdef HAVE_REGEX
	case XLAT_REGEX:
		XLAT_DEBUG("%.*sxlat_aprint REGEX", lvl, xlat_spaces);
		if (regex_request_to_sub(ctx, &str, request, node->regex_index) < 0) return NULL;

		break;
#endif

	case XLAT_ALTERNATE:
		XLAT_DEBUG("%.*sxlat_aprint ALTERNATE", lvl, xlat_spaces);
		rad_assert(node->child != NULL);
		rad_assert(node->alternate != NULL);

		/*
		 *	If there are no "next" nodes, call ourselves
		 *	recursively, which is fast.
		 *
		 *	If there are "next" nodes, call xlat_process()
		 *	which does a ton more work.
		 */
		if (!node->next) {
			str = xlat_aprint(ctx, request, node->child, escape, escape_ctx, lvl);
			if (str) {
				XLAT_DEBUG("%.*sALTERNATE got first string: %s", lvl, xlat_spaces, str);
			} else {
				str = xlat_aprint(ctx, request, node->alternate, escape, escape_ctx, lvl);
				XLAT_DEBUG("%.*sALTERNATE got alternate string %s", lvl, xlat_spaces, str);
			}
		} else {

			if (xlat_process(ctx, &str, request, node->child, escape, escape_ctx) > 0) {
				XLAT_DEBUG("%.*sALTERNATE got first string: %s", lvl, xlat_spaces, str);
			} else {
				(void) xlat_process(ctx, &str, request, node->alternate, escape, escape_ctx);
				XLAT_DEBUG("%.*sALTERNATE got alternate string %s", lvl, xlat_spaces, str);
			}
		}
		break;
	}

	/*
	 *	If there's no data, return that, instead of an empty string.
	 */
	if (str && !str[0]) {
		talloc_free(str);
		return NULL;
	}

	/*
	 *	Escape the non-literals we found above.
	 */
	if (str && escape) {
		size_t len;
		char *escaped;
		void *mutable;

		len = talloc_array_length(str) * 3;

		escaped = talloc_array(ctx, char, len);

		memcpy(&mutable, &escape_ctx, sizeof(mutable));
		escape(request, escaped, len, str, mutable);
		talloc_free(str);
		str = escaped;
	}

	return str;
}


static size_t xlat_process(TALLOC_CTX *ctx, char **out, REQUEST *request, xlat_exp_t const * const head,
			   xlat_escape_t escape, void const *escape_ctx)
{
	int i, list;
	size_t total;
	char **array, *answer;
	xlat_exp_t const *node;

	*out = NULL;

	/*
	 *	There are no nodes to process, so the result is a zero
	 *	length string.
	 */
	if (!head) {
		*out = talloc_zero_array(ctx, char, 1);
		return 0;
	}

	/*
	 *	Hack for speed.  If it's one expansion, just allocate
	 *	that and return, instead of allocating an intermediary
	 *	array.
	 */
	if (!head->next) {
		/*
		 *	Pass the MAIN escape function.  Recursive
		 *	calls will call node-specific escape
		 *	functions.
		 */
		answer = xlat_aprint(ctx, request, head, escape, escape_ctx, 0);
		if (!answer) {
			*out = talloc_zero_array(ctx, char, 1);
			return 0;
		}
		*out = answer;
		return strlen(answer);
	}

	list = 0;		/* FIXME: calculate this once */
	for (node = head; node != NULL; node = node->next) {
		list++;
	}

	array = talloc_array(ctx, char *, list);
	if (!array) return -1;

	for (node = head, i = 0; node != NULL; node = node->next, i++) {
		array[i] = xlat_aprint(array, request, node, escape, escape_ctx, 0); /* may be NULL */
	}

	total = 0;
	for (i = 0; i < list; i++) {
		if (array[i]) total += strlen(array[i]); /* FIXME: calculate strlen once */
	}

	if (!total) {
		talloc_free(array);
		*out = talloc_zero_array(ctx, char, 1);
		return 0;
	}

	answer = talloc_array(ctx, char, total + 1);

	total = 0;
	for (i = 0; i < list; i++) {
		size_t len;

		if (array[i]) {
			len = strlen(array[i]);
			memcpy(answer + total, array[i], len);
			total += len;
		}
	}
	answer[total] = '\0';
	talloc_free(array);	/* and child entries */

	*out = answer;
	return total;
}

/** Replace %whatever in a string.
 *
 * See 'doc/configuration/variables.rst' for more information.
 *
 * @param[in] ctx		to allocate expansion buffers in.
 * @param[out] out		Where to write pointer to output buffer.
 * @param[in] outlen		Size of out.
 * @param[in] request		current request.
 * @param[in] node		the xlat structure to expand
 * @param[in] escape		function to escape final value e.g. SQL quoting.
 * @param[in] escape_ctx	pointer to pass to escape function.
 * @return length of string written @bug should really have -1 for failure.
 */
static ssize_t _xlat_eval_compiled(TALLOC_CTX *ctx, char **out, size_t outlen, REQUEST *request,
				  xlat_exp_t const *node, xlat_escape_t escape, void const *escape_ctx)
{
	char *buff;
	ssize_t len;

	rad_assert(node != NULL);

	len = xlat_process(ctx, &buff, request, node, escape, escape_ctx);
	if ((len < 0) || !buff) {
		rad_assert(buff == NULL);
		if (*out) **out = '\0';
		return len;
	}

	len = strlen(buff);

	/*
	 *	If out doesn't point to an existing buffer
	 *	copy the pointer to our buffer over.
	 */
	if (!*out) {
		*out = buff;
		return len;
	}

	/*
	 *	Otherwise copy the talloced buffer to the fixed one.
	 */
	strlcpy(*out, buff, outlen);
	talloc_free(buff);
	return len;
}

static ssize_t _xlat_eval(TALLOC_CTX *ctx, char **out, size_t outlen, REQUEST *request, char const *fmt,
			   xlat_escape_t escape, void const *escape_ctx) CC_HINT(nonnull (2, 4, 5));

/** Replace %whatever in a string.
 *
 * See 'doc/configuration/variables.rst' for more information.
 *
 * @param[in] ctx		to allocate expansion buffers in.
 * @param[out] out		Where to write pointer to output buffer.
 * @param[in] outlen		Size of out.
 * @param[in] request		current request.
 * @param[in] fmt		string to expand.
 * @param[in] escape		function to escape final value e.g. SQL quoting.
 * @param[in] escape_ctx	pointer to pass to escape function.
 * @return length of string written @bug should really have -1 for failure.
 */
static ssize_t _xlat_eval(TALLOC_CTX *ctx, char **out, size_t outlen, REQUEST *request, char const *fmt,
			   xlat_escape_t escape, void const *escape_ctx)
{
	ssize_t len;
	xlat_exp_t *node;

	RDEBUG2("EXPAND %s", fmt);
	RINDENT();

	/*
	 *	Give better errors than the old code.
	 */
	len = xlat_tokenize_request(ctx, request, fmt, &node);
	if (len == 0) {
		if (*out) {
			**out = '\0';
		} else {
			*out = talloc_zero_array(ctx, char, 1);
		}
		REXDENT();
		return 0;
	}

	if (len < 0) {
		if (*out) **out = '\0';
		REXDENT();
		return -1;
	}

	len = _xlat_eval_compiled(ctx, out, outlen, request, node, escape, escape_ctx);
	talloc_free(node);

	REXDENT();
	RDEBUG2("--> %s", *out);

	return len;
}

ssize_t xlat_eval(char *out, size_t outlen, REQUEST *request,
		  char const *fmt, xlat_escape_t escape, void const *escape_ctx)
{
	return _xlat_eval(request, &out, outlen, request, fmt, escape, escape_ctx);
}

ssize_t xlat_eval_compiled(char *out, size_t outlen, REQUEST *request,
			   xlat_exp_t const *xlat, xlat_escape_t escape, void const *escape_ctx)
{
	return _xlat_eval_compiled(request, &out, outlen, request, xlat, escape, escape_ctx);
}

ssize_t xlat_aeval(TALLOC_CTX *ctx, char **out, REQUEST *request, char const *fmt,
		   xlat_escape_t escape, void const *escape_ctx)
{
	*out = NULL;
	return _xlat_eval(ctx, out, 0, request, fmt, escape, escape_ctx);
}

ssize_t xlat_aeval_compiled(TALLOC_CTX *ctx, char **out, REQUEST *request,
			    xlat_exp_t const *xlat, xlat_escape_t escape, void const *escape_ctx)
{
	*out = NULL;
	return _xlat_eval_compiled(ctx, out, 0, request, xlat, escape, escape_ctx);
}
