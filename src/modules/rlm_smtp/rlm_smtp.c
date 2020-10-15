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
 * @file rlm_smtp.c
 * @brief smtp server authentication.
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/curl/base.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/server/cf_priv.h>

static fr_dict_t const 	*dict_radius; /*dictionary for radius protocol*/
static fr_dict_t const 	*dict_freeradius;

#define MAX_ATTRMAP	128

extern fr_dict_autoload_t rlm_smtp_dict[];
fr_dict_autoload_t rlm_smtp_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_freeradius, .proto = "freeradius"},
	{ NULL }
};

static fr_dict_attr_t const 	*attr_auth_type;
static fr_dict_attr_t const 	*attr_user_password;
static fr_dict_attr_t const 	*attr_user_name;
static fr_dict_attr_t const 	*attr_smtp_header;
static fr_dict_attr_t const 	*attr_smtp_body;

extern fr_dict_attr_autoload_t rlm_smtp_dict_attr[];
fr_dict_attr_autoload_t rlm_smtp_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_smtp_header, .name = "SMTP-Mail-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_body, .name = "SMTP-Mail-Body", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL },
};

typedef struct {
	char const		*uri;			//!< URI of smtp server
	char const		*template_dir;		//!< The directory that contains all email attachments
	char const		*envelope_address;	//!< The address used to send the message
	tmpl_t 			**sender_address;	//!< The address used to generate the FROM: header
	tmpl_t 			**attachments;		//!< The attachments to be set
	tmpl_t 			**recipient_addrs;	//!< Comma separated list of emails. Overrides elements in to, cc, bcc
	tmpl_t 			**to_addrs;		//!< Comma separated list of emails to be listed in TO:
	tmpl_t 			**cc_addrs;		//!< Comma separated list of emails to be listed in CC:
	tmpl_t 			**bcc_addrs;		//!< Comma separated list of emails not to be listed
	fr_time_delta_t 	timeout;		//!< Timeout for connection and server response
	fr_curl_tls_t		tls;			//!< Used for handled all tls specific curl components
	char const		*name;			//!< Auth-Type value for this module instance.
	fr_dict_enum_t		*auth_type;
	vp_map_t		*header_maps;		//!< Attribute map used to process header elements
	CONF_SECTION		*cs;
	bool 			set_date;
} rlm_smtp_t;

typedef struct {
	rlm_smtp_t const    	*inst;		//!< Instance of rlm_smtp.
	fr_curl_handle_t    	*mhandle;	//!< Thread specific multi handle.  Serves as the dispatch and coralling structure for smtp requests
} rlm_smtp_thread_t;

/*
 *	Holds the context for parsing the email elements
 */
typedef struct {
	REQUEST			*request;
	fr_curl_io_request_t	*randle;
	fr_cursor_t		cursor;
	fr_cursor_t		body_cursor;
	fr_dbuff_t		vp_in;
	struct curl_slist	*recipients;
	struct curl_slist	*header;
	struct curl_slist 	*body_header;
	fr_time_t 		time;
	char 			time_str[60];
	curl_mime		*mime;
} fr_mail_ctx;

/*
 * 	Used to ensure that only strings are being set to the tmpl_t ** output
 */
static int cf_table_parse_tmpl(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			  CONF_ITEM *ci, CONF_PARSER const *rule)
{
	int 				rcode = 0;
	ssize_t				slen;
	int				type = rule->type;
	bool 				tmpl = (type & FR_TYPE_TMPL);
	CONF_PAIR			*cp = cf_item_to_pair(ci);
	tmpl_t				*vpt;

	static tmpl_rules_t	rules = {
					.allow_unknown = true,
					.allow_unresolved = true,
					.allow_foreign = true
				};

	if (!tmpl) {
		cf_log_err(cp, "Failed parsing attribute reference");
		rcode = -1;
		goto finish;
	}

	slen = tmpl_afrom_substr(cp, &vpt, &FR_SBUFF_IN(cf_pair_value(cp), strlen(cf_pair_value(cp))),
				 cf_pair_value_quote(cp),
				 tmpl_parse_rules_unquoted[cf_pair_value_quote(cp)],
				 &rules);

	/* There was an error */
	if (slen < 0) {
		char *spaces, *text;

		fr_canonicalize_error(ctx, &spaces, &text, slen, cp->value);

		cf_log_err(cp, "Failed parsing attribute reference:");
		cf_log_err(cp, "%s", text);
		cf_log_perr(cp, "%s^", spaces);

		talloc_free(spaces);
		talloc_free(text);
		/* Return error */
		rcode = -1;
		goto finish;
	}

	if(tmpl_is_list(vpt)) {
		rcode = -1;
		goto finish;
	}

	/* Only string values should be used for SMTP components */
	if(tmpl_expanded_type(vpt) != FR_TYPE_STRING) {
		cf_log_err(cp, "Attribute reference must be a string");
		rcode = -1;
		goto finish;
	}

	*(tmpl_t **)out = vpt;

	cp->parsed = true;

finish:
	return rcode;
}

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("uri", FR_TYPE_STRING, rlm_smtp_t, uri) },
	{ FR_CONF_OFFSET("template_directory", FR_TYPE_STRING, rlm_smtp_t, template_dir) },
	{ FR_CONF_OFFSET("attachments", FR_TYPE_TMPL | FR_TYPE_MULTI, rlm_smtp_t, attachments),
		.func = cf_table_parse_tmpl, .dflt = "&SMTP-Attachments[*]", .quote = T_BARE_WORD},
	{ FR_CONF_OFFSET("sender_address", FR_TYPE_TMPL | FR_TYPE_MULTI, rlm_smtp_t, sender_address),
		.func = cf_table_parse_tmpl},
	{ FR_CONF_OFFSET("envelope_address", FR_TYPE_STRING, rlm_smtp_t, envelope_address) },
	{ FR_CONF_OFFSET("recipients", FR_TYPE_TMPL | FR_TYPE_MULTI, rlm_smtp_t, recipient_addrs),
		.func = cf_table_parse_tmpl, .dflt = "&SMTP-Recipients[*]", .quote = T_BARE_WORD},
	{ FR_CONF_OFFSET("TO", FR_TYPE_TMPL | FR_TYPE_MULTI, rlm_smtp_t, to_addrs), .func = cf_table_parse_tmpl,
		.dflt = "&SMTP-TO[*]", .quote = T_BARE_WORD},
	{ FR_CONF_OFFSET("CC", FR_TYPE_TMPL | FR_TYPE_MULTI, rlm_smtp_t, cc_addrs),
		.func = cf_table_parse_tmpl, .dflt = "&SMTP-CC[*]", .quote = T_BARE_WORD},
	{ FR_CONF_OFFSET("BCC", FR_TYPE_TMPL | FR_TYPE_MULTI, rlm_smtp_t, bcc_addrs),
		.func = cf_table_parse_tmpl, .dflt = "&SMTP-BCC[*]", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_TIME_DELTA, rlm_smtp_t, timeout) },
	{ FR_CONF_OFFSET("set_date", FR_TYPE_BOOL, rlm_smtp_t, set_date), .dflt = "yes" },
	{ FR_CONF_OFFSET("tls", FR_TYPE_SUBSECTION, rlm_smtp_t, tls), .subcs = (void const *) fr_curl_tls_config },//!<loading the tls values
	CONF_PARSER_TERMINATOR
};

/*
 * 	Adds every element associated with a dict_attr to a curl_slist
 */
static int da_to_slist(fr_mail_ctx *uctx, struct curl_slist **out, const fr_dict_attr_t *dict_attr)
{
	REQUEST 			*request = ((fr_mail_ctx *)uctx)->request;
	VALUE_PAIR			*vp;
	int 				elems_added = 0;

	/* Iterate over the VP and add the string value to the curl_slist */
	vp = fr_cursor_iter_by_da_init(&uctx->cursor, &uctx->request->packet->vps, dict_attr);
	while (vp) {
		*out = curl_slist_append(*out, vp->vp_strvalue);
		elems_added++;
		vp = fr_cursor_next(&uctx->cursor);
	}
	/* Check that the elements were found */
	if (elems_added == 0) {
		RDEBUG3("There were no %s elements found", dict_attr->name);
	}
	return elems_added;
}

/*
 * 	Takes a TMPL_TYPE_ATTR and adds it to an slist
 */
static int tmpl_attr_to_slist(fr_mail_ctx *uctx, struct curl_slist **out, tmpl_t * const tmpl)
{
	REQUEST 			*request = ((fr_mail_ctx *)uctx)->request;
	VALUE_PAIR			*vp;
	tmpl_cursor_ctx_t       	cc;
	int 				count = 0;

	/* Iterate over the VP and add the string value to the curl_slist */
	vp = tmpl_cursor_init(NULL, NULL, &cc, &uctx->cursor, request, tmpl);
	while (vp) {
		count += 1;
		*out = curl_slist_append(*out, vp->vp_strvalue);
		vp = fr_cursor_next(&uctx->cursor);
	}
	/* Return the number of elements that were found */
	tmpl_cursor_clear(&cc);
	return count;
}

/*
 * 	Parse through an array of tmpl * elements and add them to an slist
 */
static int tmpl_arr_to_slist (rlm_smtp_thread_t *t, fr_mail_ctx *uctx, struct curl_slist **out, tmpl_t ** const tmpl)
{
	REQUEST 	*request = uctx->request;
	int 		count = 0;
	char 		*expanded_str;

	talloc_foreach(tmpl, current) {
		if (current->type == TMPL_TYPE_ATTR) {
			/* If the element contains a reference to an attribute, parse every value it references */
			count += tmpl_attr_to_slist(uctx, out, current);
		} else {
			/* If the element is just a normal string, add it's name to the slist*/
			if( tmpl_aexpand(t, &expanded_str, request, current, NULL, NULL) < 0) {
				RDEBUG2("Could not expand the element %s", current->name);
				break;
			}
			*out = curl_slist_append(*out, expanded_str);
			count += 1;
		}
	}

	return count;
}

/*
 * 	Adds every element associated with a tmpl_attr to an sbuff
 */
static ssize_t tmpl_attr_to_sbuff (fr_mail_ctx *uctx, fr_sbuff_t *out, tmpl_t const *vpt, char const *delimeter)
{
	VALUE_PAIR		*vp;
	tmpl_cursor_ctx_t       cc;

	ssize_t			copied = 0;

	/* Loop through the elements to be added to the sbuff */
	vp = tmpl_cursor_init(NULL, NULL, &cc, &uctx->cursor, uctx->request, vpt);
	while (vp) {
		copied += fr_sbuff_in_bstrncpy(out, vp->vp_strvalue, vp->vp_length);
		vp = fr_cursor_next(&uctx->cursor);
		/* If there will be more values, add a comma and whitespace */
		if (vp) {
			copied += fr_sbuff_in_strcpy(out, delimeter);
		}
	}
	tmpl_cursor_clear(&cc);
	return copied;
}

/*
 * 	Adds every value in a dict_attr to a curl_slist as a comma separated list with a preposition
 */
static int tmpl_arr_to_header (rlm_smtp_thread_t *t, fr_mail_ctx *uctx, struct curl_slist **out, tmpl_t ** const tmpl,
		const char *preposition)
{
	REQUEST			*request = uctx->request;
	fr_sbuff_t 		sbuff;
	fr_sbuff_uctx_talloc_t 	sbuff_ctx;
	ssize_t 		out_len = 0;
	char 			*expanded_str;

	/* Initialize the buffer for the recipients. Used for TO */
	fr_sbuff_init_talloc(uctx, &sbuff, &sbuff_ctx, 256, SIZE_MAX);
	/* Add the preposition for the header element */
	fr_sbuff_in_strcpy(&sbuff, preposition);

	talloc_foreach(tmpl, vpt) {
		/* If there have already been elements added, keep them comma separated */
		if (out_len > 0) {
			out_len += fr_sbuff_in_strcpy(&sbuff, ", ");
		}
		/* Add the tmpl to the header sbuff */
		if (vpt->type == TMPL_TYPE_ATTR) {
			/* If the element contains a reference to an attribute, parse every value it references */
			out_len += tmpl_attr_to_sbuff(uctx, &sbuff, vpt, ", ");
		} else {
			/* If the element is just a normal string, add it's name to the slist*/
			if( tmpl_aexpand(t, &expanded_str, request, vpt, NULL, NULL) < 0) {
				RDEBUG2("Could not expand the element %s", vpt->name);
				break;
			}
			out_len += fr_sbuff_in_bstrncpy(&sbuff, expanded_str, vpt->len);
		}
	}

	/* Add the generated buffer the the curl_slist if elements were added */
	if (out_len > 0) {
		*out = curl_slist_append(*out, sbuff.buff);
		talloc_free(sbuff.buff);
		/* one element was successfully added */
		return 1;
	}
	talloc_free(sbuff.buff);
	/* The element failed to be added */
	RDEBUG2("Failed to add the element to the header");
	return 0;
}

/*
 * 	Takes a string value and adds it as a file path to upload as an attachment
 */
static int str_to_attachments (fr_mail_ctx *uctx, curl_mime *mime, char const * str, size_t len,
		fr_sbuff_t *path_buffer, fr_sbuff_marker_t *m)
{
	int 			attachments_set = 0;
	REQUEST			*request = uctx->request;
	curl_mimepart		*part;

	/* Move to the end of the template directory filepath */
	fr_sbuff_set(path_buffer, m);

	/* Check to see if the file attachment is valid, skip it if not */
	RDEBUG2("Trying to set attachment: %s", str);

	if(strncmp(str, "/", 1) == 0) {
		RDEBUG2("File attachments cannot be an absolute path");
		return 0;
	}
	if(strncmp(str, "..", 2) == 0) {
		RDEBUG2("Cannot access values outside of template_directory");
		return 0;
	}

	/* Copy the filename into the buffer */
	fr_sbuff_in_bstrncpy(path_buffer, str, len);
	/* Add the file attachment as a mime encoded part */
	attachments_set++;
	part = curl_mime_addpart(mime);
	curl_mime_encoder(part, "base64");
	curl_mime_filedata(part, path_buffer->buff);
	return 1;
}

/*
 * 	Parse a tmpl attr into a file attachment path and add it as a mime part
 */
static int tmpl_attr_to_attachment (fr_mail_ctx *uctx, curl_mime *mime, const tmpl_t * tmpl,
		fr_sbuff_t *path_buffer, fr_sbuff_marker_t *m)
{
	VALUE_PAIR 		*vp;
	REQUEST			*request = uctx->request;
	tmpl_cursor_ctx_t       cc;
	int 			attachments_set = 0;

	/* Check for any file attachments */
	for( vp = tmpl_cursor_init(NULL, NULL, &cc, &uctx->cursor, request, tmpl);
	vp;
       	vp = fr_cursor_next(&uctx->cursor)){
		if(vp->vp_tainted) {
			RDEBUG2("Skipping a tainted attachment");
			continue;
		}
		attachments_set += str_to_attachments(uctx, mime, vp->vp_strvalue, vp->vp_length, path_buffer, m);
	}
	tmpl_cursor_clear(&cc);
	return attachments_set;
}

/*
 * 	Adds every element in a tmpl** to an attachment path, then adds it to the email
 */
static int tmpl_arr_to_attachments (rlm_smtp_thread_t *t, fr_mail_ctx *uctx, curl_mime *mime, tmpl_t ** const tmpl,
		fr_sbuff_t *path_buffer, fr_sbuff_marker_t *m)
{
	REQUEST		*request = uctx->request;
	ssize_t 	count = 0;
	ssize_t 	expanded_str_len;
	char 		*expanded_str;

	talloc_foreach(tmpl, current) {
		/* write the elements to the sbuff as a comma separated list */
		if(current->type == TMPL_TYPE_ATTR) {
			count += tmpl_attr_to_attachment(uctx, mime, current, path_buffer, m);
		} else {
			expanded_str_len = tmpl_aexpand(t, &expanded_str, request, current, NULL, NULL);
			if(expanded_str_len < 0) {
				RDEBUG2("Could not expand the element %s", current->name);
				continue;
			}
			count += str_to_attachments(uctx, mime, expanded_str, expanded_str_len, path_buffer, m);
		}
	}

	return count;
}

/*
 * 	Returns the proper envolope address
 */
static const char * get_envelope_address(rlm_smtp_t const *inst)
{
	/* If the envelope address is set in the config, use that to send the email */
	if(inst->envelope_address) return inst->envelope_address;

	/* If the envelope address is not set, use the first sender address if any are set */
	if(inst->sender_address) return inst->sender_address[0]->name;

	/* There was no available envelope address */
	return NULL;
}

/*
 * 	Generate the FROM: header
 */
static int generate_from_header (rlm_smtp_thread_t *t, fr_mail_ctx *uctx, struct curl_slist **out, rlm_smtp_t const *inst)
{
	char const 			*from = "FROM: ";
	fr_sbuff_t 			sbuff;
	fr_sbuff_uctx_talloc_t 		sbuff_ctx;

	/* If sender_address is set, then generate FROM: with those attributes */
	if (inst->sender_address) {
		tmpl_arr_to_header(t, uctx, &uctx->header, inst->sender_address, from);
		return 0;
	}
	/* Initialize the buffer for the recipients. Used for TO */
	fr_sbuff_init_talloc(uctx, &sbuff, &sbuff_ctx, 256, SIZE_MAX);
	/* Add the preposition for the header element */
	fr_sbuff_in_strcpy(&sbuff, from);

	/* Copy the envelope address as the FROM: source */
	fr_sbuff_in_bstrncpy(&sbuff, inst->envelope_address, strlen(inst->envelope_address));
	*out = curl_slist_append(*out, sbuff.buff);

	/* Free the buffer used to generate the FROM header */
	talloc_free(sbuff.buff);
	return 0;
}

/*
 *	Generates a curl_slist of recipients
 */
static int recipients_source(rlm_smtp_thread_t *t, fr_mail_ctx *uctx, rlm_smtp_t const *inst)
{
	REQUEST			*request = uctx->request;
	int 			recipients_set = 0;

	/* Try to load the recipients into the envelope recipients if they are set */
	if(inst->recipient_addrs) recipients_set += tmpl_arr_to_slist(t, uctx, &uctx->recipients, inst->recipient_addrs);

	/* If any recipients were found, ignore to cc and bcc, return the amount added. */
	if(recipients_set > 0) {
		RDEBUG2("Recipients were generated from \"SMTP-Recipients\" and/or recipients in the config");
		return recipients_set;
	}
	RDEBUG2("No addresses were found in SMTP-Recipient");

	/* Try to load the to: addresses into the envelope recipients if they are set */
	if(inst->to_addrs) recipients_set += tmpl_arr_to_slist(t, uctx, &uctx->recipients, inst->to_addrs);

	/* Try to load the cc: addresses into the envelope recipients if they are set */
	if(inst->cc_addrs) recipients_set += tmpl_arr_to_slist(t, uctx, &uctx->recipients, inst->cc_addrs);

	/* Try to load the cc: addresses into the envelope recipients if they are set */
	if(inst->bcc_addrs) recipients_set += tmpl_arr_to_slist(t, uctx, &uctx->recipients, inst->bcc_addrs);

	RDEBUG2("%d recipients set", recipients_set);
	return recipients_set;
}

/*
 *	Generates a curl_slist of header elements header elements
 */
static int header_source(rlm_smtp_thread_t *t, fr_mail_ctx *uctx, UNUSED rlm_smtp_t const *inst)
{
	fr_sbuff_t 			time_out;
	char const 			*to = "TO: ";
	char const 			*cc = "CC: ";
	REQUEST				*request = uctx->request;
	fr_sbuff_t 			conf_buffer;
	fr_sbuff_uctx_talloc_t 		conf_ctx;
	vp_map_t			*conf_map;

	char 				*expanded_rhs;

	/* Initialize the sbuff for writing the config elements as header attributes */
	fr_sbuff_init_talloc(uctx, &conf_buffer, &conf_ctx, 256, SIZE_MAX);
	conf_map = inst->header_maps;
	/* Load in all of the header elements supplies in the config */
	while (conf_map->rhs && conf_map->lhs) {
		/* Do any string expansion required in the rhs */
		if( tmpl_aexpand(t, &expanded_rhs, request, conf_map->rhs, NULL, NULL) < 0) {
			RDEBUG2("Skipping: %s's could not parse: %s", conf_map->lhs->name, conf_map->rhs->name);
			goto next;
		}
		/* Format the conf item to be a valid SMTP header */
		fr_sbuff_in_bstrncpy(&conf_buffer, conf_map->lhs->name, conf_map->lhs->len);
		fr_sbuff_in_strcpy(&conf_buffer, ": ");
		fr_sbuff_in_bstrncpy(&conf_buffer, expanded_rhs, strlen(expanded_rhs));
		/* Add the header to the curl slist */
		uctx->header = curl_slist_append(uctx->header, conf_buffer.buff);
		talloc_free(conf_buffer.buff);
		/* Check if there are more values to parse */
	next:
		if (!conf_map->next) break;
		/* reinitialize the buffer and move to the next value */
		fr_sbuff_init_talloc(uctx, &conf_buffer, &conf_ctx, 256, SIZE_MAX);
		conf_map = conf_map->next;
	}
	/* Add the FROM: line */
	generate_from_header(t, uctx, &uctx->header, inst);

	/* Add the TO: line if there is one provided in the request by SMTP-TO */
	tmpl_arr_to_header(t, uctx, &uctx->header, inst->to_addrs, to);

	/* Add the CC: line if there is one provided in the request by SMTP-CC */
	tmpl_arr_to_header(t, uctx, &uctx->header, inst->cc_addrs, cc);

	/* Add all the generic header elements in the request */
	da_to_slist(uctx, &uctx->header, attr_smtp_header);

	/* If no header elements could be found, there is an error */
	if ( uctx->header == NULL) {
		RDEBUG2("Header elements could not be added");
 		return -1;
	}

	/* Set the DATE: to the time that the request was received */
	if (inst->set_date == true){
		time_out = FR_SBUFF_OUT(uctx->time_str, sizeof(uctx->time_str));
		fr_time_strftime_local(&time_out, fr_time(), "DATE: %a, %d %b %Y %T %z, (%Z) \r\n");
		uctx->header = curl_slist_append(uctx->header, uctx->time_str);
	}
	RDEBUG2("Finished generating the curl_slist for the header elements");
	return 0;
}

/*
 * 	Add the Body elements to the email
 */
static size_t body_source(char *ptr, size_t size, size_t nmemb, void *mail_ctx)
{
	fr_mail_ctx 		*uctx = mail_ctx;
	fr_dbuff_t		out;
	REQUEST			*request = uctx->request;
	VALUE_PAIR 		*vp;

	fr_dbuff_init(&out, (uint8_t *)ptr, (size * nmemb));  /* Wrap the output buffer so we can track our position easily */

	vp = fr_cursor_current(&uctx->body_cursor);
	if (!vp) {
		RDEBUG2("vp could not be found for the body element");
		return 0;
	}
	/* Copy the vp into the email. If it cannot all be loaded, return the amount of memory that was loaded and get called again */
	if (fr_dbuff_memcpy_in_partial(&out, &uctx->vp_in, SIZE_MAX) < fr_dbuff_remaining(&uctx->vp_in)) {
		RDEBUG2("%zu bytes used (partial copy)", fr_dbuff_used(&out));
		return fr_dbuff_used(&out);
	}
	/* Once this value pair is fully copied, prepare for the next element */
	vp = fr_cursor_next(&uctx->body_cursor);
	if (vp) {
		fr_dbuff_init(&uctx->vp_in, (uint8_t const *)vp->vp_strvalue, vp->vp_length);

	}
	RDEBUG2("%zu bytes used (full copy)", fr_dbuff_used(&out));
	return fr_dbuff_used(&out);
}

/*
 * 	Initialize all the body elements to be uploaded later
 */
static int body_init (fr_mail_ctx *uctx, curl_mime *mime)
{
	VALUE_PAIR 	*vp;
	REQUEST		*request = uctx->request;

	curl_mimepart	*part;
	curl_mime	*mime_body;

	int 		body_elements = 0;

	/* Initialize a second mime to apply special conditions to the body elements */
	mime_body = curl_mime_init(uctx->randle->candle);

	/* initialize the cursor used by the body_source function*/
	vp = fr_cursor_iter_by_da_init(&uctx->body_cursor, &uctx->request->packet->vps, attr_smtp_body);
	fr_dbuff_init(&uctx->vp_in, (uint8_t const *)vp->vp_strvalue, vp->vp_length);

	/* Add a mime part to mime_body for every body element */
	while(vp){
		body_elements++;
		part = curl_mime_addpart(mime_body);
		curl_mime_encoder(part, "8bit");
		curl_mime_data_cb(part, vp->vp_length, body_source, NULL, NULL, uctx);
		vp = fr_cursor_next(&uctx->body_cursor);
	}
	RDEBUG2("initialized %d body element part(s)", body_elements);

	/* Re-initialize the cursor for use when uploading the data to curl */
	fr_cursor_iter_by_da_init(&uctx->body_cursor, &uctx->request->packet->vps, attr_smtp_body);

	/* Add body_mime as a subpart of the mime request with a local content-disposition*/
	part = curl_mime_addpart(mime);
	curl_mime_subparts(part, mime_body);
	curl_mime_type(part, "multipart/mixed" );
	uctx->body_header = curl_slist_append(NULL, "Content-Disposition: inline"); /* Initialize the body_header curl_slist */
	curl_mime_headers(part, uctx->body_header, 1);

	return body_elements;
}

/*
 * 	Adds every SMTP_Attachments file to the email as a MIME part
 */
static int attachments_source(rlm_smtp_thread_t *t, fr_mail_ctx *uctx, curl_mime *mime, rlm_smtp_t const *inst)
{
	REQUEST			*request = uctx->request;
	int 			attachments_set = 0;
	fr_sbuff_uctx_talloc_t 	sbuff_ctx;
	fr_sbuff_t 		path_buffer;
	fr_sbuff_marker_t 	m;

	/* Make sure that a template directory is provided */
	if (!inst->template_dir) return 0;

	/* Initialize the buffer to write the file path */
	fr_sbuff_init_talloc(uctx, &path_buffer, &sbuff_ctx, talloc_array_length(inst->template_dir) + 128, SIZE_MAX);

	/* Write the initial path to the buffer */
	fr_sbuff_in_bstrcpy_buffer(&path_buffer, inst->template_dir);
	/* Make sure the template_directory path ends in a "/" */
	if (inst->template_dir[talloc_array_length(inst->template_dir)-2] != '/'){
		RDEBUG2("Adding / to end of template_dir");
		fr_sbuff_in_char(&path_buffer, '/');
	}

	/* Mark the buffer so we only re-write after the template_dir component */
	fr_sbuff_marker(&m, &path_buffer);

	/* Add the attachments to the email */
	attachments_set += tmpl_arr_to_attachments(t, uctx, mime, inst->attachments, &path_buffer, &m);

	/* Check for any file attachments */
	talloc_free(path_buffer.buff);
	return attachments_set;
}

/*
 * 	Free the curl slists
 */
static int _free_mail_ctx(fr_mail_ctx *uctx)
{
	curl_mime_free(uctx->mime);
	curl_slist_free_all(uctx->header);
	curl_slist_free_all(uctx->recipients);
	return 0;
}

/*
 * 	Check if the email was successfully sent, and if the certificate information was extracted
 */
static rlm_rcode_t mod_authorize_result(module_ctx_t const *mctx, REQUEST *request, void *rctx)
{
	fr_mail_ctx 			*mail_ctx = rctx;
	rlm_smtp_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_smtp_t);
	fr_curl_io_request_t     	*randle = mail_ctx->randle;
	fr_curl_tls_t const		*tls;
	long 				curl_out;
	long				curl_out_valid;
	tls = &inst->tls;

	curl_out_valid = curl_easy_getinfo(randle->candle, CURLINFO_SSL_VERIFYRESULT, &curl_out);
	if (curl_out_valid == CURLE_OK){
		RDEBUG2("server certificate %s verified", curl_out ? "was" : "not");
	} else {
		RDEBUG2("server certificate result not found");
	}

	if (randle->result != CURLE_OK) {
		talloc_free(randle);
		return RLM_MODULE_REJECT;
	}

	if (tls->extract_cert_attrs) fr_curl_response_certinfo(request, randle);
	talloc_free(randle);

	return RLM_MODULE_OK;
}

/*
 *	Checks that there is a User-Name and User-Password field in the request
 *	As well as all of the required SMTP elements
 *	Sets the: username, password
 *		website URI
 *		timeout information
 *		TLS information
 *		Sender and recipient information
 *		Email header and body
 *		File attachments
 *
 *	Then it queues the request and yeilds until a response is given
 *	When it responds, mod_authorize_resume is called.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_smtp_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_smtp_t);
	rlm_smtp_thread_t       	*t = talloc_get_type_abort(mctx->thread, rlm_smtp_thread_t);
	fr_curl_io_request_t     	*randle;
	fr_mail_ctx			*mail_ctx;
	const char 			*envelope_address;

	VALUE_PAIR const 		*smtp_body, *username, *password;

	if (fr_pair_find_by_da(request->control, attr_auth_type) != NULL) {
		RDEBUG3("Auth-Type is already set.  Not setting 'Auth-Type := %s'", inst->name);
		return RLM_MODULE_NOOP;
	}

	/* Elements provided by the request */
	username = fr_pair_find_by_da(request->packet->vps, attr_user_name);
	password = fr_pair_find_by_da(request->packet->vps, attr_user_password);
	smtp_body = fr_pair_find_by_da(request->packet->vps, attr_smtp_body);

	/* Make sure all of the essential email components are present and possible*/
	if(!smtp_body) {
		RDEBUG2("Attribute \"smtp-body\" is required for smtp");
		return RLM_MODULE_INVALID;
	}
	if (!inst->sender_address && !inst->envelope_address) {
		RDEBUG2("At least one of \"sender_address\" or \"envelope_address\" in the config, or \"SMTP-Sender-Address\" in the request is needed");
		return RLM_MODULE_INVALID;
	}

	/* allocate the handle and set the curl options */
	randle = fr_curl_io_request_alloc(request);
	if (!randle){
		RDEBUG2("A handle could not be allocated for the request");
		return RLM_MODULE_FAIL;
	}

	/* Initialize the uctx to perform the email */
	mail_ctx = talloc_zero(randle, fr_mail_ctx);
	*mail_ctx = (fr_mail_ctx) {
		.request 	= request,
		.randle 	= randle,
		.mime 		= curl_mime_init(randle->candle),
		.time 		= fr_time() /* time the request was received. Used to set DATE: */
	};

	/* Set the destructor function to free all of the curl_slist elements */
	talloc_set_destructor(mail_ctx, _free_mail_ctx);

	/* Set the generic curl request conditions */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_URL, inst->uri);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_DEFAULT_PROTOCOL, "smtp");
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_TIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	if(RDEBUG_ENABLED3) {
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_VERBOSE, 1L);
	}
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_UPLOAD, 1L);

	/* Set the username and pasword if they have been provided */
	if (username && username->vp_length != 0 && password) {
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_USERNAME, username->vp_strvalue);
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_PASSWORD, password->vp_strvalue);
		RDEBUG2("Username and password set");
	}

	/* Send the envelope address */
	envelope_address = get_envelope_address(inst);
	if(envelope_address == NULL) {
		RDEBUG2("The envelope address must be set");
		goto error;
	}
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MAIL_FROM, get_envelope_address(inst));

	/* Set the recipients */
	mail_ctx->recipients = NULL; /* Prepare the recipients curl_slist to be initialized */
       	if(recipients_source(t, mail_ctx, inst) <= 0) {
		RDEBUG2("At least one recipient is required to send an email");
		goto error;
	}
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MAIL_RCPT, mail_ctx->recipients);

	/* Set the header elements */
	mail_ctx->header = NULL; /* Prepare the header curl_slist to be initialized */
       	if(header_source(t, mail_ctx, inst) != 0) {
		RDEBUG2("The header slist could not be generated");
		goto error;
	}
	/* CURLOPT_HTTPHEADER is the option that they use for the header in the curl example
	 * https://curl.haxx.se/libcurl/c/smtp-mime.html */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_HTTPHEADER, mail_ctx->header);

	/* Initialize the body elements to be uploaded */
	if (body_init(mail_ctx, mail_ctx->mime) == 0) {
		RDEBUG2("The body could not be generated");
		goto error;
	}

	/* Initialize the attachments if there are any*/
	if(attachments_source(t, mail_ctx, mail_ctx->mime, inst) == 0){
		RDEBUG2("No files were attached to the email");
	}

	/* Add the mime endoced elements to the curl request */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MIMEPOST, mail_ctx->mime);

	/* Initialize tls if it has been set up */
	if (fr_curl_easy_tls_init(randle, &inst->tls) != 0) return RLM_MODULE_INVALID;

	if (fr_curl_io_request_enqueue(t->mhandle, request, randle)) return RLM_MODULE_INVALID;

	return unlang_module_yield(request, mod_authorize_result, NULL, mail_ctx);
error:
	return RLM_MODULE_INVALID;
}

/*
 * 	Called when the smtp server responds
 * 	It checks if the response was CURLE_OK
 * 	If it was, it tries to extract the certificate attributes
 * 	If the response was not OK, we REJECT the request
 * 	This does not confirm an email may be sent, only that the provided login credentials are valid for the server
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate_resume(module_ctx_t const *mctx, REQUEST *request, void *rctx)
{
	rlm_smtp_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_smtp_t);
	fr_curl_io_request_t     	*randle = rctx;
	fr_curl_tls_t const		*tls;
	long 				curl_out;
	long				curl_out_valid;

	tls = &inst->tls;

	curl_out_valid = curl_easy_getinfo(randle->candle, CURLINFO_SSL_VERIFYRESULT, &curl_out);
	if (curl_out_valid == CURLE_OK){
		RDEBUG2("server certificate %s verified", curl_out ? "was" : "not");
	} else {
		RDEBUG2("server certificate result not found");
	}

	if (randle->result != CURLE_OK) {
		talloc_free(randle);
		return RLM_MODULE_REJECT;
	}

	if (tls->extract_cert_attrs) fr_curl_response_certinfo(request, randle);

	talloc_free(randle);
	return RLM_MODULE_OK;
}

/*
 *	Checks that there is a User-Name and User-Password field in the request
 *	Checks that User-Password is not Blank
 *	Sets the: username, password
 *		website URI
 *		timeout information
 *		and TLS information
 *
 *	Then it queues the request and yeilds until a response is given
 *	When it responds, mod_authenticate_resume is called.
 */
static rlm_rcode_t CC_HINT(nonnull(1,2)) mod_authenticate(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_smtp_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_smtp_t);
	rlm_smtp_thread_t       *t = talloc_get_type_abort(mctx->thread, rlm_smtp_thread_t);
	VALUE_PAIR const 	*username, *password;
	fr_curl_io_request_t    *randle;

	randle = fr_curl_io_request_alloc(request);
	if (!randle){
	error:
		return RLM_MODULE_FAIL;
	}

	username = fr_pair_find_by_da(request->packet->vps, attr_user_name);
	password = fr_pair_find_by_da(request->packet->vps, attr_user_password);

	/* Make sure we have a user-name and user-password, and that they are possible */
	if (!username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");
		return RLM_MODULE_INVALID;
	}
	if (username->vp_length == 0) {
		RDEBUG2("\"User-Password\" must not be empty");
		return RLM_MODULE_INVALID;
	}
	if (!password) {
		RDEBUG2("Attribute \"User-Password\" is required for authentication");
		return RLM_MODULE_INVALID;
	}

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_DEFAULT_PROTOCOL, "smtp");
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_URL, inst->uri);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_TIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_VERBOSE, 1L);

	if (fr_curl_easy_tls_init(randle, &inst->tls) != 0) return RLM_MODULE_INVALID;

	if (fr_curl_io_request_enqueue(t->mhandle, request, randle)) return RLM_MODULE_INVALID;

	return unlang_module_yield(request, mod_authenticate_resume, NULL, randle);
}

/*
 *	Initialize global curl instance
 */
static int mod_load(void)
{
	if (fr_curl_init() < 0) return -1;
	return 0;
}

/*
 *	Close global curl instance
 */
static void mod_unload(void)
{
	fr_curl_free();
}

/** Verify that a map in the header section makes sense
 *
 */
static int smtp_verify(vp_map_t *map, void *ctx)
{
	if (unlang_fixup_update(map, ctx) < 0) return -1;

	return 0;
}

static int mod_bootstrap(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_smtp_t 	*inst = instance;

	talloc_foreach(inst->recipient_addrs, vpt) INFO("NAME: %s", vpt->name);

	return 0;
}


static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_smtp_t	*inst = instance;
	CONF_SECTION	*header;

	inst->cs = conf;

	header = cf_section_find(inst->cs, "header", NULL);
	if (!header) {
		return 0;
	}

	/*
	 *	Make sure the users don't screw up too badly.
	 */
	{
		tmpl_rules_t	parse_rules = {
			.allow_foreign = true,	/* Because we don't know where we'll be called */
			.allow_unknown = true,
			.allow_unresolved = true,
			.prefix = TMPL_ATTR_REF_PREFIX_AUTO,
		};
		if (map_afrom_cs(inst, &inst->header_maps, header,
				 &parse_rules, &parse_rules, smtp_verify, NULL, MAX_ATTRMAP) < 0) {
			return -1;
		}
	}

	return 0;
}

/*
 *	Initialize a new thread with a curl instance
 */
static int mod_thread_instantiate(UNUSED CONF_SECTION const *conf, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_smtp_thread_t    		*t = thread;
	fr_curl_handle_t    		*mhandle;

	t->inst = instance;

	mhandle = fr_curl_io_init(t, el, false);
	if (!mhandle) return -1;

	t->mhandle = mhandle;
	return 0;
}

/*
 *	Close the thread and free the memory
 */
static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	rlm_smtp_thread_t    *t = thread;
	talloc_free(t->mhandle);
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
extern module_t rlm_smtp;
module_t rlm_smtp = {
	.magic		        = RLM_MODULE_INIT,
	.name		        = "smtp",
	.type		        = RLM_TYPE_THREAD_SAFE,
	.inst_size	        = sizeof(rlm_smtp_t),
	.thread_inst_size   	= sizeof(rlm_smtp_thread_t),
	.config		        = module_config,
	.bootstrap 		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.onload            	= mod_load,
	.unload             	= mod_unload,
	.thread_instantiate 	= mod_thread_instantiate,
	.thread_detach      	= mod_thread_detach,

	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]         = mod_authorize,
	},
};
