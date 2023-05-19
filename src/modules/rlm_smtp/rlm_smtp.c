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
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/curl/base.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cf_priv.h>
#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/util/slab.h>

static fr_dict_t const 	*dict_radius; /*dictionary for radius protocol*/
static fr_dict_t const 	*dict_freeradius;

extern fr_dict_autoload_t rlm_smtp_dict[];
fr_dict_autoload_t rlm_smtp_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_freeradius, .proto = "freeradius"},
	{ NULL }
};

static fr_dict_attr_t const 	*attr_user_password;
static fr_dict_attr_t const 	*attr_user_name;
static fr_dict_attr_t const 	*attr_smtp_header;
static fr_dict_attr_t const 	*attr_smtp_body;

extern fr_dict_attr_autoload_t rlm_smtp_dict_attr[];
fr_dict_attr_autoload_t rlm_smtp_dict_attr[] = {
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_smtp_header, .name = "SMTP-Mail-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_body, .name = "SMTP-Mail-Body", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL },
};

extern global_lib_autoinst_t const * const rlm_smtp_lib[];
global_lib_autoinst_t const * const rlm_smtp_lib[] = {
	&fr_curl_autoinst,
	GLOBAL_LIB_TERMINATOR
};

/** Call environment for sending emails.
*/
typedef struct {
	fr_value_box_t		username;		//!< User to authenticate as when sending emails.
	tmpl_t			*username_tmpl;		//!< The tmpl used to produce the above.
	fr_value_box_t		password;		//!< Password for authenticated mails.
} rlm_smtp_env_t;

FR_DLIST_TYPES(header_list)

/** Structure to hold definitions of SMTP headers
 */
typedef FR_DLIST_HEAD(header_list) header_list_t;
typedef struct {
	char const			*name;		//!< SMTP header name
	tmpl_t				*value;		//!< Tmpl to expand to as header value
	FR_DLIST_ENTRY(header_list)	entry;		//!< Entry in the list of headers
} rlm_smtp_header_t;

FR_DLIST_FUNCS(header_list, rlm_smtp_header_t, entry)
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

	header_list_t		header_list;		//!< List of SMTP headers to add to emails.
	bool 			set_date;

	fr_curl_conn_config_t	conn_config;		//!< Re-usable CURL handle config
} rlm_smtp_t;

/*
 *	Two types of SMTP connections are used:
 *	 - persistent - where the connection can be left established as the same
 *			authentication is used for all mails sent.
 *	 - onetime    - where the connection is torn down after each use, since
 *			different authentication is needed each time.
 *
 * 	Memory for the handles for each is stored in slabs.
 */

FR_SLAB_TYPES(smtp, fr_curl_io_request_t)
FR_SLAB_FUNCS(smtp, fr_curl_io_request_t)

typedef struct {
	fr_curl_handle_t  	*mhandle;	//!< Thread specific multi handle.  Serves as the dispatch and
						///< coralling structure for smtp requests
	smtp_slab_list_t	*slab_persist;	//!< Slab list for persistent connections.
	smtp_slab_list_t	*slab_onetime;	//!< Slab list for onetime use connections.
} rlm_smtp_thread_t;

/*
 *	Holds the context for parsing the email elements
 */
typedef struct {
	request_t		*request;
	fr_curl_io_request_t	*randle;
	fr_dcursor_t		cursor;
	fr_dcursor_t		body_cursor;
	fr_dbuff_t		vp_in;

	struct curl_slist	*recipients;
	struct curl_slist	*header;
	struct curl_slist 	*body_header;

	fr_time_t 		time;
	char 			time_str[60];
	curl_mime		*mime;
} fr_mail_ctx_t;

/*
 * 	Used to ensure that only strings are being set to the tmpl_t ** output
 */
static int cf_table_parse_tmpl(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			       CONF_ITEM *ci, CONF_PARSER const *rule)
{
	int 			ret = 0;
	ssize_t			slen;
	int			type = rule->type;
	bool 			tmpl = (type & FR_TYPE_TMPL);
	CONF_PAIR		*cp = cf_item_to_pair(ci);
	tmpl_t			*vpt;

	static tmpl_rules_t	rules = {
					.attr = {
						.allow_unknown = true,
						.allow_unresolved = true,
						.allow_foreign = true
					}
				};
	rules.attr.list_def = request_attr_request;

	if (!tmpl) {
		cf_log_err(cp, "Failed parsing attribute reference");
		ret = -1;
		goto finish;
	}

	slen = tmpl_afrom_substr(cp, &vpt, &FR_SBUFF_IN(cf_pair_value(cp), strlen(cf_pair_value(cp))),
				 cf_pair_value_quote(cp),
				 value_parse_rules_unquoted[cf_pair_value_quote(cp)],
				 &rules);

	/* There was an error */
	if (!vpt) {
		char *spaces, *text;

		fr_canonicalize_error(ctx, &spaces, &text, slen, cp->value);

		cf_log_err(cp, "Failed parsing attribute reference:");
		cf_log_err(cp, "%s", text);
		cf_log_perr(cp, "%s^", spaces);

		talloc_free(spaces);
		talloc_free(text);
		/* Return error */
		ret = -1;
		goto finish;
	}

	/* Only string values should be used for SMTP components */
	if(tmpl_expanded_type(vpt) != FR_TYPE_STRING) {
		cf_log_err(cp, "Attribute reference must be a string");
		ret = -1;
		goto finish;
	}

	*(tmpl_t **)out = vpt;

	cp->parsed = true;

finish:
	return ret;
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
	{ FR_CONF_OFFSET("connection", FR_TYPE_SUBSECTION, rlm_smtp_t, conn_config), .subcs = (void const *) fr_curl_conn_config },
	CONF_PARSER_TERMINATOR
};

/*
 * 	Adds every element associated with a dict_attr to a curl_slist
 */
static int da_to_slist(fr_mail_ctx_t *uctx, struct curl_slist **out, const fr_dict_attr_t *dict_attr)
{
	request_t 			*request = ((fr_mail_ctx_t *)uctx)->request;
	fr_pair_t			*vp;
	int 				elems_added = 0;

	/* Iterate over the VP and add the string value to the curl_slist */
	vp = fr_pair_dcursor_by_da_init(&uctx->cursor, &uctx->request->request_pairs, dict_attr);

	while (vp) {
		*out = curl_slist_append(*out, vp->vp_strvalue);
		vp = fr_dcursor_next(&uctx->cursor);
		elems_added++;
	}

	if (!elems_added) RDEBUG3("There were no %s elements found", dict_attr->name);

	return elems_added;
}

/*
 * 	Takes a TMPL_TYPE_ATTR and adds it to an slist
 */
static int tmpl_attr_to_slist(fr_mail_ctx_t *uctx, struct curl_slist **out, tmpl_t * const tmpl)
{
	request_t 			*request = ((fr_mail_ctx_t *)uctx)->request;
	fr_pair_t			*vp;
	tmpl_dcursor_ctx_t       	cc;
	int 				count = 0;

	/* Iterate over the VP and add the string value to the curl_slist */
	vp = tmpl_dcursor_init(NULL, NULL, &cc, &uctx->cursor, request, tmpl);

	while (vp) {
		*out = curl_slist_append(*out, vp->vp_strvalue);
		vp = fr_dcursor_next(&uctx->cursor);
		count++;
	}

	/* Return the number of elements which were found */
	tmpl_dcursor_clear(&cc);
	return count;
}

/*
 * 	Parse through an array of tmpl * elements and add them to an slist
 */
static int tmpl_arr_to_slist(fr_mail_ctx_t *uctx, struct curl_slist **out, tmpl_t ** const tmpl)
{
	request_t 	*request = uctx->request;
	int 		count = 0;
	char 		*expanded_str;

	talloc_foreach(tmpl, current) {
		if (current->type == TMPL_TYPE_ATTR) {
			/* If the element contains a reference to an attribute, parse every value it references */
			count += tmpl_attr_to_slist(uctx, out, current);

		} else {
			/* If the element is just a normal string, add it's name to the slist*/
			if (tmpl_aexpand(request, &expanded_str, request, current, NULL, NULL) < 0) {
				RDEBUG2("Could not expand the element %s", current->name);
				break;
			}

			*out = curl_slist_append(*out, expanded_str);
			count++;
		}
	}

	return count;
}

/*
 * 	Adds every element associated with a tmpl_attr to an sbuff
 */
static ssize_t tmpl_attr_to_sbuff(fr_mail_ctx_t *uctx, fr_sbuff_t *out, tmpl_t const *vpt, char const *delimiter)
{
	fr_pair_t		*vp;
	tmpl_dcursor_ctx_t       cc;

	ssize_t			copied = 0;

	/* Loop through the elements to be added to the sbuff */
	vp = tmpl_dcursor_init(NULL, NULL, &cc, &uctx->cursor, uctx->request, vpt);
	while (vp) {
		copied += fr_sbuff_in_bstrncpy(out, vp->vp_strvalue, vp->vp_length);

		vp = fr_dcursor_next(&uctx->cursor);
		/* If there will be more values, add a comma and whitespace */
		if (vp) {
			copied += fr_sbuff_in_strcpy(out, delimiter);
		}
	}
	tmpl_dcursor_clear(&cc);
	return copied;
}

/*
 * 	Adds every value in a dict_attr to a curl_slist as a comma separated list with a preposition
 */
static int tmpl_arr_to_header(fr_mail_ctx_t *uctx, struct curl_slist **out, tmpl_t ** const tmpl,
			      const char *preposition)
{
	request_t		*request = uctx->request;
	fr_sbuff_t 		sbuff;
	fr_sbuff_uctx_talloc_t 	sbuff_ctx;
	ssize_t 		out_len = 0;
	char 			*expanded_str;

	/* Initialize the buffer for the recipients. Used for TO */
	fr_sbuff_init_talloc(uctx, &sbuff, &sbuff_ctx, 256, SIZE_MAX);
	/* Add the preposition for the header element */
	(void) fr_sbuff_in_strcpy(&sbuff, preposition);

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
			if( tmpl_aexpand(request, &expanded_str, request, vpt, NULL, NULL) < 0) {
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
		return 1;
	}

	talloc_free(sbuff.buff);
	RDEBUG2("Failed to add the element to the header");
	return 0;
}

/*
 * 	Takes a string value and adds it as a file path to upload as an attachment
 */
static int str_to_attachments(fr_mail_ctx_t *uctx, curl_mime *mime, char const * str, size_t len,
			      fr_sbuff_t *path_buffer, fr_sbuff_marker_t *m)
{
	request_t		*request = uctx->request;
	curl_mimepart		*part;

	/* Move to the end of the template directory filepath */
	fr_sbuff_set(path_buffer, m);

	/* Check to see if the file attachment is valid, skip it if not */
	RDEBUG2("Trying to set attachment: %s", str);

	if (strncmp(str, "/", 1) == 0) {
		RDEBUG2("File attachments cannot be an absolute path");
		return 0;
	}

	if (strncmp(str, "..", 2) == 0) {
		RDEBUG2("Cannot access values outside of template_directory");
		return 0;
	}

	/* Copy the filename into the buffer */
	/* coverity[check_return] */
	fr_sbuff_in_bstrncpy(path_buffer, str, len);

	/* Add the file attachment as a mime encoded part */
	part = curl_mime_addpart(mime);
	curl_mime_encoder(part, "base64");
	if (curl_mime_filedata(part, path_buffer->buff) != CURLE_OK) {
		REDEBUG2("Cannot add file attachment");
		return 0;
	}

	return 1;
}

/*
 * 	Parse a tmpl attr into a file attachment path and add it as a mime part
 */
static int tmpl_attr_to_attachment(fr_mail_ctx_t *uctx, curl_mime *mime, const tmpl_t * tmpl,
				   fr_sbuff_t *path_buffer, fr_sbuff_marker_t *m)
{
	fr_pair_t 		*vp;
	request_t		*request = uctx->request;
	tmpl_dcursor_ctx_t	cc;
	int 			attachments_set = 0;

	/* Check for any file attachments */
	for (vp = tmpl_dcursor_init(NULL, NULL, &cc, &uctx->cursor, request, tmpl);
	     vp;
	     vp = fr_dcursor_next(&uctx->cursor)) {
		if (vp->vp_tainted) {
			RDEBUG2("Skipping tainted attachment");
			continue;
		}

		attachments_set += str_to_attachments(uctx, mime, vp->vp_strvalue, vp->vp_length, path_buffer, m);
	}

	tmpl_dcursor_clear(&cc);
	return attachments_set;
}

/*
 * 	Adds every element in a tmpl** to an attachment path, then adds it to the email
 */
static int tmpl_arr_to_attachments (fr_mail_ctx_t *uctx, curl_mime *mime, tmpl_t ** const tmpl,
				    fr_sbuff_t *path_buffer, fr_sbuff_marker_t *m)
{
	request_t	*request = uctx->request;
	ssize_t 	count = 0;
	ssize_t 	expanded_str_len;
	char 		*expanded_str;

	talloc_foreach(tmpl, current) {
		/* write the elements to the sbuff as a comma separated list */
		if (current->type == TMPL_TYPE_ATTR) {
			count += tmpl_attr_to_attachment(uctx, mime, current, path_buffer, m);

		} else {
			expanded_str_len = tmpl_aexpand(request, &expanded_str, request, current, NULL, NULL);
			if (expanded_str_len < 0) {
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
static const char *get_envelope_address(rlm_smtp_t const *inst)
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
static int generate_from_header(fr_mail_ctx_t *uctx, struct curl_slist **out, rlm_smtp_t const *inst)
{
	char const 			*from = "FROM: ";
	fr_sbuff_t 			sbuff;
	fr_sbuff_uctx_talloc_t 		sbuff_ctx;

	/* If sender_address is set, then generate FROM: with those attributes */
	if (inst->sender_address) {
		tmpl_arr_to_header(uctx, &uctx->header, inst->sender_address, from);
		return 0;
	}

	/* Initialize the buffer for the recipients. Used for TO */
	fr_sbuff_init_talloc(uctx, &sbuff, &sbuff_ctx, 256, SIZE_MAX);

	/* Add the preposition for the header element */
	(void) fr_sbuff_in_strcpy(&sbuff, from);

	/* Copy the envelope address as the FROM: source */
	/* coverity[check_return] */
	fr_sbuff_in_bstrncpy(&sbuff, inst->envelope_address, strlen(inst->envelope_address));
	*out = curl_slist_append(*out, sbuff.buff);

	/* Free the buffer used to generate the FROM header */
	talloc_free(sbuff.buff);

	return 0;
}

/*
 *	Generates a curl_slist of recipients
 */
static int recipients_source(fr_mail_ctx_t *uctx, rlm_smtp_t const *inst)
{
	request_t		*request = uctx->request;
	int 			recipients_set = 0;

	/*
	  *	Try to load the recipients into the envelope recipients if they are set
	  */
	if(inst->recipient_addrs) recipients_set += tmpl_arr_to_slist(uctx, &uctx->recipients, inst->recipient_addrs);

	/*
	 *	If any recipients were found, ignore to cc and bcc, return the amount added.
	 **/
	if (recipients_set) {
		RDEBUG2("Recipients were generated from \"SMTP-Recipients\" and/or recipients in the config");
		return recipients_set;
	}
	RDEBUG2("No addresses were found in SMTP-Recipient");

	/*
	 *	Try to load the to: addresses into the envelope recipients if they are set
	 */
	if (inst->to_addrs) recipients_set += tmpl_arr_to_slist(uctx, &uctx->recipients, inst->to_addrs);

	/*
	 *	Try to load the cc: addresses into the envelope recipients if they are set
	 */
	if (inst->cc_addrs) recipients_set += tmpl_arr_to_slist(uctx, &uctx->recipients, inst->cc_addrs);

	/*
	 *	Try to load the cc: addresses into the envelope recipients if they are set
	 */
	if (inst->bcc_addrs) recipients_set += tmpl_arr_to_slist(uctx, &uctx->recipients, inst->bcc_addrs);

	RDEBUG2("%d recipients set", recipients_set);
	return recipients_set;
}

/*
 *	Generates a curl_slist of header elements header elements
 */
static int header_source(fr_mail_ctx_t *uctx, rlm_smtp_t const *inst)
{
	fr_sbuff_t 			time_out;
	char const 			*to = "TO: ";
	char const 			*cc = "CC: ";
	request_t			*request = uctx->request;
	fr_sbuff_t 			conf_buffer;
	fr_sbuff_uctx_talloc_t 		conf_ctx;
	rlm_smtp_header_t const		*header = NULL;
	char 				*expanded_rhs;

	/*
	 *	Load in all of the header elements supplied in the config
	 */
	while ((header = header_list_next(&inst->header_list, header))) {
		/* Do any string expansion required in the rhs */
		if( tmpl_aexpand(request, &expanded_rhs, request, header->value, NULL, NULL) < 0) {
			RDEBUG2("Skipping: %s's could not parse: %s", header->name, header->value->name);
			continue;
		}

		fr_sbuff_init_talloc(uctx, &conf_buffer, &conf_ctx, 256, SIZE_MAX);

		/* Format the conf item to be a valid SMTP header */
		/* coverity[check_return] */
		fr_sbuff_in_bstrncpy(&conf_buffer, header->name, strlen(header->name));
		fr_sbuff_in_strcpy(&conf_buffer, ": ");
		fr_sbuff_in_bstrncpy(&conf_buffer, expanded_rhs, strlen(expanded_rhs));

		/* Add the header to the curl slist */
		uctx->header = curl_slist_append(uctx->header, fr_sbuff_buff(&conf_buffer));
		talloc_free(conf_buffer.buff);
	}

	/* Add the FROM: line */
	generate_from_header(uctx, &uctx->header, inst);

	/* Add the TO: line if there is one provided in the request by SMTP-TO */
	tmpl_arr_to_header(uctx, &uctx->header, inst->to_addrs, to);

	/* Add the CC: line if there is one provided in the request by SMTP-CC */
	tmpl_arr_to_header(uctx, &uctx->header, inst->cc_addrs, cc);

	/* Add all the generic header elements in the request */
	da_to_slist(uctx, &uctx->header, attr_smtp_header);

	/* If no header elements could be found, there is an error */
	if (!uctx->header) {
		RDEBUG2("Header elements could not be added");
 		return -1;
	}

	/* Set the DATE: to the time that the request was received */
	if (inst->set_date) {
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
	fr_mail_ctx_t 		*uctx = mail_ctx;
	fr_dbuff_t		out;
	request_t		*request = uctx->request;
	fr_pair_t 		*vp;

	fr_dbuff_init(&out, (uint8_t *)ptr, (size * nmemb));  /* Wrap the output buffer so we can track our position easily */

	vp = fr_dcursor_current(&uctx->body_cursor);
	if (!vp) {
		RDEBUG2("vp could not be found for the body element");
		return 0;
	}

	/*
	 *	Copy the vp into the email. If it cannot all be
	 *	loaded, return the amount of memory that was loaded
	 *	and get called again.
	 */
	if (fr_dbuff_in_memcpy_partial(&out, &uctx->vp_in, SIZE_MAX) < fr_dbuff_remaining(&uctx->vp_in)) {
		RDEBUG2("%zu bytes used (partial copy)", fr_dbuff_used(&out));
		return fr_dbuff_used(&out);
	}

	/*
	 *	Once this value pair is fully copied, prepare for the next element
	 */
	vp = fr_dcursor_next(&uctx->body_cursor);
	if (vp) {
		fr_dbuff_init(&uctx->vp_in, (uint8_t const *)vp->vp_strvalue, vp->vp_length);

	}

	RDEBUG2("%zu bytes used (full copy)", fr_dbuff_used(&out));
	return fr_dbuff_used(&out);
}

/*
 * 	Initialize all the body elements to be uploaded later
 */
static int body_init(fr_mail_ctx_t *uctx, curl_mime *mime)
{
	fr_pair_t 	*vp;
	request_t	*request = uctx->request;

	curl_mimepart	*part;
	curl_mime	*mime_body;

	int 		body_elements = 0;

	/* Initialize a second mime to apply special conditions to the body elements */
	MEM(mime_body = curl_mime_init(uctx->randle->candle));

	/* initialize the cursor used by the body_source function*/
	vp = fr_pair_dcursor_by_da_init(&uctx->body_cursor, &uctx->request->request_pairs, attr_smtp_body);
	fr_dbuff_init(&uctx->vp_in, (uint8_t const *)vp->vp_strvalue, vp->vp_length);

	/* Add a mime part to mime_body for every body element */
	while (vp) {
		body_elements++;
		MEM(part = curl_mime_addpart(mime_body));

		curl_mime_encoder(part, "8bit");
		curl_mime_data_cb(part, vp->vp_length, body_source, NULL, NULL, uctx);

		vp = fr_dcursor_next(&uctx->body_cursor);
	}
	RDEBUG2("initialized %d body element part(s)", body_elements);

	/* Re-initialize the cursor for use when uploading the data to curl */
	fr_pair_dcursor_by_da_init(&uctx->body_cursor, &uctx->request->request_pairs, attr_smtp_body);

	/*
	 *	Add body_mime as a subpart of the mime request with a local content-disposition
	 */
	MEM(part = curl_mime_addpart(mime));
	curl_mime_subparts(part, mime_body);
	MEM(curl_mime_type(part, "multipart/mixed") == CURLE_OK);
	uctx->body_header = curl_slist_append(NULL, "Content-Disposition: inline"); /* Initialize the body_header curl_slist */
	curl_mime_headers(part, uctx->body_header, 1);

	return body_elements;
}

/*
 * 	Adds every SMTP_Attachments file to the email as a MIME part
 */
static int attachments_source(fr_mail_ctx_t *uctx, curl_mime *mime, rlm_smtp_t const *inst)
{
	request_t		*request = uctx->request;
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
		(void) fr_sbuff_in_char(&path_buffer, '/');
	}

	/* Mark the buffer so we only re-write after the template_dir component */
	fr_sbuff_marker(&m, &path_buffer);

	/* Add the attachments to the email */
	attachments_set += tmpl_arr_to_attachments(uctx, mime, inst->attachments, &path_buffer, &m);

	/* Check for any file attachments */
	talloc_free(path_buffer.buff);
	return attachments_set;
}

static void smtp_io_module_signal(module_ctx_t const *mctx, request_t *request, UNUSED fr_signal_t action)
{
	fr_curl_io_request_t	*randle = talloc_get_type_abort(mctx->rctx, fr_curl_io_request_t);
	rlm_smtp_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_smtp_thread_t);
	CURLMcode		ret;

	RDEBUG2("Forcefully cancelling pending SMTP request");

	ret = curl_multi_remove_handle(t->mhandle->mandle, randle->candle);	/* Gracefully terminate the request */
	if (ret != CURLM_OK) {
		RERROR("Failed removing curl handle from multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
		/* Not much we can do */
	}
	t->mhandle->transfers--;
	smtp_slab_release(randle);
}

/** 	Callback to process response of SMTP server
 *
 * 	It checks if the response was CURLE_OK
 * 	If it was, it tries to extract the certificate attributes
 * 	If the response was not OK, we REJECT the request
 * 	When responding to requests initiated by mod_authenticate this is simply
 *	a check on the username and password.
 *	When responding to requests initiated by mod_mail this indicates
 *	the mail has been queued.
 */
static unlang_action_t smtp_io_module_resume(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_smtp_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_smtp_t);
	fr_curl_io_request_t     	*randle = talloc_get_type_abort(mctx->rctx, fr_curl_io_request_t);
	fr_curl_tls_t const		*tls = &inst->tls;
	long 				curl_out;
	long				curl_out_valid;

	curl_out_valid = curl_easy_getinfo(randle->candle, CURLINFO_SSL_VERIFYRESULT, &curl_out);
	if (curl_out_valid == CURLE_OK){
		RDEBUG2("server certificate %s verified", curl_out ? "was" : "not");
	} else {
		RDEBUG2("server certificate result not found");
	}

	if (randle->result != CURLE_OK) {
		CURLcode result = randle->result;
		smtp_slab_release(randle);
		switch (result) {
		case CURLE_PEER_FAILED_VERIFICATION:
		case CURLE_LOGIN_DENIED:
			RETURN_MODULE_REJECT;
		default:
			RETURN_MODULE_FAIL;
		}
	}

	if (tls->extract_cert_attrs) fr_curl_response_certinfo(request, randle);
	smtp_slab_release(randle);

	RETURN_MODULE_OK;
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
 *	When it responds, smtp_io_module_resume is called.
 */
static unlang_action_t CC_HINT(nonnull) mod_mail(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_smtp_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_smtp_t);
	rlm_smtp_thread_t       	*t = talloc_get_type_abort(mctx->thread, rlm_smtp_thread_t);
	rlm_smtp_env_t			*call_env = talloc_get_type_abort(mctx->env_data, rlm_smtp_env_t);
	fr_curl_io_request_t     	*randle = NULL;
	fr_mail_ctx_t			*mail_ctx;
	const char 			*envelope_address;

	fr_pair_t const 		*smtp_body;

	/* Elements provided by the request */
	smtp_body = fr_pair_find_by_da(&request->request_pairs, NULL, attr_smtp_body);

	/* Make sure all of the essential email components are present and possible*/
	if (!smtp_body) {
		RDEBUG2("Attribute \"smtp-body\" is required for smtp");
		RETURN_MODULE_INVALID;
	}

	if (!inst->sender_address && !inst->envelope_address) {
		RDEBUG2("At least one of \"sender_address\" or \"envelope_address\" in the config, or \"SMTP-Sender-Address\" in the request is needed");
	error:
		if (randle) smtp_slab_release(randle);
		RETURN_MODULE_INVALID;
	}

	/*
	 *	If the username is defined and is not static data
	 *	a onetime connection is used, otherwise a persistent one
	 *	can be used.
	 */
	randle = (call_env->username_tmpl &&
		  !tmpl_is_data(call_env->username_tmpl)) ? smtp_slab_reserve(t->slab_onetime) :
							    smtp_slab_reserve(t->slab_persist);
	if (!randle) {
		RDEBUG2("A handle could not be allocated for the request");
		RETURN_MODULE_FAIL;
	}

	/* Initialize the uctx to perform the email */
	mail_ctx = talloc_get_type_abort(randle->uctx, fr_mail_ctx_t);
	*mail_ctx = (fr_mail_ctx_t) {
		.request 	= request,
		.randle 	= randle,
		.mime 		= curl_mime_init(randle->candle),
		.time 		= fr_time(), /* time the request was received. Used to set DATE: */
		.recipients	= NULL,
		.header		= NULL
	};

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_UPLOAD, 1L);

	/* Set the username and password if they have been provided */
	if (call_env->username.vb_strvalue) {
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_USERNAME, call_env->username.vb_strvalue);

		if (!call_env->password.vb_strvalue) goto skip_auth;

		FR_CURL_REQUEST_SET_OPTION(CURLOPT_PASSWORD, call_env->password.vb_strvalue);
		RDEBUG2("Username and password set");
	}
skip_auth:

	/* Send the envelope address */
	envelope_address = get_envelope_address(inst);
	if (!envelope_address) {
		REDEBUG("The envelope address must be set");
		goto error;
	}
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MAIL_FROM, get_envelope_address(inst));

	/* Set the recipients */
       	if (recipients_source(mail_ctx, inst) <= 0) {
		REDEBUG("At least one recipient is required to send an email");
		goto error;
	}
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MAIL_RCPT, mail_ctx->recipients);

	/* Set the header elements */
       	if (header_source(mail_ctx, inst) != 0) {
		REDEBUG("The header slist could not be generated");
		goto error;
	}

	/*
	 *	CURLOPT_HTTPHEADER is the option that they use for the header in the curl example
	 *
	 *	https://curl.haxx.se/libcurl/c/smtp-mime.html
	 */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_HTTPHEADER, mail_ctx->header);

	/* Initialize the body elements to be uploaded */
	if (body_init(mail_ctx, mail_ctx->mime) == 0) {
		REDEBUG("The body could not be generated");
		goto error;
	}

	/* Initialize the attachments if there are any*/
	if (attachments_source(mail_ctx, mail_ctx->mime, inst) == 0){
		RDEBUG2("No files were attached to the email");
	}

	/* Add the mime endoced elements to the curl request */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MIMEPOST, mail_ctx->mime);

	if (fr_curl_io_request_enqueue(t->mhandle, request, randle)) RETURN_MODULE_INVALID;

	return unlang_module_yield(request, smtp_io_module_resume, smtp_io_module_signal, ~FR_SIGNAL_CANCEL, randle);
}

/*
 *	Checks that there is a User-Name and User-Password field in the request
 *	Checks that User-Password is not Blank
 *	Sets the: username, password
 *		website URI
 *		timeout information
 *		and TLS information
 *
 *	Then it queues the request and yields until a response is given
 *	When it responds, smtp_io_module_resume is called.
 */
static unlang_action_t CC_HINT(nonnull(1,2)) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_smtp_thread_t       *t = talloc_get_type_abort(mctx->thread, rlm_smtp_thread_t);
	fr_pair_t const 	*username, *password;
	fr_curl_io_request_t    *randle;

	randle = smtp_slab_reserve(t->slab_onetime);
	if (!randle) RETURN_MODULE_FAIL;

	username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	password = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_password);

	/* Make sure we have a user-name and user-password, and that they are possible */
	if (!username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");
	error:
		smtp_slab_release(randle);
		RETURN_MODULE_INVALID;
	}
	if (username->vp_length == 0) {
		RDEBUG2("\"User-Password\" must not be empty");
		goto error;
	}
	if (!password) {
		RDEBUG2("Attribute \"User-Password\" is required for authentication");
		goto error;
	}

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_USERNAME, username->vp_strvalue);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_PASSWORD, password->vp_strvalue);

	if (fr_curl_io_request_enqueue(t->mhandle, request, randle)) RETURN_MODULE_INVALID;

	return unlang_module_yield(request, smtp_io_module_resume, smtp_io_module_signal, ~FR_SIGNAL_CANCEL, randle);
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_smtp_t 	*inst = talloc_get_type_abort(mctx->inst->data, rlm_smtp_t );

	talloc_foreach(inst->recipient_addrs, vpt) INFO("NAME: %s", vpt->name);

	return 0;
}


static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_smtp_t			*inst = talloc_get_type_abort(mctx->inst->data, rlm_smtp_t);
	CONF_SECTION			*conf = mctx->inst->conf;
	CONF_SECTION			*cs;
	CONF_ITEM			*ci;
	CONF_PAIR			*cp;
	tmpl_rules_t			parse_rules;
	rlm_smtp_header_t		*header;
	char const			*value;
	char				*unescaped_value = NULL;
	fr_token_t			type;
	ssize_t				slen;
	fr_sbuff_parse_rules_t const	*p_rules;

	header_list_init(&inst->header_list);
	cs = cf_section_find(conf, "header", NULL);
	if (!cs) return 0;

	parse_rules = (tmpl_rules_t) {
		.attr = {
			.allow_foreign = true,	/* Because we don't know where we'll be called */
			.allow_unknown = true,
			.allow_unresolved = true,
			.prefix = TMPL_ATTR_REF_PREFIX_AUTO,
			.list_def = request_attr_request
		}
	};

	for (ci = cf_item_next(cs, NULL); ci != NULL; ci = cf_item_next(cs,ci)) {
		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "Entry is not in \"header = value\" format");
		error:
			TALLOC_FREE(unescaped_value);
			header_list_talloc_free(&inst->header_list);
			return -1;
		}

		cp = cf_item_to_pair(ci);
		fr_assert(cp != NULL);

		MEM(header = talloc_zero(inst, rlm_smtp_header_t));

		header->name = talloc_strdup(header, cf_pair_attr(cp));
		value = cf_pair_value(cp);
		type = cf_pair_value_quote(cp);
		p_rules = value_parse_rules_unquoted[type];

		if (type == T_DOUBLE_QUOTED_STRING || type == T_BACK_QUOTED_STRING) {
			slen = fr_sbuff_out_aunescape_until(NULL, &unescaped_value,
				&FR_SBUFF_IN(value, talloc_array_length(value) - 1), SIZE_MAX, p_rules->terminals, p_rules->escapes);
			if (slen < 0) {
				char *spaces, *text;
			parse_error:
				cf_log_err(ci, "Failed to parse value %s", value);
				fr_canonicalize_error(inst, &spaces, &text, slen, value);
				cf_log_err(cp, "%s", text);
				cf_log_perr(cp, "%s^", spaces);

				talloc_free(spaces);
				talloc_free(text);
				goto error;
			}
			value = unescaped_value;
			p_rules = NULL;
		} else {
			slen = talloc_array_length(value) - 1;
		}

		slen = tmpl_afrom_substr(header, &header->value, &FR_SBUFF_IN(value, slen), type, p_rules, &parse_rules);
		if (slen < 0) goto parse_error;

		header_list_insert_tail(&inst->header_list, header);
		TALLOC_FREE(unescaped_value);
	}

	inst->conn_config.reuse.num_children = 1;
	inst->conn_config.reuse.child_pool_size = sizeof(fr_mail_ctx_t);

	return 0;
}

#define SMTP_COMMON_CLEANUP \
	fr_mail_ctx_t	*mail_ctx = talloc_get_type_abort(randle->uctx, fr_mail_ctx_t); \
	if (mail_ctx->mime) curl_mime_free(mail_ctx->mime); \
	if (mail_ctx->header) curl_slist_free_all(mail_ctx->header); \
	if (mail_ctx->recipients) curl_slist_free_all(mail_ctx->recipients)

static int smtp_onetime_request_cleanup(fr_curl_io_request_t *randle, UNUSED void *uctx)
{
	SMTP_COMMON_CLEANUP;

	if (randle->candle) curl_easy_cleanup(randle->candle);

	return 0;
}

static int smtp_persist_request_cleanup(fr_curl_io_request_t *randle, UNUSED void *uctx)
{
	SMTP_COMMON_CLEANUP;

	if (randle->candle) curl_easy_reset(randle->candle);

	return 0;
}

static int smtp_onetime_conn_alloc(fr_curl_io_request_t *randle, UNUSED void *uctx)
{
	fr_mail_ctx_t		*mail_ctx = NULL;

	MEM(mail_ctx = talloc_zero(randle, fr_mail_ctx_t));
	randle->uctx = mail_ctx;

	smtp_slab_element_set_destructor(randle, smtp_onetime_request_cleanup, NULL);

	return 0;
}

static int smtp_mail_ctx_free(fr_mail_ctx_t *mail_ctx)
{
	if (mail_ctx->randle && mail_ctx->randle->candle) curl_easy_cleanup(mail_ctx->randle->candle);

	return 0;
}

static int smtp_persist_conn_alloc(fr_curl_io_request_t *randle, UNUSED void *uctx)
{
	fr_mail_ctx_t		*mail_ctx = NULL;

	MEM(mail_ctx = talloc_zero(randle, fr_mail_ctx_t));
	mail_ctx->randle = randle;
	randle->uctx = mail_ctx;
	randle->candle = curl_easy_init();
	if (unlikely(!randle->candle)) {
		fr_strerror_printf("Unable to initialise CURL handle");
		return -1;
	}
	talloc_set_destructor(mail_ctx, smtp_mail_ctx_free);

	smtp_slab_element_set_destructor(randle, smtp_persist_request_cleanup, NULL);

	return 0;
}

static inline int smtp_conn_common_init(fr_curl_io_request_t *randle, rlm_smtp_t const *inst)
{
#if CURL_AT_LEAST_VERSION(7,45,0)
	FR_CURL_SET_OPTION(CURLOPT_DEFAULT_PROTOCOL, "smtp");
#endif
	FR_CURL_SET_OPTION(CURLOPT_URL, inst->uri);
#if CURL_AT_LEAST_VERSION(7,85,0)
	FR_CURL_SET_OPTION(CURLOPT_PROTOCOLS_STR, "smtp,smtps");
#else
	FR_CURL_SET_OPTION(CURLOPT_PROTOCOLS, CURLPROTO_SMTP | CURLPROTO_SMTPS);
#endif
	FR_CURL_SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	FR_CURL_SET_OPTION(CURLOPT_TIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));

	if (DEBUG_ENABLED3) FR_CURL_SET_OPTION(CURLOPT_VERBOSE, 1L);

	if (fr_curl_easy_tls_init(randle, &inst->tls) != 0) goto error;

	return 0;
error:
	return -1;
}

static int smtp_onetime_conn_init(fr_curl_io_request_t *randle, void *uctx)
{
	rlm_smtp_t const	*inst = talloc_get_type_abort(uctx, rlm_smtp_t);
	fr_mail_ctx_t		*mail_ctx = talloc_get_type_abort(randle->uctx, fr_mail_ctx_t);

	randle->candle = curl_easy_init();
	if (unlikely(!randle->candle)) {
		fr_strerror_printf("Unable to initialise CURL handle");
		return -1;
	}

	memset(mail_ctx, 0, sizeof(fr_mail_ctx_t));

	return smtp_conn_common_init(randle, inst);
}


static int smtp_persist_conn_init(fr_curl_io_request_t *randle, void *uctx)
{
	rlm_smtp_t const	*inst = talloc_get_type_abort(uctx, rlm_smtp_t);
	fr_mail_ctx_t		*mail_ctx = talloc_get_type_abort(randle->uctx, fr_mail_ctx_t);

	memset(mail_ctx, 0, sizeof(fr_mail_ctx_t));

	return smtp_conn_common_init(randle, inst);
}

/*
 *	Initialize a new thread with a curl instance
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_smtp_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_smtp_t);
	rlm_smtp_thread_t    	*t = talloc_get_type_abort(mctx->thread, rlm_smtp_thread_t);
	fr_curl_handle_t    	*mhandle;

	if (!(t->slab_onetime = smtp_slab_list_alloc(t, mctx->el, &inst->conn_config.reuse,
						     smtp_onetime_conn_alloc, smtp_onetime_conn_init,
						     inst, false, false))) {
		ERROR("Connection handle pool instantiation failed");
		return -1;
	}
	if (!(t->slab_persist = smtp_slab_list_alloc(t, mctx->el, &inst->conn_config.reuse,
						     smtp_persist_conn_alloc, smtp_persist_conn_init,
						     inst, false, true))) {
		ERROR("Connection handle pool instantiation failed");
		return -1;
	}

	mhandle = fr_curl_io_init(t, mctx->el, false);
	if (!mhandle) return -1;

	t->mhandle = mhandle;
	return 0;
}

/*
 *	Close the thread and free the memory
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_smtp_thread_t    		*t = talloc_get_type_abort(mctx->thread, rlm_smtp_thread_t);

	talloc_free(t->mhandle);
	talloc_free(t->slab_persist);
	talloc_free(t->slab_onetime);
	return 0;
}

static const call_env_t call_env[] = {
	{ FR_CALL_ENV_TMPL_OFFSET("username", FR_TYPE_STRING, rlm_smtp_env_t, username, username_tmpl, NULL,
				T_DOUBLE_QUOTED_STRING, false, true, true) },
	{ FR_CALL_ENV_OFFSET("password", FR_TYPE_STRING, rlm_smtp_env_t, password, NULL,
				T_DOUBLE_QUOTED_STRING, false, true, true) },
	CALL_ENV_TERMINATOR
};

static const call_method_env_t method_env = {
	.inst_size = sizeof(rlm_smtp_env_t),
	.inst_type = "rlm_smtp_env_t",
	.env = call_env
};

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_smtp;
module_rlm_t rlm_smtp = {
	.common = {
		.magic		        = MODULE_MAGIC_INIT,
		.name		        = "smtp",
		.type		        = MODULE_TYPE_THREAD_SAFE,
		.inst_size	        = sizeof(rlm_smtp_t),
		.thread_inst_size   	= sizeof(rlm_smtp_thread_t),
		.config		        = module_config,
		.bootstrap 		= mod_bootstrap,
		.instantiate		= mod_instantiate,
		.thread_instantiate 	= mod_thread_instantiate,
		.thread_detach      	= mod_thread_detach,
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = "mail",		.name2 = CF_IDENT_ANY,		.method = mod_mail,
		  .method_env = &method_env },
		{ .name1 = "authenticate",	.name2 = CF_IDENT_ANY,		.method = mod_authenticate },
		MODULE_NAME_TERMINATOR
	}
};
