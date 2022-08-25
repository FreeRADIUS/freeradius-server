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
 * @file rlm_detail.c
 * @brief Write plaintext versions of packets to flatfiles.
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/exfile.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/perm.h>

#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#ifdef HAVE_GRP_H
#  include <grp.h>
#endif

#define DIRLEN	8192		//!< Maximum path length.

/** Instance configuration for rlm_detail
 *
 * Holds the configuration and preparsed data for a instance of rlm_detail.
 */
typedef struct {
	char const	*filename;	//!< File/path to write to.
	uint32_t	perm;		//!< Permissions to use for new files.
	char const	*group;		//!< Group to use for new files.

	tmpl_t		*header;	//!< Header format.
	bool		locking;	//!< Whether the file should be locked.

	bool		log_srcdst;	//!< Add IP src/dst attributes to entries.

	bool		escape;		//!< do filename escaping, yes / no

	xlat_escape_legacy_t	escape_func; //!< escape function

	exfile_t    	*ef;		//!< Log file handler

	fr_hash_table_t *ht;		//!< Holds suppressed attributes.
} rlm_detail_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_OUTPUT | FR_TYPE_XLAT, rlm_detail_t, filename), .dflt = "%A/%{Packet-Src-IP-Address}/detail" },
	{ FR_CONF_OFFSET("header", FR_TYPE_TMPL | FR_TYPE_XLAT | FR_TYPE_NON_BLOCKING, rlm_detail_t, header),
	  .dflt = "%t", .quote = T_DOUBLE_QUOTED_STRING },
	{ FR_CONF_OFFSET("permissions", FR_TYPE_UINT32, rlm_detail_t, perm), .dflt = "0600" },
	{ FR_CONF_OFFSET("group", FR_TYPE_STRING, rlm_detail_t, group) },
	{ FR_CONF_OFFSET("locking", FR_TYPE_BOOL, rlm_detail_t, locking), .dflt = "no" },
	{ FR_CONF_OFFSET("escape_filenames", FR_TYPE_BOOL, rlm_detail_t, escape), .dflt = "no" },
	{ FR_CONF_OFFSET("log_packet_header", FR_TYPE_BOOL, rlm_detail_t, log_srcdst), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_detail_dict[];
fr_dict_autoload_t rlm_detail_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_src_ipv4_address;
static fr_dict_attr_t const *attr_packet_dst_ipv4_address;
static fr_dict_attr_t const *attr_packet_src_ipv6_address;
static fr_dict_attr_t const *attr_packet_dst_ipv6_address;
static fr_dict_attr_t const *attr_packet_src_port;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_protocol;

static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_detail_dict_attr[];
fr_dict_attr_autoload_t rlm_detail_dict_attr[] = {
	{ .out = &attr_packet_dst_ipv4_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_ipv6_address, .name = "Packet-Dst-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ipv4_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ipv6_address, .name = "Packet-Src-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_protocol, .name = "Protocol", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

static uint32_t detail_hash(void const *data)
{
	fr_dict_attr_t const *da = data;
	return fr_hash(&da, sizeof(da));
}

static int8_t detail_cmp(void const *a, void const *b)
{
	return CMP(a, b);
}

/*
 *	(Re-)read radiusd.conf into memory.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_detail_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_detail_t);
	CONF_SECTION	*conf = mctx->inst->conf;
	CONF_SECTION	*cs;

	/*
	 *	Escape filenames only if asked.
	 */
	if (inst->escape) {
		inst->escape_func = rad_filename_escape;
	} else {
		inst->escape_func = rad_filename_make_safe;
	}

	inst->ef = module_rlm_exfile_init(inst, conf, 256, fr_time_delta_from_sec(30), inst->locking, NULL, NULL);
	if (!inst->ef) {
		cf_log_err(conf, "Failed creating log file context");
		return -1;
	}

	/*
	 *	Suppress certain attributes.
	 */
	cs = cf_section_find(conf, "suppress", NULL);
	if (cs) {
		CONF_ITEM	*ci;

		inst->ht = fr_hash_table_alloc(inst, detail_hash, detail_cmp, NULL);

		for (ci = cf_item_next(cs, NULL);
		     ci != NULL;
		     ci = cf_item_next(cs, ci)) {
			char const	*attr;
			fr_dict_attr_t const	*da;

			if (!cf_item_is_pair(ci)) continue;

			attr = cf_pair_attr(cf_item_to_pair(ci));
			if (!attr) continue; /* pair-anoia */

			da = fr_dict_attr_search_by_qualified_oid(NULL, dict_radius, attr, false, false);
			if (!da) {
				cf_log_perr(conf, "Failed resolving attribute");
				return -1;
			}

			/*
			 *	Be kind to minor mistakes.
			 */
			if (fr_hash_table_find(inst->ht, da)) {
				WARN("Ignoring duplicate entry '%s'", attr);
				continue;
			}


			if (!fr_hash_table_insert(inst->ht, da)) {
				ERROR("Failed inserting '%s' into suppression table", attr);
				return -1;
			}

			DEBUG("'%s' suppressed, will not appear in detail output", attr);
		}

		/*
		 *	If we didn't suppress anything, delete the hash table.
		 */
		if (fr_hash_table_num_elements(inst->ht) == 0) {
			TALLOC_FREE(inst->ht);
		} else {
			fr_hash_table_fill(inst->ht);
		}
	}

	return 0;
}

/*
 *	Wrapper for VPs allocated on the stack.
 */
static void detail_fr_pair_fprint(TALLOC_CTX *ctx, FILE *out, fr_pair_t const *stacked)
{
	fr_pair_t *vp;

	vp = talloc(ctx, fr_pair_t);
	if (!vp) return;

	/* coverity[store_writes_const_field] */
	memcpy(vp, stacked, sizeof(*vp));
	vp->op = T_OP_EQ;
	fr_pair_fprint(out, vp);
	talloc_free(vp);
}


/** Write a single detail entry to file pointer
 *
 * @param[in] out Where to write entry.
 * @param[in] inst Instance of rlm_detail.
 * @param[in] request The current request.
 * @param[in] packet associated with the request (request, reply...).
 * @param[in] compat Write out entry in compatibility mode.
 */
static int detail_write(FILE *out, rlm_detail_t const *inst, request_t *request,
			fr_radius_packet_t *packet, fr_pair_list_t *list, bool compat)
{
	char timestamp[256];
	char *header;

	if (tmpl_expand(&header, timestamp, sizeof(timestamp), request, inst->header, NULL, NULL) < 0) {
		return -1;
	}

	if (fr_pair_list_empty(list)) {
		RWDEBUG("Skipping empty packet");
		return 0;
	}

#define WRITE(fmt, ...) do {\
	if (fprintf(out, fmt, ## __VA_ARGS__) < 0) {\
		RERROR("Failed writing to detail file: %s", fr_syserror(errno));\
		return -1;\
	}\
} while(0)

	WRITE("%s\n", timestamp);

	/*
	 *	Write the information to the file.
	 */
	if (!compat) {
		fr_dict_attr_t const *da;
		char const *name = NULL;

		da = fr_dict_attr_by_name(NULL, fr_dict_root(request->dict), "Packet-Type");
		if (da) name = fr_dict_enum_name_by_value(da, fr_box_uint32(packet->code));

		/*
		 *	Print out names, if they're OK.
		 *	Numbers, if not.
		 */
		if (name) {
			WRITE("\tPacket-Type = %s\n", name);
		} else {
			WRITE("\tPacket-Type = %u\n", packet->code);
		}
	}

	if (inst->log_srcdst) {
		fr_pair_t src_vp, dst_vp;

		fr_pair_init_null(&src_vp);
		fr_pair_init_null(&dst_vp);

		switch (packet->socket.inet.src_ipaddr.af) {
		case AF_INET:
			fr_pair_reinit_from_da(NULL, &src_vp, attr_packet_src_ipv4_address);
			fr_value_box(&src_vp.data, &packet->socket.inet.src_ipaddr, true);

			fr_pair_reinit_from_da(NULL, &dst_vp, attr_packet_dst_ipv4_address);
			fr_value_box(&dst_vp.data, &packet->socket.inet.dst_ipaddr, true);
			break;

		case AF_INET6:
			fr_pair_reinit_from_da(NULL, &src_vp, attr_packet_src_ipv6_address);
			fr_value_box(&src_vp.data, &packet->socket.inet.src_ipaddr, true);

			fr_pair_reinit_from_da(NULL, &dst_vp, attr_packet_dst_ipv6_address);
			fr_value_box(&dst_vp.data, &packet->socket.inet.dst_ipaddr, true);
			break;

		default:
			break;
		}

		detail_fr_pair_fprint(request, out, &src_vp);
		detail_fr_pair_fprint(request, out, &dst_vp);

		fr_pair_reinit_from_da(NULL, &src_vp, attr_packet_src_port);
		fr_value_box(&src_vp.data, packet->socket.inet.src_port, true);

		fr_pair_reinit_from_da(NULL, &dst_vp, attr_packet_dst_port);
		fr_value_box(&dst_vp.data, packet->socket.inet.dst_port, true);

		detail_fr_pair_fprint(request, out, &src_vp);
		detail_fr_pair_fprint(request, out, &dst_vp);
	}

	/* Write each attribute/value to the log file */
	fr_pair_list_foreach(list, vp) {
		if (inst->ht && fr_hash_table_find(inst->ht, vp->da)) continue;

		/*
		 *	Don't print passwords in old format...
		 */
		if (compat && (vp->da == attr_user_password)) continue;

		fr_pair_fprint(out, vp);
	}

	/*
	 *	Add the original protocol of the request, this should
	 *	be used by the detail reader to set the default
	 *	dictionary used for decoding.
	 */
//	WRITE("\t%s = %s", attr_protocol->name, fr_dict_root(request->dict)->name);
	WRITE("\tTimestamp = %lu\n", (unsigned long) fr_time_to_sec(request->packet->timestamp));

	WRITE("\n");

	return 0;
}

/*
 *	Do detail, compatible with old accounting
 */
static unlang_action_t CC_HINT(nonnull) detail_do(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request,
						  fr_radius_packet_t *packet, fr_pair_list_t *list,
						  bool compat)
{
	int		outfd, dupfd;
	char		buffer[DIRLEN];

	FILE		*outfp;

#ifdef HAVE_GRP_H
	gid_t		gid;
	char		*endptr;
#endif

	rlm_detail_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_detail_t);

	/*
	 *	Generate the path for the detail file.  Use the same
	 *	format, but truncate at the last /.  Then feed it
	 *	through xlat_eval() to expand the variables.
	 */
	if (xlat_eval(buffer, sizeof(buffer), request, inst->filename, inst->escape_func, NULL) < 0) {
		RETURN_MODULE_FAIL;
	}

	RDEBUG2("%s expands to %s", inst->filename, buffer);

	outfd = exfile_open(inst->ef, buffer, inst->perm);
	if (outfd < 0) {
		RPERROR("Couldn't open file %s", buffer);
		RETURN_MODULE_FAIL;
	}

	if (inst->group != NULL) {
		gid = strtol(inst->group, &endptr, 10);
		if (*endptr != '\0') {
			if (fr_perm_gid_from_str(request, &gid, inst->group) < 0) {
				RDEBUG2("Unable to find system group '%s'", inst->group);
				goto skip_group;
			}
		}

		if (chown(buffer, -1, gid) == -1) {
			RDEBUG2("Unable to change system group of '%s'", buffer);
		}
	}

skip_group:
	outfp = NULL;
	dupfd = dup(outfd);
	if (dupfd < 0) {
		RERROR("Failed to dup() file descriptor for detail file");
		goto fail;
	}

	/*
	 *	Open the output fp for buffering.
	 */
	if ((outfp = fdopen(dupfd, "a")) == NULL) {
		RERROR("Couldn't open file %s: %s", buffer, fr_syserror(errno));
	fail:
		if (outfp) fclose(outfp);
		exfile_close(inst->ef, outfd);
		RETURN_MODULE_FAIL;
	}

	if (detail_write(outfp, inst, request, packet, list, compat) < 0) goto fail;

	/*
	 *	Flush everything
	 */
	fclose(outfp);
	exfile_close(inst->ef, outfd);

	/*
	 *	And everything is fine.
	 */
	RETURN_MODULE_OK;
}

/*
 *	Accounting - write the detail files.
 */
static unlang_action_t CC_HINT(nonnull) mod_accounting(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	return detail_do(p_result, mctx, request, request->packet, &request->request_pairs, true);
}

/*
 *	Incoming Access Request - write the detail files.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	return detail_do(p_result, mctx, request, request->packet, &request->request_pairs, false);
}

/*
 *	Outgoing Access-Request Reply - write the detail files.
 */
static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	return detail_do(p_result, mctx, request, request->reply, &request->reply_pairs, false);
}


/* globally exported name */
extern module_rlm_t rlm_detail;
module_rlm_t rlm_detail = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "detail",
		.inst_size	= sizeof(rlm_detail_t),
		.config		= module_config,
		.instantiate	= mod_instantiate
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = "recv",		.name2 = "accounting-request",	.method = mod_accounting },
		{ .name1 = "recv",		.name2 = CF_IDENT_ANY,		.method = mod_authorize },
		{ .name1 = "accounting",	.name2 = CF_IDENT_ANY,		.method = mod_accounting },
		{ .name1 = "send",		.name2 = CF_IDENT_ANY,		.method = mod_post_auth },
		MODULE_NAME_TERMINATOR
	}
};
