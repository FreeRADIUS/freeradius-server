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
#include <freeradius-devel/server/cf_util.h>
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
	gid_t		group;		//!< Resolved group.
	bool		group_is_set;	//!< Whether group was set.

	tmpl_t		*header;	//!< Header format.
	bool		locking;	//!< Whether the file should be locked.

	bool		log_srcdst;	//!< Add IP src/dst attributes to entries.

	bool		escape;		//!< do filename escaping, yes / no

	xlat_escape_legacy_t	escape_func; //!< escape function

	exfile_t    	*ef;		//!< Log file handler

	fr_hash_table_t *ht;		//!< Holds suppressed attributes.
} rlm_detail_t;

int detail_group_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent,
		       CONF_ITEM *ci, conf_parser_t const *rule);

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_FILE_OUTPUT | CONF_FLAG_XLAT, rlm_detail_t, filename), .dflt = "%A/%{Net.Src.IP}/detail" },
	{ FR_CONF_OFFSET_FLAGS("header", CONF_FLAG_XLAT, rlm_detail_t, header), .dflt = "%t", .quote = T_DOUBLE_QUOTED_STRING },
	{ FR_CONF_OFFSET("permissions", rlm_detail_t, perm), .dflt = "0600" },
	{ FR_CONF_OFFSET_IS_SET("group", FR_TYPE_VOID, 0, rlm_detail_t, group), .func = detail_group_parse },
	{ FR_CONF_OFFSET("locking", rlm_detail_t, locking), .dflt = "no" },
	{ FR_CONF_OFFSET("escape_filenames", rlm_detail_t, escape), .dflt = "no" },
	{ FR_CONF_OFFSET("log_packet_header", rlm_detail_t, log_srcdst), .dflt = "no" },
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

static fr_dict_attr_t const *attr_net;
static fr_dict_attr_t const *attr_net_src_address;
static fr_dict_attr_t const *attr_net_dst_address;
static fr_dict_attr_t const *attr_net_src_port;
static fr_dict_attr_t const *attr_net_dst_port;
static fr_dict_attr_t const *attr_protocol;

static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_detail_dict_attr[];
fr_dict_attr_autoload_t rlm_detail_dict_attr[] = {
	{ .out = &attr_net, .name = "Net", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_net_dst_address, .name = "Net.Dst.IP", .type = FR_TYPE_COMBO_IP_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_net_dst_port, .name = "Net.Dst.Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_net_src_address, .name = "Net.Src.IP", .type = FR_TYPE_COMBO_IP_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_net_src_port, .name = "Net.Src.Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_protocol, .name = "Protocol", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

/** Print one attribute and value to FP
 *
 * Complete string with '\\t' and '\\n' is written to buffer before printing to
 * avoid issues when running with multiple threads.
 *
 * @todo - This function should print *flattened* lists.
 *
 * @param fp to output to.
 * @param vp to print.
 */
static void CC_HINT(nonnull) fr_pair_fprint(FILE *fp, fr_pair_t const *vp)
{
	char		buff[1024];
	fr_sbuff_t	sbuff = FR_SBUFF_OUT(buff, sizeof(buff));

	PAIR_VERIFY(vp);

	(void) fr_sbuff_in_char(&sbuff, '\t');
	(void) fr_pair_print(&sbuff, NULL, vp);
	(void) fr_sbuff_in_char(&sbuff, '\n');

	fputs(buff, fp);
}



/** Generic function for parsing conf pair values as int
 *
 * @note This should be used for enum types as c99 6.4.4.3 states that the enumeration
 * constants are of type int.
 *
 */
int detail_group_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent,
		       CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	char const 			*group;
	char				*endptr;
	gid_t				gid;

	group = cf_pair_value(cf_item_to_pair(ci));
	gid = strtol(group, &endptr, 10);
	if (*endptr != '\0') {
		if (fr_perm_gid_from_str(parent, &gid, group) < 0) {
			cf_log_err(ci, "Unable to find system group '%s'", group);
			return -1;
		}
	}
	*((gid_t *)out) = gid;

	return 0;
}

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

	vp = fr_pair_copy(ctx, stacked);
	if (unlikely(vp == NULL)) return;

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
 * @param[in] list of pairs to write.
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

	/*
	 *	Put these at the top as distinct (not nested) VPs.
	 */
	if (inst->log_srcdst) {
		fr_pair_t *src_vp, *dst_vp;

		src_vp = fr_pair_find_by_da_nested(&request->control_pairs, NULL, attr_net_src_address);
		dst_vp = fr_pair_find_by_da_nested(&request->control_pairs, NULL, attr_net_dst_address);

		/*
		 *	These pairs will exist, but Coverity doesn't know that
		 */
		if (src_vp) detail_fr_pair_fprint(request, out, src_vp);
		if (dst_vp) detail_fr_pair_fprint(request, out, dst_vp);

		src_vp = fr_pair_find_by_da_nested(&request->control_pairs, NULL, attr_net_src_port);
		dst_vp = fr_pair_find_by_da_nested(&request->control_pairs, NULL, attr_net_dst_port);

		if (src_vp) detail_fr_pair_fprint(request, out, src_vp);
		if (dst_vp) detail_fr_pair_fprint(request, out, dst_vp);
	}

	/* Write each attribute/value to the log file */
	fr_pair_list_foreach_leaf(list, vp) {
		if (inst->ht && fr_hash_table_find(inst->ht, vp->da)) continue;

		/*
		 *	Skip Net.* if we're not logging src/dst
		 */
		if (!inst->log_srcdst && (fr_dict_by_da(vp->da) == dict_freeradius)) {
			fr_dict_attr_t const *da = vp->da;

			while (da->depth > attr_net->depth) {
				da = da->parent;
			}

			if (da == attr_net) continue;
		}

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

	FILE		*outfp = NULL;

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

	outfd = exfile_open(inst->ef, buffer, inst->perm, NULL);
	if (outfd < 0) {
		RPERROR("Couldn't open file %s", buffer);
		*p_result = RLM_MODULE_FAIL;
		/* coverity[missing_unlock] */
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	if (inst->group_is_set) {
		if (chown(buffer, -1, inst->group) == -1) {
			RERROR("Unable to set detail file group to '%s': %s", buffer, fr_syserror(errno));
			goto fail;
		}
	}

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
