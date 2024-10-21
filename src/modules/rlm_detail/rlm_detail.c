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

/** Instance configuration for rlm_detail
 *
 * Holds the configuration and preparsed data for a instance of rlm_detail.
 */
typedef struct {
	uint32_t	perm;		//!< Permissions to use for new files.
	gid_t		group;		//!< Resolved group.
	bool		group_is_set;	//!< Whether group was set.

	bool		locking;	//!< Whether the file should be locked.

	bool		log_srcdst;	//!< Add IP src/dst attributes to entries.

	bool		escape;		//!< do filename escaping, yes / no

	exfile_t    	*ef;		//!< Log file handler
} rlm_detail_t;

typedef struct {
	fr_value_box_t	filename;	//!< File / path to write to.
	tmpl_t		*filename_tmpl;	//!< tmpl used to expand filename (for debug output)
	fr_value_box_t	header;		//!< Header format
	fr_hash_table_t	*ht;		//!< Holds suppressed attributes.
} rlm_detail_env_t;

int detail_group_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent,
		       CONF_ITEM *ci, conf_parser_t const *rule);

static const conf_parser_t module_config[] = {
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
	rlm_detail_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_detail_t);
	CONF_SECTION	*conf = mctx->mi->conf;

	inst->ef = module_rlm_exfile_init(inst, conf, 256, fr_time_delta_from_sec(30), inst->locking, NULL, NULL);
	if (!inst->ef) {
		cf_log_err(conf, "Failed creating log file context");
		return -1;
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
 * @param[in] header To print above packet
 * @param[in] packet associated with the request (request, reply...).
 * @param[in] list of pairs to write.
 * @param[in] compat Write out entry in compatibility mode.
 * @param[in] ht Hash table containing attributes to be suppressed in the output.
 */
static int detail_write(FILE *out, rlm_detail_t const *inst, request_t *request, fr_value_box_t *header,
			fr_packet_t *packet, fr_pair_list_t *list, bool compat, fr_hash_table_t *ht)
{
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

	WRITE("%s\n", header->vb_strvalue);

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
		if (ht && fr_hash_table_find(ht, vp->da)) continue;

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
						  fr_packet_t *packet, fr_pair_list_t *list,
						  bool compat)
{
	rlm_detail_env_t	*env = talloc_get_type_abort(mctx->env_data, rlm_detail_env_t);
	int			outfd, dupfd;
	FILE			*outfp = NULL;

	rlm_detail_t const *inst = talloc_get_type_abort_const(mctx->mi->data, rlm_detail_t);

	RDEBUG2("%s expands to %pV", env->filename_tmpl->name, &env->filename);

	outfd = exfile_open(inst->ef, env->filename.vb_strvalue, inst->perm, NULL);
	if (outfd < 0) {
		RPERROR("Couldn't open file %pV", &env->filename);
		*p_result = RLM_MODULE_FAIL;
		/* coverity[missing_unlock] */
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	if (inst->group_is_set) {
		if (chown(env->filename.vb_strvalue, -1, inst->group) == -1) {
			RERROR("Unable to set detail file group to '%d': %s", inst->group, fr_syserror(errno));
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
		RERROR("Couldn't open file %pV: %s", &env->filename, fr_syserror(errno));
	fail:
		if (outfp) fclose(outfp);
		exfile_close(inst->ef, outfd);
		RETURN_MODULE_FAIL;
	}

	if (detail_write(outfp, inst, request, &env->header, packet, list, compat, env->ht) < 0) goto fail;

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

static int call_env_filename_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules,
				   CONF_ITEM *ci,
				   call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_detail_t const	*inst = talloc_get_type_abort_const(cec->mi->data, rlm_detail_t);
	tmpl_t			*parsed;
	CONF_PAIR const		*to_parse = cf_item_to_pair(ci);
	tmpl_rules_t		our_rules;

	our_rules = *t_rules;
	our_rules.escape.func = (inst->escape) ? rad_filename_box_escape : rad_filename_box_make_safe;
	our_rules.escape.safe_for = (inst->escape) ? (fr_value_box_safe_for_t)rad_filename_box_escape :
						     (fr_value_box_safe_for_t)rad_filename_box_make_safe;
	our_rules.escape.mode = TMPL_ESCAPE_PRE_CONCAT;
	our_rules.literals_safe_for = our_rules.escape.safe_for;

	if (tmpl_afrom_substr(ctx, &parsed,
			      &FR_SBUFF_IN(cf_pair_value(to_parse), talloc_array_length(cf_pair_value(to_parse)) - 1),
			      cf_pair_value_quote(to_parse), value_parse_rules_quoted[cf_pair_value_quote(to_parse)],
			      &our_rules) < 0) return -1;

	*(void **)out = parsed;
	return 0;
}

static int call_env_suppress_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules,
				   CONF_ITEM *ci,
				   UNUSED call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	CONF_SECTION const	*cs = cf_item_to_section(ci);
	CONF_SECTION const	*parent = cf_item_to_section(cf_parent(ci));
	call_env_parsed_t	*parsed;
	CONF_ITEM const		*to_parse = NULL;
	char const		*attr;
	fr_dict_attr_t const	*da;
	fr_hash_table_t		*ht;

	MEM(parsed = call_env_parsed_add(ctx, out,
					 &(call_env_parser_t) { FR_CALL_ENV_PARSE_ONLY_OFFSET("suppress", FR_TYPE_VOID, 0, rlm_detail_env_t, ht )}));

	ht = fr_hash_table_alloc(parsed, detail_hash, detail_cmp, NULL);

	while ((to_parse = cf_item_next(cs, to_parse))) {
		if (!cf_item_is_pair(to_parse)) continue;

		attr = cf_pair_attr(cf_item_to_pair(to_parse));
		if (!attr) continue;

		da = fr_dict_attr_search_by_qualified_oid(NULL, t_rules->attr.dict_def, attr, false, false);
		if (!da) {
			cf_log_perr(to_parse, "Failed resolving attribute");
			return -1;
		}

		/*
		 *	Be kind to minor mistakes
		 */
		if (fr_hash_table_find(ht, da)) {
			cf_log_warn(to_parse, "Ignoring duplicate entry '%s'", attr);
			continue;
		}

		if (!fr_hash_table_insert(ht, da)) {
			cf_log_perr(to_parse, "Failed inserting '%s' into suppression table", attr);
			return -1;
		}

		DEBUG("%s - '%s' suppressed, will not appear in detail output", cf_section_name(parent), attr);
	}

	/*
	 *	Clear up if nothing is actually to be suppressed
	 */
	if (fr_hash_table_num_elements(ht) == 0) {
		talloc_free(ht);
		call_env_parsed_free(out, parsed);
		return 0;
	}

	fr_hash_table_fill(ht);
	call_env_parsed_set_data(parsed, ht);

	return 0;
}

static const call_env_method_t method_env = {
	FR_CALL_ENV_METHOD_OUT(rlm_detail_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_PARSE_OFFSET("filename", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED, rlm_detail_env_t, filename, filename_tmpl),
		  .pair.func =  call_env_filename_parse },
		{ FR_CALL_ENV_OFFSET("header", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, rlm_detail_env_t, header),
		  .pair.dflt = "%t", .pair.dflt_quote = T_DOUBLE_QUOTED_STRING },
		{ FR_CALL_ENV_SUBSECTION_FUNC("suppress", NULL, CALL_ENV_FLAG_NONE, call_env_suppress_parse) },
		CALL_ENV_TERMINATOR
	}
};

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
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("accounting", CF_IDENT_ANY), .method = mod_accounting, .method_env = &method_env },
			{ .section = SECTION_NAME("recv", "accounting-request"), .method = mod_accounting, .method_env = &method_env },
			{ .section = SECTION_NAME("send", "accounting-response"), .method = mod_accounting, .method_env = &method_env },
			{ .section = SECTION_NAME("recv", CF_IDENT_ANY), .method = mod_authorize, .method_env = &method_env },
			{ .section = SECTION_NAME("send", CF_IDENT_ANY), .method = mod_post_auth, .method_env = &method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
