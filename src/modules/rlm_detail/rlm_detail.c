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
 * @copyright 2000,2006  The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/detail.h>
#include <freeradius-devel/exfile.h>

#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef HAVE_FNMATCH_H
#  include <fnmatch.h>
#endif

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
typedef struct detail_instance {
	char const	*name;		//!< Instance name.
	char const	*filename;	//!< File/path to write to.
	uint32_t	perm;		//!< Permissions to use for new files.
	char const	*group;		//!< Group to use for new files.

	char const	*header;	//!< Header format.
	bool		locking;	//!< Whether the file should be locked.

	bool		log_srcdst;	//!< Add IP src/dst attributes to entries.

	bool		escape;		//!< do filename escaping, yes / no

	xlat_escape_t escape_func; //!< escape function

	exfile_t    	*ef;		//!< Log file handler

	fr_hash_table_t *ht;		//!< Holds suppressed attributes.
} rlm_detail_t;

static const CONF_PARSER module_config[] = {
	{ "detailfile", FR_CONF_OFFSET(PW_TYPE_FILE_OUTPUT | PW_TYPE_DEPRECATED, rlm_detail_t, filename), NULL },
	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_OUTPUT | PW_TYPE_REQUIRED | PW_TYPE_XLAT, rlm_detail_t, filename), "%A/%{Client-IP-Address}/detail" },
	{ "header", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_detail_t, header), "%t" },
	{ "detailperm", FR_CONF_OFFSET(PW_TYPE_INTEGER | PW_TYPE_DEPRECATED, rlm_detail_t, perm), NULL },
	{ "permissions", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_detail_t, perm), "0600" },
	{ "group", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_detail_t, group), NULL },
	{ "locking", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_detail_t, locking), "no" },
	{ "escape_filenames", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_detail_t, escape), "no" },
	{ "log_packet_header", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_detail_t, log_srcdst), "no" },
	CONF_PARSER_TERMINATOR
};


/*
 *	Clean up.
 */
static int mod_detach(void *instance)
{
	rlm_detail_t *inst = instance;
	if (inst->ht) fr_hash_table_free(inst->ht);
	return 0;
}


static uint32_t detail_hash(void const *data)
{
	DICT_ATTR const *da = data;
	return fr_hash(&da, sizeof(da));
}

static int detail_cmp(void const *a, void const *b)
{
	DICT_ATTR const *one = a;
	DICT_ATTR const *two = b;

	return one - two;
}

/*
 *	(Re-)read radiusd.conf into memory.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_detail_t *inst = instance;
	CONF_SECTION	*cs;

	inst->name = cf_section_name2(conf);
	if (!inst->name) {
		inst->name = cf_section_name1(conf);
	}

	/*
	 *	Escape filenames only if asked.
	 */
	if (inst->escape) {
		inst->escape_func = rad_filename_escape;
	} else {
		inst->escape_func = rad_filename_make_safe;
	}

	inst->ef = exfile_init(inst, 256, 30, inst->locking);
	if (!inst->ef) {
		cf_log_err_cs(conf, "Failed creating log file context");
		return -1;
	}

	/*
	 *	Suppress certain attributes.
	 */
	cs = cf_section_sub_find(conf, "suppress");
	if (cs) {
		CONF_ITEM	*ci;

		inst->ht = fr_hash_table_create(detail_hash, detail_cmp, NULL);

		for (ci = cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci = cf_item_find_next(cs, ci)) {
			char const	*attr;
			DICT_ATTR const	*da;

			if (!cf_item_is_pair(ci)) continue;

			attr = cf_pair_attr(cf_item_to_pair(ci));
			if (!attr) continue; /* pair-anoia */

			da = dict_attrbyname(attr);
			if (!da) {
				cf_log_err_cs(conf, "No such attribute '%s'", attr);
				return -1;
			}

			/*
			 *	Be kind to minor mistakes.
			 */
			if (fr_hash_table_finddata(inst->ht, da)) {
				WARN("rlm_detail (%s): Ignoring duplicate entry '%s'", inst->name, attr);
				continue;
			}


			if (!fr_hash_table_insert(inst->ht, da)) {
				ERROR("rlm_detail (%s): Failed inserting '%s' into suppression table",
				      inst->name, attr);
				return -1;
			}

			DEBUG("rlm_detail (%s): '%s' suppressed, will not appear in detail output", inst->name, attr);
		}

		/*
		 *	If we didn't suppress anything, delete the hash table.
		 */
		if (fr_hash_table_num_elements(inst->ht) == 0) {
			fr_hash_table_free(inst->ht);
			inst->ht = NULL;
		}
	}

	return 0;
}

/*
 *	Wrapper for VPs allocated on the stack.
 */
static void detail_vp_print(TALLOC_CTX *ctx, FILE *out, VALUE_PAIR const *stacked)
{
	VALUE_PAIR *vp;

	vp = talloc(ctx, VALUE_PAIR);
	if (!vp) return;

	memcpy(vp, stacked, sizeof(*vp));
	vp->op = T_OP_EQ;
	vp_print(out, vp);
	talloc_free(vp);
}


/** Write a single detail entry to file pointer
 *
 * @param[in] out Where to write entry.
 * @param[in] inst Instance of rlm_detail.
 * @param[in] request The current request.
 * @param[in] packet associated with the request (request, reply, proxy-request, proxy-reply...).
 * @param[in] compat Write out entry in compatibility mode.
 */
static int detail_write(FILE *out, rlm_detail_t *inst, REQUEST *request, RADIUS_PACKET *packet, bool compat)
{
	VALUE_PAIR *vp;
	char timestamp[256];

	if (!packet->vps) {
		RWDEBUG("Skipping empty packet");
		return 0;
	}

	if (radius_xlat(timestamp, sizeof(timestamp), request, inst->header, NULL, NULL) < 0) {
		return -1;
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
		/*
		 *	Print out names, if they're OK.
		 *	Numbers, if not.
		 */
		if (is_radius_code(packet->code)) {
			WRITE("\tPacket-Type = %s\n", fr_packet_codes[packet->code]);
		} else {
			WRITE("\tPacket-Type = %u\n", packet->code);
		}
	}

	if (inst->log_srcdst) {
		VALUE_PAIR src_vp, dst_vp;

		memset(&src_vp, 0, sizeof(src_vp));
		memset(&dst_vp, 0, sizeof(dst_vp));

		switch (packet->src_ipaddr.af) {
		case AF_INET:
			src_vp.da = dict_attrbyvalue(PW_PACKET_SRC_IP_ADDRESS, 0);
			src_vp.vp_ipaddr = packet->src_ipaddr.ipaddr.ip4addr.s_addr;

			dst_vp.da = dict_attrbyvalue(PW_PACKET_DST_IP_ADDRESS, 0);
			dst_vp.vp_ipaddr = packet->dst_ipaddr.ipaddr.ip4addr.s_addr;
			break;

		case AF_INET6:
			src_vp.da = dict_attrbyvalue(PW_PACKET_SRC_IPV6_ADDRESS, 0);
			memcpy(&src_vp.vp_ipv6addr, &packet->src_ipaddr.ipaddr.ip6addr,
			       sizeof(packet->src_ipaddr.ipaddr.ip6addr));
			dst_vp.da = dict_attrbyvalue(PW_PACKET_DST_IPV6_ADDRESS, 0);
			memcpy(&dst_vp.vp_ipv6addr, &packet->dst_ipaddr.ipaddr.ip6addr,
			       sizeof(packet->dst_ipaddr.ipaddr.ip6addr));
			break;

		default:
			break;
		}

		detail_vp_print(request, out, &src_vp);
		detail_vp_print(request, out, &dst_vp);

		src_vp.da = dict_attrbyvalue(PW_PACKET_SRC_PORT, 0);
		src_vp.vp_integer = packet->src_port;
		dst_vp.da = dict_attrbyvalue(PW_PACKET_DST_PORT, 0);
		dst_vp.vp_integer = packet->dst_port;

		detail_vp_print(request, out, &src_vp);
		detail_vp_print(request, out, &dst_vp);
	}

	{
		vp_cursor_t cursor;
		/* Write each attribute/value to the log file */
		for (vp = fr_cursor_init(&cursor, &packet->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			FR_TOKEN op;

			if (inst->ht && fr_hash_table_finddata(inst->ht, vp->da)) continue;

			/*
			 *	Don't print passwords in old format...
			 */
			if (compat && !vp->da->vendor && (vp->da->attr == PW_USER_PASSWORD)) continue;

			/*
			 *	Print all of the attributes, operator should always be '='.
			 */
			op = vp->op;
			vp->op = T_OP_EQ;
			vp_print(out, vp);
			vp->op = op;
		}
	}

	/*
	 *	Add non-protocol attributes.
	 */
	if (compat) {
#ifdef WITH_PROXY
		if (request->proxy) {
			char proxy_buffer[128];

			inet_ntop(request->proxy->dst_ipaddr.af, &request->proxy->dst_ipaddr.ipaddr,
				  proxy_buffer, sizeof(proxy_buffer));
			WRITE("\tFreeradius-Proxied-To = %s\n", proxy_buffer);
		}
#endif
	}
	WRITE("\tTimestamp = %ld\n", (unsigned long) request->timestamp);

	WRITE("\n");

	return 0;
}

/*
 *	Do detail, compatible with old accounting
 */
static rlm_rcode_t CC_HINT(nonnull) detail_do(void *instance, REQUEST *request, RADIUS_PACKET *packet, bool compat)
{
	int		outfd, dupfd;
	char		buffer[DIRLEN];

	FILE		*outfp;

#ifdef HAVE_GRP_H
	gid_t		gid;
	char		*endptr;
#endif

	rlm_detail_t *inst = instance;

	/*
	 *	Generate the path for the detail file.  Use the same
	 *	format, but truncate at the last /.  Then feed it
	 *	through radius_xlat() to expand the variables.
	 */
	if (radius_xlat(buffer, sizeof(buffer), request, inst->filename, inst->escape_func, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	RDEBUG2("%s expands to %s", inst->filename, buffer);

#ifdef WITH_ACCOUNTING
#if defined(HAVE_FNMATCH_H) && defined(FNM_FILE_NAME)
	/*
	 *	If we read it from a detail file, and we're about to
	 *	write it back to the SAME detail file directory, then
	 *	suppress the write.  This check prevents an infinite
	 *	loop.
	 */
	if ((request->listener->type == RAD_LISTEN_DETAIL) &&
	    (fnmatch(((listen_detail_t *)request->listener->data)->filename,
		     buffer, FNM_FILE_NAME | FNM_PERIOD ) == 0)) {
		RWDEBUG2("Suppressing infinite loop");
		return RLM_MODULE_NOOP;
	}
#endif
#endif

	outfd = exfile_open(inst->ef, buffer, inst->perm);
	if (outfd < 0) {
		RERROR("Couldn't open file %s: %s", buffer, fr_strerror());
		return RLM_MODULE_FAIL;
	}

	if (inst->group != NULL) {
		gid = strtol(inst->group, &endptr, 10);
		if (*endptr != '\0') {
			if (rad_getgid(request, &gid, inst->group) < 0) {
				RDEBUG2("Unable to find system group '%s'", inst->group);
				goto skip_group;
			}
		}

		if (chown(buffer, -1, gid) == -1) {
			RDEBUG2("Unable to change system group of '%s'", buffer);
		}
	}

skip_group:
	/*
	 *	Open the output fp for buffering.
	 */
	outfp = NULL;
	dupfd = dup(outfd);
	if (dupfd < 0) {
		RERROR("Failed to dup() file descriptor for detail file");
		goto fail;
	}

	if ((outfp = fdopen(dupfd, "a")) == NULL) {
		RERROR("Couldn't open file %s: %s", buffer, fr_syserror(errno));
	fail:
		if (outfp) fclose(outfp);
		exfile_close(inst->ef, outfd);
		return RLM_MODULE_FAIL;
	}

	if (detail_write(outfp, inst, request, packet, compat) < 0) goto fail;

	/*
	 *	Flush everything
	 */
	fclose(outfp);
	exfile_close(inst->ef, outfd);

	/*
	 *	And everything is fine.
	 */
	return RLM_MODULE_OK;
}

/*
 *	Accounting - write the detail files.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
#ifdef WITH_DETAIL
	if (request->listener->type == RAD_LISTEN_DETAIL &&
	    strcmp(((rlm_detail_t *)instance)->filename,
		   ((listen_detail_t *)request->listener->data)->filename) == 0) {
		RDEBUG("Suppressing writes to detail file as the request was just read from a detail file");
		return RLM_MODULE_NOOP;
	}
#endif

	return detail_do(instance, request, request->packet, true);
}

/*
 *	Incoming Access Request - write the detail files.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	return detail_do(instance, request, request->packet, false);
}

/*
 *	Outgoing Access-Request Reply - write the detail files.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	return detail_do(instance, request, request->reply, false);
}

#ifdef WITH_COA
/*
 *	Incoming CoA - write the detail files.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_recv_coa(void *instance, REQUEST *request)
{
	return detail_do(instance, request, request->packet, false);
}

/*
 *	Outgoing CoA - write the detail files.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_send_coa(void *instance, REQUEST *request)
{
	return detail_do(instance, request, request->reply, false);
}
#endif

/*
 *	Outgoing Access-Request to home server - write the detail files.
 */
#ifdef WITH_PROXY
static rlm_rcode_t CC_HINT(nonnull) mod_pre_proxy(void *instance, REQUEST *request)
{
	if (request->proxy && request->proxy->vps) {
		return detail_do(instance, request, request->proxy, false);
	}

	return RLM_MODULE_NOOP;
}


/*
 *	Outgoing Access-Request Reply - write the detail files.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_proxy(void *instance, REQUEST *request)
{
	if (request->proxy_reply && request->proxy_reply->vps) {
		return detail_do(instance, request, request->proxy_reply, false);
	}

	/*
	 *	No reply: we must be doing Post-Proxy-Type = Fail.
	 *
	 *	Note that we just call the normal accounting function,
	 *	to minimize the amount of code, and to highlight that
	 *	it's doing normal accounting.
	 */
	if (!request->proxy_reply) {
		rlm_rcode_t rcode;

		rcode = mod_accounting(instance, request);
		if (rcode == RLM_MODULE_OK) {
			request->reply->code = PW_CODE_ACCOUNTING_RESPONSE;
		}
		return rcode;
	}

	return RLM_MODULE_NOOP;
}
#endif

/* globally exported name */
extern module_t rlm_detail;
module_t rlm_detail = {
	.magic		= RLM_MODULE_INIT,
	.name		= "detail",
	.type		= RLM_TYPE_HUP_SAFE,
	.inst_size	= sizeof(rlm_detail_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_accounting,
		[MOD_ACCOUNTING]	= mod_accounting,
#ifdef WITH_PROXY
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
#endif
		[MOD_POST_AUTH]		= mod_post_auth,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_recv_coa,
		[MOD_SEND_COA]		= mod_send_coa
#endif
	},
};

