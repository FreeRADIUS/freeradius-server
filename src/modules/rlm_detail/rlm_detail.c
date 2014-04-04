/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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
	char		*filename;	//!< File/path to write to.
	int		perm;		//!< Permissions to use for new files.
	char		*group;		//!< Group to use for new files.

	int		dirperm;	//!< Directory permissions to use for new files.

	char		*header;	//!< Header format.
	bool		locking;	//!< Whether the file should be locked.

	bool		log_srcdst;	//!< Add IP src/dst attributes to entries.

	fr_hash_table_t *ht;		//!< Holds suppressed attributes.
} detail_instance_t;

static const CONF_PARSER module_config[] = {
	{ "detailfile", PW_TYPE_FILE_OUTPUT | PW_TYPE_DEPRECATED, offsetof(detail_instance_t, filename),
	 NULL, NULL },
	{ "filename", PW_TYPE_FILE_OUTPUT | PW_TYPE_REQUIRED, offsetof(detail_instance_t, filename),
	 NULL, "%A/%{Client-IP-Address}/detail" },
	{ "header", PW_TYPE_STRING_PTR, offsetof(detail_instance_t, header), NULL, "%t" },
	{ "detailperm",	PW_TYPE_INTEGER | PW_TYPE_DEPRECATED, offsetof(detail_instance_t, perm), NULL, NULL },
	{ "permissions", PW_TYPE_INTEGER, offsetof(detail_instance_t, perm), NULL, "0600" },
	{ "group", PW_TYPE_STRING_PTR, offsetof(detail_instance_t, group), NULL,  NULL},
	{ "dir_permissions", PW_TYPE_INTEGER, offsetof(detail_instance_t, dirperm), NULL, "0755" },
	{ "locking", PW_TYPE_BOOLEAN, offsetof(detail_instance_t, locking), NULL, "no" },
	{ "log_packet_header", PW_TYPE_BOOLEAN, offsetof(detail_instance_t, log_srcdst), NULL, "no" },
	{ NULL, -1, 0, NULL, NULL }
};


/*
 *	Clean up.
 */
static int mod_detach(void *instance)
{
	detail_instance_t *inst = instance;
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
	detail_instance_t *inst = instance;
	CONF_SECTION	*cs;

	inst->name = cf_section_name2(conf);
	if (!inst->name) {
		inst->name = cf_section_name1(conf);
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

			attr = cf_pair_attr(cf_itemtopair(ci));
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
static int detail_write(FILE *out, detail_instance_t *inst, REQUEST *request, RADIUS_PACKET *packet, bool compat)
{
	VALUE_PAIR *vp;
	char timestamp[256];

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
			WRITE("\tPacket-Type = %d\n", packet->code);
		}
	}

	if (inst->log_srcdst) {
		VALUE_PAIR src_vp, dst_vp;

		memset(&src_vp, 0, sizeof(src_vp));
		memset(&dst_vp, 0, sizeof(dst_vp));
		src_vp.op = dst_vp.op = T_OP_EQ;

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
			if (inst->ht &&
			    fr_hash_table_finddata(inst->ht, vp->da)) continue;

			/*
			 *	Don't print passwords in old format...
			 */
			if (compat && !vp->da->vendor && (vp->da->attr == PW_USER_PASSWORD)) continue;

			/*
			 *	Print all of the attributes.
			 */
			vp_print(out, vp);
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

		WRITE("\tTimestamp = %ld\n", (unsigned long) request->timestamp);
	}

	WRITE("\n");

	return 0;
}

/*
 *	Do detail, compatible with old accounting
 */
static rlm_rcode_t detail_do(void *instance, REQUEST *request, RADIUS_PACKET *packet, bool compat)
{
	int		outfd;
	char		buffer[DIRLEN];
	char		*p;
	struct stat	st;
	int		locked;
	int		lock_count;
	struct timeval	tv;

	off_t		fsize;
	FILE		*outfp;

#ifdef HAVE_GRP_H
	gid_t		gid;
	struct group	*grp;
	char		*endptr;
#endif

	detail_instance_t *inst = instance;

	rad_assert(request != NULL);

	/*
	 *	Nothing to log: don't do anything.
	 */
	if (!packet) {
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Generate the path for the detail file.  Use the same
	 *	format, but truncate at the last /.  Then feed it
	 *	through radius_xlat() to expand the variables.
	 */
	if (radius_xlat(buffer, sizeof(buffer), request, inst->filename, NULL, NULL) < 0) {
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

	/*
	 *	Grab the last directory delimiter.
	 */
	p = strrchr(buffer,'/');

	/*
	 *	There WAS a directory delimiter there, and the file
	 *	doesn't exist, so we must create it the directories..
	 */
	if (p) {
		*p = '\0';

		/*
		 *	Always try to create the directory.  If it
		 *	exists, rad_mkdir() will check via stat(), and
		 *	return immediately.
		 *
		 *	This catches the case where some idiot deleted
		 *	a directory that the server was using.
		 */
		if (rad_mkdir(buffer, inst->dirperm) < 0) {
			RERROR("Failed to create directory %s: %s", buffer, fr_syserror(errno));
			return RLM_MODULE_FAIL;
		}

		*p = '/';
	} /* else there was no directory delimiter. */

	locked = 0;
	lock_count = 0;
	do {
		/*
		 *	Open & create the file, with the given
		 *	permissions.
		 */
		if ((outfd = open(buffer, O_WRONLY | O_APPEND | O_CREAT, inst->perm)) < 0) {
			RERROR("Couldn't open file %s: %s", buffer, fr_syserror(errno));
			return RLM_MODULE_FAIL;
		}

		/*
		 *	If we fail to aquire the filelock in 80 tries
		 *	(approximately two seconds) we bail out.
		 */
		if (inst->locking) {
			lseek(outfd, 0L, SEEK_SET);
			if (rad_lockfd_nonblock(outfd, 0) < 0) {
				close(outfd);
				tv.tv_sec = 0;
				tv.tv_usec = 25000;
				select(0, NULL, NULL, NULL, &tv);
				lock_count++;
				continue;
			}

			/*
			 *	The file might have been deleted by
			 *	radrelay while we tried to acquire
			 *	the lock (race condition)
			 */
			if (fstat(outfd, &st) != 0) {
				RERROR("Couldn't stat file %s: %s", buffer, fr_syserror(errno));
				close(outfd);
				return RLM_MODULE_FAIL;
			}
			if (st.st_nlink == 0) {
				RDEBUG2("File '%s' removed by another program, retrying", buffer);
				close(outfd);
				lock_count = 0;
				continue;
			}

			RDEBUG2("Acquired filelock, tried %d time(s)", lock_count + 1);
			locked = 1;
		}
	} while (inst->locking && !locked && lock_count < 80);

	if (inst->locking && !locked) {
		close(outfd);
		RERROR("Failed to acquire filelock for '%s', giving up", buffer);
		return RLM_MODULE_FAIL;
	}


#ifdef HAVE_GRP_H
	if (inst->group != NULL) {
		gid = strtol(inst->group, &endptr, 10);
		if (*endptr != '\0') {
			grp = getgrnam(inst->group);
			if (!grp) {
				RDEBUG2("Unable to find system group '%s'", inst->group);
				goto skip_group;
			}
			gid = grp->gr_gid;
		}

		if (chown(buffer, -1, gid) == -1) {
			RDEBUG2("Unable to change system group of '%s'", buffer);
		}
	}

skip_group:
#endif

	fsize = lseek(outfd, 0L, SEEK_END);
	if (fsize < 0) {
		RERROR("Failed to seek to the end of detail file '%s'", buffer);
		close(outfd);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Open the output fp for buffering.
	 */
	if ((outfp = fdopen(outfd, "a")) == NULL) {
		RERROR("Couldn't open file %s: %s", buffer, fr_syserror(errno));
		close(outfd);
		return RLM_MODULE_FAIL;
	}

	if (detail_write(outfp, inst, request, packet, compat) < 0) {
		fclose(outfp);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	If we can't flush it to disk, truncate the file and return an error.
	 */
	if (fflush(outfp) != 0) {
		int ret;
		ret = ftruncate(outfd, fsize);
		if (ret) {
			REDEBUG4("Failed truncating detail file: %s", fr_syserror(ret));
		}

		fclose(outfp);
		return RLM_MODULE_FAIL;
	}

	fclose(outfp);

	/*
	 *	And everything is fine.
	 */
	return RLM_MODULE_OK;
}

/*
 *	Accounting - write the detail files.
 */
static rlm_rcode_t mod_accounting(void *instance, REQUEST *request)
{
#ifdef WITH_DETAIL
	if (request->listener->type == RAD_LISTEN_DETAIL &&
	    strcmp(((detail_instance_t *)instance)->filename,
		   ((listen_detail_t *)request->listener->data)->filename) == 0) {
		RDEBUG("Suppressing writes to detail file as the request was just read from a detail file.");
		return RLM_MODULE_NOOP;
	}
#endif

	return detail_do(instance, request, request->packet, true);
}

/*
 *	Incoming Access Request - write the detail files.
 */
static rlm_rcode_t mod_authorize(void *instance, REQUEST *request)
{
	return detail_do(instance, request, request->packet, false);
}

/*
 *	Outgoing Access-Request Reply - write the detail files.
 */
static rlm_rcode_t mod_post_auth(void *instance, REQUEST *request)
{
	return detail_do(instance, request, request->reply, false);
}

#ifdef WITH_COA
/*
 *	Incoming CoA - write the detail files.
 */
static rlm_rcode_t mod_recv_coa(void *instance, REQUEST *request)
{
	return detail_do(instance, request, request->packet, false);
}

/*
 *	Outgoing CoA - write the detail files.
 */
static rlm_rcode_t mod_send_coa(void *instance, REQUEST *request)
{
	return detail_do(instance, request, request->reply, false);
}
#endif

/*
 *	Outgoing Access-Request to home server - write the detail files.
 */
#ifdef WITH_PROXY
static rlm_rcode_t mod_pre_proxy(void *instance, REQUEST *request)
{
	if (request->proxy && request->proxy->vps) {
		return detail_do(instance, request, request->proxy, false);
	}

	return RLM_MODULE_NOOP;
}


/*
 *	Outgoing Access-Request Reply - write the detail files.
 */
static rlm_rcode_t mod_post_proxy(void *instance, REQUEST *request)
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
module_t rlm_detail = {
	RLM_MODULE_INIT,
	"detail",
	RLM_TYPE_THREAD_UNSAFE | RLM_TYPE_HUP_SAFE,
	sizeof(detail_instance_t),
	module_config,
	mod_instantiate,		/* instantiation */
	mod_detach,			/* detach */
	{
		NULL,			/* authentication */
		mod_authorize,		/* authorization */
		NULL,			/* preaccounting */
		mod_accounting,		/* accounting */
		NULL,			/* checksimul */
#ifdef WITH_PROXY
		mod_pre_proxy,      	/* pre-proxy */
		mod_post_proxy,		/* post-proxy */
#else
		NULL, NULL,
#endif
		mod_post_auth		/* post-auth */
#ifdef WITH_COA
		, mod_recv_coa,
		mod_send_coa
#endif
	},
};

