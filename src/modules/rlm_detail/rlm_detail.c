/*
 * rlm_detail.c	accounting:    Write the "detail" files.
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
 */

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>
#include	<freeradius-devel/detail.h>

#include	<ctype.h>
#include	<fcntl.h>
#include	<sys/stat.h>

#ifdef HAVE_FNMATCH_H
#include	<fnmatch.h>
#endif

#define 	DIRLEN	8192

struct detail_instance {
	/* detail file */
	char *detailfile;

	/* detail file permissions */
	int detailperm;

	/* directory permissions */
	int dirperm;

	/* last made directory */
	char *last_made_directory;

	/* timestamp & stuff */
	char *header;

	/* if we want file locking */
	int locking;

	/* log src/dst information */
	int log_srcdst;

	fr_hash_table_t *ht;
};

static const CONF_PARSER module_config[] = {
	{ "detailfile",    PW_TYPE_STRING_PTR,
	  offsetof(struct detail_instance,detailfile), NULL, "%A/%{Client-IP-Address}/detail" },
	{ "header",    PW_TYPE_STRING_PTR,
	  offsetof(struct detail_instance,header), NULL, "%t" },
	{ "detailperm",    PW_TYPE_INTEGER,
	  offsetof(struct detail_instance,detailperm), NULL, "0600" },
	{ "dirperm",       PW_TYPE_INTEGER,
	  offsetof(struct detail_instance,dirperm),    NULL, "0755" },
	{ "locking",       PW_TYPE_BOOLEAN,
	  offsetof(struct detail_instance,locking),    NULL, "no" },
	{ "log_packet_header",       PW_TYPE_BOOLEAN,
	  offsetof(struct detail_instance,log_srcdst),    NULL, "no" },
	{ NULL, -1, 0, NULL, NULL }
};


/*
 *	Clean up.
 */
static int detail_detach(void *instance)
{
        struct detail_instance *inst = instance;
	free((char*) inst->last_made_directory);
	if (inst->ht) fr_hash_table_free(inst->ht);

        free(inst);
	return 0;
}


static uint32_t detail_hash(const void *data)
{
	const DICT_ATTR *da = data;
	return fr_hash(&(da->attr), sizeof(da->attr));
}

static int detail_cmp(const void *a, const void *b)
{
	return ((const DICT_ATTR *)a)->attr - ((const DICT_ATTR *)b)->attr;
}


/*
 *	(Re-)read radiusd.conf into memory.
 */
static int detail_instantiate(CONF_SECTION *conf, void **instance)
{
	struct detail_instance *inst;
	CONF_SECTION	*cs;

	inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	if (cf_section_parse(conf, inst, module_config) < 0) {
		detail_detach(inst);
		return -1;
	}

	inst->last_made_directory = NULL;

	/*
	 *	Suppress certain attributes.
	 */
	cs = cf_section_sub_find(conf, "suppress");
	if (cs) {
		CONF_ITEM	*ci;

		inst->ht = fr_hash_table_create(detail_hash, detail_cmp,
						  NULL);

		for (ci = cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci = cf_item_find_next(cs, ci)) {
			const char	*attr;
			DICT_ATTR	*da;

			if (!cf_item_is_pair(ci)) continue;

			attr = cf_pair_attr(cf_itemtopair(ci));
			if (!attr) continue; /* pair-anoia */

			da = dict_attrbyname(attr);
			if (!da) {
				radlog(L_INFO, "rlm_detail: WARNING: No such attribute %s: Cannot suppress printing it.", attr);
				continue;
			}

			/*
			 *	For better distribution we should really
			 *	hash the attribute number or name.  But
			 *	since the suppression list will usually
			 *	be small, it doesn't matter.
			 */
			if (!fr_hash_table_insert(inst->ht, da)) {
				radlog(L_ERR, "rlm_detail: Failed trying to remember %s", attr);
				detail_detach(inst);
				return -1;
			}
		}
	}


	*instance = inst;
	return 0;
}

/*
 * Perform a checked write. If the write fails or is not complete, truncate
 * the file, eliminating the last bytes_accum + current partial write.
 */
static int checked_write(REQUEST *request, off_t *bytes_accum, int fd,
			 const char *format, ...)
{
	char buf[2048];
	int buf_used, written;
	va_list args;

	va_start(args, format);
	buf_used = vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	if (buf_used == 0) return 0;

	if (buf_used >= (int) sizeof(buf)) {
		radlog_request(L_ERR, 0, request, "Truncated vsnprintf");
		return -1;
	}

	written = write(fd, buf, buf_used);
	if (written > 0) {
		*bytes_accum += written;
	}
	if (written != buf_used) {
		/*
		 *	Don't worry if the truncate fails, since the
		 *	detail reader ignores partial entries.
		 */
		ftruncate(fd, lseek(fd, 0, SEEK_CUR) - *bytes_accum);
		close(fd);

		radlog_request(L_ERR, 0, request, "Truncated write (wanted %d, wrote %d)",
			       buf_used, written);		
		return -1;
	}
	return written;
}


static int checked_write_vp(REQUEST *request, off_t *bytes_accum, int fd,
			    VALUE_PAIR *vp)
{
	char buffer[1024];

	vp_prints(buffer, sizeof(buffer), vp);

	if (checked_write(request, bytes_accum, fd, "\t%s\n", buffer) < 0) {
		return -1;
	}

	return 0;
}

/*
 *	Do detail, compatible with old accounting
 */
static int do_detail(void *instance, REQUEST *request, RADIUS_PACKET *packet,
		     int compat)
{
	int		outfd;
	char		timestamp[256];
	char		buffer[DIRLEN];
	char		*p;
	struct stat	st;
	int		locked;
	int		lock_count;
	off_t		bytes_accum = 0;
	struct timeval	tv;
	VALUE_PAIR	*pair;

	struct detail_instance *inst = instance;

	rad_assert(request != NULL);

	/*
	 *	Nothing to log: don't do anything.
	 */
	if (!packet) {
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Create a directory for this nas.
	 *
	 *	Generate the path for the detail file.  Use the
	 *	same format, but truncate at the last /.  Then
	 *	feed it through radius_xlat() to expand the
	 *	variables.
	 */
	if (radius_xlat(buffer, sizeof(buffer), inst->detailfile, request, NULL) == 0) {
		radlog_request(L_ERR, 0, request, "rlm_detail: Failed to expand detail file %s",
		    inst->detailfile);
	    return RLM_MODULE_FAIL;
	}
	RDEBUG2("%s expands to %s", inst->detailfile, buffer);

	/*
	 *	Grab the last directory delimiter.
	 */
	p = strrchr(buffer,'/');

	/*
	 *	There WAS a directory delimiter there, and
	 *	the file doesn't exist, so
	 *	we prolly must create it the dir(s)
	 */
	if ((p) && (stat(buffer, &st) < 0)) {
		*p = '\0';
		/*
		 *	NO previously cached directory name, so we've
		 *	got to create a new one.
		 *
		 *	OR the new directory name is different than the old,
		 *	so we've got to create a new one.
		 *
		 *	OR the cached directory has somehow gotten removed,
		 *	so we've got to create a new one.
		 */
		if ((inst->last_made_directory == NULL) ||
#ifndef HAVE_FNMATCH_H
		    (strcmp(inst->last_made_directory, buffer) != 0)
#else
		    (fnmatch(((listen_detail_t *)request->listener->data)->filename,
			     ((struct detail_instance *)instance)->detailfile,
			     FNM_FILE_NAME | FNM_PERIOD ) == 0)
#endif
		    ) {
			free((char *) inst->last_made_directory);
			inst->last_made_directory = strdup(buffer);
		}

		/*
		 *	stat the directory, and don't do anything if
		 *	it exists.  If it doesn't exist, create it.
		 *
		 *	This also catches the case where some idiot
		 *	deleted a directory that the server was using.
		 */
		if (rad_mkdir(inst->last_made_directory, inst->dirperm) < 0) {
			radlog_request(L_ERR, 0, request, "rlm_detail: Failed to create directory %s: %s", inst->last_made_directory, strerror(errno));
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
		if ((outfd = open(buffer, O_WRONLY | O_APPEND | O_CREAT,
				  inst->detailperm)) < 0) {
			radlog_request(L_ERR, 0, request, "rlm_detail: Couldn't open file %s: %s",
			       buffer, strerror(errno));
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
				radlog_request(L_ERR, 0, request, "rlm_detail: Couldn't stat file %s: %s",
				       buffer, strerror(errno));
				close(outfd);
				return RLM_MODULE_FAIL;
			}
			if (st.st_nlink == 0) {
				RDEBUG2("File %s removed by another program, retrying",
				      buffer);
				close(outfd);
				lock_count = 0;
				continue;
			}

			RDEBUG2("Acquired filelock, tried %d time(s)",
			      lock_count + 1);
			locked = 1;
		}
	} while (inst->locking && !locked && lock_count < 80);

	if (inst->locking && !locked) {
		close(outfd);
		radlog_request(L_ERR, 0, request, "rlm_detail: Failed to acquire filelock for %s, giving up",
		       buffer);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Post a timestamp
	 */
	if (lseek(outfd, 0L, SEEK_END) < 0) {
		radlog_request(L_ERR, 0, request, "rlm_detail: Failed to seek to the end of detail file %s",
			buffer);
		close(outfd);
		return RLM_MODULE_FAIL;
	}
	if (radius_xlat(timestamp, sizeof(timestamp), inst->header, request, NULL) == 0) {
		radlog_request(L_ERR, 0, request, "rlm_detail: Unable to expand detail header format %s",
			inst->header);
		close(outfd);
		return RLM_MODULE_FAIL;
	}
	if (checked_write(request, &bytes_accum, outfd,
			  "%s\n", timestamp) < 0) {
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Write the information to the file.
	 */
	if (!compat) {
		/*
		 *	Print out names, if they're OK.
		 *	Numbers, if not.
		 */
		if ((packet->code > 0) &&
		    (packet->code < FR_MAX_PACKET_CODE)) {
			if (checked_write(request, &bytes_accum, outfd,
					  "\tPacket-Type = %s\n",
					  fr_packet_codes[packet->code]) == -1) {
				return RLM_MODULE_FAIL;	
			}
		} else {
			if (checked_write(request, &bytes_accum, outfd,
					  "\tPacket-Type = %d\n", packet->code) == -1) {
				return RLM_MODULE_FAIL;
			}
		}
	}

	if (inst->log_srcdst) {
		VALUE_PAIR src_vp, dst_vp;

		memset(&src_vp, 0, sizeof(src_vp));
		memset(&dst_vp, 0, sizeof(dst_vp));
		src_vp.operator = dst_vp.operator = T_OP_EQ;

		switch (packet->src_ipaddr.af) {
		case AF_INET:
			src_vp.type = PW_TYPE_IPADDR;
			src_vp.attribute = PW_PACKET_SRC_IP_ADDRESS;
			src_vp.vp_ipaddr = packet->src_ipaddr.ipaddr.ip4addr.s_addr;
			dst_vp.type = PW_TYPE_IPADDR;
			dst_vp.attribute = PW_PACKET_DST_IP_ADDRESS;
			dst_vp.vp_ipaddr = packet->dst_ipaddr.ipaddr.ip4addr.s_addr;
			break;
		case AF_INET6:
			src_vp.type = PW_TYPE_IPV6ADDR;
			src_vp.attribute = PW_PACKET_SRC_IPV6_ADDRESS;
			memcpy(src_vp.vp_strvalue,
			       &packet->src_ipaddr.ipaddr.ip6addr,
			       sizeof(packet->src_ipaddr.ipaddr.ip6addr));
			dst_vp.type = PW_TYPE_IPV6ADDR;
			dst_vp.attribute = PW_PACKET_DST_IPV6_ADDRESS;
			memcpy(dst_vp.vp_strvalue,
			       &packet->dst_ipaddr.ipaddr.ip6addr,
			       sizeof(packet->dst_ipaddr.ipaddr.ip6addr));
			break;
		default:
			break;
		}

		if (checked_write_vp(request, &bytes_accum,
				     outfd, &src_vp) < 0) {
			return RLM_MODULE_FAIL;
		}
		if (checked_write_vp(request, &bytes_accum,
				     outfd, &dst_vp) < 0) {
			return RLM_MODULE_FAIL;
		}

		src_vp.attribute = PW_PACKET_SRC_PORT;
		src_vp.type = PW_TYPE_INTEGER;
		src_vp.vp_integer = packet->src_port;
		dst_vp.attribute = PW_PACKET_DST_PORT;
		dst_vp.type = PW_TYPE_INTEGER;
		dst_vp.vp_integer = packet->dst_port;

		if (checked_write_vp(request, &bytes_accum,
				     outfd, &src_vp) < 0) {
			return RLM_MODULE_FAIL;
		}
		if (checked_write_vp(request, &bytes_accum,
				     outfd, &dst_vp) < 0) {
			return RLM_MODULE_FAIL;
		}
	}

	/* Write each attribute/value to the log file */
	for (pair = packet->vps; pair != NULL; pair = pair->next) {
		DICT_ATTR da;
		da.attr = pair->attribute;

		if (inst->ht &&
		    fr_hash_table_finddata(inst->ht, &da)) continue;

		/*
		 *	Don't print passwords in old format...
		 */
		if (compat && (pair->attribute == PW_USER_PASSWORD)) continue;

		/*
		 *	Print all of the attributes.
		 */
		if (checked_write_vp(request, &bytes_accum,
				     outfd, pair) < 0) {
			return RLM_MODULE_FAIL;
		}
	}

	/*
	 *	Add non-protocol attibutes.
	 */
	if (compat) {
		if (request->proxy) {
			char proxy_buffer[128];

			inet_ntop(request->proxy->dst_ipaddr.af,
				  &request->proxy->dst_ipaddr.ipaddr,
				  proxy_buffer, sizeof(proxy_buffer));
			if (checked_write(request, &bytes_accum, outfd,
				"\tFreeradius-Proxied-To = %s\n",
				proxy_buffer) < 0) {
				return RLM_MODULE_FAIL;   
			}
			RDEBUG("Freeradius-Proxied-To = %s",
				proxy_buffer);
		}

		if (checked_write(request, &bytes_accum, outfd,
			"\tTimestamp = %ld\n",
			(unsigned long) request->timestamp) < 0) {
			return RLM_MODULE_FAIL;
		}
	}

	if (checked_write(request, &bytes_accum, outfd, "\n") < 0) {
		return RLM_MODULE_FAIL;
	}

	if (inst->locking) {
		lseek(outfd, 0L, SEEK_SET);
		rad_unlockfd(outfd, 0);
		RDEBUG2("Released filelock");
	}

	close(outfd);

	/*
	 *	And everything is fine.
	 */
	return RLM_MODULE_OK;
}

/*
 *	Accounting - write the detail files.
 */
static int detail_accounting(void *instance, REQUEST *request)
{
	if (request->listener->type == RAD_LISTEN_DETAIL &&
	    strcmp(((struct detail_instance *)instance)->detailfile,
	           ((listen_detail_t *)request->listener->data)->filename) == 0) {
		RDEBUG("Suppressing writes to detail file as the request was just read from a detail file.");
		return RLM_MODULE_NOOP;
	}

	return do_detail(instance,request,request->packet, TRUE);
}

/*
 *	Incoming Access Request - write the detail files.
 */
static int detail_authorize(void *instance, REQUEST *request)
{
	return do_detail(instance,request,request->packet, FALSE);
}

/*
 *	Outgoing Access-Request Reply - write the detail files.
 */
static int detail_postauth(void *instance, REQUEST *request)
{
	return do_detail(instance,request,request->reply, FALSE);
}

#ifdef WITH_COA
/*
 *	Incoming CoA - write the detail files.
 */
static int detail_recv_coa(void *instance, REQUEST *request)
{
	return do_detail(instance,request,request->packet, FALSE);
}

/*
 *	Outgoing CoA - write the detail files.
 */
static int detail_send_coa(void *instance, REQUEST *request)
{
	return do_detail(instance,request,request->reply, FALSE);
}
#endif

/*
 *	Outgoing Access-Request to home server - write the detail files.
 */
static int detail_pre_proxy(void *instance, REQUEST *request)
{
	if (request->proxy &&
	    request->proxy->vps) {
		return do_detail(instance,request,request->proxy, FALSE);
	}

	return RLM_MODULE_NOOP;
}


/*
 *	Outgoing Access-Request Reply - write the detail files.
 */
static int detail_post_proxy(void *instance, REQUEST *request)
{
	if (request->proxy_reply &&
	    request->proxy_reply->vps) {
		return do_detail(instance,request,request->proxy_reply, FALSE);
	}

	/*
	 *	No reply: we must be doing Post-Proxy-Type = Fail.
	 *
	 *	Note that we just call the normal accounting function,
	 *	to minimize the amount of code, and to highlight that
	 *	it's doing normal accounting.
	 */
	if (!request->proxy_reply) {
		int rcode;

		rcode = detail_accounting(instance, request);
		if (rcode == RLM_MODULE_OK) {
			request->reply->code = PW_ACCOUNTING_RESPONSE;
		}
		return rcode;
	}

	return RLM_MODULE_NOOP;
}


/* globally exported name */
module_t rlm_detail = {
	RLM_MODULE_INIT,
	"detail",
	RLM_TYPE_THREAD_UNSAFE | RLM_TYPE_CHECK_CONFIG_SAFE | RLM_TYPE_HUP_SAFE,
	detail_instantiate,		/* instantiation */
	detail_detach,			/* detach */
	{
		NULL,			/* authentication */
		detail_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		detail_accounting,	/* accounting */
		NULL,			/* checksimul */
		detail_pre_proxy,      	/* pre-proxy */
		detail_post_proxy,	/* post-proxy */
		detail_postauth		/* post-auth */
#ifdef WITH_COA
		, detail_recv_coa,
		detail_send_coa
#endif
	},
};

