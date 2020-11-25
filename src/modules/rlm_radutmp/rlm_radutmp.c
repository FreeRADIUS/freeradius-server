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
 * @file rlm_radutmp.c
 * @brief Tracks sessions.
 *
 * @copyright 2000-2013 The FreeRADIUS server project
 */
RCSID("$Id$")

#include	<freeradius-devel/server/base.h>
#include	<freeradius-devel/server/radutmp.h>
#include	<freeradius-devel/server/module.h>
#include	<freeradius-devel/util/debug.h>
#include	<freeradius-devel/radius/radius.h>

#include	<fcntl.h>

#include "config.h"

#define LOCK_LEN sizeof(struct radutmp)

static char const porttypes[] = "ASITX";

/*
 *	used for caching radutmp lookups in the accounting component.
 */
typedef struct nas_port_s NAS_PORT;
struct nas_port_s {
	uint32_t		nasaddr;
	uint16_t		port;
	off_t			offset;
	NAS_PORT 		*next;
};

typedef struct {
	NAS_PORT	*nas_port_list;
	char const	*filename;
	char const	*username;
	bool		check_nas;
	uint32_t	permission;
	bool		caller_id_ok;
} rlm_radutmp_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_OUTPUT | FR_TYPE_REQUIRED, rlm_radutmp_t, filename), .dflt = RADUTMP },
	{ FR_CONF_OFFSET("username", FR_TYPE_STRING | FR_TYPE_REQUIRED | FR_TYPE_XLAT, rlm_radutmp_t, username), .dflt = "%{User-Name}" },
	{ FR_CONF_OFFSET("check_with_nas", FR_TYPE_BOOL, rlm_radutmp_t, check_nas), .dflt = "yes" },
	{ FR_CONF_OFFSET("permissions", FR_TYPE_UINT32, rlm_radutmp_t, permission), .dflt = "0644" },
	{ FR_CONF_OFFSET("caller_id", FR_TYPE_BOOL, rlm_radutmp_t, caller_id_ok), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_radutmp_dict[];
fr_dict_autoload_t rlm_radutmp_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_acct_delay_time;
static fr_dict_attr_t const *attr_acct_session_id;
static fr_dict_attr_t const *attr_acct_session_time;
static fr_dict_attr_t const *attr_acct_status_type;
static fr_dict_attr_t const *attr_calling_station_id;
static fr_dict_attr_t const *attr_framed_ip_address;
static fr_dict_attr_t const *attr_framed_protocol;
static fr_dict_attr_t const *attr_login_ip_host;
static fr_dict_attr_t const *attr_nas_ip_address;
static fr_dict_attr_t const *attr_nas_port;
static fr_dict_attr_t const *attr_nas_port_type;

extern fr_dict_attr_autoload_t rlm_radutmp_dict_attr[];
fr_dict_attr_autoload_t rlm_radutmp_dict_attr[] = {
	{ .out = &attr_acct_delay_time, .name = "Acct-Delay-Time", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_acct_session_id, .name = "Acct-Session-Id", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_acct_session_time, .name = "Acct-Session-Time", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_calling_station_id, .name = "Calling-Station-Id", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_framed_ip_address, .name = "Framed-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_framed_protocol, .name = "Framed-Protocol", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_login_ip_host, .name = "Login-IP-Host", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_nas_ip_address, .name = "NAS-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_nas_port, .name = "NAS-Port", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_nas_port_type, .name = "NAS-Port-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ NULL }
};

/*
 *	Zap all users on a NAS from the radutmp file.
 */
static unlang_action_t radutmp_zap(rlm_rcode_t *p_result, request_t *request, char const *filename, uint32_t nasaddr, time_t t)
{
	struct radutmp	u;
	int		fd;

	if (t == 0) time(&t);

	fd = open(filename, O_RDWR);
	if (fd < 0) {
		REDEBUG("Error accessing file %s: %s", filename, fr_syserror(errno));
		RETURN_MODULE_FAIL;
	}

	/*
	*	Lock the utmp file, prefer lockf() over flock().
	*/
	if (rad_lockfd(fd, LOCK_LEN) < 0) {
		REDEBUG("Failed to acquire lock on file %s: %s", filename, fr_syserror(errno));
		close(fd);
		RETURN_MODULE_FAIL;
	}

	/*
	*	Find the entry for this NAS / portno combination.
	*/
	while (read(fd, &u, sizeof(u)) == sizeof(u)) {
		if ((nasaddr != 0 && nasaddr != u.nas_address) || u.type != P_LOGIN) {
			continue;
		}
		/*
		 *	Match. Zap it.
		 */
		if (lseek(fd, -(off_t)sizeof(u), SEEK_CUR) < 0) {
			REDEBUG("radutmp_zap: negative lseek!");
			lseek(fd, (off_t)0, SEEK_SET);
		}
		u.type = P_IDLE;
		u.time = t;

		if (write(fd, &u, sizeof(u)) < 0) {
			REDEBUG("Failed writing: %s", fr_syserror(errno));

			close(fd);
			RETURN_MODULE_FAIL;
		}
	}
	close(fd);	/* and implicitely release the locks */

	RETURN_MODULE_OK;
}

/*
 *	Lookup a NAS_PORT in the nas_port_list
 */
static NAS_PORT *nas_port_find(NAS_PORT *nas_port_list, uint32_t nasaddr, uint16_t port)
{
	NAS_PORT	*cl;

	for(cl = nas_port_list; cl; cl = cl->next) {
		if (nasaddr == cl->nasaddr &&
			port == cl->port)
			break;
	}

	return cl;
}


/*
 *	Store logins in the RADIUS utmp file.
 */
static unlang_action_t CC_HINT(nonnull) mod_accounting(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_radutmp_t		*inst = talloc_get_type_abort(mctx->instance, rlm_radutmp_t);
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	struct radutmp		ut, u;
	fr_cursor_t		cursor;
	fr_pair_t		*vp;
	int			status = -1;
	int			protocol = -1;
	time_t			t;
	int			fd = -1;
	bool			port_seen = false;
	int			off;
	char			ip_name[INET_ADDRSTRLEN]; /* 255.255.255.255 */
	char const		*nas;
	NAS_PORT		*cache;
	int			r;

	char			*filename = NULL;
	char			*expanded = NULL;

	if (request->dict != dict_radius) RETURN_MODULE_NOOP;

	if (request->packet->socket.inet.src_ipaddr.af != AF_INET) {
		RDEBUG2("IPv6 not supported!");
		RETURN_MODULE_NOOP;
	}

	/*
	 *	Which type is this.
	 */
	if ((vp = fr_pair_find_by_da(&request->request_pairs, attr_acct_status_type)) == NULL) {
		RDEBUG2("No Accounting-Status-Type record");
		RETURN_MODULE_NOOP;
	}
	status = vp->vp_uint32;

	/*
	 *	Look for weird reboot packets.
	 *
	 *	ComOS (up to and including 3.5.1b20) does not send
	 *	standard FR_STATUS_ACCOUNTING_XXX messages.
	 *
	 *	Check for:  o no Acct-Session-Time, or time of 0
	 *		    o Acct-Session-Id of "00000000".
	 *
	 *	We could also check for NAS-Port, that attribute
	 *	should NOT be present (but we don't right now).
	 */
	if ((status != FR_STATUS_ACCOUNTING_ON) &&
	    (status != FR_STATUS_ACCOUNTING_OFF)) do {
		int check1 = 0;
		int check2 = 0;

		if ((vp = fr_pair_find_by_da(&request->request_pairs, attr_acct_session_time))
		     == NULL || vp->vp_uint32 == 0)
			check1 = 1;
		if ((vp = fr_pair_find_by_da(&request->request_pairs, attr_acct_session_id))
		     != NULL && vp->vp_length == 8 &&
		     memcmp(vp->vp_strvalue, "00000000", 8) == 0)
			check2 = 1;
		if (check1 == 0 || check2 == 0) {
			break;
		}
		RIDEBUG("Converting reboot records");
		if (status == FR_STATUS_STOP) status = FR_STATUS_ACCOUNTING_OFF;
		else if (status == FR_STATUS_START) status = FR_STATUS_ACCOUNTING_ON;
	} while(0);

	time(&t);
	memset(&ut, 0, sizeof(ut));
	ut.porttype = 'A';
	ut.nas_address = htonl(INADDR_NONE);

	/*
	 *	First, find the interesting attributes.
	 */
	for (vp = fr_cursor_init(&cursor, &request->request_pairs);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if ((vp->da == attr_login_ip_host) ||
		    (vp->da == attr_framed_ip_address)) {
			ut.framed_address = vp->vp_ipv4addr;
		} else if (vp->da == attr_framed_protocol) {
			protocol = vp->vp_uint32;
		} else if (vp->da == attr_nas_ip_address) {
			ut.nas_address = vp->vp_ipv4addr;
		} else if (vp->da == attr_nas_port) {
			ut.nas_port = vp->vp_uint32;
			port_seen = true;
		} else if (vp->da == attr_acct_delay_time) {
			ut.delay = vp->vp_uint32;
		} else if (vp->da == attr_acct_session_id) {
			/*
			 *	If length > 8, only store the
			 *	last 8 bytes.
			 */
			off = vp->vp_length - sizeof(ut.session_id);
			/*
			 * 	Ascend is br0ken - it adds a \0
			 * 	to the end of any string.
			 * 	Compensate.
			 */
			if ((vp->vp_length > 0) && (vp->vp_strvalue[vp->vp_length - 1] == 0)) off--;
			if (off < 0) off = 0;
			memcpy(ut.session_id, vp->vp_strvalue + off, sizeof(ut.session_id));
			break;
		} else if (vp->da == attr_nas_port_type) {
			if (vp->vp_uint32 <= 4) ut.porttype = porttypes[vp->vp_uint32];
		} else if (vp->da == attr_calling_station_id) {
			if (inst->caller_id_ok) strlcpy(ut.caller_id, vp->vp_strvalue, sizeof(ut.caller_id));
		}
	}

	/*
	 *	If we didn't find out the NAS address, use the
	 *	originator's IP address.
	 */
	if (ut.nas_address == htonl(INADDR_NONE)) {
		ut.nas_address = request->packet->socket.inet.src_ipaddr.addr.v4.s_addr;
		nas = request->client->shortname;

	} else if (request->packet->socket.inet.src_ipaddr.addr.v4.s_addr == ut.nas_address) {		/* might be a client, might not be. */
		nas = request->client->shortname;

	/*
	 *	The NAS isn't a client, it's behind
	 *	a proxy server.  In that case, just
	 *	get the IP address.
	 */
	} else {
		nas = inet_ntop(AF_INET, &ut.nas_address, ip_name, sizeof(ip_name));
	}

	/*
	 *	Set the protocol field.
	 */
	if (protocol == FR_PPP) {
		ut.proto = 'P';
	} else if (protocol == FR_SLIP) {
		ut.proto = 'S';
	} else {
		ut.proto = 'T';
	}

	ut.time = t - ut.delay;

	/*
	 *	Get the utmp filename, via xlat.
	 */
	filename = NULL;
	if (xlat_aeval(request, &filename, request, inst->filename, NULL, NULL) < 0) {
		RETURN_MODULE_FAIL;
	}

	/*
	 *	See if this was a reboot.
	 *
	 *	Hmm... we may not want to zap all of the users when the NAS comes up, because of issues with receiving
	 *	UDP packets out of order.
	 */
	if (status == FR_STATUS_ACCOUNTING_ON && (ut.nas_address != htonl(INADDR_NONE))) {
		RIDEBUG("NAS %s restarted (Accounting-On packet seen)", nas);
		radutmp_zap(&rcode, request, filename, ut.nas_address, ut.time);

		goto finish;
	}

	if (status == FR_STATUS_ACCOUNTING_OFF && (ut.nas_address != htonl(INADDR_NONE))) {
		RIDEBUG("NAS %s rebooted (Accounting-Off packet seen)", nas);
		radutmp_zap(&rcode, request, filename, ut.nas_address, ut.time);

		goto finish;
	}

	/*
	 *	If we don't know this type of entry pretend we succeeded.
	 */
	if (status != FR_STATUS_START && status != FR_STATUS_STOP && status != FR_STATUS_ALIVE) {
		REDEBUG("NAS %s port %u unknown packet type %d)", nas, ut.nas_port, status);
		rcode = RLM_MODULE_NOOP;

		goto finish;
	}

	/*
	 *	Translate the User-Name attribute, or whatever else they told us to use.
	 */
	if (xlat_aeval(request, &expanded, request, inst->username, NULL, NULL) < 0) {
		rcode = RLM_MODULE_FAIL;

		goto finish;
	}
	strlcpy(ut.login, expanded, RUT_NAMESIZE);
	TALLOC_FREE(expanded);

	/*
	 *	Perhaps we don't want to store this record into
	 *	radutmp. We skip records:
	 *
	 *	- without a NAS-Port (telnet / tcp access)
	 *	- with the username "!root" (console admin login)
	 */
	if (!port_seen) {
		RWDEBUG2("No NAS-Port seen.  Cannot do anything. Checkrad will probably not work!");
		rcode = RLM_MODULE_NOOP;

		goto finish;
	}

	if (strncmp(ut.login, "!root", RUT_NAMESIZE) == 0) {
		RDEBUG2("Not recording administrative user");
		rcode = RLM_MODULE_NOOP;

		goto finish;
	}

	/*
	 *	Enter into the radutmp file.
	 */
	fd = open(filename, O_RDWR|O_CREAT, inst->permission);
	if (fd < 0) {
		REDEBUG("Error accessing file %s: %s", filename, fr_syserror(errno));
		rcode = RLM_MODULE_FAIL;

		goto finish;
	}

	/*
	 *	Lock the utmp file, prefer lockf() over flock().
	 */
	if (rad_lockfd(fd, LOCK_LEN) < 0) {
		REDEBUG("Error acquiring lock on %s: %s", filename, fr_syserror(errno));
		rcode = RLM_MODULE_FAIL;

		goto finish;
	}

	/*
	 *	Find the entry for this NAS / portno combination.
	 */
	if ((cache = nas_port_find(inst->nas_port_list, ut.nas_address, ut.nas_port)) != NULL) {
		if (lseek(fd, (off_t)cache->offset, SEEK_SET) < 0) {
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}
	}

	r = 0;
	off = 0;
	while (read(fd, &u, sizeof(u)) == sizeof(u)) {
		off += sizeof(u);
		if ((u.nas_address != ut.nas_address) || (u.nas_port != ut.nas_port)) {
			continue;
		}

		/*
		 *	Don't compare stop records to unused entries.
		 */
		if (status == FR_STATUS_STOP && u.type == P_IDLE) {
			continue;
		}

		if ((status == FR_STATUS_STOP) && strncmp(ut.session_id, u.session_id, sizeof(u.session_id)) != 0) {
			/*
			 *	Don't complain if this is not a
			 *	login record (some clients can
			 *	send _only_ logout records).
			 */
			if (u.type == P_LOGIN) {
				RWDEBUG("Logout entry for NAS %s port %u has wrong ID", nas, u.nas_port);
			}

			r = -1;
			break;
		}

		if ((status == FR_STATUS_START) && strncmp(ut.session_id, u.session_id, sizeof(u.session_id)) == 0  &&
		    u.time >= ut.time) {
			if (u.type == P_LOGIN) {
				RIDEBUG("Login entry for NAS %s port %u duplicate", nas, u.nas_port);
				r = -1;
				break;
			}

			RWDEBUG("Login entry for NAS %s port %u wrong order", nas, u.nas_port);
			r = -1;
			break;
		}

		/*
		 *	FIXME: the ALIVE record could need some more checking, but anyway I'd
		 *	rather rewrite this mess -- miquels.
		 */
		if ((status == FR_STATUS_ALIVE) && strncmp(ut.session_id, u.session_id, sizeof(u.session_id)) == 0  &&
		    u.type == P_LOGIN) {
			/*
			 *	Keep the original login time.
			 */
			ut.time = u.time;
		}

		if (lseek(fd, -(off_t)sizeof(u), SEEK_CUR) < 0) {
			RWDEBUG("negative lseek!");
			lseek(fd, (off_t)0, SEEK_SET);
			off = 0;
		} else {
			off -= sizeof(u);
		}

		r = 1;
		break;
	} /* read the file until we find a match */

	/*
	 *	Found the entry, do start/update it with
	 *	the information from the packet.
	 */
	if ((r >= 0) && (status == FR_STATUS_START || status == FR_STATUS_ALIVE)) {
		/*
		 *	Remember where the entry was, because it's
		 *	easier than searching through the entire file.
		 */
		if (!cache) {
			cache = talloc_zero(NULL, NAS_PORT);
			if (cache) {
				cache->nasaddr = ut.nas_address;
				cache->port = ut.nas_port;
				cache->offset = off;
				cache->next = inst->nas_port_list;
				inst->nas_port_list = cache;
			}
		}

		ut.type = P_LOGIN;
		if (write(fd, &ut, sizeof(u)) < 0) {
			REDEBUG("Failed writing: %s", fr_syserror(errno));

			rcode = RLM_MODULE_FAIL;
			goto finish;
		}
	}

	/*
	 *	The user has logged off, delete the entry by
	 *	re-writing it in place.
	 */
	if (status == FR_STATUS_STOP) {
		if (r > 0) {
			u.type = P_IDLE;
			u.time = ut.time;
			u.delay = ut.delay;
			if (write(fd, &u, sizeof(u)) < 0) {
				REDEBUG("Failed writing: %s", fr_syserror(errno));

				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
		} else if (r == 0) {
			RWDEBUG("Logout for NAS %s port %u, but no Login record", nas, ut.nas_port);
		}
	}

	finish:

	talloc_free(filename);

	if (fd > -1) {
		close(fd);	/* and implicitely release the locks */
	}

	RETURN_MODULE_RCODE(rcode);
}

/* globally exported name */
extern module_t rlm_radutmp;
module_t rlm_radutmp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radutmp",
	.type		= RLM_TYPE_THREAD_UNSAFE,
	.inst_size	= sizeof(rlm_radutmp_t),
	.config		= module_config,
	.methods = {
		[MOD_ACCOUNTING]	= mod_accounting,
	},
};

