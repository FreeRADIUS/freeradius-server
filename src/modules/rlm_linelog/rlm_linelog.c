/*
 * rlm_linelog.c
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
 * Copyright 2004,2006  The FreeRADIUS server project
 * Copyright 2004  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/exfile.h>

#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#ifdef HAVE_GRP_H
#  include <grp.h>
#endif

#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#  ifndef LOG_INFO
#    define LOG_INFO (0)
#  endif
#endif

#include <sys/uio.h>

typedef enum {
	LINELOG_DST_INVALID = 0,
	LINELOG_DST_FILE,				//!< Log to a file.
	LINELOG_DST_SYSLOG,				//!< Log to syslog.
	LINELOG_DST_UNIX,				//!< Log via Unix socket.
	LINELOG_DST_UDP,				//!< Log via UDP.
	LINELOG_DST_TCP,				//!< Log via TCP.
} linelog_dst_t;

static FR_NAME_NUMBER const linelog_dst_table[] = {
	{ "file",	LINELOG_DST_FILE	},
	{ "syslog",	LINELOG_DST_SYSLOG	},
	{ "unix",	LINELOG_DST_UNIX	},
	{ "udp",	LINELOG_DST_UDP		},
	{ "tcp",	LINELOG_DST_TCP		},

	{  NULL , -1 }
};

typedef struct linelog_net {
	fr_ipaddr_t		dst_ipaddr;		//!< Network server.
	fr_ipaddr_t		src_ipaddr;		//!< Send requests from a given src_ipaddr.
	uint16_t		port;			//!< Network port.
	struct timeval		timeout;		//!< How long to wait for read/write operations.
} linelog_net_t;

/** linelog module instance
 */
typedef struct linelog_instance_t {
	char const		*name;			//!< Module instance name.
	fr_connection_pool_t	*pool;			//!< Connection pool instance.

	char const		*delimiter;		//!< Line termination string (usually \n).
	size_t			delimiter_len;		//!< Length of line termination string.

	vp_tmpl_t		*log_src;		//!< Source of log messages.

	vp_tmpl_t		*log_ref;		//!< Path to a #CONF_PAIR (to use as the source of
							///< log messages).

	linelog_dst_t		log_dst;		//!< Logging destination.
	char const		*log_dst_str;		//!< Logging destination string.

	struct {
		char const		*facility;		//!< Syslog facility string.
		char const		*severity;		//!< Syslog severity string.
		int			priority;		//!< Bitwise | of severity and facility.
	} syslog;

	struct {
		char const		*name;			//!< File to write to.
		uint32_t		permissions;		//!< Permissions to use when creating new files.
		char const		*group_str;		//!< Group to set on new files.
		gid_t			group;			//!< Resolved gid.
		exfile_t		*ef;			//!< Exclusive file access handle.
	} file;

	struct {
		char const		*path;			//!< Where the UNIX socket lives.
		struct timeval		timeout;		//!< How long to wait for read/write operations.
	} unix;

	linelog_net_t		tcp;			//!< TCP server.
	linelog_net_t		udp;			//!< UDP server.

	CONF_SECTION		*cs;			//!< #CONF_SECTION to use as the root for #log_ref lookups.
} linelog_instance_t;

typedef struct linelog_conn {
	int			sockfd;			//!< File descriptor associated with socket
} linelog_conn_t;


static const CONF_PARSER file_config[] = {
	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_OUTPUT | PW_TYPE_XLAT, linelog_instance_t, file.name), NULL },
	{ "permissions", FR_CONF_OFFSET(PW_TYPE_INTEGER, linelog_instance_t, file.permissions), "0600" },
	{ "group", FR_CONF_OFFSET(PW_TYPE_STRING, linelog_instance_t, file.group_str), NULL },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static const CONF_PARSER syslog_config[] = {
	{ "facility", FR_CONF_OFFSET(PW_TYPE_STRING, linelog_instance_t, syslog.facility), NULL },
	{ "severity", FR_CONF_OFFSET(PW_TYPE_STRING, linelog_instance_t, syslog.severity), "info" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static const CONF_PARSER unix_config[] = {
	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, linelog_instance_t, unix.path), NULL },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static const CONF_PARSER udp_config[] = {
	{ "server", FR_CONF_OFFSET(PW_TYPE_COMBO_IP_ADDR, linelog_net_t, dst_ipaddr), NULL },
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, linelog_net_t, port), NULL },
	{ "timeout", FR_CONF_OFFSET(PW_TYPE_TIMEVAL, linelog_net_t, timeout), "1000" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static const CONF_PARSER tcp_config[] = {
	{ "server", FR_CONF_OFFSET(PW_TYPE_COMBO_IP_ADDR, linelog_net_t, dst_ipaddr), NULL },
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, linelog_net_t, port), NULL },
	{ "timeout", FR_CONF_OFFSET(PW_TYPE_TIMEVAL, linelog_net_t, timeout), "1000" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "destination", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, linelog_instance_t, log_dst_str), NULL },

	{ "delimiter", FR_CONF_OFFSET(PW_TYPE_STRING, linelog_instance_t, delimiter), "\n" },
	{ "format", FR_CONF_OFFSET(PW_TYPE_TMPL, linelog_instance_t, log_src), NULL },
	{ "reference", FR_CONF_OFFSET(PW_TYPE_TMPL, linelog_instance_t, log_ref), NULL },

	/*
	 *	Log destinations
	 */
	{ "file", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) file_config },
	{ "syslog", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) syslog_config },
	{ "unix", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) unix_config },
	{ "tcp", FR_CONF_OFFSET(PW_TYPE_SUBSECTION, linelog_instance_t, tcp), (void const *) tcp_config },
	{ "udp", FR_CONF_OFFSET(PW_TYPE_SUBSECTION, linelog_instance_t, udp), (void const *) udp_config },

	/*
	 *	Deprecated config items
	 */
	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_OUTPUT | PW_TYPE_DEPRECATED, linelog_instance_t, file.name), NULL },
	{ "permissions", FR_CONF_OFFSET(PW_TYPE_INTEGER | PW_TYPE_DEPRECATED, linelog_instance_t, file.permissions), NULL },
	{ "group", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, linelog_instance_t, file.group_str), NULL },

	{ "syslog_facility", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, linelog_instance_t, syslog.facility), NULL },
	{ "syslog_severity", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, linelog_instance_t, syslog.severity), NULL },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


static int _mod_conn_free(linelog_conn_t *conn)
{
	if (shutdown(conn->sockfd, SHUT_RDWR) < 0) DEBUG3("Shutdown failed: %s", fr_syserror(errno));
	if (close(conn->sockfd) < 0) DEBUG3("Closing socket failed: %s", fr_syserror(errno));

	return 0;
}

static void *mod_conn_create(TALLOC_CTX *ctx, void *instance)
{
	linelog_instance_t	*inst = instance;
	linelog_conn_t		*conn;
	int			sockfd = -1;
	struct timeval		*timeout = NULL;

	switch (inst->log_dst) {
	case LINELOG_DST_UNIX:
		if (inst->unix.timeout.tv_sec || inst->unix.timeout.tv_usec) timeout = &inst->unix.timeout;

		DEBUG2("rlm_linelog (%s): Opening UNIX socket at \"%s\"", inst->name, inst->unix.path);
		sockfd = fr_socket_client_unix(inst->unix.path, true);
		if (sockfd < 0) {
			ERROR("rlm_linelog (%s): Failed opening UNIX socket: %s", inst->name, fr_strerror());
			return NULL;
		}
		break;

	case LINELOG_DST_TCP:
		if (inst->tcp.timeout.tv_sec || inst->tcp.timeout.tv_usec) timeout = &inst->tcp.timeout;

		if (DEBUG_ENABLED2) {
			char buff[INET6_ADDRSTRLEN + 4]; /* IPv6 + /<d><d><d> */

			fr_ntop(buff, sizeof(buff), &inst->tcp.dst_ipaddr);

			DEBUG2("rlm_linelog (%s): Opening TCP connection to %s:%u", inst->name, buff, inst->tcp.port);
		}

		sockfd = fr_socket_client_tcp(NULL, &inst->tcp.dst_ipaddr, inst->tcp.port, true);
		if (sockfd < 0) {
			ERROR("rlm_linelog (%s): Failed opening TCP socket: %s", inst->name, fr_strerror());
			return NULL;
		}
		break;

	case LINELOG_DST_UDP:
		if (inst->udp.timeout.tv_sec || inst->udp.timeout.tv_usec) timeout = &inst->udp.timeout;

		if (DEBUG_ENABLED2) {
			char buff[INET6_ADDRSTRLEN + 4]; /* IPv6 + /<d><d><d> */

			fr_ntop(buff, sizeof(buff), &inst->udp.dst_ipaddr);

			DEBUG2("rlm_linelog (%s): Opening UDP connection to %s:%u", inst->name, buff, inst->udp.port);
		}

		sockfd = fr_socket_client_udp(NULL, &inst->udp.dst_ipaddr, inst->udp.port, true);
		if (sockfd < 0) {
			ERROR("rlm_linelog (%s): Failed opening UDP socket: %s", inst->name, fr_strerror());
			return NULL;
		}
		break;

	/*
	 *	Are not connection oriented destinations
	 */
	case LINELOG_DST_INVALID:
	case LINELOG_DST_FILE:
	case LINELOG_DST_SYSLOG:
		rad_assert(0);
		return NULL;
	}

	if (errno == EINPROGRESS) {
		if (timeout) {
			DEBUG2("rlm_linelog (%s): Waiting for connection to complete...", inst->name);
		} else {
			DEBUG2("rlm_linelog (%s): Blocking until connection complete...", inst->name);
		}
		if (fr_socket_wait_for_connect(sockfd, timeout) < 0) {
			ERROR("rlm_linelog (%s): %s", inst->name, fr_strerror());
			close(sockfd);
			return NULL;
		}
	}
	DEBUG2("rlm_linelog (%s): Connection successful", inst->name);

	/*
	 *	Set blocking operation as we have no timeout set
	 */
	if (!timeout && (fr_blocking(sockfd) < 0)) {
		ERROR("rlm_linelog (%s): Failed setting nonblock flag on fd", inst->name);
		close(sockfd);
		return NULL;
	}

	conn = talloc_zero(ctx, linelog_conn_t);
	conn->sockfd = sockfd;
	talloc_set_destructor(conn, _mod_conn_free);

	return conn;
}

static int mod_detach(void *instance)
{
	linelog_instance_t *inst = instance;

	fr_connection_pool_free(inst->pool);

	return 0;
}


/*
 *	Instantiate the module.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	linelog_instance_t	*inst = instance;
	char			prefix[100];

	inst->log_dst = fr_str2int(linelog_dst_table, inst->log_dst_str, LINELOG_DST_INVALID);
	if (inst->log_dst == LINELOG_DST_INVALID) {
		cf_log_err_cs(conf, "Invalid log destination \"%s\"", inst->log_dst_str);
		return -1;
	}

	if (!inst->log_src && !inst->log_ref) {
		cf_log_err_cs(conf, "Must specify a log format, or reference");
		return -1;
	}

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	snprintf(prefix, sizeof(prefix), "rlm_linelog (%s)", inst->name);

	/*
	 *	Setup the logging destination
	 */
	switch (inst->log_dst) {
	case LINELOG_DST_FILE:
	{
		if (!inst->file.name) {
			cf_log_err_cs(conf, "No value provided for 'filename'");
			return -1;
		}

		inst->file.ef = exfile_init(inst, 64, 30);
		if (!inst->file.ef) {
			cf_log_err_cs(conf, "Failed creating log file context");
			return -1;
		}

		if (inst->file.group_str) {
			char *endptr;

			inst->file.group = strtol(inst->file.group_str, &endptr, 10);
			if (*endptr != '\0') {
				if (rad_getgid(inst, &(inst->file.group), inst->file.group_str) < 0) {
					cf_log_err_cs(conf, "Unable to find system group \"%s\"",
						      inst->file.group_str);
					return -1;
				}
			}
		}
	}
		break;

	case LINELOG_DST_SYSLOG:
	{
		int num;

#ifndef HAVE_SYSLOG_H
		cf_log_err_cs(conf, "Syslog output is not supported on this system");
		return -1;
#else
		if (inst->syslog.facility) {
			num = fr_str2int(syslog_facility_table, inst->syslog.facility, -1);
			if (num < 0) {
				cf_log_err_cs(conf, "Invalid syslog facility \"%s\"", inst->syslog.facility);
				return -1;
			}
			inst->syslog.priority |= num;
		}

		num = fr_str2int(syslog_severity_table, inst->syslog.severity, -1);
		if (num < 0) {
			cf_log_err_cs(conf, "Invalid syslog severity \"%s\"", inst->syslog.severity);
			return -1;
		}
		inst->syslog.priority |= num;
#endif
	}
		break;

	case LINELOG_DST_UNIX:
#ifndef HAVE_SYS_UN_H
		cf_log_err_cs(conf, "Unix sockets are not supported on this sytem");
		return -1;
#else
		inst->pool = fr_connection_pool_module_init(cf_section_sub_find(conf, "unix"),
							    inst, mod_conn_create, NULL, prefix);
		if (!inst->pool) return -1;
#endif
		break;

	case LINELOG_DST_UDP:
		inst->pool = fr_connection_pool_module_init(cf_section_sub_find(conf, "udp"),
							    inst, mod_conn_create, NULL, prefix);
		if (!inst->pool) return -1;
		break;

	case LINELOG_DST_TCP:
		inst->pool = fr_connection_pool_module_init(cf_section_sub_find(conf, "tcp"),
							    inst, mod_conn_create, NULL, prefix);
		if (!inst->pool) return -1;
		break;

	case LINELOG_DST_INVALID:
		rad_assert(0);
		break;
	}

	inst->delimiter_len = talloc_array_length(inst->delimiter) - 1;
	inst->cs = conf;

	return 0;
}

/** Escape unprintable characters
 *
 * ``\n``, ``\r`` are escaped as ``\r`` and ``\n``, all other unprintables are escaped as
 * ``\<oct><oct><oct>``.
 *
 * @param request The current request.
 * @param out Where to write the escaped string.
 * @param outlen Length of the output buffer.
 * @param in String to escape.
 * @param arg unused.
 */
static size_t linelog_escape_func(UNUSED REQUEST *request, char *out, size_t outlen,
				  char const *in, UNUSED void *arg)
{
	int len = 0;

	if (outlen == 0) return 0;
	if (outlen == 1) {
		*out = '\0';
		return 0;
	}

	while (in[0]) {
		if (in[0] >= ' ') {
			if (in[0] == '\\') {
				if (outlen <= 2) break;
				outlen--;
				*out++ = '\\';
				len++;
			}

			outlen--;
			if (outlen == 1) break;
			*out++ = *in++;
			len++;
			continue;
		}

		switch (in[0]) {
		case '\n':
			if (outlen <= 2) break;
			*out++ = '\\';
			*out++ = 'n';
			in++;
			len += 2;
			break;

		case '\r':
			if (outlen <= 2) break;
			*out++ = '\\';
			*out++ = 'r';
			in++;
			len += 2;
			break;

		default:
			if (outlen <= 4) break;
			snprintf(out, outlen,  "\\%03o", (uint8_t) *in);
			in++;
			out += 4;
			outlen -= 4;
			len += 4;
			break;
		}
	}

	*out = '\0';
	return len;
}

/** Write a linelog message
 *
 * Write a log message to syslog or a flat file.
 *
 * @param instance of rlm_linelog.
 * @param request The current request.
 * @return #RLM_MODULE_NOOP if no message to log, #RLM_MODULE_FAIL if we failed writing the
 *	message, #RLM_MODULE_OK on success.
 */
static rlm_rcode_t mod_do_linelog(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_do_linelog(void *instance, REQUEST *request)
{
	int			fd = -1;
	linelog_conn_t		*conn;
	struct timeval		*timeout = NULL;

	char			buff[4096];
	char			*p = buff;
	linelog_instance_t	*inst = instance;
	char const		*value;
	vp_tmpl_t		empty, *vpt = NULL, *vpt_p = NULL;
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	ssize_t			slen;

	struct iovec		vector_s[2];
	struct iovec		*vector = NULL, *vector_p;
	size_t			vector_len;
	bool			with_delim;

	buff[0] = '.';	/* force to be in current section */
	buff[1] = '\0';
	buff[2] = '\0';

	/*
	 *	Expand log_ref to a config path, using the module
	 *	configuration section as the root.
	 */
	if (inst->log_ref) {
		CONF_ITEM	*ci;
		CONF_PAIR	*cp;
		char const	*tmpl_str;

		if (tmpl_expand(NULL, buff + 1, sizeof(buff) - 1,
				request, inst->log_ref, linelog_escape_func, NULL) < 0) {
			return RLM_MODULE_FAIL;
		}

		if (buff[1] == '.') p++;

		/*
		 *	Don't go back up.
		 */
		if (buff[2] == '.') {
			REDEBUG("Invalid path \"%s\"", p);
			return RLM_MODULE_FAIL;
		}

		ci = cf_reference_item(NULL, inst->cs, p);
		if (!ci) {
			RDEBUG2("Path \"%s\" doesn't exist", p);
			goto default_msg;
		}

		if (!cf_item_is_pair(ci)) {
			REDEBUG("Path \"%s\" resolves to a section (should be a pair)", p);
			return RLM_MODULE_FAIL;
		}

		cp = cf_item_to_pair(ci);
		tmpl_str = cf_pair_value(cp);
		if (!tmpl_str || (tmpl_str[0] == '\0')) {
			RDEBUG2("Path \"%s\" resolves to an empty config pair", p);
			vpt_p = tmpl_init(&empty, TMPL_TYPE_LITERAL, "", 0);
			goto build_vector;
		}

		/*
		 *	Alloc a template from the value of the CONF_PAIR
		 *	using request as the context (which will hopefully avoid a malloc).
		 */
		slen = tmpl_afrom_str(request, &vpt, tmpl_str, talloc_array_length(tmpl_str) - 1,
				      cf_pair_value_type(cp), REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
		if (slen <= 0) {
			REMARKER(tmpl_str, -slen, fr_strerror());
			return RLM_MODULE_FAIL;
		}
		vpt_p = vpt;
	} else {
	default_msg:
		/*
		 *	Use the default format string
		 */
		if (!inst->log_src) {
			RDEBUG2("No default message configured");
			return RLM_MODULE_NOOP;
		}
		/*
		 *	Use the pre-parsed format template
		 */
		RDEBUG2("Using default message");
		vpt_p = inst->log_src;
	}

build_vector:
	with_delim = (inst->log_dst != LINELOG_DST_SYSLOG) && (inst->delimiter_len > 0);

	/*
	 *	Log all the things!
	 */
	switch (vpt_p->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
	{
		#define VECTOR_INCREMENT 20
		vp_cursor_t	cursor;
		VALUE_PAIR	*vp;
		int		alloced = VECTOR_INCREMENT, i;

		MEM(vector = talloc_array(request, struct iovec, alloced));
		for (vp = tmpl_cursor_init(NULL, &cursor, request, vpt_p), i = 0;
		     vp;
		     vp = tmpl_cursor_next(&cursor, vpt_p), i++) {
		     	/* need extra for line terminator */
			if ((with_delim && ((i + 1) >= alloced)) ||
			    (i >= alloced)) {
				alloced += VECTOR_INCREMENT;
				MEM(vector = talloc_realloc(request, vector, struct iovec, alloced));
			}

			switch (vp->da->type) {
			case PW_TYPE_OCTETS:
			case PW_TYPE_STRING:
				vector[i].iov_base = vp->data.ptr;
				vector[i].iov_len = vp->vp_length;
				break;

			default:
				p = vp_aprints_value(vector, vp, '\0');
				vector[i].iov_base = p;
				vector[i].iov_len = talloc_array_length(p) - 1;
				break;
			}

			/*
			 *	Add the line delimiter string
			 */
			if (with_delim) {
				i++;
				memcpy(&vector[i].iov_base, &(inst->delimiter), sizeof(vector[i].iov_base));
				vector[i].iov_len = inst->delimiter_len;
			}
		}
		vector_p = vector;
		vector_len = i;
	}
		break;

	/*
	 *	Log a single thing.
	 */
	default:
		slen = tmpl_expand(&value, buff, sizeof(buff), request, vpt_p, linelog_escape_func, NULL);
		if (slen < 0) {
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		/* iov_base is not declared as const *sigh* */
		memcpy(&vector_s[0].iov_base, &value, sizeof(vector_s[0].iov_base));
		vector_s[0].iov_len = slen;

		if (!with_delim) {
			vector_len = 1;
		} else {
			memcpy(&vector_s[1].iov_base, &(inst->delimiter), sizeof(vector_s[1].iov_base));
			vector_s[1].iov_len = inst->delimiter_len;
			vector_len = 2;
		}

		vector_p = &vector_s[0];
	}

	if (vector_len == 0) {
		RDEBUG("No data to write");
		rcode = RLM_MODULE_NOOP;
		goto finish;
	}

	/*
	 *	Reserve a handle, write out the data, close the handle
	 */
	switch (inst->log_dst) {
	case LINELOG_DST_FILE:
	{
		char path[2048];

		if (radius_xlat(path, sizeof(path), request, inst->file.name, rad_filename_escape, NULL) < 0) {
			return RLM_MODULE_FAIL;
		}

		/* check path and eventually create subdirs */
		p = strrchr(path, '/');
		if (p) {
			*p = '\0';
			if (rad_mkdir(path, 0700, -1, -1) < 0) {
				RERROR("Failed to create directory %s: %s", path, fr_syserror(errno));
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
			*p = '/';
		}

		fd = exfile_open(inst->file.ef, path, inst->file.permissions, true);
		if (fd < 0) {
			RERROR("Failed to open %s: %s", path, fr_syserror(errno));
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		if (inst->file.group_str && (chown(path, -1, inst->file.group) == -1)) {
			RWARN("Unable to change system group of \"%s\": %s", path, fr_strerror());
		}

		if (writev(fd, vector_p, vector_len) < 0) {
			RERROR("Failed writing to \"%s\": %s", path, fr_syserror(errno));
			exfile_close(inst->file.ef, fd);

			/* Assert on the extra fatal errors */
			rad_assert((errno != EINVAL) && (errno != EFAULT));

			return RLM_MODULE_FAIL;
		}

		exfile_close(inst->file.ef, fd);
	}
		break;

	case LINELOG_DST_UNIX:
		if (inst->unix.timeout.tv_sec || inst->unix.timeout.tv_usec) timeout = &inst->unix.timeout;
		goto do_write;

	case LINELOG_DST_UDP:
		if (inst->udp.timeout.tv_sec || inst->udp.timeout.tv_usec) timeout = &inst->udp.timeout;
		goto do_write;

	case LINELOG_DST_TCP:
	{
		int i, num;
		if (inst->tcp.timeout.tv_sec || inst->tcp.timeout.tv_usec) timeout = &inst->tcp.timeout;

	do_write:
		num = fr_connection_get_num(inst->pool);
		conn = fr_connection_get(inst->pool);
		if (!conn) {
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		for (i = num; i >= 0; i--) {
			ssize_t wrote;
			char discard[64];

			wrote = fr_writev(conn->sockfd, vector_p, vector_len, timeout);
			if (wrote < 0) switch (errno) {
			/* Errors that indicate we should reconnect */
			case EDESTADDRREQ:
			case EPIPE:
			case EBADF:
			case ECONNRESET:
			case ENETDOWN:
			case ENETUNREACH:
			case EADDRNOTAVAIL: /* Which is OSX for outbound interface is down? */
				RWARN("Failed writing to socket: %s.  Will reconnect and try again...",
				      fr_syserror(errno));
				conn = fr_connection_reconnect(inst->pool, conn);
				if (!conn) {
					rcode = RLM_MODULE_FAIL;
					goto done;
				}
				continue;

			/* Assert on the extra fatal errors */
			case EINVAL:
			case EFAULT:
				rad_assert(0);
				/* FALL-THROUGH */

			/* Normal errors that just cause the module to fail */
			default:
				RERROR("Failed writing to socket: %s", fr_syserror(errno));
				rcode = RLM_MODULE_FAIL;
				goto done;
			}
			RDEBUG2("Wrote %zi bytes", wrote);

			/* Drain the receive buffer */
			while (read(conn->sockfd, discard, sizeof(discard)) > 0);
			break;
		}
	done:
		fr_connection_release(inst->pool, conn);
	}
		break;

#ifdef HAVE_SYSLOG_H
	case LINELOG_DST_SYSLOG:
	{
		size_t i;

		for (i = 0; i < vector_len; i++) {
			syslog(inst->syslog.priority, "%.*s", (int)vector_p[i].iov_len, (char *)vector_p[i].iov_base);
		}
	}
		break;
#endif
	case LINELOG_DST_INVALID:
		rad_assert(0);
		rcode = RLM_MODULE_FAIL;
		break;
	}

finish:
	talloc_free(vpt);
	talloc_free(vector);

	return rcode;
}


/*
 *	Externally visible module definition.
 */
extern module_t rlm_linelog;
module_t rlm_linelog = {
	RLM_MODULE_INIT,
	"linelog",
	RLM_TYPE_HUP_SAFE,   	/* type */
	sizeof(linelog_instance_t),
	module_config,
	mod_instantiate,		/* instantiation */
	mod_detach,			/* detach */
	{
		mod_do_linelog,		/* authentication */
		mod_do_linelog,		/* authorization */
		mod_do_linelog,		/* preaccounting */
		mod_do_linelog,		/* accounting */
		NULL,			/* checksimul */
		mod_do_linelog, 	/* pre-proxy */
		mod_do_linelog,		/* post-proxy */
		mod_do_linelog		/* post-auth */
#ifdef WITH_COA
		, mod_do_linelog,	/* recv-coa */
		mod_do_linelog		/* send-coa */
#endif
	},
};
