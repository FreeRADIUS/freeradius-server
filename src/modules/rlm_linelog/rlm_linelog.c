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
 * @copyright 2004,2006 The FreeRADIUS server project
 * @copyright 2004 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/exfile.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/iovec.h>
#include <freeradius-devel/util/perm.h>

#include <freeradius-devel/unlang/xlat_func.h>

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
	LINELOG_DST_REQUEST,				//!< Log to the request->log
	LINELOG_DST_SYSLOG,				//!< Log to syslog.
	LINELOG_DST_UNIX,				//!< Log via Unix socket.
	LINELOG_DST_UDP,				//!< Log via UDP.
	LINELOG_DST_TCP,				//!< Log via TCP.
	LINELOG_DST_STDOUT,				//!< Log to stdout.
	LINELOG_DST_STDERR,				//!< Log to stderr.
} linefr_log_dst_t;

static fr_table_num_sorted_t const linefr_log_dst_table[] = {
	{ L("file"),	LINELOG_DST_FILE	},
	{ L("request"),	LINELOG_DST_REQUEST	},
	{ L("stderr"),	LINELOG_DST_STDERR	},
	{ L("stdout"),	LINELOG_DST_STDOUT	},
	{ L("syslog"),	LINELOG_DST_SYSLOG	},
	{ L("tcp"),	LINELOG_DST_TCP		},
	{ L("udp"),	LINELOG_DST_UDP		},
	{ L("unix"),	LINELOG_DST_UNIX	}
};
static size_t linefr_log_dst_table_len = NUM_ELEMENTS(linefr_log_dst_table);

typedef struct {
	fr_ipaddr_t		dst_ipaddr;		//!< Network server.
	fr_ipaddr_t		src_ipaddr;		//!< Send requests from a given src_ipaddr.
	uint16_t		port;			//!< Network port.
	fr_time_delta_t		timeout;		//!< How long to wait for read/write operations.
} linelog_net_t;

/** linelog module instance
 */
typedef struct {
	fr_pool_t		*pool;			//!< Connection pool instance.

	char const		*delimiter;		//!< Line termination string (usually \n).
	size_t			delimiter_len;		//!< Length of line termination string.

	tmpl_t			*log_src;		//!< Source of log messages.

	tmpl_t			*log_ref;		//!< Path to a #CONF_PAIR (to use as the source of
							///< log messages).

	tmpl_t			*log_head;		//!< Header to add to each new log file.

	linefr_log_dst_t	log_dst;		//!< Logging destination.
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
		bool			escape;			//!< Do filename escaping, yes / no.
		xlat_escape_legacy_t	escape_func;		//!< Escape function.
	} file;

	struct {
		char const		*path;			//!< Where the UNIX socket lives.
		fr_time_delta_t		timeout;		//!< How long to wait for read/write operations.
	} unix_sock;	// Lowercase unix is a macro on some systems?!

	linelog_net_t		tcp;			//!< TCP server.
	linelog_net_t		udp;			//!< UDP server.

	CONF_SECTION		*cs;			//!< #CONF_SECTION to use as the root for #log_ref lookups.
} rlm_linelog_t;

typedef struct {
	int			sockfd;			//!< File descriptor associated with socket
} linelog_conn_t;


static const conf_parser_t file_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_FILE_OUTPUT | CONF_FLAG_XLAT, rlm_linelog_t, file.name) },
	{ FR_CONF_OFFSET("permissions", rlm_linelog_t, file.permissions), .dflt = "0600" },
	{ FR_CONF_OFFSET("group", rlm_linelog_t, file.group_str) },
	{ FR_CONF_OFFSET("escape_filenames", rlm_linelog_t, file.escape), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t syslog_config[] = {
	{ FR_CONF_OFFSET("facility", rlm_linelog_t, syslog.facility) },
	{ FR_CONF_OFFSET("severity", rlm_linelog_t, syslog.severity), .dflt = "info" },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t unix_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_FILE_INPUT, rlm_linelog_t, unix_sock.path) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t udp_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("server", FR_TYPE_COMBO_IP_ADDR, 0, linelog_net_t, dst_ipaddr) },
	{ FR_CONF_OFFSET("port", linelog_net_t, port) },
	{ FR_CONF_OFFSET("timeout", linelog_net_t, timeout), .dflt = "1000" },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t tcp_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("server", FR_TYPE_COMBO_IP_ADDR, 0, linelog_net_t, dst_ipaddr) },
	{ FR_CONF_OFFSET("port", linelog_net_t, port) },
	{ FR_CONF_OFFSET("timeout", linelog_net_t, timeout), .dflt = "1000" },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_FLAGS("destination", CONF_FLAG_REQUIRED, rlm_linelog_t, log_dst_str) },

	{ FR_CONF_OFFSET("delimiter", rlm_linelog_t, delimiter), .dflt = "\n" },
	{ FR_CONF_OFFSET("format", rlm_linelog_t, log_src) },
	{ FR_CONF_OFFSET("reference", rlm_linelog_t, log_ref) },
	{ FR_CONF_OFFSET("header", rlm_linelog_t, log_head) },

	/*
	 *	Log destinations
	 */
	{ FR_CONF_POINTER("file", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) file_config },
	{ FR_CONF_POINTER("syslog", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) syslog_config },
	{ FR_CONF_POINTER("unix", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) unix_config },
	{ FR_CONF_OFFSET_SUBSECTION("tcp", 0, rlm_linelog_t, tcp, tcp_config) },
	{ FR_CONF_OFFSET_SUBSECTION("udp", 0, rlm_linelog_t, udp, udp_config) },

	/*
	 *	Deprecated config items
	 */
	{ FR_CONF_DEPRECATED("filename", rlm_linelog_t, file.name) },
	{ FR_CONF_DEPRECATED("permissions", rlm_linelog_t, file.permissions) },
	{ FR_CONF_DEPRECATED("group", rlm_linelog_t, file.group_str) },

	{ FR_CONF_DEPRECATED("syslog_facility", rlm_linelog_t, syslog.facility) },
	{ FR_CONF_DEPRECATED("syslog_severity", rlm_linelog_t, syslog.severity) },
	CONF_PARSER_TERMINATOR
};


static int _mod_conn_free(linelog_conn_t *conn)
{
	if (shutdown(conn->sockfd, SHUT_RDWR) < 0) DEBUG3("Shutdown failed: %s", fr_syserror(errno));
	if (close(conn->sockfd) < 0) DEBUG3("Closing socket failed: %s", fr_syserror(errno));

	return 0;
}

static void *mod_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_delta_t timeout)
{
	rlm_linelog_t const	*inst = talloc_get_type_abort(instance, rlm_linelog_t);
	linelog_conn_t		*conn;
	int			sockfd = -1;

	switch (inst->log_dst) {
	case LINELOG_DST_UNIX:
		DEBUG2("Opening UNIX socket at \"%s\"", inst->unix_sock.path);
		sockfd = fr_socket_client_unix(inst->unix_sock.path, true);
		if (sockfd < 0) {
			PERROR("Failed opening UNIX socket");
			return NULL;
		}
		break;

	case LINELOG_DST_TCP:
		DEBUG2("Opening TCP connection to %pV:%u", fr_box_ipaddr(inst->tcp.dst_ipaddr), inst->tcp.port);

		sockfd = fr_socket_client_tcp(NULL, NULL, &inst->tcp.dst_ipaddr, inst->tcp.port, true);
		if (sockfd < 0) {
			PERROR("Failed opening TCP socket");
			return NULL;
		}
		break;

	case LINELOG_DST_UDP:
		DEBUG2("Opening UDP connection to %pV:%u", fr_box_ipaddr(inst->udp.dst_ipaddr), inst->udp.port);

		sockfd = fr_socket_client_udp(NULL, NULL, NULL, &inst->udp.dst_ipaddr, inst->udp.port, true);
		if (sockfd < 0) {
			PERROR("Failed opening UDP socket");
			return NULL;
		}
		break;

	/*
	 *	Are not connection oriented destinations
	 */
	case LINELOG_DST_INVALID:
	case LINELOG_DST_FILE:
	case LINELOG_DST_REQUEST:
	case LINELOG_DST_SYSLOG:
	case LINELOG_DST_STDOUT:
	case LINELOG_DST_STDERR:
		fr_assert(0);
		return NULL;
	}

	if (errno == EINPROGRESS) {
		if (fr_time_delta_ispos(timeout)) {
			DEBUG2("Waiting for connection to complete...");
		} else {
			DEBUG2("Blocking until connection complete...");
		}
		if (fr_socket_wait_for_connect(sockfd, timeout) < 0) {
			PERROR("Failed connecting to log destination");
			close(sockfd);
			return NULL;
		}
	}
	DEBUG2("Connection successful");

	/*
	 *	Set blocking operation as we have no timeout set
	 */
	if (!fr_time_delta_ispos(timeout) && (fr_blocking(sockfd) < 0)) {
		ERROR("Failed setting nonblock flag on fd");
		close(sockfd);
		return NULL;
	}

	conn = talloc_zero(ctx, linelog_conn_t);
	conn->sockfd = sockfd;
	talloc_set_destructor(conn, _mod_conn_free);

	return conn;
}

/** Escape unprintable characters
 *
 * - Newline is escaped as ``\\n``.
 * - Return is escaped as ``\\r``.
 * - All other unprintables are escaped as @verbatim \<oct><oct><oct> @endverbatim.
 *
 * @param request The current request.
 * @param out Where to write the escaped string.
 * @param outlen Length of the output buffer.
 * @param in String to escape.
 * @param arg unused.
 */
/*
 *	Escape unprintable characters.
 */
static size_t linelog_escape_func(UNUSED request_t *request,
		char *out, size_t outlen, char const *in,
		UNUSED void *arg)
{
	if (outlen == 0) return 0;

	if (outlen == 1) {
		*out = '\0';
		return 0;
	}


	return fr_snprint(out, outlen, in, -1, 0);
}

static void linelog_hexdump(request_t *request, struct iovec *vector_p, size_t vector_len, char const *msg)
{
	fr_dbuff_t *agg;

	FR_DBUFF_TALLOC_THREAD_LOCAL(&agg, 1024, SIZE_MAX);
	fr_concatv(agg, vector_p, vector_len);

	RHEXDUMP3(fr_dbuff_start(agg), fr_dbuff_used(agg), "%s", msg);
}

static int linelog_write(rlm_linelog_t const *inst, request_t *request, struct iovec *vector_p, size_t vector_len, bool with_delim)
{
	int 			ret = 0;
	linelog_conn_t		*conn;
	fr_time_delta_t		timeout = fr_time_delta_wrap(0);

	/*
	 *	Reserve a handle, write out the data, close the handle
	 */
	switch (inst->log_dst) {
	case LINELOG_DST_FILE:
	{
		int		fd = -1;
		char		path[2048];
		off_t		offset;
		char		*p;
		ssize_t 	slen;

		if (xlat_eval(path, sizeof(path), request, inst->file.name, inst->file.escape_func, NULL) < 0) {
			ret = -1;
			goto finish;
		}

		/* check path and eventually create subdirs */
		p = strrchr(path, '/');
		if (p) {
			*p = '\0';
			if (fr_mkdir(NULL, path, -1, 0700, NULL, NULL) < 0) {
				RERROR("Failed to create directory %s: %s", path, fr_syserror(errno));
				ret = -1;
				goto finish;
			}
			*p = '/';
		}

		fd = exfile_open(inst->file.ef, path, inst->file.permissions, &offset);
		if (fd < 0) {
			RERROR("Failed to open %s: %s", path, fr_syserror(errno));
			ret = -1;
			goto finish;
		}

		if (inst->file.group_str && (chown(path, -1, inst->file.group) == -1)) {
			RPWARN("Unable to change system group of \"%s\": %s", path, fr_strerror());
		}

		/*
		 *	If a header format is defined and we are at the beginning
		 *	of the file then expand the format and write it out before
		 *	writing the actual log entries.
		 */
		if (inst->log_head && (offset == 0)) {
			char 		head[4096];
			char		*head_value;
			struct iovec	head_vector_s[2];
			size_t		head_vector_len;

			slen = tmpl_expand(&head_value, head, sizeof(head), request, inst->log_head,
					  linelog_escape_func, NULL);
			if (slen < 0) {
				exfile_close(inst->file.ef, fd);
				ret = -1;
				goto finish;
			}

			memcpy(&head_vector_s[0].iov_base, &head_value, sizeof(head_vector_s[0].iov_base));
			head_vector_s[0].iov_len = slen;

			if (!with_delim) {
				head_vector_len = 1;
			} else {
				memcpy(&head_vector_s[1].iov_base, &(inst->delimiter),
				       sizeof(head_vector_s[1].iov_base));
				head_vector_s[1].iov_len = inst->delimiter_len;
				head_vector_len = 2;
			}

			if (RDEBUG_ENABLED3) linelog_hexdump(request, head_vector_s, head_vector_len, "linelog header");

			if (writev(fd, &head_vector_s[0], head_vector_len) < 0) {
			write_fail:
				RERROR("Failed writing to \"%s\": %s", path, fr_syserror(errno));
				exfile_close(inst->file.ef, fd);

				/* Assert on the extra fatal errors */
				fr_assert((errno != EINVAL) && (errno != EFAULT));

				ret = -1;
				goto finish;
			}
		}

		if (RDEBUG_ENABLED3) linelog_hexdump(request, vector_p, vector_len, "linelog data");

		ret = writev(fd, vector_p, vector_len);
		if (ret < 0) goto write_fail;

		exfile_close(inst->file.ef, fd);
	}
		break;

	case LINELOG_DST_REQUEST:
	{
		size_t i;

		ret = 0;
		for (i = 0; i < vector_len; i++) {
			RINFO("%.*s", (int)vector_p[i].iov_len, (char *)vector_p[i].iov_base);
			ret += vector_p[i].iov_len;
		}
	}
		break;

	case LINELOG_DST_UNIX:
		if (fr_time_delta_ispos(inst->unix_sock.timeout)) {
			timeout = inst->unix_sock.timeout;
		}
		goto do_write;

	case LINELOG_DST_UDP:
		if (fr_time_delta_ispos(inst->udp.timeout)) {
			timeout = inst->udp.timeout;
		}
		goto do_write;

	case LINELOG_DST_TCP:
	{
		int i, num;
		if (fr_time_delta_ispos(inst->tcp.timeout)) {
			timeout = inst->tcp.timeout;
		}

	do_write:
		num = fr_pool_state(inst->pool)->num;
		conn = fr_pool_connection_get(inst->pool, request);
		if (!conn) {
			ret = -1;
			goto finish;
		}

		for (i = num; i >= 0; i--) {
			ssize_t wrote;
			char discard[64];

			if (RDEBUG_ENABLED3) linelog_hexdump(request, vector_p, vector_len, "linelog data");
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
				conn = fr_pool_connection_reconnect(inst->pool, request, conn);
				if (!conn) {
					ret = -1;
					goto done;
				}
				continue;

			/* Assert on the extra fatal errors */
			case EINVAL:
			case EFAULT:
				fr_assert(0);
				FALL_THROUGH;

			/* Normal errors that just cause the module to fail */
			default:
				RERROR("Failed writing to socket: %s", fr_syserror(errno));
				ret = -1;
				goto done;
			}
			RDEBUG2("Wrote %zi bytes", wrote);
			ret = wrote;

			/* Drain the receive buffer */
			while (read(conn->sockfd, discard, sizeof(discard)) > 0);
			break;
		}
	done:
		fr_pool_connection_release(inst->pool, request, conn);
	}
		break;

#ifdef HAVE_SYSLOG_H
	case LINELOG_DST_SYSLOG:
	{
		size_t i;

		ret = 0;
		for (i = 0; i < vector_len; i++) {
			syslog(inst->syslog.priority, "%.*s", (int)vector_p[i].iov_len, (char *)vector_p[i].iov_base);
			ret += vector_p[i].iov_len;
		}
	}
		break;
#endif

	case LINELOG_DST_STDOUT:
	case LINELOG_DST_STDERR:
	{
		int fd = inst->log_dst == LINELOG_DST_STDOUT ? STDOUT_FILENO : STDERR_FILENO;
		if ((ret = writev(fd, vector_p, vector_len)) < 0) {
			RERROR("Failed writing to \"%s\": %s",
			       fr_table_str_by_value(linefr_log_dst_table, inst->log_dst, NULL),
			       fr_syserror(errno));
		}
	}
		break;

	case LINELOG_DST_INVALID:
		fr_assert(0);
		ret = -1;
		break;
	}

finish:
	return ret;
}

static xlat_action_t linelog_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				  xlat_ctx_t const *xctx, request_t *request,
				  fr_value_box_list_t *args)
{
	rlm_linelog_t const	*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_linelog_t);
	struct iovec		vector[2];
	size_t			i = 0;
	bool			with_delim;
	fr_value_box_t		*msg, *wrote;
	ssize_t			slen;

	XLAT_ARGS(args, &msg);

	vector[i].iov_base = UNCONST(char *, msg->vb_strvalue);
	vector[i].iov_len = msg->vb_length;
	i++;

	with_delim = (inst->log_dst != LINELOG_DST_SYSLOG) && (inst->delimiter_len > 0);
	if (with_delim) {
		memcpy(&vector[i].iov_base, &(inst->delimiter), sizeof(vector[i].iov_base));
		vector[i].iov_len = inst->delimiter_len;
		i++;
	}
	slen = linelog_write(inst, request, vector, i, with_delim);
	if (slen < 0) return XLAT_ACTION_FAIL;

	MEM(wrote = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL));
	wrote->vb_size = (size_t)slen;

	fr_dcursor_insert(out, wrote);

	return XLAT_ACTION_DONE;
}

/** Write a linelog message
 *
 * Write a log message to syslog or a flat file.
 *
 * @param[in] p_result	the result of the module call:
 *			- #RLM_MODULE_NOOP if no message to log.
 *			- #RLM_MODULE_FAIL if we failed writing the message.
 *			- #RLM_MODULE_OK on success.
 * @param[in] mctx	module calling context.
 * @param[in] request	The current request.
 */
static unlang_action_t CC_HINT(nonnull) mod_do_linelog(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_linelog_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_linelog_t);
	CONF_SECTION			*conf = mctx->inst->conf;

	char				buff[4096];

	char				*p = buff;
	char const			*value;
	tmpl_t				empty, *vpt = NULL, *vpt_p = NULL;
	rlm_rcode_t			rcode = RLM_MODULE_OK;
	ssize_t				slen;

	struct iovec			vector_s[2];
	struct iovec			*vector = NULL, *vector_p;
	size_t				vector_len;
	bool				with_delim;


	if (!inst->log_src && !inst->log_ref) {
		cf_log_err(conf, "A 'format', or 'reference' configuration item must be set to call this module");
		RETURN_MODULE_FAIL;
	}

	buff[0] = '.';	/* force to be in current section (by default) */
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
		char const	*path;

		if (tmpl_expand(&path, buff + 1, sizeof(buff) - 1,
				request, inst->log_ref, linelog_escape_func, NULL) < 0) {
			RETURN_MODULE_FAIL;
		}

		if (path != buff + 1) strlcpy(buff + 1, path, sizeof(buff) - 1);

		if (buff[1] == '.') p++;

		/*
		 *	Don't go back up.
		 */
		if (buff[2] == '.') {
			REDEBUG("Invalid path \"%s\"", p);
			RETURN_MODULE_FAIL;
		}

		ci = cf_reference_item(NULL, inst->cs, p);
		if (!ci) {
			RDEBUG2("Path \"%s\" doesn't exist", p);
			goto default_msg;
		}

		if (!cf_item_is_pair(ci)) {
			REDEBUG("Path \"%s\" resolves to a section (should be a pair)", p);
			RETURN_MODULE_FAIL;
		}

		cp = cf_item_to_pair(ci);
		tmpl_str = cf_pair_value(cp);
		if (!tmpl_str || (tmpl_str[0] == '\0')) {
			RDEBUG2("Path \"%s\" resolves to an empty config pair", p);
			vpt_p = tmpl_init_shallow(&empty, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0, NULL);
			fr_value_box_init_null(&empty.data.literal);
			fr_value_box_strdup_shallow(&empty.data.literal, NULL, "", false);
			goto build_vector;
		}

		/*
		 *	Alloc a template from the value of the CONF_PAIR
		 *	using request as the context (which will hopefully avoid an alloc).
		 */
		slen = tmpl_afrom_substr(request, &vpt,
					 &FR_SBUFF_IN(tmpl_str, talloc_array_length(tmpl_str) - 1),
					 cf_pair_value_quote(cp),
					 NULL,
					 &(tmpl_rules_t){
					 	.attr = {
							.list_def = request_attr_request,
					 		.dict_def = request->dict,
					 		.allow_unknown = true,
					 		.allow_unresolved = false,
					 	},
						.xlat = {
							.runtime_el = unlang_interpret_event_list(request),
						},
					 	.at_runtime = true
					 });
		if (!vpt) {
			REMARKER(tmpl_str, -slen, "%s", fr_strerror());
			RETURN_MODULE_FAIL;
		}
		vpt_p = vpt;
	} else {
	default_msg:
		/*
		 *	Use the default format string
		 */
		if (!inst->log_src) {
			RDEBUG2("No default message configured");
			RETURN_MODULE_NOOP;
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
	{
		#define VECTOR_INCREMENT 20
		fr_dcursor_t		cursor;
		tmpl_dcursor_ctx_t	cc;
		fr_pair_t		*vp;
		int			alloced = VECTOR_INCREMENT, i;

		MEM(vector = talloc_array(request, struct iovec, alloced));
		for (vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt_p), i = 0;
		     vp;
		     vp = fr_dcursor_next(&cursor), i++) {
		     	/* need extra for line terminator */
			if ((with_delim && ((i + 1) >= alloced)) ||
			    (i >= alloced)) {
				alloced += VECTOR_INCREMENT;
				MEM(vector = talloc_realloc(request, vector, struct iovec, alloced));
			}

			switch (vp->vp_type) {
			case FR_TYPE_OCTETS:
			case FR_TYPE_STRING:
				vector[i].iov_len = vp->vp_length;
				vector[i].iov_base = vp->vp_ptr;
				break;

			default:
				vector[i].iov_len = fr_value_box_aprint(vector, &p, &vp->data, NULL);
				vector[i].iov_base = p;
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
		tmpl_dcursor_clear(&cc);
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
		RDEBUG2("No data to write");
		rcode = RLM_MODULE_NOOP;
		goto finish;
	}

	rcode = linelog_write(inst, request, vector_p, vector_len, with_delim) < 0 ? RLM_MODULE_FAIL : RLM_MODULE_OK;

finish:
	talloc_free(vpt);
	talloc_free(vector);

	RETURN_MODULE_RCODE(rcode);
}


static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_linelog_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_linelog_t);

	fr_pool_free(inst->pool);

	return 0;
}

/*
 *	Instantiate the module.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_linelog_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_linelog_t);
	CONF_SECTION		*conf = mctx->inst->conf;
	char			prefix[100];

	/*
	 *	Escape filenames only if asked.
	 */
	if (inst->file.escape) {
		inst->file.escape_func = rad_filename_escape;
	} else {
		inst->file.escape_func = rad_filename_make_safe;
	}

	inst->log_dst = fr_table_value_by_str(linefr_log_dst_table, inst->log_dst_str, LINELOG_DST_INVALID);
	if (inst->log_dst == LINELOG_DST_INVALID) {
		cf_log_err(conf, "Invalid log destination \"%s\"", inst->log_dst_str);
		return -1;
	}

	snprintf(prefix, sizeof(prefix), "rlm_linelog (%s)", mctx->inst->name);

	/*
	 *	Setup the logging destination
	 */
	switch (inst->log_dst) {
	case LINELOG_DST_FILE:
	{
		if (!inst->file.name) {
			cf_log_err(conf, "No value provided for 'file.filename'");
			return -1;
		}

		inst->file.ef = module_rlm_exfile_init(inst, conf, 256, fr_time_delta_from_sec(30), true, NULL, NULL);
		if (!inst->file.ef) {
			cf_log_err(conf, "Failed creating log file context");
			return -1;
		}

		if (inst->file.group_str) {
			char *endptr;

			inst->file.group = strtol(inst->file.group_str, &endptr, 10);
			if (*endptr != '\0') {
				if (fr_perm_gid_from_str(inst, &(inst->file.group), inst->file.group_str) < 0) {
					cf_log_err(conf, "Unable to find system group \"%s\"",
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
		cf_log_err(conf, "Syslog output is not supported on this system");
		return -1;
#else
		if (inst->syslog.facility) {
			num = fr_table_value_by_str(syslog_facility_table, inst->syslog.facility, -1);
			if (num < 0) {
				cf_log_err(conf, "Invalid syslog facility \"%s\"", inst->syslog.facility);
				return -1;
			}
			inst->syslog.priority |= num;
		}

		num = fr_table_value_by_str(syslog_severity_table, inst->syslog.severity, -1);
		if (num < 0) {
			cf_log_err(conf, "Invalid syslog severity \"%s\"", inst->syslog.severity);
			return -1;
		}
		inst->syslog.priority |= num;
#endif
	}
		break;

	case LINELOG_DST_UNIX:
#ifndef HAVE_SYS_UN_H
		cf_log_err(conf, "Unix sockets are not supported on this system");
		return -1;
#else
		inst->pool = module_rlm_connection_pool_init(cf_section_find(conf, "unix", NULL),
							 inst, mod_conn_create, NULL, prefix, NULL, NULL);
		if (!inst->pool) return -1;
#endif
		break;

	case LINELOG_DST_UDP:
		inst->pool = module_rlm_connection_pool_init(cf_section_find(conf, "udp", NULL),
							 inst, mod_conn_create, NULL, prefix, NULL, NULL);
		if (!inst->pool) return -1;
		break;

	case LINELOG_DST_TCP:
		inst->pool = module_rlm_connection_pool_init(cf_section_find(conf, "tcp", NULL),
							 inst, mod_conn_create, NULL, prefix, NULL, NULL);
		if (!inst->pool) return -1;
		break;

	case LINELOG_DST_REQUEST:
	case LINELOG_DST_STDOUT:
	case LINELOG_DST_STDERR:
		break;

	case LINELOG_DST_INVALID:
		fr_assert(0);
		break;
	}

	inst->delimiter_len = talloc_array_length(inst->delimiter) - 1;
	inst->cs = conf;

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_linelog_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_linelog_t);
	xlat_t		*xlat;

	static xlat_arg_parser_t const linelog_xlat_args[] = {
		{ .required = true, .concat = true, .type = FR_TYPE_STRING },
		XLAT_ARG_PARSER_TERMINATOR
	};

	xlat = xlat_func_register_module(inst, mctx, mctx->inst->name, linelog_xlat, FR_TYPE_SIZE);
	xlat_func_mono_set(xlat, linelog_xlat_args);

	return 0;
}

/*
 *	Externally visible module definition.
 */
extern module_rlm_t rlm_linelog;
module_rlm_t rlm_linelog = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "linelog",
		.inst_size	= sizeof(rlm_linelog_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
		.detach		= mod_detach
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = CF_IDENT_ANY,	.name2 = CF_IDENT_ANY,		.method = mod_do_linelog },
		MODULE_NAME_TERMINATOR
	}
};
