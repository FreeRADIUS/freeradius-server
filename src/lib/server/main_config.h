#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/main_config.h
 * @brief Structures and prototypes for map functions
 *
 * @copyright 2018 The FreeRADIUS server project
 */
RCSIDH(main_config_h, "$Id$")

/*
 *	Forward declarations
 */
#ifdef __cplusplus
extern "C" {
#endif

#define MAX_REQUEST_TIME	30			//!< Default maximum request time

typedef struct main_config_s main_config_t;

extern main_config_t const *main_config;		//!< Global configuration singleton.

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/main_config.h>

#include <freeradius-devel/util/dict.h>

/** Main server configuration
 *
 * The parsed version of the main server config.
 */
struct main_config_s {
	char const	*name;				//!< Name of the daemon, usually 'radiusd'.
	bool		overwrite_config_name;		//!< Overwrite the configured name, as this
							///< was specified by the user on the command line.
	CONF_SECTION	*root_cs;			//!< Root of the server config.

	bool		daemonize;			//!< Should the server daemonize on startup.
	bool		spawn_workers;			//!< Should the server spawn threads.
	char const      *pid_file;			//!< Path to write out PID file.

	fr_time_delta_t	max_request_time;		//!< How long a request can be processed for before
							//!< timing out.

	bool		drop_requests;			//!< Administratively disable request processing.

	char const	*log_dir;
	char const	*local_state_dir;
	char const	*chroot_dir;

	bool		reverse_lookups;
	bool		hostname_lookups;

	char const	*radacct_dir;
	char const	*lib_dir;
	char const	*sbin_dir;
	char const	*run_dir;
	char const	*raddb_dir;			//!< Path to raddb directory

	char const	*prefix;

	char const	*log_dest;

	char const	*log_file;
	bool		do_colourise;
	bool		log_line_number;		//!< Log src file/line the message was generated on.

	bool		log_dates_utc;
	bool		*log_timestamp;
	bool		log_timestamp_is_set;

	int32_t		syslog_facility;

	char const	*dict_dir;			//!< Where to load dictionaries from.

	size_t		talloc_pool_size;		//!< Size of pool to allocate to hold each #REQUEST.

	bool		write_pid;			//!< write the PID file

#ifdef HAVE_SETUID
	uid_t		server_uid;			//!< UID we're running as.
	gid_t		server_gid;			//!< GID we're runing as.
	uid_t		uid;				//!< UID we should run as.
	bool		uid_is_set;
	gid_t		gid;				//!< GID we should run as.
	bool		gid_is_set;
#endif

#ifdef ENABLE_OPENSSL_VERSION_CHECK
	char const	*allow_vulnerable_openssl;	//!< The CVE number of the last security issue acknowledged.
#endif

#ifdef HAVE_OPENSSL_CRYPTO_H
	bool		openssl_fips_mode;		//!< Whether OpenSSL fips mode is enabled or disabled.
	bool		openssl_fips_mode_is_set;	//!< Whether the user specified a value.
#endif

	fr_dict_t	*dict;				//!< Main dictionary.


	/*
	 *	Debugging options
	 */
	bool		allow_core_dumps;		//!< Whether the server is allowed to drop a core when
							//!< receiving a fatal signal.

	char const	*panic_action;			//!< Command to execute if the server receives a fatal
							//!< signal.

	uint32_t	debug_level;			//!< The base log level for the server.

	bool		talloc_memory_report;		//!< Print a memory report on what's left unfreed.
							//!< Can only be used when the server is running in single
							//!< threaded mode.

	size_t		talloc_memory_limit;		//!< Limit the amount of talloced memory the server uses.
							//!< Only applicable in single threaded mode.
};

void			main_config_name_set_default(main_config_t *config, char const *name, bool overwrite_config);
void			main_config_raddb_dir_set(main_config_t *config, char const *path);
void			main_config_dict_dir_set(main_config_t *config, char const *path);

main_config_t		*main_config_alloc(TALLOC_CTX *ctx);
int			main_config_init(main_config_t *config);
int			main_config_free(main_config_t **config);
void			main_config_hup(main_config_t *config);
void			hup_logfile(main_config_t *config);

#ifdef __cplusplus
}
#endif
