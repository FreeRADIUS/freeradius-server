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

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/io/worker.h>

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

	bool		write_pid;			//!< write the PID file

	char const	*log_dir;
	char const	*local_state_dir;

	bool		reverse_lookups;		//!< do IP -> host lookups.  Don't set this!
	bool		hostname_lookups;		//!< do hostname -> IP lookups
	bool		drop_requests;			//!< Administratively disable request processing.
	bool		suppress_secrets;		//!< suppress secrets (or not)

	char const	*radacct_dir;
	char const	*lib_dir;
	char const	*sbin_dir;
	char const	*run_dir;
	char const	*confdir;			//!< Path to configuration directory

	char const	*prefix;

	char const	*log_dest;
	char const	*log_file;
	bool		do_colourise;
	bool		log_line_number;		//!< Log src file/line the message was generated on.

	bool		log_dates_utc;
	bool		log_timestamp;
	bool		log_timestamp_is_set;

	int32_t		syslog_facility;

	char const	*dict_dir;			//!< Where to load dictionaries from.
	fr_dict_t	*dict;				//!< Main dictionary.

#ifdef HAVE_SETUID
	uid_t		server_uid;			//!< UID we're running as.
	gid_t		server_gid;			//!< GID we're running as.
	uid_t		uid;				//!< UID we should run as.
	bool		uid_is_set;
	gid_t		gid;				//!< GID we should run as.
	bool		gid_is_set;
#endif

	char const	*chdir;				//!< where to chdir() to when we start.
	bool		chdir_is_set;

	char const	**limit_files;			//!< where %file....() is limited to
	bool		limit_files_is_set;

	/*
	 *	OpenSSL configuration
	 */
#ifdef ENABLE_OPENSSL_VERSION_CHECK
	char const	*allow_vulnerable_openssl;	//!< The CVE number of the last security issue acknowledged.
#endif

#ifdef WITH_TLS
	bool		openssl_fips_mode;		//!< Whether OpenSSL fips mode is enabled or disabled.
	bool		openssl_fips_mode_is_set;	//!< Whether the user specified a value.

	size_t		openssl_async_pool_init;		//!< Tuning option to set the minimum number of requests
							///< in the async ctx pool.

	size_t		openssl_async_pool_max;		//!< Tuning option to set the maximum number of requests
							///< in the async ctx pool.
#endif

	/*
	 *	Debugging options
	 */
	uint32_t	debug_level;			//!< The base log level for the server.

	bool		talloc_memory_report;		//!< Print a memory report on what's left unfreed.
							//!< Can only be used when the server is running in single
							//!< threaded mode.

	bool		talloc_skip_cleanup;		//!< skip talloc cleanups at exit

	bool		allow_core_dumps;		//!< Whether the server is allowed to drop a core when
							//!< receiving a fatal signal.

	char const	*panic_action;			//!< Command to execute if the server receives a fatal
							//!< signal.


	/*
	 *	Multiple processing sharing configs
	 */
	bool		allow_multiple_procs;		//!< Allow multiple instances of radiusd to run with the
							///< same config file.

	int		multi_proc_sem_id;		//!< Semaphore we use to prevent multiple processes running.
	char		*multi_proc_sem_path;		//!< Semaphore path.

	/*
	 *	Internal scheduler configuration
	 */
	uint32_t	max_networks;			//!< for the scheduler
	uint32_t	max_workers;			//!< for the scheduler
	fr_time_delta_t	stats_interval;			//!< for the scheduler

	fr_worker_config_t	worker;			//!< Worker thread configuration.

#ifndef NDEBUG
	uint32_t	ins_max;			//!< max instruction count
	bool		ins_countup;			//!< count up to "max"
#endif
};

void			main_config_name_set_default(main_config_t *config, char const *name, bool overwrite_config);
void			main_config_confdir_set(main_config_t *config, char const *path);
void			main_config_dict_dir_set(main_config_t *config, char const *path);

int			main_config_save_override(char const *value);

void			main_config_exclusive_proc_done(main_config_t  const *config);
int			main_config_exclusive_proc_child(main_config_t const *config);
int			main_config_exclusive_proc(main_config_t *config);

main_config_t		*main_config_alloc(TALLOC_CTX *ctx);
int			main_config_init(main_config_t *config);
int			main_config_free(main_config_t **config);
void			main_config_hup(main_config_t *config);
void			hup_logfile(main_config_t *config);

#ifdef __cplusplus
}
#endif
