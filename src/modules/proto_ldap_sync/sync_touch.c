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
 * @file src/modules/proto_ldap_sync/sync_touch.c
 *
 * @brief Touch entries, causing them to be re-processed by the proto_ldap_sync module.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/server/rad_assert.h>

typedef struct {
	uint64_t	id;		//!< Bitfield ID.
	bool		master;		//!< Server is a master.
	char const	*uri;
	bool		start_tls;	//!< Whether we should use the StartTLS extension.
} sync_host_t;


typedef struct {
	char const	*bind_dn;
	char const	*bind_pw;
} sync_touch_conf_t;

int main(int argc, char **argv)
{
	int			c;
	sync_touch_conf_t	*conf;
	int			ret;
	int			sockfd;

	conf = talloc_zero(NULL, sync_touch_conf_t);
	conf->proto = IPPROTO_UDP;
	conf->dict_dir = DICTDIR;
	conf->raddb_dir = RADDBDIR;
	conf->secret = talloc_strdup(conf, "testing123");
	conf->timeout = fr_time_delta_from_sec(3);
	conf->retries = 5;

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("sync_touch");
		exit(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	while ((c = getopt(argc, argv, "46c:d:D:f:Fhi:l:n:p:qr:sS:t:vx")) != -1) switch (c) {
		case 'S':
		{
			char *p;
			fp = fopen(optarg, "r");
			if (!fp) {
			       ERROR("Error opening %s: %s", optarg, fr_syserror(errno));
			       exit(EXIT_FAILURE);
			}
			if (fgets(filesecret, sizeof(filesecret), fp) == NULL) {
			       ERROR("Error reading %s: %s", optarg, fr_syserror(errno));
			       exit(EXIT_FAILURE);
			}
			fclose(fp);

			/* truncate newline */
			p = filesecret + strlen(filesecret) - 1;
			while ((p >= filesecret) &&
			      (*p < ' ')) {
			       *p = '\0';
			       --p;
			}

			if (strlen(filesecret) < 2) {
			       ERROR("Secret in %s is too short", optarg);
			       exit(EXIT_FAILURE);
			}
			talloc_free(conf->secret);
			conf->secret = talloc_strdup(conf, filesecret);
		}
		       break;

		case 't':
			if (fr_time_delta_from_str(&conf->timeout, optarg, FR_TIME_RES_SEC) < 0) {
				PERROR("Failed parsing timeout value");
				exit(EXIT_FAILURE);
			}
			break;

		case 'v':
			DEBUG("%s", sync_touch_version);
			exit(0);

		case 'x':
			fr_debug_lvl++;
			break;

		case 'h':
		default:
			usage();
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if ((argc < 2)  || ((conf->secret == NULL) && (argc < 3))) {
		ERROR("Insufficient arguments");
		usage();
	}
	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("sync_touch");
		exit(EXIT_FAILURE);
	}

	if (!fr_dict_global_ctx_init(autofree, dict_dir)) {
		fr_perror("sync_touch");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_internal_afrom_file(&conf->dict, FR_DICTIONARY_FILE) < 0) {
		fr_perror("sync_touch");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_read(dict_freeradius, conf->raddb_dir, FR_DICTIONARY_FILE) == -1) {
		fr_perror("sync_touch");
		exit(EXIT_FAILURE);
	}
	fr_strerror();	/* Clear the error buffer */

	fr_set_signal(SIGPIPE, rs_signal_stop);
	fr_set_signal(SIGINT, rs_signal_stop);
	fr_set_signal(SIGTERM, rs_signal_stop);
#ifdef SIGQUIT
	fr_set_signal(SIGQUIT, rs_signal_stop);
#endif

	DEBUG("%s - Starting pass_persist read loop", sync_touch_version);
	ret = sync_touch_send_recv(conf, sockfd);
	DEBUG("Read loop done");

finish:
	/*
	 *	Everything should be parented from conf
	 */
	talloc_free(conf);

	return ret;
}
