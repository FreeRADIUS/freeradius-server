/* Relay UDT/all SCCP messages */
/*
 * (C) 2010-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2011 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <mtp_data.h>
#include <osmocom/mtp/mtp_level3.h>
#include <mtp_pcap.h>
#include <thread.h>
#include <bsc_data.h>
#include <snmp_mtp.h>
#include <cellmgr_debug.h>
#include <sctp_m2ua.h>
#include <ss7_application.h>

#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/sigtran/m2ua_types.h>

#include <osmocom/core/application.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/talloc.h>

#include <osmocom/sccp/sccp.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>

#undef PACKAGE_NAME
#undef PACKAGE_VERSION
#undef PACKAGE_BUGREPORT
#undef PACKAGE_TARNAME
#undef PACKAGE_STRING
#include <cellmgr_config.h>

char *config = "osmo_stp.cfg";

struct bsc_data *bsc;
extern void cell_vty_init(void);
extern void handle_options(int argc, char **argv);

static void mgcp_destroy_cb(struct mgcp_callagent *agent, struct msgb *msg)
{
	/* we do not care about potential responses here */
	msgb_free(msg);
}

static struct mtp_link_set *find_link_set(struct bsc_data *bsc,
					  int len, const char *buf)
{
	struct mtp_link_set *set;

	llist_for_each_entry(set, &bsc->linksets, entry)
		if (strncmp(buf, set->name, len) == 0)
			return set;

	return NULL;
}

static int inject_read_cb(struct osmo_fd *fd, unsigned int what)
{
	struct msgb *msg;
	struct xua_msg_part *data, *link;
	struct bsc_data *bsc;
	struct xua_msg *m2ua;
	struct mtp_link_set *out_set;
	uint8_t buf[4096];

	bsc = fd->data;

	int rc = read(fd->fd, buf, sizeof(buf));
	if (rc <= 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to read from the console.\n");
		return -1;
	}

	if (!bsc->allow_inject) {
		LOGP(DINP, LOGL_ERROR, "Injecting messages is not allowed.\n");
		return -1;
	}

	m2ua = xua_from_msg(M2UA_VERSION, rc, buf);
	if (!m2ua) {
		LOGP(DINP, LOGL_ERROR, "Failed to parse M2UA.\n");
		return -1;
	}

	if (m2ua->hdr.msg_class == M2UA_CLS_MAUP && m2ua->hdr.msg_type == M2UA_MAUP_DATA) {
		data = xua_msg_find_tag(m2ua, M2UA_TAG_DATA);
		if (!data) {
			LOGP(DINP, LOGL_ERROR, "MAUP Data without data.\n");
			goto exit;
		}

		if (data->len > 2048) {
			LOGP(DINP, LOGL_ERROR, "Data is too big for this configuration.\n");
			goto exit;
		}

		link = xua_msg_find_tag(m2ua, MUA_TAG_IDENT_TEXT);
		if (!link) {
			LOGP(DINP, LOGL_ERROR, "Interface Identifier Text is mandantory.\n");
			goto exit;
		}

		if (link->len > 255) {
			LOGP(DINP, LOGL_ERROR, "Spec violation. Ident text should be shorter than 255.\n");
			goto exit;
		}

		out_set = find_link_set(bsc, link->len, (const char *) link->dat);
		if (!out_set) {
			LOGP(DINP, LOGL_ERROR, "Identified linkset does not exist.\n");
			goto exit;
		}

		msg = msgb_alloc(2048, "inject-data");
		if (!msg) {
			LOGP(DINP, LOGL_ERROR, "Failed to allocate storage.\n");
			goto exit;
		}

		msg->l2h = msgb_put(msg, data->len);
		memcpy(msg->l2h, data->dat, data->len);

		/* we are diretcly going to the output. no checking of anything  */
		if (mtp_link_set_send(out_set, msg) != 0) {
			LOGP(DINP, LOGL_ERROR, "Failed to send message.\n");
			msgb_free(msg);
		}
	}

exit:
	xua_msg_free(m2ua);
	return 0;
}

static int inject_init(struct bsc_data *bsc)
{
	int fd;
	struct sockaddr_in addr;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(5001);

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to bind to port 5001.\n");
		close(fd);
		return -1;
	}

	bsc->inject_fd.fd = fd;
	bsc->inject_fd.when = BSC_FD_READ;
	bsc->inject_fd.cb = inject_read_cb;
	bsc->inject_fd.data = bsc;

	if (osmo_fd_register(&bsc->inject_fd) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register.\n");
		close(fd);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int rc;
	struct ss7_application *app;

	rate_ctr_init(NULL);

	thread_init();

	osmo_init_logging(&log_info);

	/* enable filters */
	log_set_category_filter(osmo_stderr_target, DINP, 1, LOGL_INFO);
	log_set_category_filter(osmo_stderr_target, DSCCP, 1, LOGL_INFO);
	log_set_category_filter(osmo_stderr_target, DMSC, 1, LOGL_INFO);
	log_set_category_filter(osmo_stderr_target, DMGCP, 1, LOGL_INFO);
	log_set_print_timestamp(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	sccp_set_log_area(DSCCP);
	xua_set_log_area(DM2UA);

	bsc = bsc_data_create();
	if (!bsc)
		return -1;

	handle_options(argc, argv);

	srand(time(NULL));

	cell_vty_init();
	rc = telnet_init(NULL, NULL, 4242);
	if (rc < 0)
		return rc;

	if (inject_init(bsc) != 0) {
		LOGP(DINP, LOGL_NOTICE, "Failed to initialize inject interface.\n");
		return -1;
	}

	/* now bind the the UDP and SCTP port */
	if (link_global_init(&bsc->udp_data) != 0) {
		LOGP(DINP, LOGL_ERROR, "Global UDP input init failed.\n");
		return -1;
	}

	bsc->m2ua_trans = sctp_m2ua_transp_create(bsc);
	if (!bsc->m2ua_trans) {
		LOGP(DINP, LOGL_ERROR, "Failed to create SCTP transport.\n");
		return -1;
	}

	if (vty_read_config_file(config, NULL) < 0) {
		fprintf(stderr, "Failed to read the VTY config.\n");
		return -1;
	}

	if (link_global_bind(&bsc->udp_data, bsc->udp_src_port) != 0) {
		LOGP(DINP, LOGL_ERROR, "Global UDP bind failed.\n");
		return -1;
	}

	if (sctp_m2ua_transport_bind(bsc->m2ua_trans, "0.0.0.0", bsc->m2ua_src_port) != 0) {
		LOGP(DINP, LOGL_ERROR,
		     "Failed to bind on port %d\n", bsc->m2ua_src_port);
		return -1;
	}

	if (mgcp_create_port(&bsc->mgcp_agent) != 0) {
		LOGP(DINP, LOGL_ERROR,
			"Failed to create the MGCP call agent.\n");
		return -1;
	}
	bsc->mgcp_agent.read_cb = mgcp_destroy_cb;

	/* start all apps */
	llist_for_each_entry(app, &bsc->apps, entry) {
		LOGP(DINP, LOGL_NOTICE,
		     "Going to start app %d/%s.\n", app->nr, app->name);
		ss7_application_start(app);
	}

        while (1) {
		osmo_select_main(0);
        }

	return 0;
}

