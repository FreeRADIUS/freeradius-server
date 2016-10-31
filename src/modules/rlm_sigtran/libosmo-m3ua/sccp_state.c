/* The routines to handle the state */
/*
 * (C) 2010-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2011 by On-Waves
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <mtp_data.h>
#include <msc_connection.h>
#include <osmocom/mtp/mtp_level3.h>
#include <bss_patch.h>
#include <bssap_sccp.h>
#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <bsc_sccp.h>
#include <bsc_ussd.h>
#include <ss7_application.h>

#include <osmocom/core/talloc.h>

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

static void send_reset_ack(struct mtp_link_set *set, int sls);
static void handle_local_sccp(struct mtp_link_set *set, struct msgb *inp, struct sccp_parse_result *res, int sls);
static void send_local_rlsd(struct mtp_link_set *set, struct sccp_parse_result *res);
static void update_con_state(struct ss7_application *ss7, int rc, struct sccp_parse_result *result, struct msgb *msg, int from_msc, int sls);

static void send_direct(struct msc_connection *msc, struct msgb *_msg)
{
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "SCCP to MSC");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to alloc MSC msg.\n");
		return;
	}

	msg->l2h = msgb_put(msg, msgb_l2len(_msg));
	memcpy(msg->l2h, _msg->l2h, msgb_l2len(_msg));
	msc_send_direct(msc, msg);
}

/*
 * methods called from the MTP Level3 part
 */
void app_forward_sccp(struct ss7_application *app, struct msgb *_msg, int sls)
{
	int rc;
	struct sccp_parse_result result;
	struct msc_connection *msc;
	struct mtp_link_set *set;

	struct msgb *msg;

	set = app->route_src.set;
	msc = app->route_dst.msc;

	if (app->forward_only) {
		send_direct(msc, _msg);
		return;
	}

	rc = bss_patch_filter_msg(app, _msg, &result, BSS_DIR_MSC);
	if (rc == BSS_FILTER_RESET) {
		LOGP(DMSC, LOGL_NOTICE, "Filtering BSS Reset from the BSC\n");
		msc_mgcp_reset(msc);
		send_reset_ack(set, sls);
		return;
	}

	/* special responder */
	if (msc->msc_link_down) {
		if (rc == BSS_FILTER_RESET_ACK && app->reset_count > 0) {
			LOGP(DMSC, LOGL_ERROR, "Received reset ack for closing.\n");
			app_clear_connections(app);
			app_resources_released(app);
			return;
		}

		if (rc != 0 && rc != BSS_FILTER_RLSD && rc != BSS_FILTER_RLC) {
			LOGP(DMSC, LOGL_ERROR, "Ignoring unparsable msg during closedown.\n");
			return;
		}

		return handle_local_sccp(set, _msg, &result, sls);
	}

	/* update the connection state */
	update_con_state(app, rc, &result, _msg, 0, sls);

	if (rc == BSS_FILTER_CLEAR_COMPL) {
		send_local_rlsd(set, &result);
	} else if (rc == BSS_FILTER_RLC || rc == BSS_FILTER_RLSD) {
		LOGP(DMSC, LOGL_DEBUG, "Not forwarding RLC/RLSD to the MSC.\n");
		return;
	}

	/* now send it out */
	bsc_ussd_handle_out_msg(msc, &result, _msg);

	msg = msgb_alloc_headroom(4096, 128, "SCCP to MSC");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to alloc MSC msg.\n");
		return;
	}

	bss_rewrite_header_for_msc(rc, msg, _msg, &result);
	msc_send_direct(msc, msg);
}

/*
 * handle local message in close down mode
 */
static void handle_local_sccp(struct mtp_link_set *set, struct msgb *inpt, struct sccp_parse_result *result, int sls)
{
	/* Handle msg with a reject */
	if (inpt->l2h[0] == SCCP_MSG_TYPE_CR) {
		struct sccp_connection_request *cr;
		struct msgb *msg;

		LOGP(DINP, LOGL_NOTICE, "Handling CR localy.\n");
		cr = (struct sccp_connection_request *) inpt->l2h;
		msg = create_sccp_refuse(&cr->source_local_reference);
		if (msg) {
			mtp_link_set_submit_sccp_data(set, sls, msg->l2h, msgb_l2len(msg));
			msgb_free(msg);
		}
		return;
	} else if (inpt->l2h[0] == SCCP_MSG_TYPE_DT1 && result->data_len >= 3) {
		struct active_sccp_con *con;
		struct sccp_data_form1 *form1;
		struct msgb *msg;

		if (inpt->l3h[0] == 0 && inpt->l3h[2] == BSS_MAP_MSG_CLEAR_COMPLETE) {
			LOGP(DINP, LOGL_DEBUG, "Received Clear Complete. Sending Release.\n");

			form1 = (struct sccp_data_form1 *) inpt->l2h;

			llist_for_each_entry(con, &set->app->sccp_connections, entry) {
				if (memcmp(&form1->destination_local_reference,
					   &con->dst_ref, sizeof(con->dst_ref)) == 0) {
					LOGP(DINP, LOGL_DEBUG, "Sending a release request now.\n");
					msg = create_sccp_rlsd(&con->dst_ref, &con->src_ref);
					if (msg) {
						mtp_link_set_submit_sccp_data(set, con->sls, msg->l2h, msgb_l2len(msg));
						msgb_free(msg);
					}
					return;
				}
			}

			LOGP(DINP, LOGL_ERROR, "Could not find connection for the Clear Command.\n");
		}
	} else if (inpt->l2h[0] == SCCP_MSG_TYPE_UDT && result->data_len >= 3) {
		if (inpt->l3h[0] == 0 && inpt->l3h[2] == BSS_MAP_MSG_RESET_ACKNOWLEDGE) {
			LOGP(DINP, LOGL_NOTICE, "Reset ACK. Connecting to the MSC again.\n");
			app_resources_released(set->app);
			return;
		}
	}


	/* Update the state, maybe the connection was released? */
	update_con_state(set->app, 0, result, inpt, 0, sls);
	if (llist_empty(&set->app->sccp_connections))
		app_resources_released(set->app);
	return;
}

void app_clear_connections(struct ss7_application *app)
{
	struct active_sccp_con *tmp, *con;

	llist_for_each_entry_safe(con, tmp, &app->sccp_connections, entry) {
		free_con(con);
	}

	link_clear_all(app->route_src.set);
}

void app_resources_released(struct ss7_application *app)
{
	osmo_timer_del(&app->reset_timeout);
}

static void bsc_reset_timeout(void *_app)
{
	struct msgb *msg;
	struct ss7_application *app = _app;
	struct mtp_link_set *set = app->route_src.set;

	/* no reset */
	if (app->reset_count > 0) {
		LOGP(DINP, LOGL_ERROR, "The BSC did not answer the GSM08.08 reset. Restart MTP\n");
		mtp_link_set_stop(app->route_src.set);
		app_clear_connections(app);
		link_reset_all(app->route_src.set);
		app_resources_released(app);
		return;
	}

	msg = create_reset();
	if (!msg) {
		osmo_timer_schedule(&app->reset_timeout, 10, 0);
		return;
	}

	++app->reset_count;
	mtp_link_set_submit_sccp_data(set, -1, msg->l2h, msgb_l2len(msg));
	msgb_free(msg);
	osmo_timer_schedule(&app->reset_timeout, 20, 0);
}

/*
 * We have lost the connection to the MSC. This is tough. We
 * can not just bring down the MTP link as this will disable
 * the BTS radio. We will have to do the following:
 *
 *  1.) Bring down all open SCCP connections. As this will close
 *      all radio resources
 *  2.) Bring down all MGCP endpoints
 *  3.) Clear the connection data.
 *
 * To make things worse we need to buffer the BSC messages... atfer
 * everything has been sent we will try to connect to the MSC again.
 *
 * We will have to veriy that all connections are closed properly..
 * this means we need to parse response message. In the case the
 * MTP link is going down while we are sending. We will simply
 * reconnect to the MSC.
 *
 * This could be called for the relay type and the cellmgr type, in case
 * of the relay type the list of connections should be empty so we can
 * avoid branching out.
 */
void release_bsc_resources(struct msc_connection *fw)
{
	struct ss7_application *app;
	struct mtp_link_set *set;
	struct active_sccp_con *tmp;
	struct active_sccp_con *con;

	if (!fw->app) {
		LOGP(DINP, LOGL_ERROR, "No app assigned to the MSC connection %d/%s\n",
		     fw->nr, fw->name);
		return;
	}

	app = fw->app;
	set = app->route_src.set;
	osmo_timer_del(&app->reset_timeout);

	/* 2. clear the MGCP endpoints */
	msc_mgcp_reset(fw);

	/* 1. send BSSMAP Cleanup.. if we have any connection */
	llist_for_each_entry_safe(con, tmp, &app->sccp_connections, entry) {
		if (!con->has_dst_ref) {
			free_con(con);
			continue;
		}

		struct msgb *msg = create_clear_command(&con->src_ref);
		if (!msg)
			continue;

		/* wait for the clear commands */
		mtp_link_set_submit_sccp_data(set, con->sls, msg->l2h, msgb_l2len(msg));
		msgb_free(msg);
	}

	if (llist_empty(&app->sccp_connections)) {
		app_resources_released(app);
	} else {
		/* Send a reset in 20 seconds if we fail to bring everything down */
		app->reset_timeout.cb = bsc_reset_timeout;
		app->reset_timeout.data = app;
		app->reset_count = 0;
		osmo_timer_schedule(&app->reset_timeout, 10, 0);
	}
}

/**
 * update the connection state and helpers below
 */
static void send_rlc_to_bsc(struct mtp_link_set *set,
			    unsigned int sls, struct sccp_source_reference *src,
			    struct sccp_source_reference *dst)
{
	struct msgb *msg;

	msg = create_sccp_rlc(src, dst);
	if (!msg)
		return;

	mtp_link_set_submit_sccp_data(set, sls, msg->l2h, msgb_l2len(msg));
	msgb_free(msg);
}

static void handle_rlsd(struct ss7_application *app, struct sccp_connection_released *rlsd, int from_msc)
{
	struct active_sccp_con *con;
	struct msc_connection *msc = app->route_dst.msc;
	struct mtp_link_set *set = app->route_src.set;

	if (from_msc) {
		/* search for a connection, reverse src/dest for MSC */
		con = find_con_by_src_dest_ref(app, &rlsd->destination_local_reference,
					       &rlsd->source_local_reference);
		if (con) {
			LOGP(DINP, LOGL_DEBUG, "RLSD conn still alive: local: 0x%x remote: 0x%x\n",
			     sccp_src_ref_to_int(&con->src_ref),
			     sccp_src_ref_to_int(&con->dst_ref));
			con->released_from_msc = 1;
		} else {
			/* send RLC */
			LOGP(DINP, LOGL_DEBUG, "Sending RLC for MSC: src: 0x%x dst: 0x%x\n",
			     sccp_src_ref_to_int(&rlsd->destination_local_reference),
			     sccp_src_ref_to_int(&rlsd->source_local_reference));
			msc_send_rlc(msc, &rlsd->destination_local_reference,
				 &rlsd->source_local_reference);
		}
	} else {
		unsigned int sls = -1;
		con = find_con_by_src_dest_ref(app, &rlsd->source_local_reference,
					       &rlsd->destination_local_reference);
		if (con) {
			LOGP(DINP, LOGL_DEBUG, "Timeout on BSC. Sending RLC. src: 0x%x\n",
			     sccp_src_ref_to_int(&rlsd->source_local_reference));

			if (con->released_from_msc)
				msc_send_rlc(msc, &con->src_ref, &con->dst_ref);
			sls = con->sls;
			free_con(con);
		} else {
			LOGP(DINP, LOGL_ERROR, "Timeout on BSC for unknown connection. src: 0x%x\n",
			     sccp_src_ref_to_int(&rlsd->source_local_reference));
		}

		/* now send a rlc back to the BSC */
		send_rlc_to_bsc(set, sls, &rlsd->destination_local_reference, &rlsd->source_local_reference);
	}
}

/*
 * Update connection state and also send message.....
 *
 * RLSD from MSC:
 *      1.) We don't find the entry in this case we will send a
 *          forged RLC to the MSC and we are done.
 *      2.) We find an entry in this we will need to register that
 *          we need to send a RLC and we are done for now.
 * RLSD from BSC:
 *      1.) This is an error we are ignoring for now.
 * RLC from BSC:
 *      1.) We are destroying the connection, we might send a RLC to
 *          the MSC if we are waiting for one.
 */
void update_con_state(struct ss7_application *app, int rc, struct sccp_parse_result *res, struct msgb *msg, int from_msc, int sls)
{
	struct active_sccp_con *con;
	struct sccp_connection_request *cr;
	struct sccp_connection_confirm *cc;
	struct sccp_connection_release_complete *rlc;
	struct sccp_connection_refused *cref;
	struct msc_connection *msc;

	/* was the header okay? */
	if (rc < 0)
		return;

	msc = app->route_dst.msc;

	/* the header was size checked */
	switch (msg->l2h[0]) {
	case SCCP_MSG_TYPE_CR:
		if (from_msc) {
			LOGP(DMSC, LOGL_ERROR, "CR from MSC is not handled.\n");
			return;
		}

		cr = (struct sccp_connection_request *) msg->l2h;
		con = find_con_by_src_ref(app, &cr->source_local_reference);
		if (con) {
			LOGP(DINP, LOGL_ERROR, "Duplicate SRC reference for: 0x%x. Reusing\n",
				sccp_src_ref_to_int(&con->src_ref));
			free_con(con);
		}

		con = talloc_zero(NULL, struct active_sccp_con);
		if (!con) {
			LOGP(DINP, LOGL_ERROR, "Failed to allocate\n");
			return;
		}

		con->src_ref = cr->source_local_reference;
		con->sls = sls;
		con->app = app;
		llist_add_tail(&con->entry, &app->sccp_connections);
		LOGP(DINP, LOGL_DEBUG, "Adding CR: local ref: 0x%x\n", sccp_src_ref_to_int(&con->src_ref));
		break;
	case SCCP_MSG_TYPE_CC:
		if (!from_msc) {
			LOGP(DINP, LOGL_ERROR, "CC from BSC is not handled.\n");
			return;
		}

		cc = (struct sccp_connection_confirm *) msg->l2h;
		con = find_con_by_src_ref(app, &cc->destination_local_reference);
		if (con) {
			con->dst_ref = cc->source_local_reference;
			con->has_dst_ref = 1;
			LOGP(DINP, LOGL_DEBUG, "Updating CC: local: 0x%x remote: 0x%x\n",
				sccp_src_ref_to_int(&con->src_ref), sccp_src_ref_to_int(&con->dst_ref));
			return;
		}

		LOGP(DINP, LOGL_ERROR, "CCed connection can not be found: 0x%x\n",
		     sccp_src_ref_to_int(&cc->destination_local_reference));
		break;
	case SCCP_MSG_TYPE_CREF:
		if (!from_msc) {
			LOGP(DINP, LOGL_ERROR, "CREF from BSC is not handled.\n");
			return;
		}

		cref = (struct sccp_connection_refused *) msg->l2h;
		con = find_con_by_src_ref(app, &cref->destination_local_reference);
		if (con) {
			LOGP(DINP, LOGL_DEBUG, "Releasing local: 0x%x\n", sccp_src_ref_to_int(&con->src_ref));
			free_con(con);
			return;
		}

		LOGP(DINP, LOGL_ERROR, "CREF from BSC is not handled.\n");
		break;
	case SCCP_MSG_TYPE_RLSD:
		handle_rlsd(app, (struct sccp_connection_released *) msg->l2h, from_msc);
		break;
	case SCCP_MSG_TYPE_RLC:
		if (from_msc) {
			LOGP(DINP, LOGL_ERROR, "RLC from MSC is wrong.\n");
			return;
		}

		rlc = (struct sccp_connection_release_complete *) msg->l2h;
		con = find_con_by_src_dest_ref(app, &rlc->source_local_reference,
					       &rlc->destination_local_reference);
		if (con) {
			LOGP(DINP, LOGL_DEBUG, "Releasing local: 0x%x\n", sccp_src_ref_to_int(&con->src_ref));
			if (con->released_from_msc)
				msc_send_rlc(msc, &con->src_ref, &con->dst_ref);
			free_con(con);
			return;
		}

		LOGP(DINP, LOGL_ERROR, "RLC can not be found. 0x%x 0x%x\n",
		     sccp_src_ref_to_int(&rlc->source_local_reference),
		     sccp_src_ref_to_int(&rlc->destination_local_reference));
		break;
	}
}

static void send_local_rlsd_for_con(void *data)
{
	struct msgb *rlsd;
	struct active_sccp_con *con = (struct active_sccp_con *) data;
	struct mtp_link_set *set;

	/* try again in three seconds */
	con->rlc_timeout.data = con;
	con->rlc_timeout.cb = send_local_rlsd_for_con;
	osmo_timer_schedule(&con->rlc_timeout, 3, 0);

	/* we send this to the BSC so we need to switch src and dest */
	rlsd = create_sccp_rlsd(&con->dst_ref, &con->src_ref);
	if (!rlsd)
		return;

	++con->rls_tries;

	set = con->app->route_src.set;
	if (!set) {
		LOGP(DINP, LOGL_DEBUG, "Application %d has no linkset\n", con->app->nr);
		return;
	}

	LOGP(DINP, LOGL_DEBUG, "Sending RLSD for 0x%x the %d time.\n",
	     sccp_src_ref_to_int(&con->src_ref), con->rls_tries);
	mtp_link_set_submit_sccp_data(set, con->sls, rlsd->l2h, msgb_l2len(rlsd));
	msgb_free(rlsd);
}

static void send_local_rlsd(struct mtp_link_set *set, struct sccp_parse_result *res)
{
	struct active_sccp_con *con;

	LOGP(DINP, LOGL_DEBUG, "Received GSM Clear Complete. Sending RLSD locally.\n");

	con = find_con_by_dest_ref(set->app, res->destination_local_reference);
	if (!con)
		return;
	con->rls_tries = 0;
	send_local_rlsd_for_con(con);
}

static void send_reset_ack(struct mtp_link_set *set, int sls)
{
	static const uint8_t reset_ack[] = {
		0x09, 0x00, 0x03, 0x05, 0x7, 0x02, 0x42, 0xfe,
		0x02, 0x42, 0xfe, 0x03,
		0x00, 0x01, 0x31
	};

	mtp_link_set_submit_sccp_data(set, sls, reset_ack, sizeof(reset_ack));
}

void msc_dispatch_sccp(struct msc_connection *msc, struct msgb *msg)
{
	struct mtp_link_set *set;

	if (!msc->app) {
		LOGP(DINP, LOGL_ERROR, "The MSC Connection %d/%s has no app assigned.\n",
		     msc->nr, msc->name);
		return;
	}


	set = msc->app->route_src.set;

	/* we can not forward it right now */
	if (msc->app->forward_only) {
		if (!set->sccp_up)
			return;
		mtp_link_set_submit_sccp_data(set, -1,
					      msg->l2h, msgb_l2len(msg));
	} else {
		struct sccp_parse_result result;
		int rc;

		rc = bss_patch_filter_msg(msc->app, msg, &result, BSS_DIR_BSC);

		if (rc == BSS_FILTER_RESET_ACK) {
			LOGP(DMSC, LOGL_NOTICE, "Filtering reset ack from the MSC\n");
		} else if (rc == BSS_FILTER_RLSD) {
			LOGP(DMSC, LOGL_DEBUG, "Filtering RLSD from the MSC\n");
			update_con_state(msc->app, rc, &result, msg, 1, 0);
		} else if (rc == BSS_FILTER_RLC) {
			/* if we receive this we have forwarded a RLSD to the network */
			LOGP(DMSC, LOGL_ERROR, "RLC from the network. BAD!\n");
		} else if (rc == BSS_FILTER_CLEAR_COMPL) {
			LOGP(DMSC, LOGL_ERROR, "Clear Complete from the network.\n");
		} else if (set->sccp_up) {
			unsigned int sls;

			update_con_state(msc->app, rc, &result, msg, 1, 0);
			sls = sls_for_src_ref(msc->app, result.destination_local_reference);

			/* Check for Location Update Accept */
			bsc_ussd_handle_in_msg(msc, &result, msg);

			/* Remove PointCodes to avoid routing issues */
			bss_rewrite_header_to_bsc(msg, set->opc, set->dpc);

			/* we can not forward it right now */
			mtp_link_set_submit_sccp_data(set, sls,
						      msg->l2h, msgb_l2len(msg));
		}
	}
}
