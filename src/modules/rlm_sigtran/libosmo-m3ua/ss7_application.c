/*
 * The SS7 Application part for forwarding or nat...
 *
 * (C) 2010-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2012 by On-Waves
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

#include <ss7_application.h>
#include <bsc_data.h>
#include <bsc_sccp.h>
#include <cellmgr_debug.h>
#include <msc_connection.h>
#include <sctp_m2ua.h>
#include <counter.h>
#include <isup_filter.h>

#include <osmocom/core/talloc.h>


/* the SS7 dispatch... maybe as function pointers in the future */
static void forward_sccp_stp(struct mtp_link_set *set, struct msgb *_msg, int sls)
{
	struct mtp_link_set *other;
	other = set->app->route_src.set == set ?
			set->app->route_dst.set : set->app->route_src.set;
	mtp_link_set_submit_sccp_data(other, sls, _msg->l2h, msgb_l2len(_msg));
}

static void forward_isup_stp(struct mtp_link_set *set, struct msgb *msg, int sls)
{
	struct mtp_link_set *other;
	other = set->app->route_src.set == set ?
			set->app->route_dst.set : set->app->route_src.set;
	isup_scan_for_reset(set->app, msg);
	mtp_link_set_submit_isup_data(other, sls, msg->l3h, msgb_l3len(msg));
}

void mtp_link_set_forward_sccp(struct mtp_link_set *set, struct msgb *_msg, int sls)
{
	if (!set->app) {
		LOGP(DINP, LOGL_ERROR, "Linkset %d/%s has no application.\n",
		     set->nr, set->name);
		return;
	}

	switch (set->app->type) {
	case APP_STP:
		forward_sccp_stp(set, _msg, sls);
		break;
	case APP_CELLMGR:
	case APP_RELAY:
		app_forward_sccp(set->app, _msg, sls);
		break;
	}
}

void mtp_link_set_forward_isup(struct mtp_link_set *set, struct msgb *msg, int sls)
{
	if (!set->app) {
		LOGP(DINP, LOGL_ERROR, "Linkset %d/%s has no application.\n",
		     set->nr, set->name);
		return;
	}


	switch (set->app->type) {
	case APP_STP:
		forward_isup_stp(set, msg, sls);
		break;
	case APP_CELLMGR:
	case APP_RELAY:
		LOGP(DINP, LOGL_ERROR, "ISUP is not handled.\n");
		break;
	}
}

void mtp_linkset_down(struct mtp_link_set *set)
{
	set->available = 0;
	mtp_link_set_stop(set);

	if (!set->app)
		return;

	if (set->app->type == APP_STP) {
		if (set->app->route_src.set == set)
			set->app->route_src.up = 0;
		else
			set->app->route_dst.up = 0;
	} else {
		app_clear_connections(set->app);

		/* If we have an A link send a reset to the MSC */
		msc_mgcp_reset(set->app->route_dst.msc);
		msc_send_reset(set->app->route_dst.msc);
	}
}

void mtp_linkset_up(struct mtp_link_set *set)
{
	set->available = 1;

	/* we have not gone through link down */
	if (set->app) {
		if (set->app->type == APP_STP) {
			if (set->app->route_src.set == set)
				set->app->route_src.up = 1;
			else
				set->app->route_dst.up = 1;
		} else if (set->app->type != APP_STP &&
			   set->app->route_dst.msc->msc_link_down) {
			app_clear_connections(set->app);
			app_resources_released(set->app);
		}
	}

	mtp_link_set_reset(set);
}


struct ss7_application *ss7_application_alloc(struct bsc_data *bsc)
{
	struct ss7_application *app;

	app = talloc_zero(bsc, struct ss7_application);
	if (!app) {
		LOGP(DINP, LOGL_ERROR, "Failed to create SS7 Application.\n");
		return NULL;
	}

	INIT_LLIST_HEAD(&app->sccp_connections);
	llist_add_tail(&app->entry, &bsc->apps);
	app->nr = bsc->num_apps++;
	app->bsc = bsc;

	return app;
}

struct ss7_application *ss7_application_num(struct bsc_data *bsc, int num)
{
	struct ss7_application *ss7;

	llist_for_each_entry(ss7, &bsc->apps, entry)
		if (ss7->nr == num)
			return ss7;

	return NULL;
}

static int ss7_app_setup_stp(struct ss7_application *app,
			     int src_type, int src_num,
			     int dst_type, int dst_num)
{
	struct mtp_link_set *src, *dst;

	if (src_type != SS7_SET_LINKSET) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s source needs to be a linkset.\n",
		     app->nr, app->name);
		return -1;
	}

	if (dst_type != SS7_SET_LINKSET) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s destination needs to be a linkset.\n",
		     app->nr, app->name);
		return -1;
	}

	/* veryify the MTP Linkset */
	src = mtp_link_set_num(app->bsc, src_num);
	if (!src) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s source linkset not found with nr: %d.\n",
		     app->nr, app->name, src_num);
		return -2;
	}

	if (src->app) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s is using linkset %d/%s\n",
		      src->app->nr, src->app->name,
		      src->nr, src->name);
		return -3;
	}

	/* veryify the MTP Linkset */
	dst = mtp_link_set_num(app->bsc, dst_num);
	if (!dst) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s destionation linkset not found with nr: %d.\n",
		     app->nr, app->name, dst_num);
		return -2;
	}

	if (dst->app) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s is using linkset %d/%s\n",
		      dst->app->nr, dst->app->name,
		      dst->nr, dst->name);
		return -3;
	}

	/* now connect it */
	src->app = app;
	app->route_src.type = src_type;
	app->route_src.nr = src_num;
	app->route_src.set = src;
	app->route_src.msc = NULL;

	dst->app = app;
	app->route_dst.type = dst_type;
	app->route_dst.nr = dst_num;
	app->route_dst.set = dst;
	app->route_dst.msc = NULL;

	app->type = APP_STP;
	app->bsc->m2ua_trans->started = 1;
	app->route_is_set = 1;

	return 0;
}

static int ss7_app_setup_relay(struct ss7_application *app, int type,
			       int src_type, int src_num, int dst_type, int dst_num)
{
	struct mtp_link_set *mtp;
	struct msc_connection *msc;

	/* verify the types */
	if (src_type != SS7_SET_LINKSET) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s source needs to be a linkset.\n",
		     app->nr, app->name);
		return -1;
	}

	if (dst_type != SS7_SET_MSC) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s dest needs to be a MSC.\n",
		     app->nr, app->name);
		return -1;
	}

	/* veryify the MTP Linkset */
	mtp = mtp_link_set_num(app->bsc, src_num);
	if (!mtp) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s source linkset not found with nr: %d.\n",
		     app->nr, app->name, src_num);
		return -2;
	}

	if (mtp->app) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s is using linkset %d/%s\n",
		      mtp->app->nr, mtp->app->name,
		      mtp->nr, mtp->name);
		return -3;
	}

	/* verify the MSC connection */
	msc = msc_connection_num(app->bsc, dst_num);
	if (!msc) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s dest MSC not found with nr: %d.\n",
		     app->nr, app->name, dst_num);
		return -4;
	}

	if (msc->app) {
		LOGP(DINP, LOGL_ERROR,
		     "SS7 %d/%s is using MSC connection %d/%s\n",
		      msc->app->nr, msc->app->name,
		      msc->nr, msc->name);
		return -5;
	}


	/* now connect it and run the app */
	mtp->app = app;
	app->route_src.type = src_type;
	app->route_src.nr = src_num;
	app->route_src.set = mtp;
	app->route_src.msc = NULL;

	msc->app = app;
	app->route_dst.type = dst_type;
	app->route_dst.nr = dst_num;
	app->route_dst.set = NULL;
	app->route_dst.msc = msc;

	app->type = type;
	app->bsc->m2ua_trans->started = 1;
	app->route_is_set = 1;

	return 0;
}

int ss7_application_setup(struct ss7_application *ss7, int type,
			  int src_type, int src_num,
			  int dst_type, int dst_num)
{
	switch (type) {
	case APP_CELLMGR:
	case APP_RELAY:
		return ss7_app_setup_relay(ss7, type, src_type, src_num,
					   dst_type, dst_num);
		break;
	case APP_STP:
		return ss7_app_setup_stp(ss7, src_type, src_num,
					 dst_type, dst_num);
	default:
		LOGP(DINP, LOGL_ERROR,
		     "SS7 Application %d is not supported.\n", type);
		return -1;
	}
}

static void start_mtp(struct mtp_link_set *set)
{
	struct mtp_link *link;

	llist_for_each_entry(link, &set->links, entry)
		link->reset(link);
}

static void start_msc(struct msc_connection *msc)
{
	msc_connection_start(msc);
}

static void start_set(struct mtp_link_set *set)
{
	if (!set)
		return;
	start_mtp(set);
}

static void prepare_set(struct ss7_application *app, struct mtp_link_set *set)
{
	if (!set)
		return;

	set->isup_opc = set->isup_opc >= 0 ? set->isup_opc : set->opc;
	set->sccp_opc = set->sccp_opc >= 0 ? set->sccp_opc : set->opc;
	set->pass_all_isup = app->isup_pass;
}

static void shutdown_set(struct mtp_link_set *set)
{
	struct mtp_link *link;

	if (!set)
		return;

	llist_for_each_entry(link, &set->links, entry) {
		link->shutdown(link);
		mtp_link_down(link);
	}
}

int ss7_application_start(struct ss7_application *app)
{
	if (!app->route_is_set) {
		LOGP(DINP, LOGL_ERROR,
		     "The routes are not configured on app %d.\n", app->nr);
		return -1;
	}

	prepare_set(app, app->route_src.set);
	prepare_set(app, app->route_dst.set);
	if (!app->force_down) {
		start_set(app->route_src.set);
		start_set(app->route_dst.set);
	}

	if (app->route_src.msc)
		start_msc(app->route_src.msc);
	if (app->route_dst.msc)
		start_msc(app->route_dst.msc);

	LOGP(DINP, LOGL_NOTICE, "SS7 Application %d/%s is now running.\n",
	     app->nr, app->name);
	return 0;
}

void ss7_application_pass_isup(struct ss7_application *app, int pass)
{
	app->isup_pass = pass;

	if (app->route_src.set)
		app->route_src.set->pass_all_isup = pass;
	if (app->route_dst.set)
		app->route_dst.set->pass_all_isup = pass;
}

void mtp_link_submit(struct mtp_link *link, struct msgb *msg)
{
	if (link->set->app && link->set->app->type == APP_STP) {
		if (!link->set->app->route_src.up || !link->set->app->route_dst.up) {
			LOGP(DINP, LOGL_NOTICE, "Not sending data as application is down %d/%s.\n",
			     link->set->app->nr, link->set->app->name);
			msgb_free(msg);
			return;
		}
	}

	rate_ctr_inc(&link->ctrg->ctr[MTP_LNK_OUT]);
	rate_ctr_inc(&link->set->ctrg->ctr[MTP_LSET_TOTA_OUT_MSG]);
	link->write(link, msg);
}

int mtp_link_set_data(struct mtp_link *link, struct msgb *msg)
{
	if (link->set->app && link->set->app->type == APP_STP) {
		if (!link->set->app->route_src.up || !link->set->app->route_dst.up) {
			LOGP(DINP, LOGL_NOTICE, "Not handling data as application is down %d/%s.\n",
			     link->set->app->nr, link->set->app->name);
			return -1;
		}
	}

	return mtp_link_handle_data(link, msg);
}

int ss7_application_mgcp_domain_name(struct ss7_application *app,
				     const char *name)
{
	talloc_free(app->mgcp_domain_name);
	app->mgcp_domain_name = talloc_strdup(app, name);

	return app->mgcp_domain_name == NULL;
}

int ss7_application_trunk_name(struct ss7_application *app, const char *name)
{
	talloc_free(app->trunk_name);
	app->trunk_name = talloc_strdup(app, name);

	return app->trunk_name == NULL;
}

int ss7_application_msc_up(struct ss7_application *app)
{
	if (!app->force_down)
		return 0;
	start_set(app->route_src.set);
	start_set(app->route_dst.set);
	return 0;
}

int ss7_application_msc_down(struct ss7_application *app)
{
	if (!app->force_down)
		return 0;
	shutdown_set(app->route_src.set);
	shutdown_set(app->route_dst.set);
	return 0;
}
