/*
 * (C) 2012 by Holger Hans Peter Freyther
 * (C) 2012 by On-Waves
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

#include <isup_filter.h>
#include <isup_types.h>
#include <mgcp_callagent.h>
#include <ss7_application.h>
#include <bsc_data.h>
#include <cellmgr_debug.h>


#include <osmocom/core/msgb.h>

#include <stdio.h>
#include <string.h>

static void send_reset(struct ss7_application *app, int endp, int range)
{
	char buf[1024];

	snprintf(buf, sizeof(buf) - 1,
			"RSIP 2 %s/%d@127.0.0.1 MGCP 1.0\r\n"
			"R: %d\n", app->trunk_name, endp, range);
	buf[sizeof(buf) - 1] = '\0';
	abort();
/*
	mgcp_forward(&app->bsc->mgcp_agent,
			(const uint8_t *) buf, strlen(buf));
*/
}


static void reset_cic(struct ss7_application *app, int cic)
{
	return send_reset(app, cic, 1);
}

static void reset_cics(struct ss7_application *app, int cic, int range)
{
	return send_reset(app, cic, range);
}

/**
 * Discover resets and forward them to the local MGCP gateway
 */
int isup_scan_for_reset(struct ss7_application *app, struct msgb *msg)
{
	struct isup_msg_hdr *hdr;
	int range;
	uint16_t cic;

	/* too small for an isup message? */
	if (msgb_l3len(msg) < sizeof(*hdr)) {
		LOGP(DISUP, LOGL_ERROR, "Message too small for the header\n");
		return -1;
	}

	/* no trunk name, don't bother forwarding */
	if (!app->trunk_name) {
		LOGP(DISUP, LOGL_DEBUG,
			"No trunk name defined for: %s\n", app->name);
		return 0;
	}

	hdr = (struct isup_msg_hdr *) msg->l3h;
	cic = isup_cic_to_local(hdr);

	switch (hdr->msg_type) {
	case ISUP_MSG_GRS:
		range = isup_parse_status(&hdr->data[0],
				msgb_l3len(msg) - sizeof(*hdr));
		if (range <= 0) {
			LOGP(DISUP, LOGL_ERROR,
				"Failed to parse range on app %s\n", app->name);
			return -1;
		}

		LOGP(DISUP, LOGL_DEBUG,
			"Going to reset ISUP for app %s, cic %d range %d\n",
			app->name, cic, range);
		reset_cics(app, cic, range);
		break;
	case ISUP_MSG_RSC:
		LOGP(DISUP, LOGL_DEBUG,
			"Going to reset single CIC %d on app %s\n",
			cic, app->name);
		reset_cic(app, cic);
		break;
	}

	return 0;
}
