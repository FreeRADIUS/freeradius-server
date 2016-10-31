/* link management code */
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

#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <msc_connection.h>
#include <mtp_data.h>
#include <osmocom/mtp/mtp_level3.h>
#include <mtp_pcap.h>
#include <snmp_mtp.h>

#include <osmocom/core/talloc.h>

extern struct bsc_data *bsc;

int is_one_up(struct mtp_link_set *set)
{
	struct mtp_link *entry;

	llist_for_each_entry(entry, &set->links, entry)
		if (entry->available)
			return 1;
	return 0;
}

void mtp_link_down(struct mtp_link *link)
{
	int one_up;
	int was_up;

	was_up = link->available;
	link->available = 0;
	link->was_up = 0;
	one_up = is_one_up(link->set);

	/* our linkset is now unsuable */
	if (was_up && !one_up)
		mtp_linkset_down(link->set);
	link->clear_queue(link);
	mtp_link_stop_link_test(link);
	mtp_link_set_init_slc(link->set);
}

void mtp_link_up(struct mtp_link *link)
{
	int one_up;

	if (link->blocked) {
		LOGP(DINP, LOGL_ERROR,
		     "Ignoring link up on blocked link %d/%s of linkset %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		return;
	}

	one_up = is_one_up(link->set);
	link->available = 1;
	link->was_up = 0;

	mtp_link_set_init_slc(link->set);
	if (!one_up)
		mtp_linkset_up(link->set);
	else
		mtp_link_start_link_test(link);
}

void mtp_link_restart(struct mtp_link *link)
{
	LOGP(DINP, LOGL_ERROR, "Need to restart the SS7 link.\n");
	link->reset(link);
}

struct mtp_link_set *link_set_create(struct bsc_data *bsc)
{
	struct mtp_link_set *set;

	set = mtp_link_set_alloc(bsc);
	set->name = talloc_strdup(set, "MTP");

	set->ni = MTP_NI_NATION_NET;
	set->spare = 0;

	set->supported_ssn[1] = 1;
	set->supported_ssn[7] = 1;
	set->supported_ssn[8] = 1;
	set->supported_ssn[146] = 1;
	set->supported_ssn[254] = 1;

	return set;
}

int link_init(struct bsc_data *bsc, struct mtp_link_set *set)
{
	int i;
	struct mtp_udp_link *lnk;
	struct mtp_link *blnk;


	if (!bsc->udp_src_port) {
		LOGP(DINP, LOGL_ERROR, "You need to set a UDP address.\n");
		return -1;
	}

	LOGP(DINP, LOGL_NOTICE, "Using UDP MTP mode.\n");

	if (link_global_init(&bsc->udp_data) != 0)
		return -1;

	if (link_global_bind(&bsc->udp_data, bsc->udp_src_port) != 0)
		return -1;

	for (i = 1; i <= bsc->udp_nr_links; ++i) {
		blnk = mtp_link_alloc(set);
		lnk = mtp_udp_link_init(blnk);

		lnk->link_index = i;

		/* now connect to the transport */
		if (snmp_mtp_peer_name(lnk->session, bsc->udp_ip) != 0)
			return -1;

		if (link_udp_init(lnk, bsc->udp_ip, bsc->udp_port) != 0)
			return -1;
	}

	return 0;
}

int link_shutdown_all(struct mtp_link_set *set)
{
	struct mtp_link *lnk;

	llist_for_each_entry(lnk, &set->links, entry)
		lnk->shutdown(lnk);
	return 0;
}

int link_reset_all(struct mtp_link_set *set)
{
	struct mtp_link *lnk;

	llist_for_each_entry(lnk, &set->links, entry)
		lnk->reset(lnk);
	return 0;
}

int link_clear_all(struct mtp_link_set *set)
{
	struct mtp_link *lnk;

	llist_for_each_entry(lnk, &set->links, entry)
		lnk->clear_queue(lnk);
	return 0;
}

int mtp_handle_pcap(struct mtp_link *link, int dir, const uint8_t *data, int len)
{
	if (link->pcap_fd >= 0)
		mtp_pcap_write_msu(link->pcap_fd, data, len);
	if (link->set->pcap_fd >= 0)
		mtp_pcap_write_msu(link->set->pcap_fd, data, len);

	/* This might be too expensive? */
	LOGP(DPCAP, LOGL_DEBUG, "Packet: %s\n", osmo_hexdump(data, len));
	return 0;
}
