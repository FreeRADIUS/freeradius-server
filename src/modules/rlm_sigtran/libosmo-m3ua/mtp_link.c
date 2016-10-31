/* MTP level3 link */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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
#include <osmocom/mtp/mtp_level3.h>
#include <cellmgr_debug.h>
#include <counter.h>

#include <osmocom/core/talloc.h>

#include <string.h>

static struct msgb *mtp_create_sltm(struct mtp_link *link)
{
	const uint8_t test_ptrn[14] = { 'G', 'S', 'M', 'M', 'M', 'S', };
	struct mtp_level_3_hdr *hdr;
	struct mtp_level_3_mng *mng;
	struct msgb *msg = mtp_msg_alloc(link->set);
	uint8_t *data;
	if (!msg)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) msg->l2h;
	hdr->ser_ind = MTP_SI_MNT_REG_MSG;
	hdr->addr = MTP_ADDR(link->nr % 16, link->set->dpc, link->set->opc);

	mng = (struct mtp_level_3_mng *) msgb_put(msg, sizeof(*mng));
	mng->cmn.h0 = MTP_TST_MSG_GRP;
	mng->cmn.h1 = MTP_TST_MSG_SLTM;
	mng->length = ARRAY_SIZE(test_ptrn);

	data = msgb_put(msg, ARRAY_SIZE(test_ptrn));
	memcpy(data, test_ptrn, ARRAY_SIZE(test_ptrn));

	/* remember the last tst ptrn... once we have some */
	memcpy(link->test_ptrn, test_ptrn, ARRAY_SIZE(test_ptrn));

	return msg;
}

static void mtp_send_sltm(struct mtp_link *link)
{
	struct msgb *msg;

	link->sltm_pending = 1;
	msg = mtp_create_sltm(link);
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate SLTM on link %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		return;
	}

	mtp_link_submit(link, msg);
}

static void mtp_sltm_t1_timeout(void *_link)
{
	struct mtp_link *link = (struct mtp_link *) _link;

	rate_ctr_inc(&link->ctrg->ctr[MTP_LNK_SLTM_TOUT]);

	if (link->slta_misses == 0) {
		LOGP(DINP, LOGL_ERROR,
		     "No SLTM response on link %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		++link->slta_misses;
		mtp_send_sltm(link);
		osmo_timer_schedule(&link->t1_timer, MTP_T1);
	} else {
		LOGP(DINP, LOGL_ERROR,
		     "Two missing SLTAs on link %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		osmo_timer_del(&link->t2_timer);
		mtp_link_failure(link);
	}
}

static void mtp_sltm_t2_timeout(void *_link)
{
	struct mtp_link *link = (struct mtp_link *) _link;

	if (!link->set->running) {
		LOGP(DINP, LOGL_INFO,
		     "The linkset is not active. Stopping link test on %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		return;
	}

	link->slta_misses = 0;
	mtp_send_sltm(link);

	osmo_timer_schedule(&link->t1_timer, MTP_T1);

	if (link->set->sltm_once && link->was_up)
		LOGP(DINP, LOGL_INFO, "Not sending SLTM again on link %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
	else
		osmo_timer_schedule(&link->t2_timer, MTP_T2);
}

void mtp_link_stop_link_test(struct mtp_link *link)
{
	osmo_timer_del(&link->t1_timer);
	osmo_timer_del(&link->t2_timer);

	link->sltm_pending = 0;
}

void mtp_link_start_link_test(struct mtp_link *link)
{
	if (link->blocked) {
		LOGP(DINP, LOGL_ERROR, "Not starting linktest on %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		return;
	}

	if (link->skip_link_test) {
		LOGP(DINP, LOGL_ERROR, "Skipping starting linktest on %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		link->sltm_pending = 0;
		link->was_up = 1;
		mtp_link_verified(link);
		return;
	}

	mtp_sltm_t2_timeout(link);
}

int mtp_link_slta(struct mtp_link *link, uint16_t l3_len,
		  struct mtp_level_3_mng *mng)
{
	if (mng->length != 14) {
		LOGP(DINP, LOGL_ERROR, "Wrongly sized SLTA: %u\n", mng->length);
		return -1;
	}

	if (l3_len != 16) {
		LOGP(DINP, LOGL_ERROR, "Wrongly sized SLTA: %u\n", mng->length);
		return -1;
	}

	if (memcmp(mng->data, link->test_ptrn, sizeof(link->test_ptrn)) != 0) {
		LOGP(DINP, LOGL_ERROR, "Wrong test pattern SLTA\n");
		return -1;
	}

	/* we had a matching slta */
	osmo_timer_del(&link->t1_timer);
	link->sltm_pending = 0;
	link->was_up = 1;

	return 0;
}

void mtp_link_failure(struct mtp_link *link)
{
	if (link->blocked) {
		LOGP(DINP, LOGL_ERROR, "Ignoring failure on blocked link %d/%s on %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		return;
	}

	LOGP(DINP, LOGL_ERROR, "Link %d/%s of %d/%s has failed, going to reset it.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
	rate_ctr_inc(&link->ctrg->ctr[MTP_LNK_ERROR]);
	link->reset(link);
}

void mtp_link_block(struct mtp_link *link)
{
	link->blocked = 1;
	link->shutdown(link);
}

void mtp_link_unblock(struct mtp_link *link)
{
	if (!link->blocked)
		return;
	link->blocked = 0;
	link->reset(link);
}

static int dummy_arg1(struct mtp_link *link)
{
	LOGP(DINP, LOGL_ERROR, "The link %d/%s of linkset %d/%s is not typed.\n",
	     link->nr, link->name, link->set->nr, link->set->name);
	return 0;
}

static int dummy_arg2(struct mtp_link *link, struct msgb *msg)
{
	LOGP(DINP, LOGL_ERROR, "The link %d/%s of linkset %d/%s is not typed.\n",
	     link->nr, link->name, link->set->nr, link->set->name);
	msgb_free(msg);
	return 0;
}

struct mtp_link *mtp_link_alloc(struct mtp_link_set *set)
{
	struct mtp_link *link;

	link = talloc_zero(set, struct mtp_link);
	if (!link) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate the link.\n");
		return NULL;
	}

	link->nr = set->nr_links++;
	link->ctrg = rate_ctr_group_alloc(link,
					  mtp_link_rate_ctr_desc(), link->nr);
	if (!link->ctrg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate rate_ctr.\n");
		talloc_free(link);
		return NULL;
	}

	/* make sure a unconfigured link does not crash */
	link->write = dummy_arg2;
	link->shutdown = dummy_arg1;
	link->reset = dummy_arg1;
	link->clear_queue = dummy_arg1;

	link->pcap_fd = -1;

	link->t1_timer.data = link;
	link->t1_timer.cb = mtp_sltm_t1_timeout;
	link->t2_timer.data = link;
	link->t2_timer.cb = mtp_sltm_t2_timeout;

	link->set = set;

	llist_add_tail(&link->entry, &set->links);
	mtp_link_set_init_slc(set);

	return link;
}

struct mtp_link *mtp_link_num(struct mtp_link_set *set, int num)
{
	struct mtp_link *link;

	llist_for_each_entry(link, &set->links, entry)
		if (link->nr == num)
			return link;

	return NULL;
}
