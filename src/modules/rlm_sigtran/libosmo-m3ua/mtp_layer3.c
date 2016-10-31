/* MTP layer3 main handling code */
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
#include <osmocom/mtp/mtp_level3.h>
#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <isup_types.h>
#include <counter.h>

#include <osmocom/core/talloc.h>

#include <osmocom/sccp/sccp.h>

#include <arpa/inet.h>

#include <string.h>

static int mtp_int_submit(struct mtp_link_set *set, int opc, int dpc, int sls, int type, const uint8_t *data, unsigned int length);

static void linkset_t18_cb(void *_set);
static void linkset_t20_cb(void *_set);

/** Allocate the buffer, and fill in header information for an MTP message
 *
 */
struct msgb *mtp_msg_alloc(struct mtp_link_set *set)
{
	struct mtp_level_3_hdr *hdr;
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "mtp-msg");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate mtp msg\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*hdr));
	hdr = (struct mtp_level_3_hdr *) msg->l2h;
	hdr->addr = MTP_ADDR(0x0, set->dpc, set->opc);
	hdr->ni = set->ni;
	hdr->spare = set->spare;
	return msg;
}

/** Allocate a Link Test Acknowledgement message
 *
 */
static struct msgb *mtp_create_slta(struct mtp_link_set *set, int sls,
				    struct mtp_level_3_mng *in_mng, int l3_len)
{
	struct mtp_level_3_hdr *hdr;
	struct mtp_level_3_mng *mng;
	struct msgb *out = mtp_msg_alloc(set);

	if (!out)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) out->l2h;
	hdr->ser_ind = MTP_SI_MNT_REG_MSG;
	hdr->addr = MTP_ADDR(sls, set->dpc, set->opc);

	mng = (struct mtp_level_3_mng *) msgb_put(out, sizeof(*mng));
	mng->cmn.h0 = MTP_TST_MSG_GRP;
	mng->cmn.h1 = MTP_TST_MSG_SLTA;
	mng->length =  l3_len - 2;
	msgb_put(out, mng->length);
	memcpy(mng->data, in_mng->data, mng->length);

	return out;
}

/** Allocate an MTP base message (used to construct other messages)
 *
 */
static struct msgb *mtp_base_alloc(struct mtp_link *link, int msg, int apoc)
{
	struct mtp_level_3_hdr *hdr;
	struct mtp_level_3_prohib *prb;
	struct msgb *out = mtp_msg_alloc(link->set);

	if (!out)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) out->l2h;
	hdr->ser_ind = MTP_SI_MNT_SNM_MSG;
	hdr->addr = MTP_ADDR(link->first_sls, link->set->dpc, link->set->opc);
	prb = (struct mtp_level_3_prohib *) msgb_put(out, sizeof(*prb));
	prb->cmn.h0 = MTP_PROHIBIT_MSG_GRP;
	prb->cmn.h1 = msg;
	prb->apoc = MTP_MAKE_APOC(apoc);
	return out;
}

/** Allocate memory for a Transfer Paused message
 *
 */
static struct msgb *mtp_tfp_alloc(struct mtp_link *link, int apoc)
{
	return mtp_base_alloc(link, MTP_PROHIBIT_MSG_SIG, apoc);
}

/** Allocate memory for a Transfer Allowed message
 *
 */
static struct msgb *mtp_tfa_alloc(struct mtp_link *link, int apoc)
{
	return mtp_base_alloc(link, MTP_PROHIBIT_MSG_TFA, apoc);
}

/** Allocate memory for a Transfer Restricted message
 *
 */
static struct msgb *mtp_tra_alloc(struct mtp_link *link, int opc)
{
	struct mtp_level_3_hdr *hdr;
	struct mtp_level_3_cmn *cmn;
	struct msgb *out = mtp_msg_alloc(link->set);

	if (!out)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) out->l2h;
	hdr->ser_ind = MTP_SI_MNT_SNM_MSG;
	hdr->addr = MTP_ADDR(0x0, link->set->dpc, opc);
	cmn = (struct mtp_level_3_cmn *) msgb_put(out, sizeof(*cmn));
	cmn->h0 = MTP_TRF_RESTR_MSG_GRP;
	cmn->h1 = MTP_RESTR_MSG_ALLWED;
	return out;
}

/** Create an SCCP SCMG message
 *
 * SCMG messages are used to manage SCCP link states.
 *
 * @param set	to send the message out on.
 * @param type	Sub System Status Test?
 * @param assn
 * @param apoc
 * @param sls
 */
static struct msgb *mtp_sccp_alloc_scmg(struct mtp_link_set *set,
					int type, int assn, int apoc, int sls)
{
	struct sccp_data_unitdata *udt;
	struct sccp_con_ctrl_prt_mgt *prt;
	struct mtp_level_3_hdr *hdr;
	uint8_t *data;


	struct msgb *out = mtp_msg_alloc(set);

	if (!out)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) out->l2h;
	hdr->ser_ind = MTP_SI_MNT_SCCP;

	/* this appears to be round robin or such.. */
	hdr->addr = MTP_ADDR(sls % 16, set->dpc, set->sccp_opc);

	/* generate the UDT message... libsccp does not offer formating yet */
	udt = (struct sccp_data_unitdata *) msgb_put(out, sizeof(*udt));
	udt->type = SCCP_MSG_TYPE_UDT;
	udt->proto_class = SCCP_PROTOCOL_CLASS_0;
	udt->variable_called = 3;
	udt->variable_calling = 5;
	udt->variable_data = 7;

	/* put the called and calling address. It is LV */
	data = msgb_put(out, 2 + 1);
	data[0] = 2;
	data[1] = 0x42;
	data[2] = 0x1;

	data = msgb_put(out, 2 + 1);
	data[0] = 2;
	data[1] = 0x42;
	data[2] = 0x1;

	data = msgb_put(out, 1);
	data[0] = sizeof(*prt);

	prt = (struct sccp_con_ctrl_prt_mgt *) msgb_put(out, sizeof(*prt));
	prt->sst = type;
	prt->assn = assn;
	prt->apoc = apoc;
	prt->mul_ind = 0;

	return out;
}

/** Stop each link in a link set
 *
 */
void mtp_link_set_stop(struct mtp_link_set *set)
{
	struct mtp_link *lnk;
	llist_for_each_entry(lnk, &set->links, entry)
		mtp_link_stop_link_test(lnk);

	osmo_timer_del(&set->T18);
	osmo_timer_del(&set->T20);

	set->sccp_up = 0;
	set->running = 0;
	set->linkset_up = 0;
}

/** Initiate an STLM (a link test) for each link in a set
 *
 */
void mtp_link_set_reset(struct mtp_link_set *set)
{
	struct mtp_link *lnk;
	mtp_link_set_stop(set);
	set->running = 1;

	llist_for_each_entry(lnk, &set->links, entry)
		mtp_link_start_link_test(lnk);
}

/** Send a Transfer paused message
 *
 */
int send_tfp(struct mtp_link *link, int apoc)
{
	struct msgb *msg;
	msg = mtp_tfp_alloc(link, apoc);
	if (!msg)
		return -1;

	mtp_link_submit(link, msg);
	return 0;
}

/* Send Transfer restricted Message
 *
 * Indicating we can no longer send messages on this link.
 */
static int send_tra(struct mtp_link *link, int opc)
{
	struct msgb *msg;
	msg = mtp_tra_alloc(link, opc);
	if (!msg)
		return -1;
	mtp_link_submit(link, msg);
	return 0;
}

/** Send Transfer allowed Message
 *
 * Indicating we're ready to receive traffic on this link.
 */
static int send_tfa(struct mtp_link *link, int opc)
{
	struct msgb *msg;
	msg = mtp_tfa_alloc(link, opc);
	if (!msg)
		return -1;
	mtp_link_submit(link, msg);
	return 0;
}

/** Verify a link
 *
 * Here we send a TFA (Transfer Allowed Message) to indicate we're OK to
 * receive data on this link.
 */
int mtp_link_verified(struct mtp_link *link)
{
	struct mtp_link_set *set = link->set;

	/* the link set is already up */
	if (set->linkset_up)
		return 0;

	set->linkset_up = 1;
	if (set->timeout_t18 != 0)
		osmo_timer_schedule(&set->T18, set->timeout_t18, 0);
	if (set->timeout_t20 != 0)
		osmo_timer_schedule(&set->T20, set->timeout_t20, 0);

	/* More the functionality of a SSP here... */
	if (set->sccp_opc != set->opc &&
	    send_tfa(link, set->sccp_opc) != 0) {
		LOGP(DINP, LOGL_ERROR,
		     "Failed to send TFA for OPC %d on linkset %d.\n", set->sccp_opc, set->nr);
	}

	if (set->isup_opc != set->opc &&
	    send_tfa(link, set->isup_opc) != 0) {
		LOGP(DINP, LOGL_ERROR,
		     "Failed to send TFA for OPC %d on linkset %d.\n", set->sccp_opc, set->nr);
	}

	if (set->timeout_t18 == 0)
		linkset_t18_cb(set);
	if (set->timeout_t20 == 0)
		linkset_t20_cb(set);

	return 0;
}

/** T18 is used on linkset restart when we're an STP (Signalling Transfer Point)
 *
 * It's shorter than the T20, and indicates a period where we listen, but don't
 * rebroadcast TFAs from adjacent connections.
 *
 * The time between T18 and T20 is when we rebroadcast link advertisements we've
 * received, to adjacent SPs.
 */
static void linkset_t18_cb(void *_set)
{
	struct mtp_link_set *set = _set;
	struct mtp_link *link = set->slc[0];

	if (!link) {
		LOGP(DINP, LOGL_ERROR,
		     "Linkset restart but no link available on linkset %d\n", set->nr);
		osmo_timer_del(&set->T20);
		set->linkset_up = 0;
		return;
	}

	/* TODO: now send out routing states */
	LOGP(DINP, LOGL_NOTICE, "The linkset %d has collected routing data.\n", set->nr);
	set->sccp_up = 1;
}

/** T20 is used on linkset restart
 *
 * T20 is used to time a listening period (on MTP reset), where the SEP (Signalling End Point)
 * listens for routing advertisements from adjacent nodes.
 *
 */
static void linkset_t20_cb(void *_set)
{
	struct mtp_link_set *set = _set;
	struct mtp_link *link = set->slc[0];

	if (!link) {
		LOGP(DINP, LOGL_ERROR,
		     "Linkset restart but no link available on linkset %d\n", set->nr);
		osmo_timer_del(&set->T20);
		set->linkset_up = 0;
		return;
	}

	/* Send the TRA for all PCs */
	if (send_tra(link, set->opc) != 0)
		return;

	LOGP(DINP, LOGL_NOTICE,
	     "The linkset %d/%s is considered running.\n", set->nr, set->name);
	return;
}

/** Process an MTP3 link signalling message that's not destined for a higher layer
 *
 */
static int mtp_link_sign_msg(struct mtp_link_set *set, struct mtp_level_3_hdr *hdr, int l3_len)
{
	struct mtp_level_3_cmn *cmn;
	uint16_t *apc;

	if (hdr->ni != set->ni || l3_len < 1) {
		LOGP(DINP, LOGL_ERROR, "Unhandled data (ni: %d len: %d)\n",
		     hdr->ni, l3_len);
		return -1;
	}

	cmn = (struct mtp_level_3_cmn *) &hdr->data[0];
	LOGP(DINP, LOGL_DEBUG, "reg msg: h0: 0x%x h1: 0x%x\n",
             cmn->h0, cmn->h1);

	switch (cmn->h0) {
	case MTP_TRF_RESTR_MSG_GRP:
		switch (cmn->h1) {
		case MTP_RESTR_MSG_ALLWED:
			LOGP(DINP, LOGL_INFO,
			     "Received TRA on linkset %d/%s.\n", set->nr, set->name);
			/*
			 * TODO: routing should be done on a higher level. This should not
			 * arrive after we expired the timer but we are friendly here and
			 * respond with a TFA and TRA...
			 */
			osmo_timer_del(&set->T18);
			osmo_timer_del(&set->T20);
			linkset_t18_cb(set);
			linkset_t20_cb(set);
			return 0;
			break;
		}
		break;
	case MTP_PROHIBIT_MSG_GRP:
		switch (cmn->h1) {
		case MTP_PROHIBIT_MSG_SIG:
			if (l3_len < 3) {
				LOGP(DINP, LOGL_ERROR, "TFP is too short on %d/%s.\n", set->nr, set->name);
				return -1;
			}

			apc = (uint16_t *) &hdr->data[1];
			LOGP(DINP, LOGL_INFO,
			     "TFP for the affected point code %d on %d/%s\n",
			     *apc, set->nr, set->name);
			return 0;
			break;
		}
		break;
	}

	LOGP(DINP, LOGL_ERROR, "Unknown message:%d/%d %s on %d/%s.\n",
	     cmn->h0, cmn->h1, osmo_hexdump(&hdr->data[0], l3_len),
	     set->nr, set->name);
	return -1;
}

/** Process an MTP3 link message that's not destined for a higher layer
 *
 * This is so we can respond, or process the response to link tests, to prove
 * that the link is up.
 *
 * @param link		the message was received on.
 * @param hdr		Pointer to the layer 3 header.
 * @param l3_len 	Length of the layer 3 data.
 */
static int mtp_link_regular_msg(struct mtp_link *link, struct mtp_level_3_hdr *hdr, int l3_len)
{
	struct msgb *out;
	struct mtp_level_3_mng *mng;

	if (hdr->ni != link->set->ni || l3_len < 1) {
		LOGP(DINP, LOGL_ERROR, "Unhandled data (ni: %d len: %d)\n",
		     hdr->ni, l3_len);
		return -1;
	}

	if (MTP_READ_DPC(hdr->addr) != link->set->opc) {
		LOGP(DINP, LOGL_ERROR, "MSG for OPC %d not handled on %d/%s\n",
			MTP_READ_DPC(hdr->addr), link->set->nr, link->set->name);
		return -1;
	}

	mng = (struct mtp_level_3_mng *) &hdr->data[0];
	LOGP(DINP, LOGL_DEBUG, "reg msg: h0: 0x%x h1: 0x%x\n",
             mng->cmn.h0, mng->cmn.h1);

	switch (mng->cmn.h0) {
	case MTP_TST_MSG_GRP:
		switch (mng->cmn.h1) {
		case MTP_TST_MSG_SLTM:
			/* simply respond to the request... */
			out = mtp_create_slta(link->set,
					      MTP_LINK_SLS(hdr->addr),
					      mng, l3_len);
			if (!out)
				return -1;
			mtp_link_submit(link, out);
			return 0;
			break;
		case MTP_TST_MSG_SLTA:
			/* If this link is proven set it up */
			if (mtp_link_slta(link, l3_len, mng) == 0)
				mtp_link_verified(link);
			break;
		}
		break;
	}

	return -1;
}

/** Handler for incoming SCCP data from lower layer (MTP3)
 *
 * Will attempt to dispatch SCCP data to a higher level application.
 */
static int mtp_link_sccp_data(struct mtp_link_set *set, struct mtp_level_3_hdr *hdr, struct msgb *msg, int l3_len)
{
	struct msgb *out;
	struct sccp_con_ctrl_prt_mgt *prt;
	struct sccp_parse_result sccp;
	int type;

	msg->l2h = &hdr->data[0];
	if (msgb_l2len(msg) != l3_len) {
		LOGP(DINP, LOGL_ERROR, "Size is wrong after playing with the l2h header.\n");
		return -1;
	}

	if (!set->sccp_up) {
		LOGP(DINP, LOGL_ERROR, "SCCP traffic is not allowed on %d/%s\n",
		     set->nr, set->name);
		return -1;
	}

	memset(&sccp, 0, sizeof(sccp));
	if (sccp_parse_header(msg, &sccp) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to parsed SCCP header.\n");
		return -1;
	}

	/*
	 *	If it's a Sub System Test message, deal with it locally
	 *	instead of forwarding it to the application.
	 */
	if ((sccp_determine_msg_type(msg) == SCCP_MSG_TYPE_UDT) && (msg->l3h[0] == SCCP_SST)) {
		if (msgb_l3len(msg) != 5) {
			LOGP(DINP, LOGL_ERROR, "SCCP UDT msg of unexpected size: %u\n", msgb_l3len(msg));
			return -1;
		}

		prt = (struct sccp_con_ctrl_prt_mgt *) &msg->l3h[0];
		if (prt->apoc != MTP_MAKE_APOC(set->sccp_opc)) {
			LOGP(DINP, LOGL_ERROR, "Unknown APOC: %u/%u on %d/%s\n",
			     ntohs(prt->apoc), prt->apoc, set->nr, set->name);
			type = SCCP_SSP;
		} else if (!set->supported_ssn[prt->assn]) {
			LOGP(DINP, LOGL_ERROR, "Unknown affected SSN assn: %u on %d/%s\n",
			     prt->assn, set->nr, set->name);
			type = SCCP_SSP;
		} else {
			type = SCCP_SSA;
		}

		out = mtp_sccp_alloc_scmg(set, type, prt->assn, prt->apoc,
					  MTP_LINK_SLS(hdr->addr));
		if (!out)
			return -1;

		mtp_link_submit(set->slc[MTP_LINK_SLS(hdr->addr)], out);

		return 0;
	}

	rate_ctr_inc(&set->ctrg->ctr[MTP_LSET_SCCP_IN_MSG]);

	/*
	 *	Forward the SCCP message to the SCCP application.
	 */
	set->sccp_data_available_cb(set, msg, MTP_LINK_SLS(hdr->addr));

	return 0;
}

/** Receive data coming up from lower level (M2UA/M3UA etc...)
 *
 * Dispatch data to another handler depending on what the the
 * service indicator in the MTP3 packet was.
 *
 * @param link message was received on.
 * @param msg from the lower layer.
 */
int mtp_link_handle_data(struct mtp_link *link, struct msgb *msg)
{
	int rc = -1;
	struct mtp_level_3_hdr *hdr;
	int l3_len;

	if (!msg->l2h || msgb_l2len(msg) < sizeof(*hdr))
		return -1;

	if (!link->set->running) {
		LOGP(DINP, LOGL_ERROR,
		     "Link %d/%s of %d/%s is not running. Call mtp_link_reset first.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		return -1;
	}

	hdr = (struct mtp_level_3_hdr *) msg->l2h;
	l3_len = msgb_l2len(msg) - sizeof(*hdr);

	rate_ctr_inc(&link->ctrg->ctr[MTP_LNK_IN]);
	rate_ctr_inc(&link->set->ctrg->ctr[MTP_LSET_TOTA_IN_MSG]);

	switch (hdr->ser_ind) {
	case MTP_SI_MNT_SNM_MSG:
		rc = mtp_link_sign_msg(link->set, hdr, l3_len);
		break;

	case MTP_SI_MNT_REG_MSG:
		rc = mtp_link_regular_msg(link, hdr, l3_len);
		break;

	case MTP_SI_MNT_SCCP:
		rc = mtp_link_sccp_data(link->set, hdr, msg, l3_len);
		break;

	case MTP_SI_MNT_ISUP:
		msg->l3h = &hdr->data[0];
		rate_ctr_inc(&link->set->ctrg->ctr[MTP_LSET_IUSP_IN_MSG]);
		rc = mtp_link_set_isup(link->set, msg, MTP_LINK_SLS(hdr->addr));

		break;
	default:
		fprintf(stderr, "Unhandled: %u\n", hdr->ser_ind);
		break;
	}

	return rc;
}

/** Send out an SCCP packet on a link set
 *
 * Packages an SCCP packet up with the correct point codes for the link,
 * or SCCP pointcodes if set, and sends it out.
 *
 * Also sets the correct SI to indicate it's SCCP.
 */
int mtp_link_set_submit_sccp_data(struct mtp_link_set *set, int sls, const uint8_t *data, unsigned int length)
{
	if (!set->sccp_up) {
		LOGP(DINP, LOGL_ERROR, "SCCP msg after TRA and before SSA. Dropping it on %d/%s\n",
		     set->nr, set->name);
//		return -1;
	}

	if (sls == -1) {
		sls = set->last_sls;
		set->last_sls = (set->last_sls + 1) % 16;
	}

	rate_ctr_inc(&set->ctrg->ctr[MTP_LSET_SCCP_OUT_MSG]);

	return mtp_int_submit(set, set->sccp_opc,
			      set->sccp_dpc == -1 ? set->dpc : set->sccp_dpc,
			      sls, MTP_SI_MNT_SCCP, data, length);
}

/** Sent out an ISUP packet on a link set
 *
 */
int mtp_link_set_submit_isup_data(struct mtp_link_set *set, int sls,
			      const uint8_t *data, unsigned int length)
{
	rate_ctr_inc(&set->ctrg->ctr[MTP_LSET_ISUP_OUT_MSG]);
	return mtp_int_submit(set, set->isup_opc,
			      set->isup_dpc == -1 ? set->dpc : set->isup_dpc,
			      sls, MTP_SI_MNT_ISUP, data, length);
}

/** Send a message using a linkset, based on the SLS field in the outgoing packet
 *
 * SLS is Signalling Link Selection.
 *
 * @param set to select outbound link from.
 * @param msg to send.
 */
int mtp_link_set_send(struct mtp_link_set *set, struct msgb *msg)
{
	int sls;
	struct mtp_level_3_hdr *hdr;

	if (msgb_l2len(msg) < sizeof(*hdr))
		return -1;

	hdr = (struct mtp_level_3_hdr *) msg->l2h;
	sls = MTP_LINK_SLS(hdr->addr);
	if (!set->slc[sls])
		return -2;

	mtp_link_submit(set->slc[sls], msg);
	return 0;
}

/** Construct an MTP3 packet.
 *
 * @param set to select outbound link from.
 * @param opc		The origin pointcode of the MTP3 packet.
 * @param dpc		The destination pointcode of the MTP3 packet.
 * @param sls		The link selection number.
 * @param type		The service identifier SCCP, ISUP etc...
 * @param data		from higher level.
 * @param length	of that data.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mtp_int_submit(struct mtp_link_set *set, int opc, int dpc,
			  int sls, int type, const uint8_t *data,
			  unsigned int length)
{
	uint8_t *put_ptr;
	struct mtp_level_3_hdr *hdr;
	struct msgb *msg;

	if (!set->slc[sls % 16])
		return -1;

	msg = mtp_msg_alloc(set);
	if (!msg)
		return -1;

	hdr = (struct mtp_level_3_hdr *) msg->l2h;
	hdr->ser_ind = type;

	hdr->addr = MTP_ADDR(sls % 16, dpc, opc);

	/* copy the raw sccp data */
	put_ptr = msgb_put(msg, length);
	memcpy(put_ptr, data, length);

	mtp_link_submit(set->slc[sls % 16], msg);
	return 0;
}

/** Find another link within a link set
 *
 * @param set to search for link in.
 * @param data If we find this, use the link *after* it, or just use any available link
 * @return next mtp link.
 */
static struct mtp_link *find_next_link(struct mtp_link_set *set, struct mtp_link *data)
{
	int found = 0;
	struct mtp_link *next;

	if (llist_empty(&set->links))
		return NULL;

	if (data == NULL)
		found = 1;

	/* try to find the next one */
	llist_for_each_entry(next, &set->links, entry) {
		if (found && next->available)
			return next;
		if (next == data)
			found = 1;
	}

	/* try to find any one */
	llist_for_each_entry(next, &set->links, entry)
		if (next->available)
			return next;

	return NULL;
}

/** Initialise the link selection array for a link set
 *
 * @note Starts at SLS id 100
 */
void mtp_link_set_init_slc(struct mtp_link_set *set)
{
	struct mtp_link *link = NULL, *tmp;
	int i;

	llist_for_each_entry(tmp, &set->links, entry)
		tmp->first_sls = 100;


	for (i = 0; i < ARRAY_SIZE(set->slc); ++i) {
		link = find_next_link(set, link);
		set->slc[i] = link;

		if (link && i < link->first_sls)
			link->first_sls = i;
	}
}

/** Allocate a new link set
 *
 * @param bsc struct representing a higher level application
 */
struct mtp_link_set *mtp_link_set_alloc(struct bsc_data *bsc)
{
	struct mtp_link_set *set;

	set = talloc_zero(bsc, struct mtp_link_set);
	if (!set)
		return NULL;

	set->ctrg = rate_ctr_group_alloc(set,
					  mtp_link_set_rate_ctr_desc(),
					  bsc->num_linksets + 1);
	if (!set->ctrg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate counter.\n");
		return NULL;
	}

	set->ni = MTP_NI_NATION_NET;
	INIT_LLIST_HEAD(&set->links);

	set->nr = bsc->num_linksets++;
	set->sccp_opc = set->isup_opc = -1;
	set->sccp_dpc = set->isup_dpc = -1;
	set->pcap_fd = bsc->pcap_fd;
	set->bsc = bsc;

	/* timeout code */
	set->timeout_t18 = 15;
	set->timeout_t20 = 16;

	set->T18.cb = linkset_t18_cb;
	set->T18.data = set;
	set->T20.cb = linkset_t20_cb;
	set->T20.data = set;

	set->sccp_data_available_cb = mtp_link_set_forward_sccp;

	llist_add_tail(&set->entry, &bsc->linksets);

	return set;
}

void mtp_link_set_sccp_data_available_cb(struct mtp_link_set *set, sccp_data_available_cb_t func)
{
	set->sccp_data_available_cb = func;
}

struct mtp_link_set *mtp_link_set_num(struct bsc_data *bsc, int num)
{
	struct mtp_link_set *set;

	llist_for_each_entry(set, &bsc->linksets, entry)
		if (set->nr == num)
			return set;

	return NULL;
}
