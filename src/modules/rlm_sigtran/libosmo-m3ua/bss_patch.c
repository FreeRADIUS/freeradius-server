/* Patch GSM 08.08 messages for the network and BS */
/*
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2013 by On-Waves
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

#include <bss_patch.h>
#include <cellmgr_debug.h>
#include <ss7_application.h>

#include <string.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/sccp/sccp.h>

#include <arpa/inet.h>

static int handle_bss_mgmt(struct ss7_application *, struct msgb *msg, struct sccp_parse_result *sccp);
static int handle_bss_dtap(struct msgb *msg, struct sccp_parse_result *sccp, int dir);

static void patch_ass_rqst(struct msgb *msg, int length)
{
	struct tlv_parsed tp;
	uint8_t *data;
	int len;
	int i;

//	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, length - 1, 0, 0);
	abort();

	len = TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE);
	if (len < 3)
		return;

	data = (uint8_t *) TLVP_VAL(&tp, GSM0808_IE_CHANNEL_TYPE);
	/* no speech... ignore */
	if ((data[0] & 0xf) != 0x1)
		return;

	/* blindly assign FR2 on all slots */
	data[1] = GSM0808_SPEECH_FULL_PREF;
	for (i = 0; i < len - 2; ++i) {
		uint8_t audio = GSM0808_PERM_FR2;

		/* at the end? */
		if (i + 1 != len - 2)
			audio |= 0x80;
		data[2 + i] = audio;
	}
}

static void patch_ass_cmpl(struct ss7_application *app, struct msgb *msg, int length)
{
	struct tlv_parsed tp;
	uint8_t *data;

	if (length == 1 || app->fixed_ass_cmpl_reply) {
		/* We need to truncate the message to only include the codec */
		if (length > 1 && app->fixed_ass_cmpl_reply) {
			uint8_t *old = msg->tail;
			msg->tail = &msg->l3h[1];
			msg->len = old - msg->tail;
		}

		LOGP(DMSC, LOGL_ERROR, "Hacking the Assignment Complete.\n");
		msgb_v_put(msg, 0x21);
		msgb_v_put(msg, 0x09);
		msgb_v_put(msg, 0x2c);
		msgb_v_put(msg, 0x02);
		msgb_v_put(msg, 0x40);
		msgb_v_put(msg, 0x25);
		msg->l3h[-1] = 7;
		msg->l3h[-3] = 9;
		return;
	}

//	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, length - 1, 0, 0);

	abort();

	/* Now patch chosen channel and speech version */

	if (TLVP_PRESENT(&tp, GSM0808_IE_CHOSEN_CHANNEL)) {
		data = (uint8_t *) TLVP_VAL(&tp, GSM0808_IE_CHOSEN_CHANNEL);
		data[0] = 0x09;
	} else {
		LOGP(DMSC, LOGL_ERROR, "Chosen Channel not in the MSG.\n");
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_SPEECH_VERSION)) {
		data = (uint8_t *) TLVP_VAL(&tp, GSM0808_IE_SPEECH_VERSION);
		data[0] = GSM0808_PERM_HR3;
	} else {
		LOGP(DMSC, LOGL_ERROR, "Speech version not in the MSG.\n");
	}
}

int bss_patch_filter_msg(struct ss7_application *app, struct msgb *msg,
				struct sccp_parse_result *sccp, int dir)
{
	int type;
	memset(sccp, 0, sizeof(*sccp));
	if (sccp_parse_header(msg, sccp) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Failed to parse SCCP header.\n");
		return -1;
	}

	type = sccp_determine_msg_type(msg);
	switch (type) {
	case SCCP_MSG_TYPE_CR:
		if (msg->l3h)
			break;
		return 0;
		break;
	case SCCP_MSG_TYPE_CC:
	case SCCP_MSG_TYPE_CREF:
		return 0;
		break;
	case SCCP_MSG_TYPE_RLC:
		return BSS_FILTER_RLC;
		break;
	case SCCP_MSG_TYPE_RLSD:
		return BSS_FILTER_RLSD;
		break;
	}

	if (msgb_l3len(msg) < sccp->data_len) {
		LOGP(DMSC, LOGL_ERROR, "Less space than there should be.\n");
		return -1;
	}

	if (!msg->l3h || msgb_l3len(msg) < 3) {
		return -1;
	}

	if (msgb_l3len(msg) < 2 + msg->l3h[1]) {
		return -1;
	}

	if (msg->l3h[0] == BSSAP_MSG_BSS_MANAGEMENT)
		return handle_bss_mgmt(app, msg, sccp);
	if (msg->l3h[0] == BSSAP_MSG_DTAP)
		return handle_bss_dtap(msg, sccp, dir);

	/* Not handled... */
	return -1;
}

static int handle_bss_mgmt(struct ss7_application *app, struct msgb *msg,
				struct sccp_parse_result *sccp)
{
	switch (msg->l3h[2]) {
	case BSS_MAP_MSG_ASSIGMENT_RQST:
		msg->l3h = &msg->l3h[2];
		patch_ass_rqst(msg, sccp->data_len - 2);
		break;
	case BSS_MAP_MSG_ASSIGMENT_COMPLETE:
		msg->l3h = &msg->l3h[2];
		patch_ass_cmpl(app, msg, sccp->data_len - 2);
		break;
	case BSS_MAP_MSG_RESET:
		return BSS_FILTER_RESET;
		break;
	case BSS_MAP_MSG_RESET_ACKNOWLEDGE:
		return BSS_FILTER_RESET_ACK;
		break;
	case BSS_MAP_MSG_CLEAR_COMPLETE:
		return BSS_FILTER_CLEAR_COMPL;
		break;
	}

	return 0;
}

/* patch bearer capabilities towards the BSC */
static int handle_bss_dtap(struct msgb *msg, struct sccp_parse_result *sccp, int dir)
{
	struct gsm48_hdr *hdr48;
	struct tlv_parsed tp;
	uint8_t proto, msg_type;
	uint8_t *data;
	int rc, len, i, has_amr;

	/* early exit for messages not going to the MSC */
	if ((dir & BSS_DIR_MSC) == 0)
		return BSS_FILTER_DTAP;

	/* check if the plain gsm header fits */
	if (msg->l3h[2] < sizeof(*hdr48)) {
		LOGP(DMSC, LOGL_ERROR,
		     "DTAP GSM48 hdr does not fit: %d\n", msgb_l3len(msg));
		return -1;
	}

	/* check if the whole message fits */
	if (msgb_l3len(msg) - 3 < msg->l3h[2]) {
		LOGP(DMSC, LOGL_ERROR,
		     "DTAG GSM48 msg does not fit: %d\n", msgb_l3len(msg) - 3);
		return -1;
	}

	/* right now we only need to patch call control messages */
	msg->l3h = &msg->l3h[3];
	hdr48 = (struct gsm48_hdr *) &msg->l3h[0];
	proto = hdr48->proto_discr & 0x0f;
        msg_type = hdr48->msg_type & 0xbf;

	if (proto != GSM48_PDISC_CC)
		return BSS_FILTER_DTAP;

	switch (msg_type) {
	case GSM48_MT_CC_CALL_CONF:
	case GSM48_MT_CC_SETUP:
		abort();
/*
		rc = tlv_parse(&tp, &gsm48_att_tlvdef, &hdr48->data[0],
			       msgb_l3len(msg) - sizeof(*hdr48), 0, 0);
*/
		if (rc <= 0) {
			LOGP(DMSC, LOGL_ERROR,
			     "Failed to parse CC message: %d\n", rc);
			return BSS_FILTER_DTAP;
		}

		/* not judging if this is optional here or not */
		if (!TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP))
			return BSS_FILTER_DTAP;

		if (TLVP_LEN(&tp, GSM48_IE_BEARER_CAP) < 2){
			LOGP(DMSC, LOGL_ERROR,
			     "Octet3/Octet3a do not fit: %d\n",
			     TLVP_LEN(&tp, GSM48_IE_BEARER_CAP));
			return BSS_FILTER_DTAP;
		}

		data = (uint8_t *) TLVP_VAL(&tp, GSM48_IE_BEARER_CAP);
		if ((data[0] & 0x80) != 0) {
			LOGP(DMSC, LOGL_DEBUG, "Octet3a not present.\n");
			return BSS_FILTER_DTAP;
		}

		/*
		 * Some lazy bit checks that work because the defines are
		 * are 0. If this would not be the case we will need additional
		 * shifts
		 */
		if ((data[0] & 0x07) != GSM48_BCAP_ITCAP_SPEECH)
			return BSS_FILTER_DTAP;
		if ((data[0] & 0x08) != GSM48_BCAP_TMOD_CIRCUIT)
			return BSS_FILTER_DTAP;
		if ((data[0] & 0x10) != GSM48_BCAP_CODING_GSM_STD)
			return BSS_FILTER_DTAP;

		/* Check if we have fr only */
		if ((data[0] & 0x60) >> 5 == GSM48_BCAP_RRQ_FR_ONLY) {
			data[0] &= ~0x60;
			data[0] |= GSM48_BCAP_RRQ_DUAL_HR << 5;
		}

		/* Now check if HR AMR 3 shows up */
		has_amr = 0;
		len = TLVP_LEN(&tp, GSM48_IE_BEARER_CAP);
		for (i = 1; i < len && !has_amr; ++i) {
			/* ended the octet3a */
			if ((data[i] & 0x80) > 0)
				break;
			if ((data[i] & 0x0f) == 0x5)
				has_amr = 1;
		}

		/* patch HR AMR 3 as first used audio codec */
		if (!has_amr)
			data[1] = (data[1] & 0x80) | 0x5;

		break;
	}

	return BSS_FILTER_DTAP;
}

static void create_cr(struct msgb *target, struct msgb *inpt, struct sccp_parse_result *sccp)
{
	static const uint32_t optional_offset =
			offsetof(struct sccp_connection_request, optional_start);

	unsigned int optional_length, optional_start;
	struct sccp_connection_request *cr, *in_cr;

	target->l2h = msgb_put(target, sizeof(*cr));
	cr = (struct sccp_connection_request *) target->l2h;
	in_cr = (struct sccp_connection_request *) inpt->l2h;

	cr->type = in_cr->type;
	cr->proto_class = in_cr->proto_class;
	cr->source_local_reference = in_cr->source_local_reference;
	cr->variable_called = 2;
	cr->optional_start = 4;

	/* called address */
	target->l3h = msgb_put(target, 1 + 2);
	target->l3h[0] = 2;
	target->l3h[1] = 0x42;
	target->l3h[2] = 254;

	/*
	 * We need to keep the complete optional data. The SCCP parse result
         * is only pointing to the data payload.
	 */
	optional_start = in_cr->optional_start + optional_offset;
	optional_length = msgb_l2len(inpt) - optional_start;
	if (optional_start + optional_length <= msgb_l2len(inpt)) {
		target->l3h = msgb_put(target, optional_length);
		memcpy(target->l3h, inpt->l2h + optional_start, msgb_l3len(target));
	} else {
		LOGP(DINP, LOGL_ERROR, "Input should at least have a byte of data.\n");
	}
}

/** Generate a simple UDT msg. FIXME: Merge it with the SCCP code
 *
 * Generic data SCCP container.
 */
static void create_udt(struct msgb *target, struct msgb *inpt, struct sccp_parse_result *sccp)
{
	struct sccp_data_unitdata *udt, *in_udt;

	target->l2h = msgb_put(target, sizeof(*udt));
	udt = (struct sccp_data_unitdata *) target->l2h;
	in_udt = (struct sccp_data_unitdata *) inpt->l2h;

	udt->type = in_udt->type;
	udt->proto_class = in_udt->proto_class;
	udt->variable_called = 3;
	udt->variable_calling = 5;
	udt->variable_data = 7;

	target->l3h = msgb_put(target, 1 + 2);
	target->l3h[0] = 2;
	target->l3h[1] = 0x42;
	target->l3h[2] = 254;

	target->l3h = msgb_put(target, 1 + 2);
	target->l3h[0] = 2;
	target->l3h[1] = 0x42;
	target->l3h[2] = 254;

	target->l3h = msgb_put(target, sccp->data_len + 1);
	target->l3h[0] = sccp->data_len;
	memcpy(&target->l3h[1], inpt->l3h, msgb_l3len(target) - 1);
}

void bss_rewrite_header_for_msc(int rc, struct msgb *target, struct msgb *inpt, struct sccp_parse_result *sccp)
{

	switch (inpt->l2h[0]) {
	case SCCP_MSG_TYPE_CR:
		if (rc >= 0)
			create_cr(target, inpt, sccp);
		else
			target->l2h = msgb_put(target, 0);
		break;
	case SCCP_MSG_TYPE_UDT:
		if (rc >= 0)
			create_udt(target, inpt, sccp);
		else
			target->l2h = msgb_put(target, 0);
		break;
	default:
		target->l2h = msgb_put(target, msgb_l2len(inpt));
		memcpy(target->l2h, inpt->l2h, msgb_l2len(target));
		break;
	}
}

/* it is asssumed that the SCCP stack checked the size */
static int patch_address(uint32_t offset, int pc, struct msgb *msg)
{
	struct sccp_called_party_address *party;
	uint8_t *the_pc;
	uint8_t pc_low, pc_high;

	party = (struct sccp_called_party_address *)(msg->l2h + offset + 1);
	the_pc = &party->data[0];

	pc_low = pc & 0xff;
	pc_high = (pc >> 8) & 0xff;
	the_pc[0] = pc_low;
	the_pc[1] = pc_high;

	return 0;
}

int bss_rewrite_header_to_bsc(struct msgb *msg, int opc, int dpc)
{
	static const uint32_t called_offset =
		offsetof(struct sccp_data_unitdata, variable_called);
	static const uint32_t calling_offset =
		offsetof(struct sccp_data_unitdata, variable_calling);

	struct sccp_data_unitdata *udt;
	struct sccp_parse_result sccp;

	memset(&sccp, 0, sizeof(sccp));
	if (sccp_parse_header(msg, &sccp) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Failed to parse SCCP header.\n");
		return -1;
	}

	/* For now the MSC only sends the PC in UDT */
	if (msg->l2h[0] != SCCP_MSG_TYPE_UDT)
		return 0;

	/* sanity checking */
	if (sccp.called.use_poi != 1) {
		LOGP(DMSC, LOGL_ERROR, "MSC didn't send a PC in called address\n");
		return -1;
	}

	if (sccp.calling.use_poi != 1) {
		LOGP(DMSC, LOGL_ERROR, "MSC didn't send a PC in calling address\n");
		return -1;
	}

	/* Good thing is we can avoid most of the error checking */
	udt = (struct sccp_data_unitdata *) msg->l2h;
	if (patch_address(called_offset + udt->variable_called, dpc, msg) != 0)
		return -1;

	if (patch_address(calling_offset + udt->variable_calling, opc, msg) != 0)
		return -1;
	return 0;
}
