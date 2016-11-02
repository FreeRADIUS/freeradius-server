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

#include <isup_types.h>
#include <cellmgr_debug.h>
#include <mtp_data.h>
#include <osmocom/mtp/mtp_level3.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>

static struct msgb *isup_status_alloc(int cic, int msg_type, uint8_t *extra, int range, int val)
{
	struct isup_msg_hdr *hdr;
	struct msgb *msg;
	int bits, len;
	uint8_t *data;

	msg = msgb_alloc_headroom(4096, 128, "ISUP Simple MSG");
	if (!msg) {
		LOGP(DISUP, LOGL_ERROR, "Allocation of status message failed.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*hdr));

	/* write the ISUP header */
	hdr = (struct isup_msg_hdr *) msg->l2h;
	hdr->cic = cic;
	hdr->msg_type = msg_type;

	if (extra)
		msgb_v_put(msg, *extra);

	/*
	 * place the pointers here.
	 * 1.) place the variable start after us
	 * 2.) place the length
	 */
	msgb_v_put(msg, 1);

	bits = range + 1;
	len = (bits / 8) + 1;
	msgb_v_put(msg, len + 1);
	msgb_v_put(msg, range);

	data = msgb_put(msg, len);

	/* set the status bits to val... FIXME this sets the extra bits too */
	memset(data, val, len);

	return msg;
}

static struct msgb *isup_simple_alloc(int cic, int msg_type)
{
	struct isup_msg_hdr *hdr;
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "ISUP Simple MSG");
	if (!msg) {
		LOGP(DISUP, LOGL_ERROR, "Allocation of Simple message failed.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*hdr));

	/* write the ISUP header */
	hdr = (struct isup_msg_hdr *) msg->l2h;
	hdr->cic = cic;
	hdr->msg_type = msg_type;

	msgb_v_put(msg, 0);
	return msg;
}

/* this message contains the range */
int isup_parse_status(const uint8_t *data, uint8_t in_length)
{
	uint8_t ptr;

	if (in_length < 3) {
		LOGP(DISUP, LOGL_ERROR, "This needs three bytes.\n");
		return -1;
	}

	ptr = data[0];
	if (1 + ptr > in_length) {
		LOGP(DISUP, LOGL_ERROR, "Pointing outside the packet.\n");
		return -1;
	}

	if (1 + ptr + 1 > in_length) {
		LOGP(DISUP, LOGL_ERROR, "No space for the data.\n");
		return -1;
	}

	return data[0 + ptr + 1];
}


/* Handle incoming ISUP data */
static int handle_circuit_reset_grs(struct mtp_link_set *set, int sls, int cic,
				    const uint8_t *data, int size)
{
	struct msgb *resp;
	int range;

	range = isup_parse_status(data, size);
	if (range < 0)
		return -1;

	resp = isup_status_alloc(cic, ISUP_MSG_GRA, NULL, range, 0);
	if (!resp)
		return -1;

	mtp_link_set_submit_isup_data(set, sls, resp->l2h, msgb_l2len(resp));
	msgb_free(resp);
	return 0;
}

static int handle_circuit_reset_cgb(struct mtp_link_set *set, int sls, int cic,
				    const uint8_t *data, int size)
{
	struct msgb *resp;
	int range;
	uint8_t val;

	if (size < 1)
		return -1;

	range = isup_parse_status(data + 1, size - 1);
	if (range < 0)
		return -1;

	val = 0;
	resp = isup_status_alloc(cic, ISUP_MSG_CGBA, &val, range, 0xff);
	if (!resp)
		return -1;

	mtp_link_set_submit_isup_data(set, sls, resp->l2h, msgb_l2len(resp));
	msgb_free(resp);
	return 0;
}

static int send_cgu(struct mtp_link_set *set, int sls, int cic, int range)
{
	struct msgb *resp;
	uint8_t val;

	val = 0;
	resp = isup_status_alloc(cic, ISUP_MSG_CGU, &val, range, 0);
	if (!resp)
		return -1;

	mtp_link_set_submit_isup_data(set, sls, resp->l2h, msgb_l2len(resp));
	msgb_free(resp);
	return 0;
}

static int handle_cgu(struct mtp_link_set *set, int sls, int cic,
		      uint8_t *data, uint16_t size)
{
	uint8_t *out;
	struct isup_msg_hdr *hdr;
	struct msgb *resp;

	resp = msgb_alloc_headroom(4096, 128, "ISUP CGUA MSG");
	if (!resp) {
		LOGP(DISUP, LOGL_ERROR, "Allocation of CGUA message failed.\n");
		return -1;
	}

	resp->l2h = msgb_put(resp, sizeof(*hdr));

	/* write the ISUP header */
	hdr = (struct isup_msg_hdr *) resp->l2h;
	hdr->cic = cic;
	hdr->msg_type = ISUP_MSG_CGUA;

	out = msgb_put(resp, size);
	memcpy(out, data, size);

	mtp_link_set_submit_isup_data(set, sls, resp->l2h, msgb_l2len(resp));
	msgb_free(resp);
	return 0;
}

static int handle_simple_resp(struct mtp_link_set *set, int sls, int cic, int msg_type)
{
	struct msgb *resp;

	resp = isup_simple_alloc(cic, msg_type);
	if (!resp)
		return -1;
	mtp_link_set_submit_isup_data(set, sls, resp->l2h, msgb_l2len(resp));
	msgb_free(resp);
	return 0;
}

int mtp_link_set_isup(struct mtp_link_set *set, struct msgb *msg, int sls)
{
	int rc = -1;
	int payload_size;
	struct isup_msg_hdr *hdr;

	if (msgb_l3len(msg) < sizeof(*hdr)) {
		LOGP(DISUP, LOGL_ERROR, "ISUP header is too short.\n");
		return -1;
	}

	if (set->pass_all_isup) {
		mtp_link_set_forward_isup(set, msg, sls);
		return 0;
	}

	hdr = (struct isup_msg_hdr *) msg->l3h;
	payload_size = msgb_l3len(msg) - sizeof(*hdr);

	switch (hdr->msg_type) {
	case ISUP_MSG_GRS:
		rc = handle_circuit_reset_grs(set, sls, hdr->cic, hdr->data, payload_size);
		break;
	case ISUP_MSG_CGB:
		rc = handle_circuit_reset_cgb(set, sls, hdr->cic, hdr->data, payload_size);
		if (rc == 0)
			rc = send_cgu(set, sls, hdr->cic, 28);
		break;
	case ISUP_MSG_CGU:
		rc = handle_cgu(set, sls, hdr->cic, hdr->data, payload_size);
		break;
	case ISUP_MSG_CGUA:
		LOGP(DISUP, LOGL_NOTICE, "CIC %d is now unblocked on linkset %d/%s.\n",
		     hdr->cic, set->nr, set->name);
		break;
	case ISUP_MSG_RSC:
		rc = handle_simple_resp(set, sls, hdr->cic, ISUP_MSG_RLC);
		break;
	default:
		mtp_link_set_forward_isup(set, msg, sls);
		rc = 0;
		break;
	}

	return rc;
}

uint16_t isup_cic_to_local(const struct isup_msg_hdr *hdr)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return hdr->cic;
#elif __BYTE_ORDER == __BIG_ENDIAN
	return c_swap_16(hdr->cic);
#else
	#error "Unknown endian"
#endif
}

