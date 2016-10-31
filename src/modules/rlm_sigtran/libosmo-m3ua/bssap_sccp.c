/* Create GSM 08.08 messages */
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

#include <bssap_sccp.h>
#include <cellmgr_debug.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>

#include <string.h>


struct msgb *create_clear_command(struct sccp_source_reference *dest_ref)
{
	struct sccp_data_form1 *form1;
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "clear command");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate clear command.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*form1));
	form1 = (struct sccp_data_form1 *) msg->l2h;
	form1->type = SCCP_MSG_TYPE_DT1;
	form1->destination_local_reference = *dest_ref;
	form1->segmenting = 0;
	form1->variable_start = 1;

	/* create a Clear Command Call Control msg */
	msg->l3h = msgb_put(msg, 7);
	msg->l3h[0] = msgb_l3len(msg) - 1;
	msg->l3h[1] = BSSAP_MSG_BSS_MANAGEMENT;
	msg->l3h[2] = msg->l3h[0] - 2;
	msg->l3h[3] = BSS_MAP_MSG_CLEAR_CMD;
	msg->l3h[4] = 4;
	msg->l3h[5] = 1;
	msg->l3h[6] = 0x09;

	return msg;
}

struct msgb *create_sccp_rlsd(struct sccp_source_reference *src_ref,
			      struct sccp_source_reference *dst_ref)
{
	struct sccp_connection_released *rel;
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "rlsd");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate clear command.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*rel));
	rel = (struct sccp_connection_released *) msg->l2h;
	rel->type = SCCP_MSG_TYPE_RLSD;
	rel->release_cause = SCCP_RELEASE_CAUSE_END_USER_ORIGINATED;
	rel->destination_local_reference = *dst_ref;
	rel->source_local_reference = *src_ref;

	return msg;
}

struct msgb *create_sccp_rlc(struct sccp_source_reference *src_ref,
			     struct sccp_source_reference *dst_ref)
{
	struct sccp_connection_release_complete *rlc;
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "rlc");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate rlc.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*rlc));
	rlc = (struct sccp_connection_release_complete *) msg->l2h;
	rlc->type = SCCP_MSG_TYPE_RLC;
	rlc->destination_local_reference = *dst_ref;
	rlc->source_local_reference = *src_ref;

	return msg;
}

struct msgb *create_sccp_refuse(struct sccp_source_reference *dest_ref)
{
	struct sccp_connection_refused *ref;
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "rlsd");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate connection refuse.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*ref));
	ref = (struct sccp_connection_refused *) msg->l2h;
	ref->type = SCCP_MSG_TYPE_CREF;
	ref->destination_local_reference = *dest_ref;
	ref->cause = SCCP_REFUSAL_END_USER_ORIGINATED;
	ref->optional_start = 1;

	msg->l3h = msgb_put(msg, 1);
	msg->l3h[0] = SCCP_PNC_END_OF_OPTIONAL;

	return msg;
}

struct msgb *create_reset()
{
	static const uint8_t reset[] = {
		0x09, 0x00, 0x03, 0x05, 0x07, 0x02, 0x42, 0xfe,
		0x02, 0x42, 0xfe, 0x06, 0x00, 0x04, 0x30, 0x04,
		0x01, 0x20
	};

	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "reset");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate reset msg.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(reset));
	memcpy(msg->l2h, reset, msgb_l2len(msg));
	return msg;
}
