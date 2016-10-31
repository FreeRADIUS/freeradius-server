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
#include <snmp_mtp.h>
#include <cellmgr_debug.h>
#include <osmocom/core/talloc.h>

static void add_pdu_var(netsnmp_pdu *pdu, const char *mib_name, int id, const char *value)
{
	oid oid_name[MAX_OID_LEN];
	size_t name_length;

	char buf[4096];
	buf[4095] = '\0';
	snprintf(buf, sizeof(buf)-1, "%s.%d", mib_name, id);

	name_length = MAX_OID_LEN;
	if (snmp_parse_oid(buf, oid_name, &name_length) == NULL) {
		snmp_perror(buf);
		return;
	}

	if (snmp_add_var(pdu, oid_name, name_length, '=', value)) {
		snmp_perror(buf);
		return;
	}
}

static int link_up_cb(int op, netsnmp_session *ss,
		      int reqid, netsnmp_pdu *pdu, void *data)
{
	struct snmp_mtp_session *mtp = ss->myvoid;
	int link_index = (int) data;

	if (mtp->last_up_req != reqid)
		return 0;

	mtp->last_up_req = 0;
	snmp_mtp_callback(mtp, SNMP_LINK_UP,
			  op == STAT_TIMEOUT ? SNMP_STATUS_TIMEOUT : SNMP_STATUS_OK,
			  link_index);
	return 0;
}

static int link_down_cb(int op, netsnmp_session *ss,
			int reqid, netsnmp_pdu *pdu, void *data)
{
	struct snmp_mtp_session *mtp = ss->myvoid;
	int link_index = (int) data;

	if (mtp->last_do_req != reqid)
		return 0;

	mtp->last_do_req = 0;
	snmp_mtp_callback(mtp, SNMP_LINK_DOWN,
			  op == STAT_TIMEOUT ? SNMP_STATUS_TIMEOUT : SNMP_STATUS_OK,
			  link_index);
	return 0;
}

static int send_pdu(netsnmp_session *ss, netsnmp_pdu *pdu, int kind, int link_id)
{
	int status;
	netsnmp_callback cb;

	cb = kind == SNMP_LINK_UP ? link_up_cb : link_down_cb;

	status = snmp_async_send(ss, pdu, cb, (void *) link_id);
	if (status == 0) {
		snmp_log(LOG_ERR, "Failed to send async request.\n");
		snmp_free_pdu(pdu);
	}

	return status;
}

static void snmp_mtp_start_c7_datalink(struct snmp_mtp_session *session, int link_id)
{
	int status;
	netsnmp_pdu *pdu;
	pdu = snmp_pdu_create(SNMP_MSG_SET);

	add_pdu_var(pdu, "PTI-NexusWareC7-MIB::nwc7DatalinkCommand", link_id, "nwc7DatalinkCmdPowerOn");
	add_pdu_var(pdu, "PTI-NexusWareC7-MIB::nwc7Mtp2Active", link_id, "true");
	status = send_pdu(session->ss, pdu, SNMP_LINK_UP, link_id);

	if (status == 0)
		snmp_mtp_callback(session, SNMP_LINK_UP, SNMP_STATUS_TIMEOUT, link_id);
	else
		session->last_up_req = status;

}

static void snmp_mtp_stop_c7_datalink(struct snmp_mtp_session *session, int link_id)
{
	int status;
	netsnmp_pdu *pdu;
	pdu = snmp_pdu_create(SNMP_MSG_SET);

	add_pdu_var(pdu, "PTI-NexusWareC7-MIB::nwc7Mtp2Active", link_id, "false");
	status = send_pdu(session->ss, pdu, SNMP_LINK_DOWN, link_id);
	if (status == 0)
		snmp_mtp_callback(session, SNMP_LINK_DOWN, SNMP_STATUS_TIMEOUT, link_id);
	else
		session->last_do_req = status;
}

struct snmp_mtp_session *snmp_mtp_session_create()
{
	struct snmp_mtp_session *session = talloc_zero(NULL, struct snmp_mtp_session);
	if (!session)
		return NULL;

	init_snmp("cellmgr_ng");
	snmp_sess_init(&session->session);
	session->session.version = SNMP_VERSION_1;
	session->session.community = (unsigned char *) "private";
	session->session.community_len = strlen((const char *) session->session.community);
	session->session.myvoid = session;

	return session;
}

int snmp_mtp_peer_name(struct snmp_mtp_session *session, char *host)
{
	if (session->ss) {
		snmp_close(session->ss);
		session->ss = NULL;
	}

	session->session.peername = host;

	session->ss = snmp_open(&session->session);
	if (!session->ss) {
		snmp_perror("create failure");
		snmp_log(LOG_ERR, "Could not connect to the remote.\n");
		LOGP(DINP, LOGL_ERROR, "Failed to open a SNMP session.\n");
		return -1;
	}

	return 0;
}

void snmp_mtp_deactivate(struct snmp_mtp_session *session, int index)
{
	snmp_mtp_stop_c7_datalink(session, index);
}

void snmp_mtp_activate(struct snmp_mtp_session *session, int index)
{
	snmp_mtp_start_c7_datalink(session, index);
}

/**
 * This is the easiest way to integrate SNMP without
 * introducing threads. It would be nicer if it could
 * register a timeout and the fd it wants to have selected
 * for reading. We could try to find the fd's it is using
 * for the session but there is no difference in performance
 */
void snmp_mtp_poll()
{
	int num_fds = 0, block = 0;
	fd_set fds;
	FD_ZERO(&fds);
	struct timeval tv;
	int rc;

	snmp_select_info(&num_fds, &fds, &tv, &block);


	memset(&tv, 0, sizeof(tv));

	rc = select(num_fds, &fds, NULL, NULL, &tv);
	if (rc == 0)
		snmp_timeout();
	else
		snmp_read(&fds);
}
