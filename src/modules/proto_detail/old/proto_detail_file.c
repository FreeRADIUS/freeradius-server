/*
 * proto_detail.c	Process the detail file
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *  2007  The FreeRADIUS server project
 *  2007  Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/rad_assert.h>

#include "detail.h"

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#include <pthread.h>

#include <fcntl.h>

#define USEC (1000000)

static FR_NAME_NUMBER state_names[] = {
	{ "unopened", STATE_UNOPENED },
	{ "unlocked", STATE_UNLOCKED },
	{ "processing", STATE_PROCESSING },

	{ "header", STATE_HEADER },
	{ "vps", STATE_VPS },
	{ "queued", STATE_QUEUED },
	{ "running", STATE_RUNNING },
	{ "no-reply", STATE_NO_REPLY },
	{ "replied", STATE_REPLIED },

	{ NULL, 0 }
};


/*
 *	If we're limiting outstanding packets, then mark the response
 *	as being sent.
 */
static int detail_send(rad_listen_t *listener, REQUEST *request)
{
	char c = 0;
	listen_detail_t *data = listener->data;

	rad_assert(request->listener == listener);
	rad_assert(listener->send == detail_send);

	/*
	 *	This request timed out.  Remember that, and tell the
	 *	caller it's OK to read more "detail" file stuff.
	 */
	if (request->reply->code == 0) {
		data->delay_time = data->retry_interval * USEC;
		data->signal = 1;
		data->entry_state = STATE_NO_REPLY;

		RDEBUG("detail (%s): No response to request.  Will retry in %d seconds",
		       data->name, data->retry_interval);
	} else {
		int rtt;
		struct timeval now;
		/*
		 *	We call gettimeofday a lot.  But it should be OK,
		 *	because there's nothing else to do.
		 */
		gettimeofday(&now, NULL);

		/*
		 *	If we haven't sent a packet in the last second, reset
		 *	the RTT.
		 */
		now.tv_sec -= 1;
		if (fr_timeval_cmp(&data->last_packet, &now) < 0) {
			data->has_rtt = false;
		}
		now.tv_sec += 1;

		/*
		 *	Only one detail packet may be outstanding at a time,
		 *	so it's safe to update some entries in the detail
		 *	structure.
		 *
		 *	We keep smoothed round trip time (SRTT), but not round
		 *	trip timeout (RTO).  We use SRTT to calculate a rough
		 *	load factor.
		 */
		rtt = now.tv_sec - request->packet->timestamp.tv_sec;
		rtt *= USEC;
		rtt += now.tv_usec;
		rtt -= request->packet->timestamp.tv_usec;

		/*
		 *	If we're proxying, the RTT is our processing time,
		 *	plus the network delay there and back, plus the time
		 *	on the other end to process the packet.  Ideally, we
		 *	should remove the network delays from the RTT, but we
		 *	don't know what they are.
		 *
		 *	So, to be safe, we over-estimate the total cost of
		 *	processing the packet.
		 */
		if (!data->has_rtt) {
			data->has_rtt = true;
			data->srtt = rtt;
			data->rttvar = rtt / 2;

		} else {
			data->rttvar -= data->rttvar >> 2;
			data->rttvar += (data->srtt - rtt);
			data->srtt -= data->srtt >> 3;
			data->srtt += rtt >> 3;
		}

		/*
		 *	Calculate the time we wait before sending the next
		 *	packet.
		 *
		 *	rtt / (rtt + delay) = load_factor / 100
		 */
		data->delay_time = (data->srtt * (100 - data->load_factor)) / (data->load_factor);

		/*
		 *	Cap delay at no less than 4 packets/s.  If the
		 *	end system can't handle this, then it's very
		 *	broken.
		 */
		if (data->delay_time > (USEC / 4)) data->delay_time= USEC / 4;

		RDEBUG3("detail (%s): Received response for request %" PRIu64 ".  "
			"Will read the next packet in %d seconds",
			data->name, request->number, data->delay_time / USEC);

		data->last_packet = now;
		data->signal = 1;
		data->entry_state = STATE_REPLIED;
		data->counter++;
	}

	if (write(data->child_pipe[1], &c, 1) < 0) {
		RERROR("detail (%s): Failed writing ack to reader thread: %s", data->name, fr_syserror(errno));
	}

	return 0;
}


/*
 *	Open the detail file, if we can.
 *
 *	FIXME: create it, if it's not already there, so that the main
 *	server select() will wake us up if there's anything to read.
 */
static int detail_open(rad_listen_t *this)
{
	struct stat st;
	listen_detail_t *data = this->data;

	rad_assert(data->file_state == STATE_UNOPENED);
	data->delay_time = USEC;

	/*
	 *	Open detail.work first, so we don't lose
	 *	accounting packets.  It's probably better to
	 *	duplicate them than to lose them.
	 *
	 *	Note that we're not writing to the file, but
	 *	we've got to open it for writing in order to
	 *	establish the lock, to prevent rlm_detail from
	 *	writing to it.
	 *
	 *	This also means that if we're doing globbing,
	 *	this file will be read && processed before the
	 *	file globbing is done.
	 */
	data->fp = NULL;
	data->work_fd = open(data->filename_work, O_RDWR);

	/*
	 *	Couldn't open it for a reason OTHER than "it doesn't
	 *	exist".  Complain and tell the admin.
	 */
	if ((data->work_fd < 0) && (errno != ENOENT)) {
		ERROR("Failed opening detail file %s: %s",
		      data->filename_work, fr_syserror(errno));
		return 0;
	}

	/*
	 *	The file doesn't exist.  Poll for it again.
	 */
	if (data->work_fd < 0) {
#ifndef HAVE_GLOB_H
		return 0;
#else
		unsigned int	i;
		int		found;
		time_t		chtime;
		char const	*filename;
		glob_t		files;

		DEBUG2("detail (%s): Polling for detail file", data->name);

		memset(&files, 0, sizeof(files));
		if (glob(data->filename, 0, NULL, &files) != 0) {
		noop:
			globfree(&files);
			return 0;
		}

		/*
		 *	Loop over the glob'd files, looking for the
		 *	oldest one.
		 */
		chtime = 0;
		found = -1;
		for (i = 0; i < files.gl_pathc; i++) {
			if (stat(files.gl_pathv[i], &st) < 0) continue;

			if ((i == 0) || (st.st_ctime < chtime)) {
				chtime = st.st_ctime;
				found = i;
			}
		}

		if (found < 0) goto noop;

		/*
		 *	Rename detail to detail.work
		 */
		filename = files.gl_pathv[found];

		DEBUG("detail (%s): Renaming %s -> %s", data->name, filename, data->filename_work);
		if (rename(filename, data->filename_work) < 0) {
			ERROR("detail (%s): Failed renaming %s to %s: %s",
			      data->name, filename, data->filename_work, fr_syserror(errno));
			goto noop;
		}

		globfree(&files);	/* Shouldn't be using anything in files now */

		/*
		 *	And try to open the filename.
		 */
		data->work_fd = open(data->filename_work, O_RDWR);
		if (data->work_fd < 0) {
			ERROR("detail (%s): Failed opening %s: %s",
			      data->name, data->filename_work, fr_syserror(errno));
			return 0;
		}
#endif
	} /* else detail.work existed, and we opened it */

	rad_assert(data->vps == NULL);
	rad_assert(data->fp == NULL);

	data->file_state = STATE_UNLOCKED;

	data->client_ip.af = AF_UNSPEC;
	data->timestamp = 0;
	data->offset = data->last_offset = data->timestamp_offset = 0;
	data->packets = 0;
	data->tries = 0;
	data->done_entry = false;

	return 1;
}


/*
 *	FIXME: add a configuration "exit when done" so that the detail
 *	file reader can be used as a one-off tool to update stuff.
 *
 *	The time sequence for reading from the detail file is:
 *
 *	t_0		signalled that the server is idle, and we
 *			can read from the detail file.
 *
 *	t_rtt		the packet has been processed successfully,
 *			wait for t_delay to enforce load factor.
 *
 *	t_rtt + t_delay wait for signal that the server is idle.
 *
 */
static int detail_recv(rad_listen_t *listener)
{
	char c = 0;
	ssize_t rcode;
	RADIUS_PACKET *packet;
	listen_detail_t *data = listener->data;
	RAD_REQUEST_FUNP fun = NULL;

	/*
	 *	Block until there's a packet ready.
	 */
	rcode = read(data->master_pipe[0], &packet, sizeof(packet));
	if (rcode <= 0) return rcode;

	rad_assert(packet != NULL);

	switch (packet->code) {
	case FR_CODE_ACCOUNTING_REQUEST:
		fun = rad_accounting;
		break;

	case FR_CODE_COA_REQUEST:
	case FR_CODE_DISCONNECT_REQUEST:
		fun = rad_coa_recv;
		break;

	default:
		data->entry_state = STATE_REPLIED;
		goto signal_thread;
	}

	if (!request_receive(NULL, listener, packet, &data->detail_client, fun)) {
		data->entry_state = STATE_NO_REPLY;	/* try again later */

	signal_thread:
		fr_radius_free(&packet);
		if (write(data->child_pipe[1], &c, 1) < 0) {
			ERROR("detail (%s): Failed writing ack to reader thread: %s", data->name,
			      fr_syserror(errno));
		}
	}

	/*
	 *	Wait for the child thread to write an answer to the pipe
	 */
	return 0;
}

static RADIUS_PACKET *detail_poll(rad_listen_t *listener)
{
	char		key[256], op[8], value[1024];
	vp_cursor_t	cursor;
	VALUE_PAIR	*vp;
	RADIUS_PACKET	*packet;
	char		buffer[2048];
	listen_detail_t *data = listener->data;

	switch (data->file_state) {
	case STATE_UNOPENED:
open_file:
		rad_assert(data->work_fd < 0);

		if (!detail_open(listener)) return NULL;

		rad_assert(data->file_state == STATE_UNLOCKED);
		rad_assert(data->work_fd >= 0);

		/* FALL-THROUGH */

	/*
	 *	Try to lock fd.  If we can't, return.
	 *	If we can, continue.  This means that
	 *	the server doesn't block while waiting
	 *	for the lock to open...
	 */
	case STATE_UNLOCKED:
		/*
		 *	Note that we do NOT block waiting for
		 *	the lock.  We've re-named the file
		 *	above, so we've already guaranteed
		 *	that any *new* detail writer will not
		 *	be opening this file.  The only
		 *	purpose of the lock is to catch a race
		 *	condition where the execution
		 *	"ping-pongs" between radiusd &
		 *	radrelay.
		 */
		if (rad_lockfd_nonblock(data->work_fd, 0) < 0) {
			/*
			 *	Close the FD.  The main loop
			 *	will wake up in a second and
			 *	try again.
			 */
			close(data->work_fd);
			data->fp = NULL;
			data->work_fd = -1;
			data->file_state = STATE_UNOPENED;
			return NULL;
		}

		/*
		 *	Only open for writing if we're
		 *	marking requests as completed.
		 */
		data->fp = fdopen(data->work_fd, data->track ? "r+" : "r");
		if (!data->fp) {
			ERROR("detail (%s): FATAL: Failed to re-open detail file: %s",
			      data->name, fr_syserror(errno));
			fr_exit(1);
		}

		/*
		 *	Look for the header
		 */
		data->file_state = STATE_PROCESSING;
		data->entry_state = STATE_HEADER;
		data->delay_time = USEC;
		data->vps = NULL;
		break;

		/*
		 *	Go to the next switch statement.
		 */
	case STATE_PROCESSING:
		break;
	}


	switch (data->entry_state) {
	case STATE_HEADER:
	do_header:
		data->done_entry = false;
		data->timestamp_offset = 0;

		data->tries = 0;
		if (!data->fp) {
			data->file_state = STATE_UNOPENED;
			goto open_file;
		}

		{
			struct stat buf;

			if (fstat(data->work_fd, &buf) < 0) {
				ERROR("detail (%s): Failed to stat detail file: %s",
				      data->name, fr_syserror(errno));

				goto cleanup;
			}
			if (((off_t) ftell(data->fp)) == buf.st_size) {	//-V595
				goto cleanup;
			}
		}

		/*
		 *	End of file.  Delete it, and re-set
		 *	everything.
		 */
		if (feof(data->fp)) {
		cleanup:
			DEBUG("detail (%s): Unlinking %s", data->name, data->filename_work);
			unlink(data->filename_work);
			if (data->fp) fclose(data->fp);
			data->fp = NULL;
			data->work_fd = -1;
			data->file_state = STATE_UNOPENED;
			rad_assert(data->vps == NULL);

			if (data->one_shot) {
				INFO("detail (%s): Finished reading \"one shot\" detail file - Exiting", data->name);
				radius_signal_self(RADIUS_SIGNAL_SELF_EXIT);
			}

			return NULL;
		}

		/*
		 *	Else go read something.
		 */
		break;

	/*
	 *	Read more value-pair's, unless we're
	 *	at EOF.  In that case, queue whatever
	 *	we have.
	 */
	case STATE_VPS:
		if (data->fp && !feof(data->fp)) break;
		data->entry_state = STATE_QUEUED;

		/* FALL-THROUGH */

	case STATE_QUEUED:
		goto alloc_packet;

	/*
	 *	Periodically check what's going on.
	 *	If the request is taking too long,
	 *	retry it.
	 */
	case STATE_RUNNING:
		if (time(NULL) < (data->running + (int)data->retry_interval)) {
			return NULL;
		}

		DEBUG("detail (%s): No response to detail request.  Retrying", data->name);
		/* FALL-THROUGH */

	/*
	 *	If there's no reply, keep
	 *	retransmitting the current packet
	 *	forever.
	 */
	case STATE_NO_REPLY:
		data->entry_state = STATE_QUEUED;
		goto alloc_packet;

	/*
	 *	We have a reply.  Clean up the old
	 *	request, and go read another one.
	 */
	case STATE_REPLIED:
		if (data->track) {
			rad_assert(data->fp != NULL);

			if (fseek(data->fp, data->timestamp_offset, SEEK_SET) < 0) {
				WARN("detail (%s): Failed seeking to timestamp offset: %s",
				     data->name, fr_syserror(errno));
			} else if (fwrite("\tDone", 1, 5, data->fp) < 5) {
				WARN("detail (%s): Failed marking request as done: %s",
				     data->name, fr_syserror(errno));
			} else if (fflush(data->fp) != 0) {
				WARN("detail (%s): Failed flushing marked detail file to disk: %s",
				     data->name, fr_syserror(errno));
			}

			if (fseek(data->fp, data->offset, SEEK_SET) < 0) {
				WARN("detail (%s): Failed seeking to next detail request: %s",
				     data->name, fr_syserror(errno));
			}
		}

		fr_pair_list_free(&data->vps);
		data->entry_state = STATE_HEADER;
		goto do_header;
	}

	fr_pair_cursor_init(&cursor, &data->vps);

	/*
	 *	Read a header, OR a value-pair.
	 */
	while (fgets(buffer, sizeof(buffer), data->fp)) {
		data->last_offset = data->offset;
		data->offset = ftell(data->fp); /* for statistics */

		/*
		 *	Badly formatted file: delete it.
		 *
		 *	FIXME: Maybe flag an error?
		 */
		if (!strchr(buffer, '\n')) {
			fr_pair_list_free(&data->vps);
			goto cleanup;
		}

		/*
		 *	We're reading VP's, and got a blank line.
		 *	Queue the packet.
		 */
		if ((data->entry_state == STATE_VPS) &&
		    (buffer[0] == '\n')) {
			data->entry_state = STATE_QUEUED;
			break;
		}

		/*
		 *	Look for date/time header, and read VP's if
		 *	found.  If not, keep reading lines until we
		 *	find one.
		 */
		if (data->entry_state == STATE_HEADER) {
			int y;

			if (sscanf(buffer, "%*s %*s %*d %*d:%*d:%*d %d", &y)) {
				data->entry_state = STATE_VPS;
			}
			continue;
		}

		/*
		 *	We have a full "attribute = value" line.
		 *	If it doesn't look reasonable, skip it.
		 *
		 *	FIXME: print an error for badly formatted attributes?
		 */
		if (sscanf(buffer, "%255s %7s %1023s", key, op, value) != 3) {
			WARN("detail (%s): Skipping badly formatted line %s", data->name, buffer);
			continue;
		}

		/*
		 *	Should be =, :=, +=, ...
		 */
		if (!strchr(op, '=')) {
			WARN("detail (%s): Skipping line without operator - %s", data->name, buffer);
			continue;
		}

		/*
		 *	Skip non-protocol attributes.
		 */
		if (!strcasecmp(key, "Request-Authenticator")) continue;

		/*
		 *	Set the original client IP address, based on
		 *	what's in the detail file.
		 *
		 *	Hmm... we don't set the server IP address.
		 *	or port.  Oh well.
		 */
		if (!strcasecmp(key, "Client-IP-Address")) {
			data->client_ip.af = AF_INET;
			if (fr_inet_hton(&data->client_ip, AF_INET, value, false) < 0) {
				ERROR("detail (%s): Failed parsing Client-IP-Address", data->name);

				fr_pair_list_free(&data->vps);
				goto cleanup;
			}
			continue;
		}

		/*
		 *	The original time at which we received the
		 *	packet.  We need this to properly calculate
		 *	Acct-Delay-Time.
		 */
		if (!strcasecmp(key, "Timestamp")) {
			data->timestamp = atoi(value);
			data->timestamp_offset = data->last_offset;

			vp = fr_pair_afrom_num(data, 0, FR_PACKET_ORIGINAL_TIMESTAMP);
			if (vp) {
				vp->vp_date = (uint32_t) data->timestamp;
				vp->type = VT_DATA;
				fr_pair_cursor_append(&cursor, vp);
			}
			continue;
		}

		if (!strcasecmp(key, "Donestamp")) {
			data->timestamp = atoi(value);
			data->done_entry = true;
			continue;
		}

		DEBUG3("detail (%s): Trying to read VP from line - %s", data->name, buffer);

		/*
		 *	Read one VP.
		 *
		 *	FIXME: do we want to check for non-protocol
		 *	attributes like radsqlrelay does?
		 */
		vp = NULL;
		if ((fr_pair_list_afrom_str(data, buffer, &vp) > 0) &&
		    (vp != NULL)) {
			fr_pair_cursor_merge(&cursor, vp);
		} else {
			WARN("detail (%s): Failed reading VP from line - %s", data->name, buffer);
		}
	}

	/*
	 *	Some kind of error.
	 *
	 *	FIXME: Leave the file in-place, and warn the
	 *	administrator?
	 */
	if (ferror(data->fp)) goto cleanup;

	data->tries = 0;
	data->packets++;

	/*
	 *	Process the packet.
	 */
 alloc_packet:
	if (data->done_entry) {
		DEBUG2("detail (%s): Skipping record for timestamp %lu", data->name, data->timestamp);
		fr_pair_list_free(&data->vps);
		data->entry_state = STATE_HEADER;
		goto do_header;
	}

	data->tries++;

	/*
	 *	The writer doesn't check that the record was
	 *	completely written.  If the disk is full, this can
	 *	result in a truncated record.  When that happens,
	 *	treat it as EOF.
	 */
	if (data->entry_state != STATE_QUEUED) {
		ERROR("detail (%s): Truncated record: treating it as EOF for detail file %s",
		      data->name, data->filename_work);
		fr_pair_list_free(&data->vps);
		goto cleanup;
	}

	/*
	 *	We're done reading the file, but we didn't read
	 *	anything.  Clean up, and don't return anything.
	 */
	if (!data->vps) {
		WARN("detail (%s): Read empty packet from file %s",
		     data->name, data->filename_work);
		data->entry_state = STATE_HEADER;
		if (!data->fp || feof(data->fp)) goto cleanup;
		return NULL;
	}

	/*
	 *	Allocate the packet.  If we fail, it's a serious
	 *	problem.
	 */
	packet = fr_radius_alloc(NULL, true);
	if (!packet) {
		ERROR("detail (%s): FATAL: Failed allocating memory for detail", data->name);
		fr_exit(1);
	}

	memset(packet, 0, sizeof(*packet));
	packet->sockfd = -1;
	packet->src_ipaddr.af = AF_INET;
	packet->src_ipaddr.addr.v4.s_addr = htonl(INADDR_NONE);

	/*
	 *	If everything's OK, this is a waste of memory.
	 *	Otherwise, it lets us re-send the original packet
	 *	contents, unmolested.
	 */
	packet->vps = fr_pair_list_copy(packet, data->vps);

	packet->code = FR_CODE_ACCOUNTING_REQUEST;
	vp = fr_pair_find_by_num(packet->vps, 0, FR_PACKET_TYPE, TAG_ANY);
	if (vp) packet->code = vp->vp_uint32;

	gettimeofday(&packet->timestamp, NULL);

	/*
	 *	Remember where it came from, so that we don't
	 *	proxy it to the place it came from...
	 */
	if (data->client_ip.af != AF_UNSPEC) {
		packet->src_ipaddr = data->client_ip;
	}

	vp = fr_pair_find_by_num(packet->vps, 0, FR_PACKET_SRC_IP_ADDRESS, TAG_ANY);
	if (vp) {
		packet->src_ipaddr.af = AF_INET;
		packet->src_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
		packet->src_ipaddr.prefix = 32;
	} else {
		vp = fr_pair_find_by_num(packet->vps, 0, FR_PACKET_SRC_IPV6_ADDRESS, TAG_ANY);
		if (vp) {
			packet->src_ipaddr.af = AF_INET6;
			memcpy(&packet->src_ipaddr.addr.v6,
			       &vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
			packet->src_ipaddr.prefix = 128;
		}
	}

	vp = fr_pair_find_by_num(packet->vps, 0, FR_PACKET_DST_IP_ADDRESS, TAG_ANY);
	if (vp) {
		packet->dst_ipaddr.af = AF_INET;
		packet->dst_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
		packet->dst_ipaddr.prefix = 32;
	} else {
		vp = fr_pair_find_by_num(packet->vps, 0, FR_PACKET_DST_IPV6_ADDRESS, TAG_ANY);
		if (vp) {
			packet->dst_ipaddr.af = AF_INET6;
			memcpy(&packet->dst_ipaddr.addr.v6,
			       &vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
			packet->dst_ipaddr.prefix = 128;
		}
	}

	/*
	 *	Generate packet ID, ports, IP via a counter.
	 */
	packet->id = data->counter & 0xff;
	packet->src_port = 1024 + ((data->counter >> 8) & 0xff);
	packet->dst_port = 1024 + ((data->counter >> 16) & 0xff);

	packet->dst_ipaddr.af = AF_INET;
	packet->dst_ipaddr.addr.v4.s_addr = htonl((INADDR_LOOPBACK & ~0xffffff) | ((data->counter >> 24) & 0xff));

	/*
	 *	Create / update accounting attributes.
	 */
	if (packet->code == FR_CODE_ACCOUNTING_REQUEST) {
		/*
		 *	Prefer the Event-Timestamp in the packet, if it
		 *	exists.  That is when the event occurred, whereas the
		 *	"Timestamp" field is when we wrote the packet to the
		 *	detail file, which could have been much later.
		 */
		vp = fr_pair_find_by_num(packet->vps, 0, FR_EVENT_TIMESTAMP, TAG_ANY);
		if (vp) {
			data->timestamp = vp->vp_uint32;
		}

		/*
		 *	Look for Acct-Delay-Time, and update
		 *	based on Acct-Delay-Time += (time(NULL) - timestamp)
		 */
		vp = fr_pair_find_by_num(packet->vps, 0, FR_ACCT_DELAY_TIME, TAG_ANY);
		if (!vp) {
			vp = fr_pair_afrom_num(packet, 0, FR_ACCT_DELAY_TIME);
			rad_assert(vp != NULL);
			fr_pair_add(&packet->vps, vp);
		}
		if (data->timestamp != 0) {
			vp->vp_uint32 += time(NULL) - data->timestamp;
		}
	}

	/*
	 *	Set the transmission count.
	 */
	vp = fr_pair_find_by_num(packet->vps, 0, FR_PACKET_TRANSMIT_COUNTER, TAG_ANY);
	if (!vp) {
		vp = fr_pair_afrom_num(packet, 0, FR_PACKET_TRANSMIT_COUNTER);
		rad_assert(vp != NULL);
		fr_pair_add(&packet->vps, vp);
	}
	vp->vp_uint32 = data->tries;

	data->entry_state = STATE_RUNNING;
	data->running = packet->timestamp.tv_sec;

	return packet;
}

/*
 *	Free detail-specific stuff.
 */
static int _detail_free(listen_detail_t *data)
{
	if (!check_config) {
		ssize_t ret;
		void *arg = NULL;

		/*
		 *	Mark the child pipes as unusable
		 */
		close(data->child_pipe[0]);
		close(data->child_pipe[1]);
		data->child_pipe[0] = -1;

		/*
		 *	Tell it to stop (interrupting its sleep)
		 */
		pthread_kill(data->pthread_id, SIGTERM);

		/*
		 *	Wait for it to acknowledge that it's stopped.
		 */
		ret = read(data->master_pipe[0], &arg, sizeof(arg));
		if (ret < 0) {
			ERROR("detail (%s): Reader thread exited without informing the master: %s",
			      data->name, fr_syserror(errno));
		} else if (ret != sizeof(arg)) {
			ERROR("detail (%s): Invalid thread pointer received from reader thread during exit",
			      data->name);
			ERROR("detail (%s): Expected %zu bytes, got %zi bytes", data->name, sizeof(arg), ret);
		}

		close(data->master_pipe[0]);
		close(data->master_pipe[1]);

		if (arg) pthread_join(data->pthread_id, &arg);
	}

	if (data->fp != NULL) {
		fclose(data->fp);
		data->fp = NULL;
	}

	return 0;
}


static int detail_print(rad_listen_t const *this, char *buffer, size_t bufsize)
{
	if (!this->server) {
		return snprintf(buffer, bufsize, "%s",
				((listen_detail_t *)(this->data))->filename);
	}

	return snprintf(buffer, bufsize, "detail file %s as server %s",
			((listen_detail_t *)(this->data))->filename,
			this->server);
}


/*
 *	Delay while waiting for a file to be ready
 */
static int detail_delay(listen_detail_t *data)
{
	int delay = (data->poll_interval - 1) * USEC;

	/*
	 *	Add +/- 0.25s of jitter
	 */
	delay += (USEC * 3) / 4;
	delay += fr_rand() % (USEC / 2);

	DEBUG2("detail (%s): Detail listener state %s waiting %d.%06d sec",
	       data->name,
	       fr_int2str(state_names, data->entry_state, "?"),
	       (delay / USEC), delay % USEC);

	return delay;
}

static int detail_encode(rad_listen_t *this, REQUEST *request)
{
	listen_detail_t *data = this->data;

	RDEBUG2("detail (%s): Finished %s packet", data->name,
		fr_packet_codes[request->packet->code]);

	return 0;
}

static int detail_decode(rad_listen_t *this, REQUEST *request)
{
	listen_detail_t *data = this->data;

	if (DEBUG_ENABLED2) {
		RDEBUG2("detail (%s): Read %s packet from %s", data->name,
			fr_packet_codes[request->packet->code], data->filename_work);
		rdebug_pair_list(L_DBG_LVL_1, request, request->packet->vps, NULL);
	}

	return 0;
}


static void *detail_handler_thread(void *arg)
{
	char c;
	rad_listen_t *this = arg;
	listen_detail_t *data = this->data;

	while (true) {
		RADIUS_PACKET *packet;

		while ((packet = detail_poll(this)) == NULL) {
			usleep(detail_delay(data));

			/*
			 *	If we're supposed to exit then tell
			 *	the master thread we've exited.
			 */
			if (data->child_pipe[0] < 0) {
				packet = NULL;
				if (write(data->master_pipe[1], &packet, sizeof(packet)) < 0) {
					ERROR("detail (%s): Failed writing exit status to master: %s",
					      data->name, fr_syserror(errno));
				}
				return NULL;
			}
		}

		/*
		 *	Keep retrying forever.
		 *
		 *	FIXME: cap the retries.
		 */
		do {
			if (write(data->master_pipe[1], &packet, sizeof(packet)) < 0) {
				ERROR("detail (%s): Failed passing detail packet pointer to master: %s",
				      data->name, fr_syserror(errno));
			}

			if (read(data->child_pipe[0], &c, 1) < 0) {
				ERROR("detail (%s): Failed getting detail packet ack from master: %s",
				      data->name, fr_syserror(errno));
				break;
			}

			if (data->delay_time > 0) usleep(data->delay_time);

			packet = detail_poll(this);
			if (!packet) break;
		} while (data->entry_state != STATE_REPLIED);
	}

	return NULL;
}


static const CONF_PARSER detail_config[] = {
	{ FR_CONF_OFFSET("detail", FR_TYPE_FILE_OUTPUT | FR_TYPE_DEPRECATED, listen_detail_t, filename) },
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_OUTPUT | FR_TYPE_REQUIRED, listen_detail_t, filename) },
	{ FR_CONF_OFFSET("load_factor", FR_TYPE_UINT32, listen_detail_t, load_factor), .dflt = STRINGIFY(10) },
	{ FR_CONF_OFFSET("poll_interval", FR_TYPE_UINT32, listen_detail_t, poll_interval), .dflt = STRINGIFY(1) },
	{ FR_CONF_OFFSET("retry_interval", FR_TYPE_UINT32, listen_detail_t, retry_interval), .dflt = STRINGIFY(30) },
	{ FR_CONF_OFFSET("one_shot", FR_TYPE_BOOL, listen_detail_t, one_shot), .dflt = "no" },
	{ FR_CONF_OFFSET("track", FR_TYPE_BOOL, listen_detail_t, track), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Parse a detail section.
 */
static int detail_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int		rcode;
	listen_detail_t *data;
	RADCLIENT	*client;
	char		buffer[2048];

	data = this->data;

	if (cf_section_rules_push(cs, detail_config) < 0) return -1;

	rcode = cf_section_parse(data, data, cs);
	if (rcode < 0) {
		cf_log_err(cs, "Failed parsing listen section");
		return -1;
	}

	data->name = cf_section_name2(cs);
	if (!data->name) data->name = data->filename;

	/*
	 *	We don't do duplicate detection for "detail" sockets.
	 */
	this->nodup = true;

	if (!data->filename) {
		cf_log_err(cs, "No detail file specified in listen section");
		return -1;
	}

	FR_INTEGER_BOUND_CHECK("load_factor", data->load_factor, >=, 1);
	FR_INTEGER_BOUND_CHECK("load_factor", data->load_factor, <=, 100);

	FR_INTEGER_BOUND_CHECK("poll_interval", data->poll_interval, >=, 1);
	FR_INTEGER_BOUND_CHECK("poll_interval", data->poll_interval, <=, 60);

	FR_INTEGER_BOUND_CHECK("retry_interval", data->retry_interval, >=, 4);
	FR_INTEGER_BOUND_CHECK("retry_interval", data->retry_interval, <=, 3600);

	/*
	 *	Only checking the config.  Don't start threads or anything else.
	 */
	if (check_config) return 0;

	/*
	 *	If the filename is a glob, use "detail.work" as the
	 *	work file name.
	 */
	if ((strchr(data->filename, '*') != NULL) ||
	    (strchr(data->filename, '[') != NULL)) {
		char *p;

#ifndef HAVE_GLOB_H
		WARN("detail (%s): File \"%s\" appears to use file globbing, but it is not supported on this system",
		     data->name, data->filename);
#endif
		strlcpy(buffer, data->filename, sizeof(buffer));
		p = strrchr(buffer, FR_DIR_SEP);
		if (p) {
			p[1] = '\0';
		} else {
			buffer[0] = '\0';
		}

		/*
		 *	Globbing cannot be done across directories.
		 */
		if ((strchr(buffer, '*') != NULL) ||
		    (strchr(buffer, '[') != NULL)) {
			cf_log_err(cs, "Wildcard directories are not supported");
			return -1;
		}

		strlcat(buffer, "detail.work",
			sizeof(buffer) - strlen(buffer));

	} else {
		snprintf(buffer, sizeof(buffer), "%s.work", data->filename);
	}

	data->filename_work = talloc_strdup(data, buffer);

	data->work_fd = -1;
	data->vps = NULL;
	data->fp = NULL;
	data->file_state = STATE_UNOPENED;
	data->entry_state = STATE_HEADER;
	data->delay_time = data->poll_interval * USEC;
	data->signal = 1;

	/*
	 *	Initialize the fake client.
	 */
	client = &data->detail_client;
	memset(client, 0, sizeof(*client));
	client->ipaddr.af = AF_INET;
	client->ipaddr.addr.v4.s_addr = INADDR_NONE;
	client->ipaddr.prefix = 0;
	client->longname = client->shortname = data->filename;
	client->secret = client->shortname;
	client->nas_type = talloc_strdup(data, "none");	/* Part of 'data' not dynamically allocated */

	this->server_cs = cf_item_to_section(cf_parent(this->cs));
	client->server_cs = this->server_cs;

	return 0;
}

/*
 *	Open detail files
 */
static int detail_socket_open(UNUSED CONF_SECTION *cs, rad_listen_t *this)
{
	listen_detail_t *data;

	data = this->data;
	talloc_set_destructor(data, _detail_free);

	/*
	 *	Create the communication pipes.
	 */
	if (pipe(data->master_pipe) < 0) {
		ERROR("detail (%s): Error opening internal pipe: %s", data->name, fr_syserror(errno));
		fr_exit(1);
	}

	if (pipe(data->child_pipe) < 0) {
		ERROR("detail (%s): Error opening internal pipe: %s", data->name, fr_syserror(errno));
		fr_exit(1);
	}

	if (pthread_create(&data->pthread_id, NULL, detail_handler_thread, this) != 0) {
		ERROR("detail (%s): Error creating detail reader thread: %s", data->name, fr_syserror(errno));
		fr_exit(1);
	}

	this->fd = data->master_pipe[0];

	return 0;
}

extern rad_protocol_t proto_detail;
rad_protocol_t proto_detail = {
	.magic = RLM_MODULE_INIT,
	.name = "detail",
	.inst_size = sizeof(listen_detail_t),
	.tls = false,
	.parse = detail_parse,
	.open = detail_socket_open,
	.recv = detail_recv,
	.send = detail_send,
	.print = detail_print,
	.debug = common_packet_debug,
	.encode = detail_encode,
	.decode = detail_decode
};
