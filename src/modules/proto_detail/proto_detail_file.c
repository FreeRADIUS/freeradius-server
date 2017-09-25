/*
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
 */

/**
 * $Id$
 * @file proto_detail_file.c
 * @brief Detail handler for files
 *
 * @copyright 2016 The FreeRADIUS server project.
 * @copyright 2016 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_detail.h"

#include <fcntl.h>

typedef struct {
	fr_time_t			timestamp;		//!< when we read the entry.
	off_t				done_offset;		//!< where we're tracking the status
} fr_detail_entry_t;

typedef struct {
	proto_detail_t	const		*parent;		//!< The module that spawned us!
	char const			*name;			//!< debug name for printing

	int				fd;			//!< file descriptor

	fr_event_list_t			*el;			//!< for various timers
	fr_schedule_t			*sc;			//!< the scheduler, where we insert new readers

	char const			*filename;     		//!< file name, usually with wildcards
	char const			*filename_work;		//!< work file name

	bool				vnode;			//!< are we the vnode instance, or the filename_work instance?
	bool				eof;			//!< are we at EOF on reading?

	off_t				header_offset;		//!< offset of the current header we're reading
	off_t				read_offset;		//!< where we're reading from in filename_work
} proto_detail_file_t;

static const CONF_PARSER file_listen_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_STRING | FR_TYPE_REQUIRED, proto_detail_file_t, filename ) },

	CONF_PARSER_TERMINATOR
};


static int mod_decode(UNUSED void const *instance, REQUEST *request, UNUSED uint8_t *const data, UNUSED size_t data_len)
{

//	fr_detail_entry_t const			*track = request->async->packet_ctx;

	request->root = &main_config;
	REQUEST_VERIFY(request);

	return 0;
}

/*
 *	@todo - put these into configuration!
 */
static uint32_t priorities[FR_MAX_PACKET_CODE] = {
	[FR_CODE_ACCESS_REQUEST] = PRIORITY_HIGH,
	[FR_CODE_ACCOUNTING_REQUEST] = PRIORITY_LOW,
	[FR_CODE_COA_REQUEST] = PRIORITY_NORMAL,
	[FR_CODE_DISCONNECT_REQUEST] = PRIORITY_NORMAL,
	[FR_CODE_STATUS_SERVER] = PRIORITY_NOW,
};

static ssize_t mod_read(void *instance, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority)
{
	proto_detail_file_t		*inst = talloc_get_type_abort(instance, proto_detail_file_t);

	ssize_t				data_size;
	size_t				packet_len;
	fr_detail_entry_t		*track;
	uint8_t				*partial, *end, *next, *p;
	size_t				room;

	rad_assert(*leftover < buffer_len);

	/*
	 *	There will be "leftover" bytes left over in the buffer
	 *	from any previous read.  At the start of the file,
	 *	"leftover" will be zero.
	 */
        partial= buffer + *leftover;
	room = buffer_len - *leftover;

	/*
	 *	Try to read as much data as possible.
	 */
	if (!inst->eof) {
		data_size = read(inst->fd, partial, room);
		if (data_size < 0) return -1;

		/*
		 *	Remember the read offset, or EOF.
		 */
		if (data_size > 0) {
			inst->read_offset = lseek(inst->fd, 0, SEEK_CUR);
		} else {
			inst->eof = true;
		}
	} else {
		/*
		 *	We didn't read any more data.
		 */
		data_size = 0;
	}

	/*
	 *	Remember where the end of all of the data is.
	 */
	end = partial + data_size;

	/*
	 *	Look for "end of record" marker.  We've already
	 *	searched "leftover" bytes for \n\n, so we only have to
	 *	search the remaining bytes.
	 *
	 *	We MIGHT have the last character of the previously
	 *	read data as \n, so we back up one character here.
	 *	That lets us catch "\n\n" which crosses a read()
	 *	boundary.
	 */
	if (*leftover > 0) partial--;

	/*
	 *	Note that all of the data MUST be printable, and raw
	 *	LFs are forbidden in attribute contents.
	 */
	next = NULL;
	for (p = partial; p < end; p++) {
		if (p[0] != '\n') continue;
		if ((p + 1) == end) break; /* no more data */
		if (p[1] == '\n') {
			next = p + 2;
			break;
		}
	}

	/*
	 *	If there is a next record, remember how large this
	 *	record is, and update "leftover" bytes.
	 */
	if (next) {
		packet_len = next - buffer;
		*leftover = end - next;

	} else if (!inst->eof) {
		/*
		 *	We're not at EOF, and there is no "next"
		 *	entry.  Remember all of the leftover data in
		 *	the buffer, and ask the caller to call us when
		 *	there's more data.
		 */
		*leftover = end - buffer;
		return 0;

	} else {
		/*
		 *	Else we're at EOF, it's OK to miss an "end of
		 *	record" marker.  We just eat all of the
		 *	remaining data.
		 */
		packet_len = end - buffer;
		*leftover = 0;
	}

	/*
	 *	Allocate the tracking entry.
	 */
	track = talloc(instance, fr_detail_entry_t);
	track->timestamp = fr_time();

	track->done_offset = 0;

	/*
	 *	Search for the "Timestamp" attribute.  We overload
	 *	that to track which entries have been used.
	 */
	end = buffer + packet_len;
	for (p = buffer; p < end; p++) {
		if (p[0] != '\n') continue;


		if (((end - p) >= 5) &&
		    (memcmp(p, "\tDone", 5) == 0)) {
			/*
			 *	@todo - try to grab another packet
			 *	from the buffer.  If there is a
			 *	packet, memmove() the data to the
			 *	start of the buffer, which is what
			 *	fr_network_read() expects to see.
			 */
			rad_assert(0 == 1);
		}

		if (((end - p) > 10) &&
		    (memcmp(p, "\tTimestamp", 10) == 0)) {
			p += 2;
			track->done_offset = inst->header_offset + (p - buffer);
		}
	}

	/*
	 *	Too big?  Ignore it.
	 */
	if (packet_len > inst->parent->max_packet_size) {
		DEBUG("Ignoring 'too large' entry at offset %llu of %s",
		      inst->header_offset, inst->filename_work);
		DEBUG("Entry size %lu is greater than allowed maximum %u",
		      packet_len, inst->parent->max_packet_size);
		return 0;
	}

	/*
	 *	We've read one more packet.
	 */
	inst->header_offset += packet_len;

	*packet_ctx = track;
	*recv_time = &track->timestamp;
	*priority = priorities[buffer[0]];

	/*
	 *	We're done reading the file, but not the buffer.  Back
	 *	up one byte so that the network code will try to read
	 *	the byte again, which lets us then finish reading the
	 *	buffer.
	 *
	 *	We could make the network code smarter, to call our
	 *	read() routine again if there are leftover bytes.  But
	 *	that logic doesn't integrate well into the event loop.
	 *	So this hack is the next best thing.
	 */
	if (inst->eof && (*leftover > 0)) {
		off_t hack;

		hack = inst->read_offset - 1;
		(void) lseek(inst->fd, 0, SEEK_SET);
	}

	return packet_len;
}

static ssize_t mod_write(void *instance, void *packet_ctx,
			 UNUSED fr_time_t request_time, uint8_t *buffer, size_t buffer_len)
{
	proto_detail_file_t		*inst = talloc_get_type_abort(instance, proto_detail_file_t);
	fr_detail_entry_t		*track = packet_ctx;

	if (buffer_len < 1) return -1;

	if (buffer[0] == 0) {
		DEBUG3("Got Do-Not-Respond, not writing reply");
		talloc_free(track);
		return buffer_len;
	}

	/*
	 *	Seek to the entry, mark it as done, and then seek to
	 *	the point in the file where we were reading from.
	 */
	if (track->done_offset > 0) {
		(void) lseek(inst->fd, track->done_offset, SEEK_SET);
		(void) write(inst->fd, "Done", 4);
		(void) lseek(inst->fd, inst->read_offset, SEEK_SET);
	}

	/*
	 *	@todo - add a used / free pool for these
	 */
	talloc_free(track);

	return buffer_len;
}

/** Open a UDP listener for RADIUS
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_detail_file_t *inst = talloc_get_type_abort(instance, proto_detail_file_t);

	inst->fd = open(inst->filename_work, O_RDWR);
	if (inst->fd < 0) return -1;

	rad_assert(inst->name == NULL);
	inst->name = talloc_asprintf(inst, "detail working file %s", inst->filename_work);

	DEBUG("Listening om %s bound to virtual server %s",
	      inst->name, cf_section_name2(inst->parent->server_cs));

	return 0;
}

/** Get the file descriptor for this socket.
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_detail_file_t const *inst = talloc_get_type_abort_const(instance, proto_detail_file_t);

	return inst->fd;
}


/** Set the event list for a new socket
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @param[in] el the event list
 */
static void mod_event_list_set(void *instance, fr_event_list_t *el)
{
	proto_detail_file_t *inst;

	memcpy(&inst, &instance, sizeof(inst)); /* const issues */

	inst = talloc_get_type_abort(instance, proto_detail_file_t);

	inst->el = el;
}


static int mod_instantiate(UNUSED void *instance, UNUSED CONF_SECTION *cs)
{
//	proto_detail_file_t *inst = talloc_get_type_abort(instance, proto_detail_file_t);


	return 0;
}

static int mod_bootstrap(void *instance, UNUSED CONF_SECTION *cs)
{
	proto_detail_file_t	*inst = talloc_get_type_abort(instance, proto_detail_file_t);
	dl_instance_t const	*dl_inst;

	/*
	 *	Find the dl_instance_t holding our instance data
	 *	so we can find out what the parent of our instance
	 *	was.
	 */
	dl_inst = dl_instance_find(instance);
	rad_assert(dl_inst);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_detail_t);

	return 0;
}

static int mod_detach(void *instance)
{
	proto_detail_file_t	*inst = talloc_get_type_abort(instance, proto_detail_file_t);

	/*
	 *	@todo - have our OWN event loop for timers, and a
	 *	"copy timer from -> to, which means we only have to
	 *	delete our child event loop from the parent on close.
	 */

	close(inst->fd);
	return 0;
}


/** Private interface for use by proto_detail_file
 *
 */
extern fr_app_io_t proto_detail_file;
fr_app_io_t proto_detail_file = {
	.magic			= RLM_MODULE_INIT,
	.name			= "detail_file",
	.config			= file_listen_config,
	.inst_size		= sizeof(proto_detail_file_t),
	.detach			= mod_detach,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 65536,

	.open			= mod_open,
	.read			= mod_read,
	.decode			= mod_decode,
	.write			= mod_write,
	.fd			= mod_fd,
	.event_list_set		= mod_event_list_set,
};
