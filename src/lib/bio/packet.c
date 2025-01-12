/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file lib/bio/packet.c
 * @brief BIO PACKET handlers
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/packet.h>

/** Inform all of the BIOs that the write is blocked.
 *
 *  This function should be set as the BIO layer "write_blocked" callback for all BIOs created as part
 *  of a #fr_bio_packet_t.  The application should also set bio->uctx=bio_packet for all BIOs.
 */
static int fr_bio_packet_write_blocked(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	/*
	 *	This function must be callable multiple times, as different portions of the BIOs can block at
	 *	different times.
	 */
	if (my->write_blocked) return 1;
	my->write_blocked = true;

	/*
	 *	The application doesn't want to know that it's blocked, so we just return.
	 */
	if (!my->cb.write_blocked) return 1;

	/*
	 *	Tell the application that IO is blocked.
	 */
	return my->cb.write_blocked(my);
}

static int fr_bio_packet_write_resume(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;
	fr_bio_t *next;
	int rcode;

	if (!my->write_blocked) return 1;
	my->write_blocked = false;

	/*
	 *	Inform each underlying BIO that it can be resumed.  Note that we might be called from a
	 *	lower-layer BIO, so we have to start from the top of the chain.
	 *
	 *	Note that if the callback returns 0, saying "I couldn't resume", then the BIO is still marked
	 *	as blocked.
	 */
	for (next = my->bio;
	     next != NULL;
	     next = fr_bio_next(next)) {

		if (!((fr_bio_common_t *) next)->priv_cb.write_resume) continue;

		rcode = ((fr_bio_common_t *) next)->priv_cb.write_resume(next);
		if (rcode < 0) return rcode;

		if (rcode == 0) {
			my->write_blocked = true;
			return 0;
		}
	}

	rcode = my->cb.write_resume(my);
	if (rcode < 0) return rcode;

	my->write_blocked = (rcode == 0);

	return rcode;
}

static int fr_bio_packet_read_blocked(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	my->read_blocked = true;

	return my->cb.read_blocked(my);
}

static int fr_bio_packet_read_resume(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	my->read_blocked = false;

	return my->cb.read_resume(my);
}

/** Called when a particular BIO is connected.
 *
 *  We see if we can connect the previous BIOs.
 */
void fr_bio_packet_connected(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	fr_assert(!my->connected);

	/*
	 *	Run the internal connected callback for previous BIOs.  If one returns "not connected", then
	 *	the packet BIO as a whole is not connected.
	 */
	while ((bio = fr_bio_prev(bio)) != NULL) {
		if (!((fr_bio_common_t *) bio)->priv_cb.connected) continue;

		/*
		 *	Tell this BIO that everything it needs has been connected.
		 */
		if (((fr_bio_common_t *) bio)->priv_cb.connected(bio) == 0) return;
	}

	/*
	 *	The top-level BIO is connected.  This means that the entire chain is now connected, and is
	 *	usable by the application.
	 */
	my->connected = true;

	/*
	 *	Stop any connection timeout.
	 */
	if (my->ev) talloc_const_free(&my->ev);

	/*
	 *	Tell the application that the packet BIO is now usable.
	 */
	my->cb.connected(my);
}

static void fr_bio_packet_shutdown(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	if (my->cb.shutdown) my->cb.shutdown(my);
	my->cb.shutdown = NULL;
}

static void fr_bio_packet_eof(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	if (my->cb.eof) my->cb.eof(my);
	my->cb.eof = NULL;
}

static void fr_bio_packet_failed(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	if (my->cb.failed) my->cb.failed(my);
	my->cb.failed = NULL;
}


void fr_bio_packet_init(fr_bio_packet_t *my)
{
	fr_bio_t *bio = my->bio;

	fr_bio_cb_funcs_t bio_cb = {
		.connected = fr_bio_packet_connected,
		.shutdown = fr_bio_packet_shutdown,
		.eof = fr_bio_packet_eof,
		.failed = fr_bio_packet_failed,

		.write_blocked = fr_bio_packet_write_blocked,
		.write_resume = fr_bio_packet_write_resume,
		.read_blocked = fr_bio_packet_read_blocked,
		.read_resume = fr_bio_packet_read_resume,
	};

	/*
	 *	Every participating BIO has us set as the bio->uctx, and we handle all BIO callbacks.
	 *
	 *	The application sets its own pointer my->uctx and sets itself via our callbacks.
	 */
	while (bio) {
		bio->uctx = my;

		fr_bio_cb_set(bio, &bio_cb);
		bio = fr_bio_next(bio);
	}
}
