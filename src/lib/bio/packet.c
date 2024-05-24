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

/*
 *	Debounce functions to get to the right callback.
 */
int fr_bio_packet_write_blocked(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	my->write_blocked = true;

	return my->cb.write_blocked(my);
}

int fr_bio_packet_write_resume(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	my->write_blocked = false;

	return my->cb.write_resume(my);
}

int fr_bio_packet_read_blocked(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	my->read_blocked = true;

	return my->cb.read_blocked(my);
}

int fr_bio_packet_read_resume(fr_bio_t *bio)
{
	fr_bio_packet_t *my = bio->uctx;

	my->read_blocked = false;

	return my->cb.read_resume(my);
}
