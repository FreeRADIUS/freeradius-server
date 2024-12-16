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
 * @file lib/bio/network.c
 * @brief BIO patricia trie filtering handlers
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/trie.h>

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/fd_priv.h>

#include <freeradius-devel/bio/network.h>

/** The network filtering bio
 */
typedef struct {
	FR_BIO_COMMON;

	fr_bio_read_t	discard;	//!< callback to run when discarding a packet due to filtering

	size_t		offset;		//!< where #fr_bio_fd_packet_ctx_t is stored

	fr_trie_t const	*trie;		//!< patricia trie for filtering
} fr_bio_network_t;

/** Read a UDP packet, and only return packets from allowed sources.
 *
 */
static ssize_t fr_bio_network_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	bool *value;
	fr_bio_network_t *my = talloc_get_type_abort(bio, fr_bio_network_t);
	fr_bio_fd_packet_ctx_t *addr;
	fr_bio_t *next;
	
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	rcode = next->read(next, packet_ctx, buffer, size);
	if (rcode <= 0) return rcode;

	if (!packet_ctx) return rcode;

	addr = fr_bio_fd_packet_ctx(my, packet_ctx);

	/*
	 *	Look up this particular source.  If it's not found, then we suppress this packet.
	 */
	value = fr_trie_lookup_by_key(my->trie,
				      &addr->socket.inet.src_ipaddr.addr, addr->socket.inet.src_ipaddr.prefix);
	if (value != FR_BIO_NETWORK_ALLOW) {
		if (my->discard) return my->discard(bio, packet_ctx, buffer, rcode);
		return 0;
	}

	return rcode;
}


/** Allocate a bio for filtering IP addresses
 *
 *  This is used for unconnected UDP bios, where we filter packets based on source IP address.
 *
 *  It is also used for accept bios, where we filter new connections based on source IP address.  The caller
 *  should chain this bio to the next FD bio, and then fr_bio_read() from the top-level bio.  The result will
 *  be filtered or "clean" FDs.
 *
 *  A patricia trie (but not the bio) could also be used in an haproxy "activate" callback, where the callback
 *  gets the haproxy socket info, and then checks if the source is allowed.  However, that patricia trie is a
 *  property of the main "accept" bio, and should be managed by the activate() callback for the haproxy bio.
 */
fr_bio_t *fr_bio_network_alloc(TALLOC_CTX *ctx, fr_ipaddr_t const *allow, fr_ipaddr_t const *deny,
			       fr_bio_read_t discard, fr_bio_t *next)
{
	fr_bio_network_t *my;
	fr_bio_t *fd;
	fr_bio_fd_info_t const *info;

	/*
	 *	We are only usable for FD bios.  We need to get "offset" into the packet_ctx, and we don't
	 *	want to have an API which allows for two different "offset" values to be passed to two
	 *	different bios.
	 */
	fd = NULL;

	/*
	 *	@todo - add an internal "type" to the bio?
	 */
	do {
		if (strcmp(talloc_get_name(next), "fr_bio_fd_t") == 0) {
			fd = next;
			break;
		}
	} while ((next = fr_bio_next(next)) != NULL);

	if (!fd) return NULL;

	info = fr_bio_fd_info(fd);
	fr_assert(info != NULL);

	/*
	 *	We can only filter connections for IP address families.
	 *
	 *	Unix domain sockets have to use a different method for filtering input connections.
	 */
	if (!((info->socket.af == AF_INET) || (info->socket.af == AF_INET6))) return NULL;

	/*
	 *	We can only be used for accept() sockets, or unconnected UDP sockets.
	 */
	switch (info->type) {
	case FR_BIO_FD_UNCONNECTED:
		break;

	case FR_BIO_FD_INVALID:
	case FR_BIO_FD_CONNECTED:
	case FR_BIO_FD_ACCEPTED:
		return NULL;

	case FR_BIO_FD_LISTEN:
		break;
	}

	my = talloc_zero(ctx, fr_bio_network_t);
	if (!my) return NULL;

	my->offset = ((fr_bio_fd_t *) fd)->offset;
	my->discard = discard;

	my->bio.write = fr_bio_next_write;
	my->bio.read = fr_bio_network_read;

	my->trie = fr_bio_network_trie_alloc(my, info->socket.af, allow, deny);
	if (!my->trie) {
		talloc_free(my);
		return NULL;
	}

	fr_bio_chain(&my->bio, next);

	return (fr_bio_t *) my;
}

/** Create a patricia trie for doing network filtering.
 *
 */
fr_trie_t *fr_bio_network_trie_alloc(TALLOC_CTX *ctx, int af, fr_ipaddr_t const *allow, fr_ipaddr_t const *deny)
{
	size_t i, num;
	fr_trie_t *trie;

	trie = fr_trie_alloc(ctx, NULL, NULL);
	if (!trie) return NULL;

	num = talloc_array_length(allow);
	fr_assert(num > 0);

	for (i = 0; i < num; i++) {
		bool *value;

		/*
		 *	Can't add v4 networks to a v6 socket, or vice versa.
		 */
		if (allow[i].af != af) {
			fr_strerror_printf("Address family in entry %zu - 'allow = %pV' "
					   "does not match 'ipaddr'", i + 1, fr_box_ipaddr(allow[i]));
		fail:
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Duplicates are bad.
		 */
		value = fr_trie_match_by_key(trie, &allow[i].addr, allow[i].prefix);
		if (value) {
			fr_strerror_printf("Cannot add duplicate entry 'allow = %pV'",
					   fr_box_ipaddr(allow[i]));
			goto fail;
		}

#if 0
		/*
		 *	Look for overlapping entries.  i.e. the networks MUST be disjoint.
		 *
		 *	Note that this catches 192.168.1/24 followed by 192.168/16, but NOT the other way
		 *	around.  The best fix is likely to add a flag to fr_trie_alloc() saying "we can only
		 *	have terminal fr_trie_user_t nodes"
		 */
		value = fr_trie_lookup_by_key(trie, &allow[i].addr, allow[i].prefix);
		if (network && (network->prefix <= allow[i].prefix)) {
			fr_strerror_printf("Cannot add overlapping entry 'allow = %pV'", fr_box_ipaddr(allow[i]));
			fr_strerror_const("Entry is completely enclosed inside of a previously defined network.");
			goto fail;
		}
#endif

		/*
		 *	Insert the network into the trie.  Lookups will return a bool ptr of allow / deny.
		 */
		if (fr_trie_insert_by_key(trie, &allow[i].addr, allow[i].prefix, FR_BIO_NETWORK_ALLOW) < 0) {
			fr_strerror_printf("Failed adding 'allow = %pV' to filtering rules", fr_box_ipaddr(allow[i]));
			return NULL;
		}
	}

	/*
	 *	And now check denied networks.
	 */
	num = talloc_array_length(deny);
	if (!num) return trie;

	/*
	 *	Since the default is to deny, you can only add a "deny" inside of a previous "allow".
	 */
	for (i = 0; i < num; i++) {
		bool *value;

		/*
		 *	Can't add v4 networks to a v6 socket, or vice versa.
		 */
		if (deny[i].af != af) {
			fr_strerror_printf("Address family in entry %zu - 'deny = %pV' "
					   "does not match 'ipaddr'", i + 1, fr_box_ipaddr(deny[i]));
			goto fail;
		}

		/*
		 *	Exact duplicates are forbidden.
		 */
		value = fr_trie_match_by_key(trie, &deny[i].addr, deny[i].prefix);
		if (value) {
			fr_strerror_printf("Cannot add duplicate entry 'deny = %pV'", fr_box_ipaddr(deny[i]));
			goto fail;
		}

		/*
		 *	A "deny" can only be within a previous "allow".
		 */
		value = fr_trie_lookup_by_key(trie, &deny[i].addr, deny[i].prefix);		
		if (!value) {
			fr_strerror_printf("The network in entry %zu - 'deny = %pV' is not "
					   "contained within a previous 'allow'", i + 1, fr_box_ipaddr(deny[i]));
			goto fail;
		}

		/*
		 *	A "deny" cannot be within a previous "deny".
		 */
		if (value == FR_BIO_NETWORK_DENY) {
			fr_strerror_printf("The network in entry %zu - 'deny = %pV' is overlaps "
					   "with another 'deny' rule", i + 1, fr_box_ipaddr(deny[i]));
			goto fail;
		}

		/*
		 *	Insert the rule into the trie.
		 */
		if (fr_trie_insert_by_key(trie, &deny[i].addr, deny[i].prefix, FR_BIO_NETWORK_DENY) < 0) {
			fr_strerror_printf("Failed adding 'deny = %pV' to filtering rules", fr_box_ipaddr(deny[i]));
			return NULL;
		}
	}

	return trie;
}
