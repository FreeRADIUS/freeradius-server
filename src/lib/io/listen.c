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
 *
 * @brief Listener ids
 * @file io/listen.c
 *
 * @copyright 2026 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/rb.h>

#include <pthread.h>

/*
 *	Every listener gets an id, unique for the life of the process, so
 *	one thread can name it to another without passing a pointer.
 *
 *	The table is filled while listeners are being set up, before the
 *	threads which read it start, so it has no lock.  Ids start at one.
 */
static fr_rb_tree_t		listen_by_id;
static pthread_once_t		listen_by_id_once = PTHREAD_ONCE_INIT;
static uint32_t			listen_next_id = 1;

static fr_cmp_ret_t listen_id_cmp(void const *one, void const *two)
{
	fr_listen_t const *a = one, *b = two;

	return CMP(a->id, b->id);
}

static void listen_by_id_init(void)
{
	(void) fr_rb_inline_init(&listen_by_id, fr_listen_t, id_node, listen_id_cmp, NULL);
}

/** Take a listener out of the table, as it is being freed
 *
 * The id itself is not reused: the counter only goes up.
 */
static int _listen_free(fr_listen_t *listen)
{
	(void) fr_rb_delete(&listen_by_id, listen);

	return 0;
}

/** Allocate a listener, and give it its id
 *
 * @param[in] ctx to allocate the listener in.
 * @param[in] listen_cs the listen section it came from.
 * @param[in] server_cs the virtual server it is bound to.
 * @param[in] app the application it belongs to, which encodes and decodes.
 * @param[in] app_instance the application's instance data.
 * @param[in] app_io the I/O path, which reads and writes.
 * @param[in] app_io_instance the I/O path's instance data.
 * @return the listener.
 */
fr_listen_t *fr_listen_alloc(TALLOC_CTX *ctx, CONF_SECTION *listen_cs, CONF_SECTION *server_cs,
			     fr_app_t const *app, void const *app_instance,
			     fr_app_io_t const *app_io, void const *app_io_instance)
{
	fr_listen_t *listen;

	(void) pthread_once(&listen_by_id_once, listen_by_id_init);

	MEM(listen = talloc_zero(ctx, fr_listen_t));
	talloc_set_destructor(listen, _listen_free);

	listen->cs = listen_cs;
	listen->server_cs = server_cs;
	listen->app = app;
	listen->app_instance = app_instance;
	listen->app_io = app_io;
	listen->app_io_instance = app_io_instance;

	listen->id = listen_next_id++;
	if (!fr_cond_assert_msg(fr_rb_insert(&listen_by_id, listen) == 0, "Duplicate listener id %u", listen->id)) {
		talloc_free(listen);
		return NULL;
	}

	return listen;
}

/** Allocate a socket of a listener
 *
 * @param[in] ctx to allocate the socket in.
 * @param[in] listen it is a socket of.
 * @return the socket.
 */
fr_listen_instance_t *fr_listen_instance_alloc(TALLOC_CTX *ctx, fr_listen_t *listen)
{
	fr_listen_instance_t *li;

	MEM(li = talloc_zero(ctx, fr_listen_instance_t));
	li->listen = listen;

	return li;
}

/** Free a socket's thread instance along with it
 *
 * For sockets whose thread instance is not a talloc child of the
 * socket.  Set as the destructor by whoever made the socket.
 */
int fr_io_listen_free(fr_listen_instance_t *li)
{
	if (!li->thread_instance) return 0;

	talloc_free(li->thread_instance);
	return 0;
}

/** Find a listener by its id
 *
 * @param[in] id of the listener.
 * @return
 *	- NULL if no listener has that id.
 *	- the listener otherwise.
 */
fr_listen_t *fr_listen_by_id(uint32_t id)
{
	fr_listen_t	*found = NULL;
	fr_listen_t	key = {
		.id = id
	};

	(void) pthread_once(&listen_by_id_once, listen_by_id_init);

	(void) fr_rb_find((void **)&found, &listen_by_id, &key);

	return found;
}
