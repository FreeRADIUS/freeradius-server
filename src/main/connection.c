/**
 * @file connection.c
 * @brief Handle pools of connections (threads, sockets, etc.)
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
 * Copyright 2011  The FreeRADIUS server project
 * Copyright 2011  Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/connection.h>

#include <freeradius-devel/rad_assert.h>

typedef struct fr_connection_t fr_connection_t;

struct fr_connection_t {
	fr_connection_t	*prev, *next;

	time_t		start;
	time_t		last_used;

	int		num_uses;
	int		used;
	int		number;	/* unique ID */
	void		*connection;
};

struct fr_connection_pool_t {
	int		start;
	int		min;
	int		max;
	int		spare;
	int		cleanup_delay;

	int		num;
	int		active;

	time_t		last_checked;
	time_t		last_spawned;

	int		max_uses;
	int		lifetime;
	int		idle_timeout;

	fr_connection_t	*head, *tail;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	mutex;
#endif

	CONF_SECTION	*cs;
	void		*ctx;

	fr_connection_create_t	create;
	fr_connection_alive_t	alive;
	fr_connection_delete_t	delete;
};

#ifndef HAVE_PTHREAD_H
#define pthread_mutex_lock(_x)
#define pthread_mutex_unlock(_x)
#endif

static const CONF_PARSER connection_config[] = {
	{ "start",    PW_TYPE_INTEGER, offsetof(fr_connection_pool_t, start),
	  0, "5" },
	{ "min",      PW_TYPE_INTEGER, offsetof(fr_connection_pool_t, min),
	  0, "5" },
	{ "max",      PW_TYPE_INTEGER, offsetof(fr_connection_pool_t, max),
	  0, "10" },
	{ "spare",    PW_TYPE_INTEGER, offsetof(fr_connection_pool_t, spare),
	  0, "3" },
	{ "uses",     PW_TYPE_INTEGER, offsetof(fr_connection_pool_t, max_uses),
	  0, "0" },
	{ "lifetime",   PW_TYPE_INTEGER, offsetof(fr_connection_pool_t, lifetime),
	  0, "0" },
	{ "idle_timeout",     PW_TYPE_INTEGER, offsetof(fr_connection_pool_t, idle_timeout),
	  0, "60" },
	{ NULL, -1, 0, NULL, NULL }
};

static void fr_connection_unlink(fr_connection_pool_t *fc,
				 fr_connection_t *this)
{

	if (this->prev) {
		rad_assert(fc->head != this);
		this->prev->next = this->next;
	} else {
		rad_assert(fc->head == this);
		fc->head = this->next;
	}
	if (this->next) {
		rad_assert(fc->tail != this);
		this->next->prev = this->prev;
	} else {
		rad_assert(fc->tail == this);
		fc->tail = this->prev;
	}

	this->prev = this->next = NULL;
}


static void fr_connection_link(fr_connection_pool_t *fc,
			       fr_connection_t *this)
{
	rad_assert(fc != NULL);
	rad_assert(this != NULL);
	rad_assert(fc->head != this);
	rad_assert(fc->tail != this);

	if (fc->head) fc->head->prev = this;
	this->next = fc->head;
	this->prev = NULL;
	fc->head = this;
	if (!fc->tail) {
		rad_assert(this->next == NULL);
		fc->tail = this;
	} else {
		rad_assert(this->next != NULL);
	}
}


static fr_connection_t *fr_connection_spawn(fr_connection_pool_t *fc,
					    time_t now)
{
	fr_connection_t *this;
	void *conn;

	rad_assert(fc != NULL);
	rad_assert(fc->num <= fc->max);

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	/*
	 *	This may take a long time, which prevents other
	 *	threads from releasing connections.  We don't care
	 *	about other threads opening new connections, as we
	 *	already have no free connections.
	 */
	conn = fc->create(fc->ctx);
	if (!conn) {
		free(this);
		return NULL;
	}

	this->start = now;
	this->connection = conn;

	fr_connection_link(fc, this);

	fc->num++;

	return this;
}

static void fr_connection_close(fr_connection_pool_t *fc,
				fr_connection_t *this)
{
	rad_assert(this->used == FALSE);

	fr_connection_unlink(fc, this);
	fc->delete(fc->ctx, this->connection);
	rad_assert(fc->num > 0);
	fc->num--;
	free(this);
}



void fr_connection_pool_delete(fr_connection_pool_t *fc)
{
	fr_connection_t *this, *next;

	pthread_mutex_lock(&fc->mutex);

	for (this = fc->head; this != NULL; this = next) {
		next = this->next;
		fr_connection_close(fc, this);
	}

	rad_assert(fc->head == NULL);
	rad_assert(fc->tail == NULL);
	rad_assert(fc->num == 0);

	cf_section_parse_free(fc->cs, fc);

	free(fc);
}

fr_connection_pool_t *fr_connection_pool_init(CONF_SECTION *parent,
					      void *ctx,
					      fr_connection_create_t c,
					      fr_connection_alive_t a,
					      fr_connection_delete_t d)
{
	int i;
	fr_connection_pool_t *fc;
	CONF_SECTION *cs;

	if (!parent || !ctx || !c || !a || !d) return NULL;

	cs = cf_section_sub_find(parent, "pool");
	if (!cs) {
		cf_log_err(cf_sectiontoitem(parent), "No \"pool\" subsection found");
		return NULL;
	}

	fc = rad_malloc(sizeof(*fc));
	memset(fc, 0, sizeof(*fc));

	fc->cs = cs;
	fc->ctx = ctx;
	fc->create = c;
	fc->alive = a;
	fc->delete = d;

	fc->head = fc->tail = NULL;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_init(&fc->mutex, NULL);
#endif

	if (cf_section_parse(cs, fc, connection_config) < 0) {
		goto error;
	}

	/*
	 *	Some simple limits
	 */
	if (fc->max > 1024) fc->max = 1024;
	if (fc->start > fc->max) fc->start = fc->max;
	if (fc->spare > (fc->max - fc->min)) {
		fc->spare = fc->max - fc->min;
	}
	if ((fc->lifetime > 0) && (fc->idle_timeout > fc->lifetime)) {
		fc->idle_timeout = 0;
	}

	/*
	 *	Create all of the connections.
	 */
	for (i = 0; i < fc->start; i++) {
		time_t now = time(NULL);

		if (!fr_connection_spawn(fc, now)) {
		error:
			fr_connection_pool_delete(fc);
			return NULL;
		}
	}

	return fc;
}


/*
 *	Called with the mutex lock held.
 */
static int fr_connection_manage(fr_connection_pool_t *fc,
				fr_connection_t *this,
				time_t now)
{
	rad_assert(fc != NULL);
	rad_assert(this != NULL);

	if ((fc->max_uses > 0) && (this->num_uses >= fc->max_uses)) {
	do_delete:
		fr_connection_close(fc, this);
		pthread_mutex_unlock(&fc->mutex);
		return 0;
	}

	if ((fc->lifetime > 0) && ((this->start + fc->lifetime) < now))
	        goto do_delete;

	if ((fc->idle_timeout > 0) && ((this->last_used + fc->idle_timeout) < now))
	        goto do_delete;

	return 1;
}


static int fr_connection_pool_check(fr_connection_pool_t *fc)
{
	int i, spare, spawn;
	time_t now = time(NULL);
	fr_connection_t *this;

	if (now == fc->last_checked) return 1;

	pthread_mutex_lock(&fc->mutex);

	spare = fc->num - fc->active;

	spawn = 0;
	if ((fc->num < fc->max) &&
	    (spare < fc->spare)) {
		spawn = fc->spare - spare;
		if ((spawn + fc->num) > fc->max) {
			spawn = fc->max - fc->num;
		}

		for (i = 0; i < spawn; i++) {
			if (!fr_connection_spawn(fc, now)) {
				pthread_mutex_unlock(&fc->mutex);
				return 0;
			}
		}
	}

	/*
	 *	We haven't spawned threads in a while, and there are
	 *	too many spare connections.  Close the one which has
	 *	been idle for the longest.
	 */
	if ((now >= (fc->last_spawned + fc->cleanup_delay)) &&
	    (spare > fc->spare)) {
		fr_connection_t *idle;

		idle = NULL;
		for (this = fc->tail; this != NULL; this = this->prev) {
			if (this->used) continue;

			if (!idle ||
			    (this->last_used < idle->last_used)) {
				idle = this;
			}
		}

		rad_assert(idle != NULL);
		fr_connection_close(fc, idle);
	}

	/*
	 *	Pass over all of the connections in the pool, limiting
	 *	lifetime, idle time, max requests, etc.
	 */
	for (this = fc->head; this != NULL; this = this->next) {
		fr_connection_manage(fc, this, now);
	}

	fc->last_checked = now;
	pthread_mutex_unlock(&fc->mutex);

	return 1;
}

int fr_connection_check(fr_connection_pool_t *fc, void *conn)
{
	int rcode = 1;
	fr_connection_t *this;

	if (!fc) return 1;

	if (!conn) return fr_connection_pool_check(fc);

	pthread_mutex_lock(&fc->mutex);

	for (this = fc->head; this != NULL; this = this->next) {
		if (this->connection == conn) {
			rcode = fr_connection_manage(fc, conn, time(NULL));
			break;
		}
	}

	pthread_mutex_unlock(&fc->mutex);

	return 1;
}


void *fr_connection_get(fr_connection_pool_t *fc)
{
	time_t now;
	fr_connection_t *this, *next;

	if (!fc) return NULL;

	pthread_mutex_lock(&fc->mutex);

	now = time(NULL);
	for (this = fc->head; this != NULL; this = next) {
		next = this->next;

		if (!fr_connection_manage(fc, this, now)) continue;

		if (!this->used) goto do_return;
	}

	if (fc->num == fc->max) {
		pthread_mutex_unlock(&fc->mutex);
		return NULL;
	}

	this = fr_connection_spawn(fc, now);
	if (!this) {
		pthread_mutex_unlock(&fc->mutex);
		return NULL;
	}

do_return:
	fc->active++;
	this->num_uses++;
	this->last_used = now;
	this->used = TRUE;

	pthread_mutex_unlock(&fc->mutex);
	return this;
}

void fr_connection_release(fr_connection_pool_t *fc, void *conn)
{
	fr_connection_t *this;

	if (!fc || !conn) return;

	pthread_mutex_lock(&fc->mutex);

	/*
	 *	FIXME: This loop could be avoided if we passed a 'void
	 *	**connection' instead.  We could use "offsetof" in
	 *	order to find top of the parent structure.
	 */
	for (this = fc->head; this != NULL; this = this->next) {
		if (this->connection == conn) {
			rad_assert(this->used == TRUE);
			this->used = FALSE;

			/*
			 *	Put it at the head of the list, so
			 *	that it will get re-used quickly.
			 */
			if (this != fc->head) {
				fr_connection_unlink(fc, this);
				fr_connection_link(fc, this);
			}
			rad_assert(fc->active > 0);
			fc->active--;
			break;
		}
	}

	pthread_mutex_unlock(&fc->mutex);
}

void *fr_connection_reconnect(fr_connection_pool_t *fc, void *conn)
{
	void *new_conn;
	fr_connection_t *this;

	if (!fc || !conn) return NULL;

	pthread_mutex_lock(&fc->mutex);

	/*
	 *	FIXME: This loop could be avoided if we passed a 'void
	 *	**connection' instead.  We could use "offsetof" in
	 *	order to find top of the parent structure.
	 */
	for (this = fc->head; this != NULL; this = this->next) {
		if (this->connection == conn) {
			rad_assert(this->used == TRUE);

			new_conn = fc->create(fc->ctx);
			if (!new_conn) {
				fr_connection_close(fc, conn);
				pthread_mutex_unlock(&fc->mutex);

				/*
				 *	Can't create a new socket.
				 *	Try grabbing a pre-existing one.
				 */
				return fr_connection_get(fc);
			}

			fc->delete(fc->ctx, conn);
			this->connection = new_conn;
			pthread_mutex_unlock(&fc->mutex);
			return new_conn;
		}
	}

	pthread_mutex_unlock(&fc->mutex);

	/*
	 *	Caller passed us something that isn't in the pool.
	 */
	return NULL;
}
