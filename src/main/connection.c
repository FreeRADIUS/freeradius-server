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

#include <freeradius-devel/radiusd.h>

#include <freeradius-devel/connection.h>

#include <freeradius-devel/rad_assert.h>

typedef struct fr_connection_t fr_connection_t;

static int fr_connection_pool_check(fr_connection_pool_t *fc);

struct fr_connection_t {
	fr_connection_t	*prev, *next;

	time_t		start;
	time_t		last_used;

	int		num_uses;
	int		used;
	int		number;		/* unique ID */
	void		*connection;
};

struct fr_connection_pool_t {
	int		start;
	int		min;
	int		max;
	int		spare;
	int		cleanup_delay;

	unsigned int    count;		/* num connections spawned */
	int		num;		/* num connections in pool */
	int		active;	 	/* num connections active */

	time_t		last_checked;
	time_t		last_spawned;
	time_t		last_failed;
	time_t		last_complained;

	int		max_uses;
	int		lifetime;
	int		idle_timeout;
	int		spawning;
	int		trigger; /* do triggering */

	fr_connection_t	*head, *tail;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	mutex;
#endif

	CONF_SECTION	*cs;
	void		*ctx;
	
	char  		*log_prefix;

	fr_connection_create_t	create;
	fr_connection_alive_t	alive;
	fr_connection_delete_t	delete;
};

#define LOG_PREFIX "rlm_%s (%s)"
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
	{ "lifetime", PW_TYPE_INTEGER, offsetof(fr_connection_pool_t, lifetime),
	  0, "0" },
	{ "cleanup_delay", PW_TYPE_INTEGER, offsetof(fr_connection_pool_t, cleanup_delay),
	  0, "5" },
	{ "idle_timeout",  PW_TYPE_INTEGER, offsetof(fr_connection_pool_t, idle_timeout),
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


/*
 *	Called with the mutex free.
 */
static fr_connection_t *fr_connection_spawn(fr_connection_pool_t *fc,
					    time_t now)
{
	fr_connection_t *this;
	void *conn;
	
	rad_assert(fc != NULL);

	pthread_mutex_lock(&fc->mutex);
	rad_assert(fc->num <= fc->max);

	if ((fc->last_failed == now) || fc->spawning) {
		pthread_mutex_unlock(&fc->mutex);
		return NULL;
	}

	fc->spawning = TRUE;

	/*
	 *	Unlock the mutex while we try to open a new
	 *	connection.  If there are issues with the back-end,
	 *	opening a new connection may take a LONG time.  In
	 *	that case, we want the other connections to continue
	 *	to be used.
	 */
	pthread_mutex_unlock(&fc->mutex);

	DEBUG("%s: Opening additional connection (%i)",
	      fc->log_prefix, fc->count);
	
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
		fc->last_failed = now;
		free(this);
		fc->spawning = FALSE; /* atomic, so no lock is needed */
		return NULL;
	}

	this->start = now;
	this->connection = conn;	

	/*
	 *	And lock the mutex again while we link the new
	 *	connection back into the pool.
	 */
	pthread_mutex_lock(&fc->mutex);

	this->number = fc->count++;
	this->last_used = now;
	fr_connection_link(fc, this);
	fc->num++;
	fc->spawning = FALSE;
	fc->last_spawned = time(NULL);

	pthread_mutex_unlock(&fc->mutex);

	if (fc->trigger) exec_trigger(NULL, fc->cs, "open", TRUE);

	return this;
}


int fr_connection_add(fr_connection_pool_t *fc, void *conn)
{
	fr_connection_t *this;

	if (!fc) return 0;

	pthread_mutex_lock(&fc->mutex);

	if (!conn) {
		conn = fc->create(fc->ctx);
		if (!conn) {
			pthread_mutex_unlock(&fc->mutex);
			return 0;
		}
	}

	/*
	 *	Too many connections: can't add it.
	 */
        if (fc->num >= fc->max) {
		pthread_mutex_unlock(&fc->mutex);
		return 0;
	}

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	this->start = time(NULL);
	this->connection = conn;

	this->number = fc->count++;
	this->last_used = time(NULL);
	fr_connection_link(fc, this);
	fc->num++;

	pthread_mutex_unlock(&fc->mutex);

	if (fc->trigger) exec_trigger(NULL, fc->cs, "open", TRUE);

	return 1;
}


static void fr_connection_close(fr_connection_pool_t *fc,
				fr_connection_t *this)
{
	if (fc->trigger) exec_trigger(NULL, fc->cs, "close", TRUE);

	rad_assert(this->used == FALSE);

	DEBUG("%s: Closing connection (%i)", fc->log_prefix, this->number);

	fr_connection_unlink(fc, this);
	fc->delete(fc->ctx, this->connection);
	rad_assert(fc->num > 0);
	fc->num--;
	free(this);
}


/*
 *	Find a connection.  Called with the mutex free.  If it finds a
 *	connection, it returns with the mutex held.  Otherwise, it
 *	releases the mutex.
 */
static fr_connection_t *fr_connection_find(fr_connection_pool_t *fc, void *conn)
{
	fr_connection_t *this;

	if (!fc || !conn) return NULL;

	pthread_mutex_lock(&fc->mutex);

	/*
	 *	FIXME: This loop could be avoided if we passed a 'void
	 *	**connection' instead.  We could use "offsetof" in
	 *	order to find top of the parent structure.
	 */
	for (this = fc->head; this != NULL; this = this->next) {
		if (this->connection == conn) return this;
	}

	pthread_mutex_unlock(&fc->mutex);
	return NULL;
}

int fr_connection_del(fr_connection_pool_t *fc, void *conn)
{
	fr_connection_t *this;

	this = fr_connection_find(fc, conn);
	if (!this) return 0;

	/*
	 *	If it's used, release it.
	 */
	if (this->used) {
		rad_assert(this->used == TRUE);
		this->used = FALSE;
		
		rad_assert(fc->active > 0);
		fc->active--;
	}

	fr_connection_close(fc, this);
	fr_connection_pool_check(fc);
	return 1;
}


void fr_connection_pool_delete(fr_connection_pool_t *fc)
{
	fr_connection_t *this, *next;

	if (!fc) return;

	DEBUG("%s: Removing connection pool", fc->log_prefix);

	pthread_mutex_lock(&fc->mutex);

	for (this = fc->head; this != NULL; this = next) {
		next = this->next;
		DEBUG("%s: Closing connection (%i)", fc->log_prefix, this->number);
		fr_connection_close(fc, this);
	}

	if (fc->trigger) exec_trigger(NULL, fc->cs, "stop", TRUE);

	rad_assert(fc->head == NULL);
	rad_assert(fc->tail == NULL);
	rad_assert(fc->num == 0);

	cf_section_parse_free(fc->cs, fc);

	free(fc->log_prefix);
	free(fc);
}

fr_connection_pool_t *fr_connection_pool_init(CONF_SECTION *parent,
					      void *ctx,
					      fr_connection_create_t c,
					      fr_connection_alive_t a,
					      fr_connection_delete_t d)
{
	int i, lp_len;
	fr_connection_pool_t *fc;
	fr_connection_t *this;
	CONF_SECTION *modules;
	CONF_SECTION *cs;
	const char *cs_name1, *cs_name2;
	time_t now = time(NULL);

	if (!parent || !ctx || !c || !d) return NULL;

	cs = cf_section_sub_find(parent, "pool");
	if (!cs) cs = cf_section_sub_find(parent, "limit");

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

	modules = cf_item_parent(cf_sectiontoitem(parent));
	if (modules) {
		cs_name1 = cf_section_name1(modules);
		if (cs_name1 && (strcmp(cs_name1, "modules") == 0)) {
			cs_name1 = cf_section_name1(parent);
			cs_name2 = cf_section_name2(parent);
			if (!cs_name2) {
				cs_name2 = cs_name1;
			}

			lp_len = (sizeof(LOG_PREFIX) - 4) + strlen(cs_name1) + strlen(cs_name2);
			fc->log_prefix = rad_malloc(lp_len);
			snprintf(fc->log_prefix, lp_len, LOG_PREFIX, cs_name1, cs_name2);
		}
	} else {		/* not a module configuration */
		cs_name1 = cf_section_name1(parent);

		fc->log_prefix = strdup(cs_name1);
	}
	
	DEBUG("%s: Initialising connection pool", fc->log_prefix);

	if (cs) {
		if (cf_section_parse(cs, fc, connection_config) < 0) {
			goto error;
		}

		if (cf_section_sub_find(cs, "trigger")) fc->trigger = TRUE;
	} else {
		fc->max = 1024;
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
	 *	Create all of the connections, unless the admin says
	 *	not to.
	 */
	for (i = 0; i < fc->start; i++) {
		this = fr_connection_spawn(fc, now);	
		if (!this) {
		error:
			fr_connection_pool_delete(fc);
			return NULL;
		}
	}

	if (fc->trigger) exec_trigger(NULL, fc->cs, "start", TRUE);

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
	
	/*
	 *	Don't terminated in-use connections
	 */
	if (this->used) return 1;

	if ((fc->max_uses > 0) &&
	    (this->num_uses >= fc->max_uses)) {
		DEBUG("%s: Closing expired connection (%i): Hit max_uses limit",
			fc->log_prefix, this->number);
	do_delete:
		if ((fc->num <= fc->min) &&
		    (fc->last_complained < now)) {
			radlog(L_INFO, "WARNING in %s: You probably need to lower \"min\"", fc->log_prefix);
			fc->last_complained = now;
		}
		fr_connection_close(fc, this);
		return 0;
	}

	if ((fc->lifetime > 0) &&
	    ((this->start + fc->lifetime) < now)) {
		DEBUG("%s: Closing expired connection (%i) ",
			fc->log_prefix, this->number);
		goto do_delete;
	}

	if ((fc->idle_timeout > 0) &&
	    ((this->last_used + fc->idle_timeout) < now)) {
		DEBUG("%s: Closing idle connection (%i)",
			fc->log_prefix, this->number);
		goto do_delete;
	}
	
	return 1;
}


/*
 *	Called with the mutex held.  Releases it.
 */
static int fr_connection_pool_check(fr_connection_pool_t *fc)
{
	int spare, spawn;
	time_t now = time(NULL);
	fr_connection_t *this, *next;

	if (fc->last_checked == now) {
		pthread_mutex_unlock(&fc->mutex);
		return 1;
	}

	spare = fc->num - fc->active;

	spawn = 0;
	if ((fc->num < fc->max) && (spare < fc->spare)) {
		spawn = fc->spare - spare;
		if ((spawn + fc->num) > fc->max) {
			spawn = fc->max - fc->num;
		}
		if (fc->spawning) spawn = 0;

		if (spawn) {
			pthread_mutex_unlock(&fc->mutex);
			fr_connection_spawn(fc, now); /* ignore return code */
			pthread_mutex_lock(&fc->mutex);
		}
	}

	/*
	 *	We haven't spawned connections in a while, and there
	 *	are too many spare ones.  Close the one which has been
	 *	idle for the longest.
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
		
		DEBUG("%s: Closing idle connection (%i): Too many free connections (%d > %d)",
		      fc->log_prefix, idle->number, spare, fc->spare);
		fr_connection_close(fc, idle);
	}

	/*
	 *	Pass over all of the connections in the pool, limiting
	 *	lifetime, idle time, max requests, etc.
	 */
	for (this = fc->head; this != NULL; this = next) {
		next = this->next;
		fr_connection_manage(fc, this, now);
	}

	fc->last_checked = now;
	pthread_mutex_unlock(&fc->mutex);

	return 1;
}

int fr_connection_check(fr_connection_pool_t *fc, void *conn)
{
	fr_connection_t *this;
	time_t now;
	
	if (!fc) return 1;

	now = time(NULL);
	pthread_mutex_lock(&fc->mutex);

	if (!conn) return fr_connection_pool_check(fc);

	for (this = fc->head; this != NULL; this = this->next) {
		if (this->connection == conn) {
			fr_connection_manage(fc, conn, now);
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

		if (!this->used) goto do_return;
	}

	if (fc->num == fc->max) {
		/*
		 *	Rate-limit complaints.
		 */
		if (fc->last_complained != now) {
			radlog(L_ERR, "%s: No connections available and at max connection limit",
			       fc->log_prefix);
			fc->last_complained = now;
		}
		pthread_mutex_unlock(&fc->mutex);
		return NULL;
	}

	pthread_mutex_unlock(&fc->mutex);
	this = fr_connection_spawn(fc, now);
	if (!this) return NULL;
	pthread_mutex_lock(&fc->mutex);

do_return:
	fc->active++;
	this->num_uses++;
	this->last_used = now;
	this->used = TRUE;

	pthread_mutex_unlock(&fc->mutex);
	
	DEBUG("%s: Reserved connection (%i)", fc->log_prefix, this->number);
	
	return this->connection;
}


void fr_connection_release(fr_connection_pool_t *fc, void *conn)
{
	fr_connection_t *this;

	this = fr_connection_find(fc, conn);
	if (!this) return;

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

	DEBUG("%s: Released connection (%i)", fc->log_prefix, this->number);

	/*
	 *	We mirror the "spawn on get" functionality by having
	 *	"delete on release".  If there are too many spare
	 *	connections, go manage the pool && clean some up.
	 */
	fr_connection_pool_check(fc);

}

void *fr_connection_reconnect(fr_connection_pool_t *fc, void *conn)
{
	void *new_conn;
	fr_connection_t *this;
	int conn_number;

	if (!fc || !conn) return NULL;

	this= fr_connection_find(fc, conn);
	if (!this) return NULL;
	
	conn_number = this->number;

	rad_assert(this->used == TRUE);
	
	DEBUG("%s: Reconnecting (%i)", fc->log_prefix, conn_number);
	
	new_conn = fc->create(fc->ctx);
	if (!new_conn) {
		time_t now = time(NULL);
		
		if (fc->last_complained == now) {
			now = 0;
		} else {
			fc->last_complained = now;
		}
		
		fr_connection_close(fc, conn);
		pthread_mutex_unlock(&fc->mutex);
		
		/*
		 *	Can't create a new socket.
		 *	Try grabbing a pre-existing one.
		 */
		new_conn = fr_connection_get(fc);
		if (new_conn) return new_conn;
		
		if (!now) return NULL;
		
		radlog(L_ERR, "%s: Failed to reconnect (%i), and no other connections available",
		       fc->log_prefix, conn_number);
		return NULL;
	}
	
	fc->delete(fc->ctx, conn);
	this->connection = new_conn;
	pthread_mutex_unlock(&fc->mutex);
	return new_conn;
}
