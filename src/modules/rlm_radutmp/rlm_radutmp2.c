/*
 * rlm_radutmp.c
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
 * Copyright 2000,2001,2002,2003,2004,2006  The FreeRADIUS server project
 */

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/radutmp.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>

#include	<fcntl.h>
#include        <limits.h>

#include "config.h"

#define LOCK_LEN sizeof(struct radutmp)

static const char porttypes[] = "ASITX";

/*
 *	Used for caching radutmp lookups in the accounting
 *	component. The session (checksimul) component doesn't use it,
 *	but probably should, though we're not sure how...
 *
 *	The intent here is to keep this structure as small as
 *	possible, so that it doesn't take up too much memory.
 */
typedef struct nas_port {
	uint32_t		nas_address;
	unsigned int		nas_port;
	off_t			offset;

	struct nas_port		*next; /* for the free list */
} NAS_PORT;


/*
 *	Per-file information.
 *
 *	Hmm... having multiple filenames managed by one instance
 *	of the module makes it difficult for the module to do
 *	simultaneous-use checking, without more code edits.
 */
typedef struct radutmp_cache_t {
	const char	*filename; /* for future reference */
	time_t		last_used; /* for future reference */

	rbtree_t	*nas_ports;
	NAS_PORT	*free_offsets;
	off_t		max_offset;
	int		cached_file;
	int		permission;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	mutex;
#endif
} radutmp_cache_t;


/*
 *	We cache the users, too, so that we only have to read radutmp
 *	once.
 */
typedef struct radutmp_simul_t {
	char		login[sizeof(((struct radutmp *) NULL)->login) + 1];
	int		simul_count;
} radutmp_simul_t;


/*
 *	Data we store per module.
 */
typedef struct rlm_radutmp_t {
	char		*filename;
	char		*username;
	int		case_sensitive;
	int		check_nas;
	int		permission;
	int		callerid_ok;

	rbtree_t	*user_tree; /* for simultaneous-use */

	/*
	 *	As the filenames can be dynamically translated,
	 *	we want to keep track of them in a separate data
	 *	structure, so that we can have per-file caches.
	 */
	radutmp_cache_t cache;
} rlm_radutmp_t;

#ifndef HAVE_PTHREAD_H
/*
 *	This is easier than ifdef's throughout the code.
 */
#define pthread_mutex_init(_x, _y)
#define pthread_mutex_destroy(_x)
#define pthread_mutex_lock(_x)
#define pthread_mutex_unlock(_x)
#endif

static const CONF_PARSER module_config[] = {
	{ "filename", PW_TYPE_STRING_PTR,
	  offsetof(rlm_radutmp_t,filename), NULL,  RADUTMP },
	{ "username", PW_TYPE_STRING_PTR,
	  offsetof(rlm_radutmp_t,username), NULL,  "%{User-Name}"},
	{ "case_sensitive", PW_TYPE_BOOLEAN,
	  offsetof(rlm_radutmp_t,case_sensitive), NULL,  "yes"},
	{ "check_with_nas", PW_TYPE_BOOLEAN,
	  offsetof(rlm_radutmp_t,check_nas), NULL,  "yes"},
	{ "perm",     PW_TYPE_INTEGER,
	  offsetof(rlm_radutmp_t,permission), NULL,  "0644" },
	{ "callerid", PW_TYPE_BOOLEAN,
	  offsetof(rlm_radutmp_t,callerid_ok), NULL, "no" },
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	NAS PORT cmp
 */
static int nas_port_cmp(const void *a, const void *b)
{
	const NAS_PORT *one = a;
	const NAS_PORT *two = b;

	if (one->nas_address < two->nas_address) return -1;
	if (one->nas_address > two->nas_address) return +1;

	if (one->nas_port < two->nas_port) return -1;
	if (one->nas_port > two->nas_port) return +1;

	return 0;
}


/*
 *	Compare two user names.
 */
static int user_cmp(const void *a, const void *b)
{
	const radutmp_simul_t *one = a;
	const radutmp_simul_t *two = b;

	return strcmp(one->login, two->login);
}


/*
 *	Compare two user names, case insensitive.
 */
static int user_case_cmp(const void *a, const void *b)
{
	const radutmp_simul_t *one = a;
	const radutmp_simul_t *two = b;

	return strcasecmp(one->login, two->login);
}


/*
 *	Detach.
 */
static int radutmp_detach(void *instance)
{
	NAS_PORT	*this, *next;
	rlm_radutmp_t *inst = instance;

	rbtree_free(inst->cache.nas_ports);

	for (this = inst->cache.free_offsets;
	     this != NULL;
	     this = next) {
		next = this->next;
		free(this);
	}

	if (inst->cache.filename) free(inst->cache.filename);

	pthread_mutex_destroy(&(inst->cache.mutex));


	rbtree_free(inst->user_tree);

	free(inst);
	return 0;
}


/*
 *	Instantiate.
 */
static int radutmp_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_radutmp_t *inst;

	inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	if (cf_section_parse(conf, inst, module_config)) {
		radutmp_detach(inst);
		return -1;
	}

	inst->cache.nas_ports = rbtree_create(nas_port_cmp, free, 0);
	if (!inst->cache.nas_ports) {
		radlog(L_ERR, "rlm_radutmp: Failed to create nas tree");
		radutmp_detach(inst);
		return -1;
	}

	pthread_mutex_init(&(inst->cache.mutex), NULL);
	inst->cache.permission = inst->permission;

	if (inst->case_sensitive) {
		inst->user_tree = rbtree_create(user_cmp, free, 0);
	} else {
		inst->user_tree = rbtree_create(user_case_cmp, free, 0);
	}
	if (!inst->user_tree) {
		radlog(L_ERR, "rlm_radutmp: Failed to create user tree");
		radutmp_detach(inst);
		return -1;
	}

	*instance = inst;
	return 0;
}


/*
 *	Reset the cached entries.
 */
static int cache_reset(rlm_radutmp_t *inst, radutmp_cache_t *cache)
{
	NAS_PORT *this, *next;

	/*
	 *	Cache is already reset, do nothing.
	 */
	if ((rbtree_num_elements(cache->nas_ports) == 0) &&
	    (cache->free_offsets == NULL)) {
		DEBUG2("  rlm_radutmp: Not resetting the cache");
		return 1;
	}
	DEBUG2("  rlm_radutmp: Resetting the cache");

	pthread_mutex_lock(&cache->mutex);

	rbtree_free(inst->user_tree);

	rbtree_free(cache->nas_ports);

	for (this = cache->free_offsets;
	     this != NULL;
	     this = next) {
		next = this->next;
		free(this);
	}
	cache->free_offsets = NULL;

	/*
	 *	Re-create the caches.
	 */
	cache->nas_ports = rbtree_create(nas_port_cmp, free, 0);
	if (!cache->nas_ports) {
		pthread_mutex_unlock(&cache->mutex);
		radlog(L_ERR, "rlm_radutmp: No memory");
		return 0;
	}

	cache->max_offset = 0;

	cache->cached_file = 1;

	if (inst->case_sensitive) {
		inst->user_tree = rbtree_create(user_cmp, free, 0);
	} else {
		inst->user_tree = rbtree_create(user_case_cmp, free, 0);
	}
	if (!inst->user_tree) {
		pthread_mutex_unlock(&cache->mutex);
		radlog(L_ERR, "rlm_radutmp: No memory");
		return 0;
	}

	pthread_mutex_unlock(&cache->mutex);

	return 1;
}


/*
 *	Compare two offsets in a tree.
 */
static int offset_cmp(const void *a, const void *b)
{
	const NAS_PORT *one = a;
	const NAS_PORT *two = b;

	if (one->offset < two->offset) return -1;
	if (one->offset > two->offset) return +1;

	return 0;
}


/*
 *	Data structure to use when walking the trees, for zap.
 */
typedef struct offset_walk_t {
	rlm_radutmp_t	*inst;
	radutmp_cache_t	*cache;
	rbtree_t	*offset_tree;
	uint32_t	nas_address;
	int		fd;
	time_t		now;
} offset_walk_t;


/*
 *	Walk over the cache, finding entries with the matching NAS IP address.
 */
static int nas_port_walk(void *context, void *data)
{
	offset_walk_t	*walk = context;
	NAS_PORT	*nas_port = data;

	/*
	 *	Doesn't match, keep going.
	 */
	if (walk->nas_address != nas_port->nas_address) return 0;

	/*
	 *	Insert it into the offset tree, for later deletion.
	 */
	if (rbtree_insert(walk->offset_tree, nas_port) != 1) {
		DEBUG2("  rlm_radumtp: Insertion failed in nas port walk.");
		return 1;
	}

	return 0;
}


/*
 *	Walk through the offset tree, operating on the cache
 */
static int offset_walk(void *context, void *data)
{
	offset_walk_t	*walk = context;
	NAS_PORT	*nas_port = data;
	struct radutmp	utmp;
	radutmp_simul_t *user, myUser;

	/*
	 *	Seek to the entry, and possibly re-write it.
	 */
	if (lseek(walk->fd, nas_port->offset, SEEK_SET) < 0) {
		rad_assert(0 == 1);
	}

	if (read(walk->fd, &utmp, sizeof(utmp)) != sizeof(utmp)) {
		rad_assert(0 == 1);
	}

	/*
	 *	If the entry in the file is NEWER than the reboot
	 *	packet, don't re-write it, and don't delete it.
	 */
	if (utmp.time > walk->now) {
		return 0;
	}

	utmp.type = P_IDLE;
	utmp.time = walk->now;

	if (lseek(walk->fd, -(off_t)sizeof(utmp), SEEK_CUR) < 0) {
		radlog(L_ERR, "rlm_radutmp: offset_walk: failed in lseek: %s",
		       strerror(errno));
		return 1;
	}

	write(walk->fd, &utmp, sizeof(utmp));

	strlcpy(myUser.login, utmp.login, sizeof(myUser.login));
	user = rbtree_finddata(walk->inst->user_tree, &myUser);
	rad_assert(user != NULL);
	rad_assert(user->simul_count > 0);
	user->simul_count--;
	if (user->simul_count == 0) {
		rbtree_deletebydata(walk->inst->user_tree, user);
	}

	if (rbtree_deletebydata(walk->cache->nas_ports, nas_port) == 0) {
		radlog(L_ERR, "rlm_radutmp: Failed to delete entry from cache");
		return 1;
	}

	/*
	 *	Insert the entry into the free list.
	 */
	nas_port->next = walk->cache->free_offsets;
	walk->cache->free_offsets = nas_port;

	return 0;
}


/*
 *	Zap all users on a NAS from the radutmp file.
 */
static int radutmp_zap(rlm_radutmp_t *inst,
		       radutmp_cache_t *cache,
		       uint32_t nas_address,
		       time_t now)
{
	int		rcode;
	rbtree_t	*offset_tree;
	offset_walk_t	walk;

	rad_assert(now != 0);

	/*
	 *	If there's nothing in the file, do nothing,
	 *	but truncate the file, just to be safe.
	 */
	if (rbtree_num_elements(cache->nas_ports) == 0) {
		truncate(cache->filename, (off_t) 0);
		DEBUG2("  rlm_radutmp: No entries in file.  Quenching zap.");
		return 1;
	}

	/*
	 *	Create the offset tree, as we want to delete utmp
	 *	entries starting from the start of the file, and we
	 *	can't delete nodes from an rbtree while we're walking
	 *	it.
	 */
	offset_tree = rbtree_create(offset_cmp, NULL, 0);
	if (!offset_tree) {
		radlog(L_ERR, "rlm_radutmp: Out of memory");
		return 0;
	}

	pthread_mutex_lock(&cache->mutex);

	/*
	 *	Walk through the cache, finding entries for this NAS,
	 *	and add those entries to the offset tree.
	 */
	memset(&walk, 0, sizeof(walk));
	walk.inst = inst;
	walk.offset_tree = offset_tree;
	walk.nas_address = nas_address;
	rcode = rbtree_walk(cache->nas_ports, PreOrder, nas_port_walk, &walk);
	if (rcode != 0) {
		pthread_mutex_unlock(&cache->mutex);
		rbtree_free(offset_tree);
		radlog(L_ERR, "rlm_radutmp: Failed walking the cache.");
		return 0;
	}

	/*
	 *	If both trees have the same number of elements, then
	 *	don't do anything special, as UDP packets may be
	 *	received out of order, by several seconds.  The
	 *	"offset_walk" routine MAY NOT delete the entries, if
	 *	it sees that the entries in the file are newer than
	 *	the reboot packet.
	 */

	/*
	 *	If there's nothing to do, don't do anything.
	 */
	if (rbtree_num_elements(offset_tree) == 0) {
		DEBUG2("  rlm_radutmp: NAS IP %08x has no users recorded in file %s.",
		       htonl(nas_address), cache->filename);
		pthread_mutex_unlock(&cache->mutex);
		rbtree_free(offset_tree);
		return 1;
	}

	/*
	 *	Open the file, to re-write only a few of the entries.
	 */
	walk.fd = open(cache->filename, O_RDWR);
	if (walk.fd < 0) {
		pthread_mutex_unlock(&cache->mutex);
		rbtree_free(offset_tree);
		radlog(L_ERR, "rlm_radutmp: Error accessing file %s: %s",
		       cache->filename, strerror(errno));
		return 0;
	}

	/*
	 *	Lock the utmp file, prefer lockf() over flock().
	 *
	 *	FIXME: maybe we want to lock per-record?
	 */
	rad_lockfd(walk.fd, LOCK_LEN);

	/*
	 *	Walk through the offset tree, from start to finish,
	 *	deleting entries from the NAS tree, adding them to
	 *	the "free offset" cache, and lseek'ing to that offset
	 *	in the file, and clearing out the data.
	 */
	walk.cache = cache;
	walk.now = now;
	rcode = rbtree_walk(offset_tree, InOrder, offset_walk, &walk);
	rbtree_free(offset_tree);
	if (rcode != 0) {
		radlog(L_ERR, "rlm_radutmp: Failed walking the offsets.");
		return 0;
	}

	close(walk.fd);	/* and implicitly release the locks */

	/*
	 *	Just to clean up the file.  If it's empty,
	 *	nuke everything.
	 */
	if (rbtree_num_elements(cache->nas_ports) == 0) {
		NAS_PORT	*this, *next; /* too many copies of code */

		for (this = inst->cache.free_offsets;
		     this != NULL;
		     this = next) {
			next = this->next;
			free(this);
		}

		truncate(cache->filename, 0);
		rad_assert(rbtree_num_elements(inst->user_tree) == 0);
	}

	pthread_mutex_unlock(&cache->mutex);

	return 1;
}


/*
 *	Read a file, to cache all of its entries.
 */
static int cache_file(rlm_radutmp_t *inst, radutmp_cache_t *cache)
{
	int		fd;
	int		read_size;
	struct		stat buf;
	struct		radutmp utmp;
	NAS_PORT	**tail;

	rad_assert(cache->max_offset == 0);
	rad_assert(cache->free_offsets == NULL);

	/*
	 *	Doesn't exist, we're fine.
	 */
	if (stat(cache->filename, &buf) < 0) {
		if (errno == ENOENT) {
			cache->cached_file = 1;
			return 0;
		}
		radlog(L_ERR, "rlm_radutmp: Cannot stat %s: %s",
		       cache->filename, strerror(errno));
		return 1;
	}

	/*
	 *	Nothing's there, we're OK.
	 */
	if (buf.st_size == 0) {
		cache->cached_file = 1;
		return 0;
	}

	/*
	 *	Don't let others much around with our data.
	 */
	pthread_mutex_lock(&cache->mutex);

	/*
	 *	Read the file and cache it's entries.
	 */
	fd = open(cache->filename, O_RDONLY, cache->permission);
	if (fd < 0) {
		pthread_mutex_unlock(&cache->mutex);
		radlog(L_ERR, "rlm_radutmp: Error opening %s: %s",
		       cache->filename, strerror(errno));
		return 1;
	}

	/*
	 *	Insert free entries into the tail, so that entries
	 *	get used from the start.
	 */
	tail = &(cache->free_offsets);

	/*
	 *	Don't lock the file, as we're only reading it.
	 */
	do {
		read_size = read(fd, &utmp, sizeof(utmp));

		/*
		 *	Read one record.
		 */
		if (read_size == sizeof(utmp)) {
			radutmp_simul_t *user, myUser;
			NAS_PORT *nas_port = rad_malloc(sizeof(*nas_port));

			memset(nas_port, 0, sizeof(nas_port));
			nas_port->offset = cache->max_offset;
			cache->max_offset += sizeof(utmp);

			/*
			 *	Idle.  Add it to the list of free
			 *	offsets.
			 */
			if (utmp.type == P_IDLE) {
				*tail = nas_port;
				tail = &(nas_port->next);
				continue;
			}

			/*
			 *	It's a login record,
			 */
			nas_port->nas_address = utmp.nas_address;
			nas_port->nas_port = utmp.nas_port;

			if (!rbtree_insert(cache->nas_ports, nas_port)) {
				rad_assert(0 == 1);
			}

			/*
			 *	Adds a trailing \0, so myUser.login has
			 *	an extra char allocated..
			 */
			strlcpy(myUser.login, utmp.login, sizeof(myUser.login));
			user = rbtree_finddata(inst->user_tree, &myUser);
			if (user) {
				user->simul_count++;
			} else {
				/*
				 *	Allocate new entry, and add it
				 *	to the tree.
				 */
				user = rad_malloc(sizeof(user));
				strlcpy(user->login, utmp.login,
					sizeof(user->login));
				user->simul_count = 1;

				if (!rbtree_insert(inst->user_tree, user)) {
					rad_assert(0 == 1);
				}
			}
			continue;
		}

		/*
		 *	We've read a partial record.  WTF?
		 */
		if (read_size != 0) {
			pthread_mutex_unlock(&cache->mutex);
			close(fd);
			radlog(L_ERR, "rlm_radutmp: Badly formed file %s",
			       cache->filename);
			return 1;
		}

		/*
		 *	Read nothing, stop.
		 */
	} while (read_size != 0);

	pthread_mutex_unlock(&cache->mutex);
	close(fd);		/* and release the lock. */
	cache->cached_file = 1;

	return 0;
}


/*
 *	Store logins in the RADIUS utmp file.
 */
static int radutmp_accounting(void *instance, REQUEST *request)
{
	rlm_radutmp_t	*inst = instance;
	struct radutmp	utmp, u;
	VALUE_PAIR	*vp;
	int		status = -1;
	uint32_t	nas_address = 0;
	uint32_t	framed_address = 0;
	int		protocol = -1;
	int		fd;
	int		port_seen = 0;
	char		buffer[256];
	char		filename[1024];
	char		ip_name[32]; /* 255.255.255.255 */
	const char	*nas;
	NAS_PORT	*nas_port, myPort;
	radutmp_cache_t *cache;
	int		read_size;
	rbnode_t	*node;

	/*
	 *	Which type is this.
	 */
	if ((vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY)) == NULL) {
		radlog(L_ERR, "rlm_radutmp: No Accounting-Status-Type record.");
		return RLM_MODULE_NOOP;
	}
	status = vp->vp_integer;

	/*
	 *	Look for weird reboot packets.
	 *
	 *	ComOS (up to and including 3.5.1b20) does not send
	 *	standard PW_STATUS_ACCOUNTING_* messages.
	 *
	 *	Check for:  o no Acct-Session-Time, or time of 0
	 *		    o Acct-Session-Id of "00000000".
	 *
	 *	We could also check for NAS-Port, that attribute
	 *	should NOT be present (but we don't right now).
	 */
	if ((status != PW_STATUS_ACCOUNTING_ON) &&
	    (status != PW_STATUS_ACCOUNTING_OFF)) do {
		int check1 = 0;
		int check2 = 0;

		if ((vp = pairfind(request->packet->vps, PW_ACCT_SESSION_TIME, 0, TAG_ANY))
		     == NULL || vp->vp_date == 0)
			check1 = 1;
		if ((vp = pairfind(request->packet->vps, PW_ACCT_SESSION_ID, 0, TAG_ANY))
		     != NULL && vp->length == 8 &&
		     memcmp(vp->vp_strvalue, "00000000", 8) == 0)
			check2 = 1;
		if (check1 == 0 || check2 == 0) {
#if 0 /* Cisco sometimes sends START records without username. */
			radlog(L_ERR, "rlm_radutmp: no username in record");
			return RLM_MODULE_FAIL;
#else
			break;
#endif
		}
		radlog(L_INFO, "rlm_radutmp: converting reboot records.");
		if (status == PW_STATUS_STOP)
			status = PW_STATUS_ACCOUNTING_OFF;
		if (status == PW_STATUS_START)
			status = PW_STATUS_ACCOUNTING_ON;
	} while(0);

	memset(&utmp, 0, sizeof(utmp));
	utmp.porttype = 'A';

	/*
	 *	First, find the interesting attributes.
	 */
	for (vp = request->packet->vps; vp; vp = vp->next) {
		switch (vp->attribute) {
			case PW_LOGIN_IP_HOST:
			case PW_FRAMED_IP_ADDRESS:
				framed_address = vp->vp_ipaddr;
				utmp.framed_address = vp->vp_ipaddr;
				break;
			case PW_FRAMED_PROTOCOL:
				protocol = vp->vp_integer;
				break;
			case PW_NAS_IP_ADDRESS:
				nas_address = vp->vp_ipaddr;
				utmp.nas_address = vp->vp_ipaddr;
				break;
			case PW_NAS_PORT:
				utmp.nas_port = vp->vp_integer;
				port_seen = 1;
				break;
			case PW_ACCT_DELAY_TIME:
				utmp.delay = vp->vp_integer;
				break;
			case PW_ACCT_SESSION_ID:
				/*
				 *	If it's too big, only use the
				 *	last bit.
				 */
				if (vp->length > sizeof(utmp.session_id)) {
					int length = vp->length - sizeof(utmp.session_id);

					/*
					 * 	Ascend is br0ken - it
					 * 	adds a \0 to the end
					 * 	of any string.
					 * 	Compensate.
					 */
					if (vp->vp_strvalue[vp->length - 1] == 0) {
						length--;
					}

					memcpy(utmp.session_id,
					      vp->vp_strvalue + length,
					      sizeof(utmp.session_id));
				} else {
					memset(utmp.session_id, 0,
					       sizeof(utmp.session_id));
					memcpy(utmp.session_id,
					       vp->vp_strvalue,
					       vp->length);
				}
				break;
			case PW_NAS_PORT_TYPE:
				if (vp->vp_integer <= 4)
					utmp.porttype = porttypes[vp->vp_integer];
				break;
			case PW_CALLING_STATION_ID:
				if(inst->callerid_ok)
					strlcpy(utmp.caller_id,
						(char *)vp->vp_strvalue,
						sizeof(utmp.caller_id));
				break;
		}
	}

	/*
	 *	If we didn't find out the NAS address, use the
	 *	originator's IP address.
	 */
	if (nas_address == 0) {
		nas_address = request->packet->src_ipaddr;
		utmp.nas_address = nas_address;
		nas = request->client->shortname;

	} else if (request->packet->src_ipaddr.ipaddr.ip4addr.s_addr == nas_address) {		/* might be a client, might not be. */
		nas = request->client->shortname;

	} else {
		/*
		 *	The NAS isn't a client, it's behind
		 *	a proxy server.  In that case, just
		 *	get the IP address.
		 */
		nas = ip_ntoa(ip_name, nas_address);
	}


	/*
	 *	Set the protocol field.
	 */
	if (protocol == PW_PPP)
		utmp.proto = 'P';
	else if (protocol == PW_SLIP)
		utmp.proto = 'S';
	else
		utmp.proto = 'T';

	utmp.time = request->timestamp - utmp.delay;

	/*
	 *	Get the utmp filename, via xlat.
	 */
	radius_xlat(filename, sizeof(filename), inst->filename, request, NULL);

	/*
	 *	Future: look up filename in filename tree, to get
	 *	radutmp_cache_t pointer
	 */
	cache = &inst->cache;

	/*
	 *	For now, double-check the filename, to be sure it isn't
	 *	changing.
	 */
	if (!cache->filename) {
		cache->filename = strdup(filename);
		rad_assert(cache->filename != NULL);

	} else if (strcmp(cache->filename, filename) != 0) {
		radlog(L_ERR, "rlm_radutmp: We do not support dynamically named files.");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	If the lookup failed, create a new one, and add it
	 *	to the filename tree, and cache the file, as below.
	 */

	/*
	 *	For aging, in the future.
	 */
	cache->last_used = request->timestamp;

	/*
	 *	If we haven't already read the file, then read the
	 *	entire file, in order to cache its entries.
	 */
	if (!cache->cached_file) {
		cache_file(inst, cache);
	}

	/*
	 *	See if this was a reboot.
	 *
	 *	Hmm... we may not want to zap all of the users when
	 *	the NAS comes up, because of issues with receiving
	 *	UDP packets out of order.
	 */
	if (status == PW_STATUS_ACCOUNTING_ON && nas_address) {
		radlog(L_INFO, "rlm_radutmp: NAS %s restarted (Accounting-On packet seen)",
		       nas);
		if (!radutmp_zap(inst, cache, nas_address, utmp.time)) {
			rad_assert(0 == 1);
		}
		return RLM_MODULE_OK;
	}

	if (status == PW_STATUS_ACCOUNTING_OFF && nas_address) {
		radlog(L_INFO, "rlm_radutmp: NAS %s rebooted (Accounting-Off packet seen)",
		       nas);
		if (!radutmp_zap(inst, cache, nas_address, utmp.time)) {
			rad_assert(0 == 1);
		}
		return RLM_MODULE_OK;
	}

	/*
	 *	If we don't know this type of entry, then pretend we
	 *	succeeded.
	 */
	if (status != PW_STATUS_START &&
	    status != PW_STATUS_STOP &&
	    status != PW_STATUS_ALIVE) {
		radlog(L_ERR, "rlm_radutmp: NAS %s port %u unknown packet type %d, ignoring it.",
		       nas, utmp.nas_port, status);
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Perhaps we don't want to store this record into
	 *	radutmp. We skip records:
	 *
	 *	- without a NAS-Port (telnet / tcp access)
	 *	- with the username "!root" (console admin login)
	 */
	if (!port_seen) {
		DEBUG2("  rlm_radutmp: No NAS-Port in the packet.  Cannot do anything.");
		DEBUG2("  rlm_radumtp: WARNING: checkrad will probably not work!");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Translate the User-Name attribute, or whatever else
	 *	they told us to use.
	 */
	*buffer = '\0';
	radius_xlat(buffer, sizeof(buffer), inst->username, request, NULL);

	/*
	 *	Don't log certain things...
	 */
	if (strcmp(buffer, "!root") == 0) {
		DEBUG2("  rlm_radutmp: Not recording administrative user");

		return RLM_MODULE_NOOP;
	}
	strlcpy(utmp.login, buffer, RUT_NAMESIZE);

	/*
	 *	First, try to open the file.  If it doesn't exist,
	 *	nuke the existing caches, and try to create it.
	 *
	 *	FIXME: Create any intermediate directories, as
	 *	appropriate.  See rlm_detail.
	 */
	fd = open(cache->filename, O_RDWR, inst->permission);
	if (fd < 0) {
		if (errno == ENOENT) {
			DEBUG2("  rlm_radutmp: File %s doesn't exist, creating it.", cache->filename);
			if (!cache_reset(inst, cache)) return RLM_MODULE_FAIL;

			/*
			 *	Try to create the file.
			 */
			fd = open(cache->filename, O_RDWR | O_CREAT,
				  inst->permission);
		}
	} else {		/* exists, but may be empty */
		struct stat buf;

		/*
		 *	If the file is empty, reset the cache.
		 */
		if ((stat(cache->filename, &buf) == 0) &&
		    (buf.st_size == 0) &&
		    (!cache_reset(inst, cache))) {
			return RLM_MODULE_FAIL;
		}
		DEBUG2("  rlm_radutmp: File %s was truncated.  Resetting cache.",
		       cache->filename);
	}

	/*
	 *	Error from creation, or error other than ENOENT: die.
	 */
	if (fd < 0) {
		radlog(L_ERR, "rlm_radutmp: Error accessing file %s: %s",
		       cache->filename, strerror(errno));
		return RLM_MODULE_FAIL;
	}

	/*
	 *	OK.  Now that we've prepared everything we want to do,
	 *	let's see if we've cached the entry.
	 */
	myPort.nas_address = utmp.nas_address;
	myPort.nas_port = utmp.nas_port;

	pthread_mutex_lock(&cache->mutex);
	node = rbtree_find(cache->nas_ports, &myPort);
	pthread_mutex_unlock(&cache->mutex);

	if (node) {
		nas_port = rbtree_node2data(cache->nas_ports, node);
#if 0

		/*
		 *	stat the file, and get excited if it's been
		 *	truncated.
		 *
		 *	i.e wipe out the cache, and re-read the file.
		 */

		/*
		 *	Now find the new entry.
		 */
		pthread_mutex_lock(&cache->mutex);
		node = rbtree_find(cache->nas_ports, &myPort);
		pthread_mutex_unlock(&cache->mutex);
#endif
	}

	if (!node) {
		radutmp_simul_t *user;

		/*
		 *	Not found in the cache, and we're trying to
		 *	delete an existing record: ignore it.
		 */
		if (status == PW_STATUS_STOP) {
			DEBUG2("  rlm_radumtp: Logout entry for NAS %s port %u with no Login: ignoring it.",
			       nas, utmp.nas_port);
			return RLM_MODULE_NOOP;
		}

		pthread_mutex_lock(&cache->mutex);

		/*
		 *	It's a START or ALIVE.  Try to find a free
		 *	offset where we can store the new entry, or
		 *	create one, if one doesn't already exist.
		 */
		if (!cache->free_offsets) {
			cache->free_offsets = rad_malloc(sizeof(NAS_PORT));
			memset(cache->free_offsets, 0,
			       sizeof(*(cache->free_offsets)));
			cache->free_offsets->offset = cache->max_offset;
			cache->max_offset += sizeof(u);
		}

		/*
		 *	Grab the offset, and put it into the various
		 *	caches.
		 */
		nas_port = cache->free_offsets;
		cache->free_offsets = nas_port->next;

		nas_port->nas_address = nas_address;
		nas_port->nas_port = utmp.nas_port;

		if (!rbtree_insert(cache->nas_ports, nas_port)) {
			rad_assert(0 == 1);
		}

		/*
		 *	Allocate new entry, and add it
		 *	to the tree.
		 */
		user = rad_malloc(sizeof(user));
		strlcpy(user->login, utmp.login,
			sizeof(user->login));
		user->simul_count = 1;

		if (!rbtree_insert(inst->user_tree, user)) {
			rad_assert(0 == 1);
		}

		pthread_mutex_unlock(&cache->mutex);

	}

	/*
	 *	Entry was found, or newly created in the cache.
	 *	Seek to the place in the file.
	 */
	lseek(fd, nas_port->offset, SEEK_SET);

	/*
	 *	Lock the utmp file, prefer lockf() over flock().
	 */
	rad_lockfd(fd, LOCK_LEN);

	/*
	 *	If it WAS found in the cache, double-check it against
	 *	what is in the file.
	 */
	if (node) {
		/*
		 *	If we didn't read anything, then this entry
		 *	doesn't exist.
		 *
		 *	Similarly, if the entry in the file doesn't
		 *	match what we recall, then nuke the cache
		 *	entry.
		 */
		read_size = read(fd, &u, sizeof(u));
		if ((read_size < 0) ||
		    ((read_size > 0) && (read_size  != sizeof(u)))) {
			/*
			 *	Bad read, or bad record.
			 */
			radlog(L_ERR, "rlm_radutmp: Badly formed file %s",
			       cache->filename);
			close(fd);
			return RLM_MODULE_FAIL;
		}

		rad_assert(read_size != 0);

		/*
		 *	We've read a record, go poke at it.
		 */
		if (read_size > 0) {
			/*
			 *	If these aren't true, then
			 *
			 *	a) we have cached a "logout" entry,
			 *	   which we don't do.
			 *
			 *	b) we have cached the wrong NAS address
			 *
			 *	c) we have cached the wrong NAS port.
			 */
			rad_assert(u.type == P_LOGIN);
			rad_assert(u.nas_address == utmp.nas_address);
			rad_assert(u.nas_port == utmp.nas_port);

			/*
			 *	An update for the same session.
			 */
			if (strncmp(utmp.session_id, u.session_id,
				    sizeof(u.session_id)) == 0) {

				/*
				 *	It's a duplicate start, so we
				 *	don't bother writing it.
				 */
				if (status == PW_STATUS_START) {
					DEBUG2("  rlm_radutmp: Login entry for NAS %s port %u duplicate, ignoring it.",
					       nas, u.nas_port);
					close(fd);
					return RLM_MODULE_OK;


				/*
				 *	ALIVE for this session, keep the
				 *	original login time.
				 */
				} else if (status == PW_STATUS_ALIVE) {
					utmp.time = u.time;

				/*
				 *	Stop: delete it from our cache.
				 */
				} else if (status == PW_STATUS_STOP) {
					radutmp_simul_t *user, myUser;

					pthread_mutex_lock(&cache->mutex);
					rbtree_deletebydata(cache->nas_ports,
							    nas_port);

					strlcpy(myUser.login,
						u.login, sizeof(myUser.login));
					user = rbtree_finddata(inst->user_tree,
							       &myUser);
					rad_assert(user != NULL);
					rad_assert(user->simul_count > 0);

					user->simul_count--;
					if (user->simul_count == 0) {
						rbtree_deletebydata(inst->user_tree, user);
					}

					pthread_mutex_unlock(&cache->mutex);

 				} else {
					/*
					 *	We don't know how to
					 *	handle this.
					 */
					rad_assert(0 == 1);
				}

			} else { /* session ID doesn't match */
				/*
				 *	STOP for the right NAS & port,
				 *	but the Acct-Session-Id is
				 *	different.  This means that
				 *	we missed the original "stop",
				 *	and a new "start".
				 */
				if (status == PW_STATUS_STOP) {
					radlog(L_ERR, "rlm_radutmp: Logout entry for NAS %s port %u has old Acct-Session-ID, ignoring it.",
					       nas, u.nas_port);
					close(fd);
					return RLM_MODULE_OK;
				}
			} /* checked session ID's */
		}  /* else we haven't read anything from the file. */
	} /* else the entry wasn't cached, but could have been inserted */

	/*
	 *	Hmm... we may have received a start or alive packet
	 *	AFTER a stop or nas-down, in that case, we want to
	 *	discard the new packet.  However, the original code
	 *	could over-write an idle record with a new login
	 *	record for another NAS && port, so we won't worry
	 *	about this case too much.
	 */

	/*
	 *	Seek to where the entry is, and write it blindly.
	 */
	lseek(fd, nas_port->offset, SEEK_SET); /* FIXME: err */

	if (status != PW_STATUS_STOP) {
		utmp.type = P_LOGIN;
		rad_assert(nas_port != NULL); /* it WAS cached */
	} else {
		/* FIXME: maybe assert that the entry was deleted... */
		memcpy(&utmp, &u, sizeof(utmp));
		utmp.type = P_IDLE;
	}

	write(fd, &utmp, sizeof(utmp)); /* FIXME: err */

	close(fd);	/* and implicitly release the locks */

	return RLM_MODULE_OK;
}

/*
 *	See if a user is already logged in. Sets request->simul_count
 *	to the current session count for this user and sets
 *	request->simul_mpp to 2 if it looks like a multilink attempt
 *	based on the requested IP address, otherwise leaves
 *	request->simul_mpp alone.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 */
static int radutmp_checksimul(void *instance, REQUEST *request)
{
	struct radutmp	u;
	int		fd;
	VALUE_PAIR	*vp;
	uint32_t	ipno = 0;
	char		*call_num = NULL;
	int		rcode;
	rlm_radutmp_t	*inst = instance;
	char		login[256];
	char		filename[1024];
	radutmp_cache_t *cache;
	radutmp_simul_t *user, myUser;

	/*
	 *	Get the filename, via xlat.
	 */
	radius_xlat(filename, sizeof(filename), inst->filename, request, NULL);

	/*
	 *	Future: look up filename in filename tree, to get
	 *	radutmp_cache_t pointer
	 */
	cache = &inst->cache;

	/*
	 *	For now, double-check the filename, to be sure it isn't
	 *	changing.
	 */
	if (!cache->filename) {
		cache->filename = strdup(filename);
		rad_assert(cache->filename != NULL);

	} else if (strcmp(cache->filename, filename) != 0) {
		radlog(L_ERR, "rlm_radutmp: We do not support dynamically named files.");
		return RLM_MODULE_FAIL;
	}

	*login = '\0';
	radius_xlat(login, sizeof(login), inst->username, request, NULL);
	if (!*login) {
		return RLM_MODULE_NOOP;
	}

	/*
	 *	WTF?  This is probably wrong... we probably want to
	 *	be able to check users across multiple session accounting
	 *	methods.
	 */
	request->simul_count = 0;

	strlcpy(myUser.login, login, sizeof(myUser.login));
	pthread_mutex_lock(&inst->cache.mutex);
	user = rbtree_finddata(inst->user_tree, &myUser);
	if (user) request->simul_count = user->simul_count;
	user = NULL;		/* someone else may delete it */
	pthread_mutex_unlock(&inst->cache.mutex);

	/*
	 *	The number of users logged in is OK,
	 *	OR, we've been told to not check the NAS.
	 */
	if ((request->simul_count < request->simul_max) ||
	    !inst->check_nas) {
		return RLM_MODULE_OK;
	}

	/*
	 *	The user is logged in at least N times, and
	 *	we're told to check the NAS.  In that case,
	 *	we've got to read the file, and check each
	 *	NAS port by hand.
	 */
	if ((fd = open(cache->filename, O_RDWR)) < 0) {
		/*
		 *	If the file doesn't exist, then no users
		 *	are logged in.
		 */
		if (errno == ENOENT) {
			request->simul_count = 0;
			return RLM_MODULE_OK;
		}

		/*
		 *	Error accessing the file.
		 */
		radlog(L_ERR, "rlm_radumtp: Error accessing file %s: %s",
		       cache->filename, strerror(errno));
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Setup some stuff, like for MPP detection.
	 */
	if ((vp = pairfind(request->packet->vps, PW_FRAMED_IP_ADDRESS, 0, TAG_ANY)) != NULL)
		ipno = vp->vp_ipaddr;
	if ((vp = pairfind(request->packet->vps, PW_CALLING_STATION_ID, 0, TAG_ANY)) != NULL)
		call_num = vp->vp_strvalue;

	/*
	 *	lock the file while reading/writing.
	 */
	rad_lockfd(fd, LOCK_LEN);

	/*
	 *	FIXME: If we get a 'Start' for a user/nas/port which is
	 *	listed, but for which we did NOT get a 'Stop', then
	 *	it's not a duplicate session.  This happens with
	 *	static IP's like DSL.
	 */
	request->simul_count = 0;
	while (read(fd, &u, sizeof(u)) == sizeof(u)) {
		if (((strncmp(login, u.login, RUT_NAMESIZE) == 0) ||
		     (!inst->case_sensitive &&
		      (strncasecmp(login, u.login, RUT_NAMESIZE) == 0))) &&
		    (u.type == P_LOGIN)) {
			char session_id[sizeof(u.session_id) + 1];
			char utmp_login[sizeof(u.login) + 1];

			strlcpy(session_id, u.session_id, sizeof(session_id));

			/*
			 *	The login name MAY fill the whole field,
			 *	and thus won't be zero-filled.
			 *
			 *	Note that we take the user name from
			 *	the utmp file, as that's the canonical
			 *	form.  The 'login' variable may contain
			 *	a string which is an upper/lowercase
			 *	version of u.login.  When we call the
			 *	routine to check the terminal server,
			 *	the NAS may be case sensitive.
			 *
			 *	e.g. We ask if "bob" is using a port,
			 *	and the NAS says "no", because "BOB"
			 *	is using the port.
			 */
			strlcpy(utmp_login, u.login, sizeof(u.login));

			/*
			 *	rad_check_ts may take seconds
			 *	to return, and we don't want
			 *	to block everyone else while
			 *	that's happening.  */
			rad_unlockfd(fd, LOCK_LEN);
			rcode = rad_check_ts(u.nas_address, u.nas_port,
					     utmp_login, session_id);
			rad_lockfd(fd, LOCK_LEN);

			if (rcode == 0) {
				/*
				 *	Stale record - zap it.
				 *
				 *	Hmm... this ends up calling
				 *	the accounting section
				 *	recursively...
				 */
				session_zap(request, u.nas_address,
					    u.nas_port, login, session_id,
					    u.framed_address, u.proto,0);
			}
			else if (rcode == 1) {
				/*
				 *	User is still logged in.
				 */
				++request->simul_count;

				/*
				 *	Does it look like a MPP attempt?
				 */
				if (strchr("SCPA", u.proto) &&
				    ipno && u.framed_address == ipno)
					request->simul_mpp = 2;
				else if (strchr("SCPA", u.proto) && call_num &&
					!strncmp(u.caller_id,call_num,16))
					request->simul_mpp = 2;
			}
			else {
				/*
				 *	Failed to check the terminal
				 *	server for duplicate logins:
				 *	Return an error.
				 */
				close(fd);
				radlog(L_ERR, "rlm_radutmp: Failed to check the terminal server for user '%s'.", utmp_login);
				return RLM_MODULE_FAIL;
			}
		}
	}
	close(fd);		/* and implicitly release the locks */

	return RLM_MODULE_OK;
}

/* globally exported name */
module_t rlm_radutmp = {
  "radutmp",
  0,       			/* type: reserved */
  NULL,                 	/* initialization */
  radutmp_instantiate,          /* instantiation */
  {
	  NULL,                 /* authentication */
	  NULL,                 /* authorization */
	  NULL,                 /* preaccounting */
	  radutmp_accounting,   /* accounting */
	  radutmp_checksimul,	/* checksimul */
	  NULL,			/* pre-proxy */
	  NULL,			/* post-proxy */
	  NULL			/* post-auth */
  },
  radutmp_detach,               /* detach */
  NULL,         	        /* destroy */
};

