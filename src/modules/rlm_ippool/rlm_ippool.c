/*
 * rlm_ippool.c
 *
 * Version:  $Id$
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  The FreeRADIUS server project
 * Copyright 2002  Kostas Kalevras <kkalev@noc.ntua.gr>
 *
 * March 2002, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - Initial release
 * April 2002, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - Add support for the Pool-Name attribute
 * May 2002, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - Check the return value of a gdbm_fetch() we didn't check
 * - Change the nas entry in the ippool_key structure from uint32 to string[64]
 *   That should allow us to also use the NAS-Identifier attribute
 * Sep 2002, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - Move from authorize to post-auth
 * - Use mutex locks when accessing the gdbm files
 * - Fail if we don't find nas port information
 * Oct 2002, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - Do a memset(0) on the key.nas before doing searches. Nusty bug
 * Jul 2003, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - Make Multilink work this time
 * - Instead of locking file operations, lock transactions. That means we only keep
 *   one big transaction lock instead of per file locks (mutexes).
 * Sep 2003, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - Fix postauth to not leak ip's
 *   Add an extra attribute in each entry <char extra> signifying if we need to delete this
 *   entry in the accounting phase. This is only true in case we are doing MPPP
 *   Various other code changes. Code comments should explain things
 *   Highly experimental at this phase.
 * Mar 2004, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - Add a timestamp and a timeout attribute in ippool_info. When we assign an ip we set timestamp
 *   to request->timestamp and timeout to %{Session-Timeout:-0}. When we search for a free entry
 *   we check if timeout has expired. If it has then we free the entry. We also add a maximum
 *   timeout configuration directive. If it is non zero then we also use that one to free entries.
 * Jul 2004, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - If Pool-Name is set to DEFAULT then always run.
 */

#include "config.h"
#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

#include <gdbm.h>
#include <time.h>

#ifdef NEEDS_GDBM_SYNC
#	define GDBM_SYNCOPT GDBM_SYNC
#else
#	define GDBM_SYNCOPT 0
#endif

#ifdef GDBM_NOLOCK
#define GDBM_IPPOOL_OPTS (GDBM_SYNCOPT | GDBM_NOLOCK)
#else
#define GDBM_IPPOOL_OPTS (GDBM_SYNCOPT)
#endif

#define MAX_NAS_NAME_SIZE 64

static const char rcsid[] = "$Id$";

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_ippool_t {
	char *session_db;
	char *ip_index;
	char *name;
	uint32_t range_start;
	uint32_t range_stop;
	uint32_t netmask;
	time_t max_timeout;
	int cache_size;
	int override;
	GDBM_FILE gdbm;
	GDBM_FILE ip;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t op_mutex;
#endif
} rlm_ippool_t;

#ifndef HAVE_PTHREAD_H
/*
 *	This is easier than ifdef's throughout the code.
 */
#define pthread_mutex_init(_x, _y)
#define pthread_mutex_destroy(_x)
#define pthread_mutex_lock(_x)
#define pthread_mutex_unlock(_x)
#endif

typedef struct ippool_info {
	uint32_t	ipaddr;
	char		active;
	char		cli[32];
	char		extra;
	time_t		timestamp;
	time_t		timeout;
} ippool_info;

typedef struct ippool_key {
	char nas[MAX_NAS_NAME_SIZE];
	unsigned int port;
} ippool_key;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static CONF_PARSER module_config[] = {
  { "session-db", PW_TYPE_STRING_PTR, offsetof(rlm_ippool_t,session_db), NULL, NULL },
  { "ip-index", PW_TYPE_STRING_PTR, offsetof(rlm_ippool_t,ip_index), NULL, NULL },
  { "range-start", PW_TYPE_IPADDR, offsetof(rlm_ippool_t,range_start), NULL, "0" },
  { "range-stop", PW_TYPE_IPADDR, offsetof(rlm_ippool_t,range_stop), NULL, "0" },
  { "netmask", PW_TYPE_IPADDR, offsetof(rlm_ippool_t,netmask), NULL, "0" },
  { "cache-size", PW_TYPE_INTEGER, offsetof(rlm_ippool_t,cache_size), NULL, "1000" },
  { "override", PW_TYPE_BOOLEAN, offsetof(rlm_ippool_t,override), NULL, "no" },
  { "maximum-timeout", PW_TYPE_INTEGER, offsetof(rlm_ippool_t,max_timeout), NULL, "0" },
  { NULL, -1, 0, NULL, NULL }
};


/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int ippool_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_ippool_t *data;
	int cache_size;
	ippool_info entry;
	ippool_key key;
	datum key_datum;
	datum data_datum;
	int i;
	unsigned j;
	const char *cli = "0";
	char *pool_name = NULL;

	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));
	if (!data) {
		return -1;
	}
	memset(data, 0, sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}
	cache_size = data->cache_size;

	if (data->session_db == NULL) {
		radlog(L_ERR, "rlm_ippool: 'session-db' must be set.");
		free(data);
		return -1;
	}
	if (data->ip_index == NULL) {
		radlog(L_ERR, "rlm_ippool: 'ip-index' must be set.");
		free(data);
		return -1;
	}
	data->range_start = htonl(data->range_start);
	data->range_stop = htonl(data->range_stop);
	data->netmask = htonl(data->netmask);
	if (data->range_start == 0 || data->range_stop == 0 || \
			 data->range_start >= data->range_stop ) {
		radlog(L_ERR, "rlm_ippool: Invalid configuration data given.");
		free(data);
		return -1;
	}

	data->gdbm = gdbm_open(data->session_db, sizeof(int),
			GDBM_WRCREAT | GDBM_IPPOOL_OPTS, 0600, NULL);
	if (data->gdbm == NULL) {
		radlog(L_ERR, "rlm_ippool: Failed to open file %s: %s",
				data->session_db, strerror(errno));
		return -1;
	}
	data->ip = gdbm_open(data->ip_index, sizeof(int),
			GDBM_WRCREAT | GDBM_IPPOOL_OPTS, 0600, NULL);
	if (data->ip == NULL) {
		radlog(L_ERR, "rlm_ippool: Failed to open file %s: %s",
				data->ip_index, strerror(errno));
		return -1;
	}
	if (gdbm_setopt(data->gdbm, GDBM_CACHESIZE, &cache_size, sizeof(int)) == -1)
		radlog(L_ERR, "rlm_ippool: Failed to set cache size");
	if (gdbm_setopt(data->ip, GDBM_CACHESIZE, &cache_size, sizeof(int)) == -1)
		radlog(L_ERR, "rlm_ippool: Failed to set cache size");

	key_datum = gdbm_firstkey(data->gdbm);
	if (key_datum.dptr == NULL){
			/*
			 * If the database does not exist initialize it.
			 * We set the nas/port pairs to not existent values and
			 * active = 0
			 */
		int rcode;
		uint32_t or_result;
		char str[32];
		const char *nas_init = "NOT_EXIST";

		DEBUG("rlm_ippool: Initializing database");
		for(i=data->range_start,j=~0;i<=data->range_stop;i++,j--){

			/*
			 * Net and Broadcast addresses are excluded
			 */
			or_result = i | data->netmask;
			if (~data->netmask != 0 &&
				(or_result == data->netmask ||
			    (~or_result == 0))) {
				DEBUG("rlm_ippool: IP %s excluded",
				      ip_ntoa(str, ntohl(i)));
				continue;
			}

			strcpy(key.nas, nas_init);
			key.port = j;
			key_datum.dptr = (char *) &key;
			key_datum.dsize = sizeof(ippool_key);

			entry.ipaddr = ntohl(i);
			entry.active = 0;
			entry.extra = 0;
			entry.timestamp = 0;
			entry.timeout = 0;
			strcpy(entry.cli,cli);

			data_datum.dptr = (char *) &entry;
			data_datum.dsize = sizeof(ippool_info);

			rcode = gdbm_store(data->gdbm, key_datum, data_datum, GDBM_REPLACE);
			if (rcode < 0) {
				radlog(L_ERR, "rlm_ippool: Failed storing data to %s: %s",
						data->session_db, gdbm_strerror(gdbm_errno));
				free(data);
				gdbm_close(data->gdbm);
				gdbm_close(data->ip);
				return -1;
			}
		}
	}
	else
		free(key_datum.dptr);

	/* Add the ip pool name */
	data->name = NULL;
	pool_name = cf_section_name2(conf);
	if (pool_name != NULL)
		data->name = strdup(pool_name);

	pthread_mutex_init(&data->op_mutex, NULL);
	*instance = data;

	return 0;
}


/*
 *	Check for an Accounting-Stop
 *	If we find one and we have allocated an IP to this nas/port combination, deallocate it.
 */
static int ippool_accounting(void *instance, REQUEST *request)
{
	rlm_ippool_t *data = (rlm_ippool_t *)instance;
	datum key_datum;
	datum data_datum;
	datum save_datum;
	int acctstatustype = 0;
	unsigned int port = ~0;
	int rcode;
	char nas[MAX_NAS_NAME_SIZE];
	ippool_info entry;
	ippool_key key;
	int num = 0;
	VALUE_PAIR *vp;
	char str[32];


	if ((vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE)) != NULL)
		acctstatustype = vp->lvalue;
	else {
		DEBUG("rlm_ippool: Could not find account status type in packet. Return NOOP.");
		return RLM_MODULE_NOOP;
	}
	switch(acctstatustype){
		case PW_STATUS_STOP:
			if ((vp = pairfind(request->packet->vps, PW_NAS_PORT)) != NULL)
				port = vp->lvalue;
			else {
				DEBUG("rlm_ippool: Could not find port number in packet. Return NOOP.");
				return RLM_MODULE_NOOP;
			}
			if ((vp = pairfind(request->packet->vps, PW_NAS_IP_ADDRESS)) != NULL)
				strncpy(nas, vp->strvalue, MAX_NAS_NAME_SIZE - 1);
			else {
				if ((vp = pairfind(request->packet->vps, PW_NAS_IDENTIFIER)) != NULL)
					strncpy(nas, vp->strvalue, MAX_NAS_NAME_SIZE - 1);
				else {
					DEBUG("rlm_ippool: Could not find nas information in packet. Return NOOP.");
					return RLM_MODULE_NOOP;
				}
			}
			break;
		default:
			/* We don't care about any other accounting packet */
			DEBUG("rlm_ippool: This is not an Accounting-Stop. Return NOOP.");

			return RLM_MODULE_NOOP;
	}

	memset(key.nas,0,MAX_NAS_NAME_SIZE);
	strncpy(key.nas,nas,MAX_NAS_NAME_SIZE -1 );
	key.port = port;
	DEBUG("rlm_ippool: Searching for an entry for nas/port: %s/%u",key.nas,key.port);
	key_datum.dptr = (char *) &key;
	key_datum.dsize = sizeof(ippool_key);

	pthread_mutex_lock(&data->op_mutex);
	data_datum = gdbm_fetch(data->gdbm, key_datum);
	if (data_datum.dptr != NULL){

		/*
		 * If the entry was found set active to zero
		 */
		memcpy(&entry, data_datum.dptr, sizeof(ippool_info));
		free(data_datum.dptr);
		DEBUG("rlm_ippool: Deallocated entry for ip/port: %s/%u",ip_ntoa(str,entry.ipaddr),port);
		entry.active = 0;
		entry.timestamp = 0;
		entry.timeout = 0;

		/*
		 * Save the reference to the entry
		 */
		save_datum.dptr = key_datum.dptr;
		save_datum.dsize = key_datum.dsize;

		data_datum.dptr = (char *) &entry;
		data_datum.dsize = sizeof(ippool_info);

		rcode = gdbm_store(data->gdbm, key_datum, data_datum, GDBM_REPLACE);
		if (rcode < 0) {
			radlog(L_ERR, "rlm_ippool: Failed storing data to %s: %s",
					data->session_db, gdbm_strerror(gdbm_errno));
			pthread_mutex_unlock(&data->op_mutex);
			return RLM_MODULE_FAIL;
		}

		/*
		 * Decrease allocated count from the ip index
		 */
		key_datum.dptr = (char *) &entry.ipaddr;
		key_datum.dsize = sizeof(uint32_t);
		data_datum = gdbm_fetch(data->ip, key_datum);
		if (data_datum.dptr != NULL){
			memcpy(&num, data_datum.dptr, sizeof(int));
			free(data_datum.dptr);
			if (num >0){
				num--;
				DEBUG("rlm_ippool: num: %d",num);
				data_datum.dptr = (char *) &num;
				data_datum.dsize = sizeof(int);
				rcode = gdbm_store(data->ip, key_datum, data_datum, GDBM_REPLACE);
				if (rcode < 0) {
					radlog(L_ERR, "rlm_ippool: Failed storing data to %s: %s",
							data->ip_index, gdbm_strerror(gdbm_errno));
					pthread_mutex_unlock(&data->op_mutex);
					return RLM_MODULE_FAIL;
				}
				if (num >0 && entry.extra == 1){
					/*
					 * We are doing MPPP and we still have nas/port entries referencing
					 * this ip. Delete this entry so that eventually we only keep one
					 * reference to this ip.
					 */
					gdbm_delete(data->gdbm,save_datum);
				}
			}
		}
		pthread_mutex_unlock(&data->op_mutex);
	}
	else{
		pthread_mutex_unlock(&data->op_mutex);
		DEBUG("rlm_ippool: Entry not found");
	}

	return RLM_MODULE_OK;
}

static int ippool_postauth(void *instance, REQUEST *request)
{
	rlm_ippool_t *data = (rlm_ippool_t *) instance;
	unsigned int port = 0;
	int delete = 0;
	int found = 0;
	int mppp = 0;
	int extra = 0;
	int rcode;
	int num = 0;
	char nas[MAX_NAS_NAME_SIZE];
	datum key_datum;
	datum nextkey;
	datum data_datum;
	datum save_datum;
	ippool_key key;
	ippool_info entry;
	VALUE_PAIR *vp;
	char *cli = NULL;
	char str[32];


	/* quiet the compiler */
	instance = instance;
	request = request;

	/* Check if Pool-Name attribute exists. If it exists check our name and
	 * run only if they match
	 */
	if ((vp = pairfind(request->config_items, PW_POOL_NAME)) != NULL){
		if (data->name == NULL || (strcmp(data->name,vp->strvalue) && strcmp(vp->strvalue,"DEFAULT")))
			return RLM_MODULE_NOOP;
	} else {
		DEBUG("rlm_ippool: Could not find Pool-Name attribute.");
		return RLM_MODULE_NOOP;
	}

	/*
	 * Get the nas ip address
	 * If not fail
	 */
	if ((vp = pairfind(request->packet->vps, PW_NAS_IP_ADDRESS)) != NULL)
		strncpy(nas, vp->strvalue, MAX_NAS_NAME_SIZE - 1);
	else{
		if ((vp = pairfind(request->packet->vps, PW_NAS_IDENTIFIER)) != NULL)
			strncpy(nas, vp->strvalue, MAX_NAS_NAME_SIZE - 1);
		else{
			DEBUG("rlm_ippool: Could not find nas information. Return NOOP.");
			return RLM_MODULE_NOOP;
		}
	}

	/*
	 * Find the caller id
	 */
	if ((vp = pairfind(request->packet->vps, PW_CALLING_STATION_ID)) != NULL)
		cli = vp->strvalue;

	/*
	 * Find the port
	 * If not fail
	 */
	if ((vp = pairfind(request->packet->vps, PW_NAS_PORT)) != NULL)
		port = vp->lvalue;
	else{
		DEBUG("rlm_ippool: Could not find nas port information. Return NOOP.");
		return RLM_MODULE_NOOP;
	}

	memset(key.nas,0,MAX_NAS_NAME_SIZE);
	strncpy(key.nas,nas,MAX_NAS_NAME_SIZE -1 );
	key.port = port;
	DEBUG("rlm_ippool: Searching for an entry for nas/port: %s/%u",key.nas,key.port);
	key_datum.dptr = (char *) &key;
	key_datum.dsize = sizeof(ippool_key);

	pthread_mutex_lock(&data->op_mutex);
	data_datum = gdbm_fetch(data->gdbm, key_datum);
	if (data_datum.dptr != NULL){
		/*
		 * If there is a corresponding entry in the database with active=1 it is stale.
		 * Set active to zero
		 */
		found = 1;
		memcpy(&entry, data_datum.dptr, sizeof(ippool_info));
		free(data_datum.dptr);
		if (entry.active){
			DEBUG("rlm_ippool: Found a stale entry for ip/port: %s/%u",ip_ntoa(str,entry.ipaddr),port);
			entry.active = 0;
			entry.timestamp = 0;
			entry.timeout = 0;

			/*
			 * Save the reference to the entry
			 */
			save_datum.dptr = key_datum.dptr;
			save_datum.dsize = key_datum.dsize;

			data_datum.dptr = (char *) &entry;
			data_datum.dsize = sizeof(ippool_info);

			rcode = gdbm_store(data->gdbm, key_datum, data_datum, GDBM_REPLACE);
			if (rcode < 0) {
				radlog(L_ERR, "rlm_ippool: Failed storing data to %s: %s",
					data->session_db, gdbm_strerror(gdbm_errno));
				pthread_mutex_unlock(&data->op_mutex);
				return RLM_MODULE_FAIL;
			}
			/* Decrease allocated count from the ip index */

			key_datum.dptr = (char *) &entry.ipaddr;
			key_datum.dsize = sizeof(uint32_t);
			data_datum = gdbm_fetch(data->ip, key_datum);
			if (data_datum.dptr != NULL){
				memcpy(&num, data_datum.dptr, sizeof(int));
				free(data_datum.dptr);
				if (num >0){
					num--;
					DEBUG("rlm_ippool: num: %d",num);
					data_datum.dptr = (char *) &num;
					data_datum.dsize = sizeof(int);
					rcode = gdbm_store(data->ip, key_datum, data_datum, GDBM_REPLACE);
					if (rcode < 0) {
						radlog(L_ERR, "rlm_ippool: Failed storing data to %s: %s",
								data->ip_index, gdbm_strerror(gdbm_errno));
						pthread_mutex_unlock(&data->op_mutex);
						return RLM_MODULE_FAIL;
					}
					if (num >0 && entry.extra == 1){
						/*
						 * We are doing MPPP and we still have nas/port entries referencing
						 * this ip. Delete this entry so that eventually we only keep one
						 * reference to this ip.
						 */
						gdbm_delete(data->gdbm,save_datum);
					}
				}
			}
		}
	}

	pthread_mutex_unlock(&data->op_mutex);

	/*
	 * If there is a Framed-IP-Address attribute in the reply, check for override
	 */
	if (pairfind(request->reply->vps, PW_FRAMED_IP_ADDRESS) != NULL) {
		DEBUG("rlm_ippool: Found Framed-IP-Address attribute in reply attribute list.");
		if (data->override)
		{
			/* Override supplied Framed-IP-Address */
			DEBUG("rlm_ippool: override is set to yes. Override the existing Framed-IP-Address attribute.");
			pairdelete(&request->reply->vps, PW_FRAMED_IP_ADDRESS);
		} else {
			/* Abort */
			DEBUG("rlm_ippool: override is set to no. Return NOOP.");
			return RLM_MODULE_NOOP;
		}
	}

	/*
	 * Walk through the database searching for an active=0 entry.
	 * We search twice. Once to see if we have an active entry with the same callerid
	 * so that MPPP can work ok and then once again to find a free entry.
	 */

	pthread_mutex_lock(&data->op_mutex);

	key_datum.dptr = NULL;
	if (cli != NULL){
		key_datum = gdbm_firstkey(data->gdbm);
		while(key_datum.dptr){
			data_datum = gdbm_fetch(data->gdbm, key_datum);
			if (data_datum.dptr){
				memcpy(&entry,data_datum.dptr, sizeof(ippool_info));
				free(data_datum.dptr);
				/*
		 		* If we find an entry for the same caller-id and nas with active=1
		 		* then we use that for multilink (MPPP) to work properly.
		 		*/
				if (strcmp(entry.cli,cli) == 0 && entry.active){
					memcpy(&key,key_datum.dptr,sizeof(ippool_key));
					if (!strcmp(key.nas,nas)){
						mppp = 1;
						break;
					}
				}
			}
			nextkey = gdbm_nextkey(data->gdbm, key_datum);
			free(key_datum.dptr);
			key_datum = nextkey;
		}
	}

	if (key_datum.dptr == NULL){
		key_datum = gdbm_firstkey(data->gdbm);
		while(key_datum.dptr){
			data_datum = gdbm_fetch(data->gdbm, key_datum);
			if (data_datum.dptr){
				memcpy(&entry,data_datum.dptr, sizeof(ippool_info));
				free(data_datum.dptr);

				/*
				 * Find an entry with active == 0
				 * or an entry that has expired
				 */
				if (entry.active == 0 || (entry.timestamp && ((entry.timeout && 
				request->timestamp >= (entry.timestamp + entry.timeout)) ||
				(data->max_timeout && request->timestamp >= (entry.timestamp + data->max_timeout))))){
					datum tmp;

					tmp.dptr = (char *) &entry.ipaddr;
					tmp.dsize = sizeof(uint32_t);
					data_datum = gdbm_fetch(data->ip, tmp);

					/*
					 * If we find an entry in the ip index and the number is zero (meaning
					 * that we haven't allocated the same ip address to another nas/port pair)
					 * or if we don't find an entry then delete the session entry so
					 * that we can change the key (nas/port)
					 * Else we don't delete the session entry since we haven't yet deallocated the
					 * corresponding ip address and we continue our search.
					 */

					if (data_datum.dptr){
						memcpy(&num,data_datum.dptr, sizeof(int));
						free(data_datum.dptr);
						if (num == 0){
							delete = 1;
							break;
						}
					}
					else{
						delete = 1;
						break;
					}
				}
			}
			nextkey = gdbm_nextkey(data->gdbm, key_datum);
			free(key_datum.dptr);
			key_datum = nextkey;
		}
	}
	/*
	 * If we have found a free entry set active to 1 then add a Framed-IP-Address attribute to
	 * the reply
	 * We keep the operation mutex locked until after we have set the corresponding entry active
	 */
	if (key_datum.dptr){
		if (found && !mppp){
			/*
			 * Found == 1 means we have the nas/port combination entry in our database
			 * We exchange the ip address between the nas/port entry and the free entry
			 * Afterwards we will save the free ip address to the nas/port entry.
			 * That is:
			 *  ---------------------------------------------
			 *  - NAS/PORT Entry  |||| Free Entry  ||| Time
			 *  -    IP1                 IP2(Free)    BEFORE
			 *  -    IP2(Free)           IP1          AFTER
			 *  ---------------------------------------------
			 *
			 * We only do this if we are NOT doing MPPP
			 *
			 */
			datum key_datum_tmp;
			datum data_datum_tmp;
			ippool_key key_tmp;

			memset(key_tmp.nas,0,MAX_NAS_NAME_SIZE);
			strncpy(key_tmp.nas,nas,MAX_NAS_NAME_SIZE -1 );
			key_tmp.port = port;
			DEBUG("rlm_ippool: Searching for an entry for nas/port: %s/%u",key_tmp.nas,key_tmp.port);
			key_datum_tmp.dptr = (char *) &key_tmp;
			key_datum_tmp.dsize = sizeof(ippool_key);

			data_datum_tmp = gdbm_fetch(data->gdbm, key_datum_tmp);
			if (data_datum_tmp.dptr != NULL){

				rcode = gdbm_store(data->gdbm, key_datum, data_datum_tmp, GDBM_REPLACE);
				if (rcode < 0) {
					radlog(L_ERR, "rlm_ippool: Failed storing data to %s: %s",
						data->session_db, gdbm_strerror(gdbm_errno));
						pthread_mutex_unlock(&data->op_mutex);
					return RLM_MODULE_FAIL;
				}
				free(data_datum_tmp.dptr);
			}
		}
		else{
			/*
			 * We have not found the nas/port combination
			 */
			if (delete){
				/*
		 	  	 * Delete the entry so that we can change the key
			 	 * All is well. We delete one entry and we add one entry
		 	 	 */
				gdbm_delete(data->gdbm, key_datum);
			}
			else{
				/*
				 * We are doing MPPP. (mppp should be 1)
				 * We don't do anything.
				 * We will create an extra not needed entry in the database in this case
				 * but we don't really care since we always also use the ip_index database
				 * when we search for a free entry.
				 * We will also delete that entry on the accounting section so that we only
				 * have one nas/port entry referencing each ip
				 */
				if (mppp)
					extra = 1;
				if (!mppp)
					radlog(L_ERR, "rlm_ippool: mppp is not one. Please report this behaviour.");
			}
		}
		free(key_datum.dptr);
		entry.active = 1;
		entry.timestamp = request->timestamp;
		if ((vp = pairfind(request->reply->vps, PW_SESSION_TIMEOUT)) != NULL)	
			entry.timeout = (time_t) vp->lvalue;
		else
			entry.timeout = 0;
		if (extra)
			entry.extra = 1;
		data_datum.dptr = (char *) &entry;
		data_datum.dsize = sizeof(ippool_info);
		memset(key.nas,0,MAX_NAS_NAME_SIZE);
		strncpy(key.nas,nas,MAX_NAS_NAME_SIZE - 1);
		key.port = port;
		key_datum.dptr = (char *) &key;
		key_datum.dsize = sizeof(ippool_key);

		DEBUG2("rlm_ippool: Allocating ip to nas/port: %s/%u",key.nas,key.port);
		rcode = gdbm_store(data->gdbm, key_datum, data_datum, GDBM_REPLACE);
		if (rcode < 0) {
			radlog(L_ERR, "rlm_ippool: Failed storing data to %s: %s",
				data->session_db, gdbm_strerror(gdbm_errno));
				pthread_mutex_unlock(&data->op_mutex);
			return RLM_MODULE_FAIL;
		}

		/* Increase the ip index count */
		key_datum.dptr = (char *) &entry.ipaddr;
		key_datum.dsize = sizeof(uint32_t);
		data_datum = gdbm_fetch(data->ip, key_datum);
		if (data_datum.dptr){
			memcpy(&num,data_datum.dptr,sizeof(int));
			free(data_datum.dptr);
		} else
			num = 0;
		num++;
		DEBUG("rlm_ippool: num: %d",num);
		data_datum.dptr = (char *) &num;
		data_datum.dsize = sizeof(int);
		rcode = gdbm_store(data->ip, key_datum, data_datum, GDBM_REPLACE);
		if (rcode < 0) {
			radlog(L_ERR, "rlm_ippool: Failed storing data to %s: %s",
				data->ip_index, gdbm_strerror(gdbm_errno));
			pthread_mutex_unlock(&data->op_mutex);
			return RLM_MODULE_FAIL;
		}
		pthread_mutex_unlock(&data->op_mutex);


		DEBUG("rlm_ippool: Allocated ip %s to client on nas %s,port %u",ip_ntoa(str,entry.ipaddr),
				key.nas,port);
		if ((vp = paircreate(PW_FRAMED_IP_ADDRESS, PW_TYPE_IPADDR)) == NULL) {
			radlog(L_ERR|L_CONS, "no memory");
			return RLM_MODULE_FAIL;
		}
		vp->lvalue = entry.ipaddr;
		ip_ntoa(vp->strvalue, vp->lvalue);
		pairadd(&request->reply->vps, vp);

		/*
		 *	If there is no Framed-Netmask attribute in the
		 *	reply, add one
		 */
		if (pairfind(request->reply->vps, PW_FRAMED_IP_NETMASK) == NULL) {
			if ((vp = paircreate(PW_FRAMED_IP_NETMASK, PW_TYPE_IPADDR)) == NULL)
				radlog(L_ERR|L_CONS, "no memory");
			else {
				vp->lvalue = ntohl(data->netmask);
				ip_ntoa(vp->strvalue, vp->lvalue);
				pairadd(&request->reply->vps, vp);
			}
		}

	}
	else{
		pthread_mutex_unlock(&data->op_mutex);
		DEBUG("rlm_ippool: No available ip addresses in pool.");
		return RLM_MODULE_NOTFOUND;
	}

	return RLM_MODULE_OK;
}

static int ippool_detach(void *instance)
{
	rlm_ippool_t *data = (rlm_ippool_t *) instance;

	gdbm_close(data->gdbm);
	gdbm_close(data->ip);
	free(data->session_db);
	free(data->ip_index);
	pthread_mutex_destroy(&data->op_mutex);

	free(instance);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_ippool = {
	"IPPOOL",
	RLM_TYPE_THREAD_SAFE,		/* type */
	NULL,				/* initialization */
	ippool_instantiate,		/* instantiation */
	{
		NULL,			/* authentication */
		NULL,		 	/* authorization */
		NULL,			/* preaccounting */
		ippool_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		ippool_postauth		/* post-auth */
	},
	ippool_detach,			/* detach */
	NULL,				/* destroy */
};
