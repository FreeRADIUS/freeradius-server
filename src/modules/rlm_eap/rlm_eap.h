/*
 * rlm_eap.h    Local Header file.
 *
 * Version:     $Id$
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
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */
#ifndef _RLM_EAP_H
#define _RLM_EAP_H

#include <ltdl.h>
#include "eap.h"

#define EAP_START		2
#define NAME_LEN		32

enum {
	EAP_NOTFOUND,    /* not found */
	EAP_FOUND,       /* found, continue */
	EAP_OK,		 /* ok, continue */
	EAP_FAIL,        /* failed, don't reply */
	EAP_NOOP,        /* succeeded without doing anything */
	EAP_INVALID,     /* invalid, don't reply */
	EAP_VALID       /* valid, continue */
};

/*
 * Structure to represent packet format of eap
 */
typedef struct eap_packet_t {
	unsigned char	code;
	unsigned char	id;
	unsigned char	length[2];
	unsigned char	data[1];
} eap_packet_t;

/*
 * Config stuff that rlm_eap depends on.
 */
typedef struct eap_conf {
	char	*default_eap_type;
	int		timer_limit;
} EAP_CONF;

/*
 * Currently there are only 2 types
 * of operations defined, 
 * apart from attach & detach for each EAP-Type.
 */
typedef enum operation_t {
	INITIATE = 0,
	AUTHENTICATE
} operation_t;

/*
 * Keep track of which sub modules we've loaded.
 */
typedef struct eap_types_t {
	struct eap_types_t  	*next;
	int		typeid;
	char	typename[NAME_LEN];
	EAP_TYPE       	*type;
	lt_dlhandle     handle;
	CONF_SECTION	*cs;
	void		*type_stuff;
} EAP_TYPES;

/*
 * This structure contains eap's persistent data.
 * echolist = EAP_HANDLERs 
 * typelist = All supported EAP-Types
 * conf     = configured values for rlm_eap only.
 */
typedef struct rlm_eap_t {
	EAP_HANDLER 	*echolist;
	EAP_TYPES 	*typelist;
	EAP_CONF	*conf;
} rlm_eap_t;

/* function definitions */
/* EAP-Type */
EAP_TYPES 	*eaptype_byid(EAP_TYPES **list, int type);
EAP_TYPES 	*eaptype_byname(EAP_TYPES **list, const char *name);
int      	eaptype_load(EAP_TYPES **tl, const char *tname, CONF_SECTION *cs);
int       	eaptype_select(EAP_TYPES *tl, EAP_HANDLER *h, char *eaptype);
int       	eaptype_call(int type, operation_t act, EAP_TYPES *tl, EAP_HANDLER *h);
void		eaptype_freelist(EAP_TYPES **tl);

/* EAP */
int  		eap_start(REQUEST *request);
void 		eap_fail(REQUEST *request, EAP_DS *eap_ds);
void 		eap_success(REQUEST *request, EAP_DS *eap_ds);
int 		eap_validation(eap_packet_t *eap_msg);
int 		eap_wireformat(EAP_PACKET *packet);
int 		eap_compose(REQUEST *request, EAP_DS *eap_ds);
eap_packet_t 	*eap_attribute(VALUE_PAIR *vps);
EAP_HANDLER 	*eap_handler(EAP_HANDLER **list, eap_packet_t **eap_msg, REQUEST *request);
char 		*eap_identity(eap_packet_t *eap_packet);
VALUE_PAIR 	*eap_useridentity(EAP_HANDLER *list, eap_packet_t *eap_packet, unsigned char id[]);
unsigned char 	*eap_generateid(REQUEST *request, unsigned char response_id);
unsigned char 	*eap_regenerateid(REQUEST *request, unsigned char response_id);

/* Memory Management */
EAP_PACKET  	*eap_packet_alloc(void);
EAP_DS      	*eap_ds_alloc(void);
EAP_HANDLER 	*eap_handler_alloc(void);
void	    	eap_packet_free(EAP_PACKET **eap_packet);
void	    	eap_ds_free(EAP_DS **eap_ds);
void	    	eap_handler_free(EAP_HANDLER **handler);

int 	    	eaplist_add(EAP_HANDLER **list, EAP_HANDLER *handler);
void	    	eaplist_clean(EAP_HANDLER **list, time_t limit);
void	    	eaplist_free(EAP_HANDLER **list);
EAP_HANDLER 	*eaplist_isreply(EAP_HANDLER **list, unsigned char id[]);
EAP_HANDLER 	*eaplist_findhandler(EAP_HANDLER *list, unsigned char id[]);

/* State */
void	    	generate_key(void);
VALUE_PAIR  	*generate_state(void);
int	    	verify_state(VALUE_PAIR *state);

#endif /*_RLM_EAP_H*/
