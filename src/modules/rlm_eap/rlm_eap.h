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
 * Keep track of which sub modules we've loaded.
 */
typedef struct eap_types_t {
	const char	*typename;
	int		typeid;
	EAP_TYPE       	*type;
	lt_dlhandle     handle;
	CONF_SECTION	*cs;
	void		*type_data;
} EAP_TYPES;

/*
 * This structure contains eap's persistent data.
 * sessions[] = EAP_HANDLERS, keyed by the first octet of the State
 *              attribute, and composed of a linked list, ordered from
 *              oldest to newest.
 * typelist = All supported EAP-Types
 * conf     = configured values for rlm_eap only.
 */
typedef struct rlm_eap_t {
	EAP_HANDLER 	*sessions[256];
	EAP_TYPES 	*types[PW_EAP_MAX_TYPES + 1];

	/*
	 *	Configuration items.
	 */
	char		*default_eap_type;
	int		timer_limit;
	int		default_eap_id;
} rlm_eap_t;

/* function definitions */
/* EAP-Type */
int		eaptype_name2id(const char *name);
EAP_TYPES 	*eaptype_byid(EAP_TYPES **list, int type);
EAP_TYPES 	*eaptype_byname(EAP_TYPES **list, const char *name);
int      	eaptype_load(EAP_TYPES **type, int id, CONF_SECTION *cs);
int       	eaptype_select(rlm_eap_t *inst, EAP_HANDLER *h);
void		eaptype_free(EAP_TYPES *tl);

/* EAP */
int  		eap_start(REQUEST *request);
void 		eap_fail(REQUEST *request, EAP_DS *eap_ds);
void 		eap_success(REQUEST *request, EAP_DS *eap_ds);
int 		eap_validation(eap_packet_t *eap_msg);
int 		eap_wireformat(EAP_PACKET *packet);
int 		eap_compose(REQUEST *request, EAP_DS *eap_ds);
eap_packet_t 	*eap_attribute(VALUE_PAIR *vps);
EAP_HANDLER 	*eap_handler(rlm_eap_t *inst, eap_packet_t **eap_msg, REQUEST *request);
char 		*eap_identity(eap_packet_t *eap_packet);

/* Memory Management */
EAP_PACKET  	*eap_packet_alloc(void);
EAP_DS      	*eap_ds_alloc(void);
EAP_HANDLER 	*eap_handler_alloc(void);
void	    	eap_packet_free(EAP_PACKET **eap_packet);
void	    	eap_ds_free(EAP_DS **eap_ds);
void	    	eap_handler_free(EAP_HANDLER **handler);

int 	    	eaplist_add(rlm_eap_t *inst, EAP_HANDLER *handler);
void	    	eaplist_free(rlm_eap_t *inst);
EAP_HANDLER 	*eaplist_find(rlm_eap_t *inst, REQUEST *request, int id);

/* State */
void	    	generate_key(void);
VALUE_PAIR  	*generate_state(time_t timestamp);
int	    	verify_state(VALUE_PAIR *state, time_t timestamp);

#endif /*_RLM_EAP_H*/
