#ifndef _EAP_H
#define _EAP_H

/*
 * TODO: This file needs cleanup.
 * 	Some local definitions & structures
 * 	should be removed from here.
 */
#include <ltdl.h>
 
#include "conffile.h"
#include "libradius.h"
#include "radiusd.h"
#include "modules.h"

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#define EAP_START		2

#define PW_EAP_REQUEST		1
#define PW_EAP_RESPONSE		2
#define PW_EAP_SUCCESS		3
#define PW_EAP_FAILURE		4
#define PW_EAP_MAX_CODES	4

#define PW_EAP_IDENTITY		1
#define PW_EAP_NOTIFICATION	2
#define PW_EAP_NAK		3
#define PW_EAP_MD5		4
#define PW_EAP_OTP		5
#define PW_EAP_GTC		6
#define PW_EAP_TLS		13
#define PW_EAP_MAX_TYPES	13

#define EAP_HEADER_LEN 		4

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
 * structure to represent packet format of eap
 */
typedef struct eap_packet_t {
	unsigned char	code;
	unsigned char	id;
	unsigned char	length[2];
	unsigned char	data[1];
} eap_packet_t;

/*
 * Contains EAP-Type specific data
 */
typedef struct eaptype_t {
	unsigned char	type;
	unsigned int	length;
	unsigned char	*data;
} eaptype_t;

/*
 * core data structure that is through out.
 *
 * length = code + id + length + type + type.data
 *	  =  1   +  1 +   2    +  1   +  X
 */
typedef struct eap_packet {
	unsigned char	code;
	unsigned char	id;
	unsigned int	length;
	eaptype_t	type;

	unsigned char   *packet;
} EAP_PACKET;

/*
 * DS with all the required information
 * Note: We are authentication server, 
 *    we get EAP-Response and we send 
 *    EAP-Request/EAP-success/EAP-failure
 */
typedef struct eap_ds {
	EAP_PACKET	*response;
	EAP_PACKET	*request;
} EAP_DS;

/*
 * EAP_HANDLER is the interface for any EAP-Type.
 * Each handler contains information for one specific EAP-Type.
 * This way we don't need to change any interfaces in future.
 * It is also a list of EAP-request handlers waiting for EAP-response
 *
 * id = Length + Request-ID + State + (NAS-IP-Address|NAS-Identifier)
 * identity = Identity, as obtained, from EAP-Identity response.
 * username = as obtained in Radius request, It might differ from identity.
 * configured = List of configured values for this user.
 * prev_eapds = Previous EAP request, for which eap_ds contains the response.
 * eap_ds   = Current EAP response.
 * opaque   = EAP-Type holds some data that corresponds to the current
 *		EAP-request/response
 * free_opaque = To release memory held by opaque, 
 * 		when this handler is timedout & needs to be deleted.
 * 		It is the responsibility of the specific EAP-TYPE 
 * 		to avoid any memory leaks in opaque
 *		Hence this pointer should be provided by the EAP-Type
 *		if opaque is not NULL
 * timestamp  = timestamp when this handler is created.
 * status   = finished/onhold/..
 */
typedef struct _eap_handler {
	unsigned char	*id;

	VALUE_PAIR	*username;
	VALUE_PAIR	*configured;

	char	*identity;

	EAP_DS 	*prev_eapds;
	EAP_DS 	*eap_ds;

	void 	*opaque;
	void 	(*free_opaque)(void **opaque);

	time_t	timestamp;
	int	status;

	struct _eap_handler *next;
} EAP_HANDLER;

/* Prototype to call eap sub mdoules */
typedef struct eap_type_t {
	const 	char *name;
	int	(*attach)(CONF_SECTION *conf, void **type_arg);
	int	(*initiate)(void *type_arg, EAP_HANDLER *handler);
	int	(*authenticate)(void *type_arg, EAP_HANDLER *handler);
	int	(*detach)(void **type_arg);
} EAP_TYPE;

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
        char            typename[NAME_LEN];
        EAP_TYPE       	*type;
        lt_dlhandle     handle;
	CONF_SECTION	*cs;
	void		*type_stuff;
} EAP_TYPES;

/*
 * currently this is not properly defined as
 * there is not much config stuff that eap depends on.
 */
typedef struct eap_conf {
        char*		default_eap_type;
        int		timer_limit;
} EAP_CONF;

typedef struct rlm_eap_t {
	EAP_HANDLER 	*echolist;
	EAP_TYPES 	*typelist;
	EAP_CONF	*conf;
} rlm_eap_t;

/* define the functions */

/* EAP-Type */
EAP_TYPES 	*eaptype_byid(EAP_TYPES **list, int type);
EAP_TYPES 	*eaptype_byname(EAP_TYPES **list, const char *name);
void      	eaptype_load(EAP_TYPES **tl, const char *tname, CONF_SECTION *cs);
int       	eaptype_select(EAP_TYPES *tl, EAP_HANDLER *h, char *eaptype);
int       	eaptype_call(int type, operation_t action, 
          		EAP_TYPES *tl, EAP_HANDLER *h);
void	    	eaptype_freelist(EAP_TYPES **tl);


/* EAP */
int  		eap_start(REQUEST *request);
void 		eap_fail(REQUEST *request, EAP_PACKET *reply);
void 		eap_success(REQUEST *request, EAP_PACKET *reply);
EAP_HANDLER 	*eap_handler(EAP_HANDLER **list, eap_packet_t **eap_msg, REQUEST *request);
char 		*eap_identity(eap_packet_t *eap_packet);
eap_packet_t 	*eap_attribute(VALUE_PAIR *vps);
int 		eap_wireformat(EAP_PACKET *packet);
int 		eap_compose(REQUEST *request, EAP_PACKET *reply);

int 		eap_validation(eap_packet_t *eap_msg);
unsigned char 	*eap_generateid(REQUEST *request, unsigned char response_id);
unsigned char 	*eap_regenerateid(REQUEST *request, unsigned char response_id);
EAP_DS 		*eap_buildds(eap_packet_t **eap_msg);
char 		*eap_identity(eap_packet_t *eap_msg);
VALUE_PAIR 	*eap_useridentity(EAP_HANDLER *list, eap_packet_t *eap_msg, unsigned char id[]);
EAP_HANDLER 	*eap_findhandler(EAP_HANDLER *list, unsigned char id[]);

/* Memory Management */
EAP_PACKET  	*eap_packet_alloc();
EAP_DS      	*eap_ds_alloc();
EAP_HANDLER 	*eap_handler_alloc();
void	    	eap_packet_free(EAP_PACKET **eap_packet);
void	    	eap_ds_free(EAP_DS **eap_ds);
void	    	eap_handler_free(EAP_HANDLER **handler);

int 	    	eaplist_add(EAP_HANDLER **list, EAP_HANDLER *handler);
void	    	eaplist_clean(EAP_HANDLER **list, time_t limit);
void	    	eaplist_free(EAP_HANDLER **list);
EAP_HANDLER 	*eaplist_isreply(EAP_HANDLER **list, unsigned char id[]);

/* State */
void	    	generate_key();
VALUE_PAIR  	*generate_state();
int	    	verify_state(VALUE_PAIR *state);

#endif /*_EAP_H*/
