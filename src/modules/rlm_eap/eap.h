#ifndef _EAP_H
#define _EAP_H

#if HAVE_NETINET_IN_H
#include <sys/types.h>
#include <netinet/in.h>
#endif

#include	<ltdl.h>
 
#include "conffile.h"
#include "libradius.h"
#include "radiusd.h"
#include "modules.h"

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

#define PACKET_DATA_LEN 	4096
#define EAP_HEADER_LEN 		4
#define MD5_LEN 		16

#define NAME_LEN		32

enum {
        EAP_NOTFOUND,    /* not found */
        EAP_FOUND,       /* found, continue */
        EAP_OK,		 /* ok, continue */
        EAP_FAIL,        /* failed, don't reply */
        EAP_NOOP,        /* succeeded without doing anything */
        EAP_INVALID,     /* invalid, don't reply */
};

/*
 * structure to represent packet format of eap
 */
typedef struct eap_packet_t {
  uint8_t	code;
  uint8_t	id;
  uint8_t	length[2];
  uint8_t	data[1];
} eap_packet_t;

/*
 * core data structure that is through out.
 */
typedef struct eap_packet {
	int		code;
	int		id;
	int		length;
	int		type;
	uint8_t		*typedata;
	int		type_len;
	VALUE_PAIR	*rad_vps;

	time_t		timestamp;
} EAP_PACKET;

/* 
 * structure to hold the complete raw EAP Packet after concatenation of all EAP_Messages
 * Note that each EAP Packet can be upto 64k
typedef struct eap_data_t {
  uint8_t	length[2];
  uint8_t	message[1];
} EAP_DATA;
 */

/*
 * DS with all the required information
 * Note: We are authentication server, 
 *    we get EAP-Response and we send 
 *    EAP-Request/EAP-success/EAP-failure
 */
typedef struct eap_ds {
	EAP_PACKET	*response;
	EAP_PACKET	*request;

	VALUE_PAIR	*username;
	VALUE_PAIR	*password;

	time_t		timestamp;
	int		finished;
} EAP_DS;

/* Prototype to call eap sub mdoules */
/*
	int	(*identity)(void *type_arg, EAP_DS *auth);
*/
typedef struct eap_type_t {
	const 	char *name;
	int	(*attach)(CONF_SECTION *conf, void **type_arg);
	int	(*initiate)(void *type_arg, EAP_DS *eap_ds);
	int	(*authenticate)(void *type_arg, EAP_DS *eap_ds, void *eap_arg);
	int	(*detach)(void **type_arg);
} EAP_TYPE;

typedef enum operation_t {
	INITIATE = 0,
	AUTHENTICATE
} operation_t;
/*
 *      Keep track of which sub modules we've loaded.
 */
typedef struct eap_types_t {
        struct eap_types_t  	*next;
	int			typeid;
        char                    typename[NAME_LEN];
        EAP_TYPE       		*type;
        lt_dlhandle             handle;
	CONF_SECTION		*cs;
	void			*type_stuff;
} EAP_TYPES;

/*
 * currently this is not properly defined as
 * there is not much config stuff that eap depends on.
 */
typedef struct eap_conf {
        char*		default_eap_type;
        int		timer_limit;
} EAP_CONF;

/*
 * To keep track the list of Auths recently sent
 * for duplicate detection & also to confirm if it is the
 * response to the recently sent request.
 * It can also be used to verify challenge data sent.
 */
typedef struct eap_list {
	struct eap_list		*next;
	EAP_DS 			*eap_ds;
} EAP_LIST;

typedef struct rlm_eap_t {
	int 			unique_id;
	EAP_LIST 		*echolist;
	EAP_TYPES 		*typelist;
	EAP_CONF		*conf;
	eap_packet_t		*eap_data;
} rlm_eap_t;

/* define the functions */

void load_type(EAP_TYPES **type_list, const char *type_name, CONF_SECTION *cs);
EAP_TYPES *find_type(EAP_TYPES **list, int type);
EAP_TYPES *find_typename(EAP_TYPES **list, const char *name);

EAP_DS *extract(eap_packet_t *eap_msg);
int identity(EAP_DS *auth);
eap_packet_t *get_eapmsg_attr(VALUE_PAIR *vps);
int eap_type_handle(int eap_type, operation_t action, EAP_TYPES *type_list, EAP_DS *eap_ds, EAP_DS *req);
int process_eap(EAP_TYPES *type_list, EAP_DS *auth, EAP_DS *response);
eap_packet_t *wire_format(EAP_PACKET *packet);
int compose(REQUEST *request, EAP_PACKET *reply);

void list_clean(EAP_LIST **list, time_t limit);
int list_add(EAP_LIST **list, EAP_DS *auth);

EAP_PACKET *eap_packet_alloc(void);
EAP_DS *eap_ds_alloc(void);

void eap_packet_free(EAP_PACKET **eap_packet_ptr);
void eap_ds_free(EAP_DS **authp);

void node_free(EAP_LIST **node);
void list_free(EAP_LIST **list);
void free_type_list(EAP_TYPES **i);
void remove_item(EAP_LIST **first, EAP_LIST *item);

int select_eap_type(EAP_LIST **el, EAP_TYPES *tl, EAP_DS *auth, char *eaptype);
int is_duplicate(EAP_LIST *list, EAP_DS *auth);
EAP_LIST *is_reply(EAP_LIST *list, EAP_DS *auth);

int eap_start(REQUEST *request);
VALUE_PAIR *get_username(eap_packet_t *vps);

void eap_fail(REQUEST *request, EAP_PACKET *reply);
void eap_success(REQUEST *request, EAP_PACKET *reply);

#endif /*_EAP_H*/
