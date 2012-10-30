/*
 * module.h	Interface to the RADIUS module system.
 *
 * Version:	$Id$
 *
 */

#ifndef RADIUS_MODULES_H
#define RADIUS_MODULES_H

#include <freeradius-devel/ident.h>
RCSIDH(modules_h, "$Id$")

#include <freeradius-devel/conffile.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*packetmethod)(void *instance, REQUEST *request);

typedef enum rlm_components {
  RLM_COMPONENT_AUTH = 0,
  RLM_COMPONENT_AUTZ,		/* 1 */
  RLM_COMPONENT_PREACCT,	/* 2 */
  RLM_COMPONENT_ACCT,		/* 3 */
  RLM_COMPONENT_SESS,		/* 4 */
  RLM_COMPONENT_PRE_PROXY,	/* 5 */
  RLM_COMPONENT_POST_PROXY,	/* 6 */
  RLM_COMPONENT_POST_AUTH,	/* 7 */
#ifdef WITH_COA
  RLM_COMPONENT_RECV_COA,	/* 8 */
  RLM_COMPONENT_SEND_COA,	/* 9 */
#endif
  RLM_COMPONENT_COUNT		/* 8 / 10: How many components are there */
} rlm_components_t;

typedef struct section_type_value_t {
        const char      *section;
        const char      *typename;
        int             attr;
} section_type_value_t;

extern const section_type_value_t section_type_value[];

#define RLM_TYPE_THREAD_SAFE		(0 << 0)
#define RLM_TYPE_THREAD_UNSAFE		(1 << 0)
#define RLM_TYPE_CHECK_CONFIG_SAFE	(1 << 1)
#define RLM_TYPE_HUP_SAFE		(1 << 2)

#define RLM_MODULE_MAGIC_NUMBER ((uint32_t) (0xf4ee4ad3))
#define RLM_MODULE_INIT RLM_MODULE_MAGIC_NUMBER

typedef struct module_t {
	uint32_t 	magic;	/* may later be opaque struct */
	const char	*name;
	int		type;
	int		(*instantiate)(CONF_SECTION *mod_cs, void **instance);
	int		(*detach)(void *instance);
	packetmethod	methods[RLM_COMPONENT_COUNT];
} module_t;

typedef enum rlm_rcodes {
	RLM_MODULE_REJECT,	/* immediately reject the request */
	RLM_MODULE_FAIL,	/* module failed, don't reply */
	RLM_MODULE_OK,		/* the module is OK, continue */
	RLM_MODULE_HANDLED,	/* the module handled the request, so stop. */
	RLM_MODULE_INVALID,	/* the module considers the request invalid. */
	RLM_MODULE_USERLOCK,	/* reject the request (user is locked out) */
	RLM_MODULE_NOTFOUND,	/* user not found */
	RLM_MODULE_NOOP,	/* module succeeded without doing anything */
	RLM_MODULE_UPDATED,	/* OK (pairs modified) */
	RLM_MODULE_NUMCODES	/* How many return codes there are */
} rlm_rcodes_t;

int setup_modules(int, CONF_SECTION *);
int detach_modules(void);
int module_hup(CONF_SECTION *modules);
int module_authorize(int type, REQUEST *request);
int module_authenticate(int type, REQUEST *request);
int module_preacct(REQUEST *request);
int module_accounting(int type, REQUEST *request);
int module_checksimul(int type, REQUEST *request, int maxsimul);
int module_pre_proxy(int type, REQUEST *request);
int module_post_proxy(int type, REQUEST *request);
int module_post_auth(int type, REQUEST *request);
#ifdef WITH_COA
int module_recv_coa(int type, REQUEST *request);
int module_send_coa(int type, REQUEST *request);
#define MODULE_NULL_COA_FUNCS ,NULL,NULL
#else
#define MODULE_NULL_COA_FUNCS
#endif
int indexed_modcall(int comp, int idx, REQUEST *request);

/*
 *	For now, these are strongly tied together.
 */
int virtual_servers_load(CONF_SECTION *config);
void virtual_servers_free(time_t when);

#ifdef __cplusplus
}
#endif

#endif /* RADIUS_MODULES_H */
