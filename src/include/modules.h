/*
 * module.h	Interface to the RADIUS module system.
 *
 * Version:	$Id$
 *
 */

#ifndef RADIUS_MODULES_H
#define RADIUS_MODULES_H
#include "conffile.h"

typedef int (*packetmethod)(void *instance, REQUEST *request);

enum {
  RLM_COMPONENT_AUTH = 0,
  RLM_COMPONENT_AUTZ,		/* 1 */
  RLM_COMPONENT_PREACCT,	/* 2 */
  RLM_COMPONENT_ACCT,		/* 3 */
  RLM_COMPONENT_SESS,		/* 4 */
  RLM_COMPONENT_PRE_PROXY,	/* 5 */
  RLM_COMPONENT_POST_PROXY,	/* 6 */
  RLM_COMPONENT_POST_AUTH,	/* 7 */
  RLM_COMPONENT_COUNT		/* 8: How many components are there */
};

#define RLM_TYPE_THREAD_SAFE	(0 << 0)
#define RLM_TYPE_THREAD_UNSAFE	(1 << 0)

typedef struct module_t {
	const char	*name;
	int	type;			/* reserved */
	int	(*init)(void);
	int	(*instantiate)(CONF_SECTION *mod_cs, void **instance);
	packetmethod	methods[RLM_COMPONENT_COUNT];
	int	(*detach)(void *instance);
 	int	(*destroy)(void);
} module_t;

extern const char *component_names[RLM_COMPONENT_COUNT];

enum {
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
};

int setup_modules(void);
int module_authorize(int type, REQUEST *request);
int module_authenticate(int type, REQUEST *request);
int module_preacct(REQUEST *request);
int module_accounting(REQUEST *request);
int module_checksimul(REQUEST *request, int maxsimul);
int module_pre_proxy(REQUEST *request);
int module_post_proxy(REQUEST *request);
int module_post_auth(REQUEST *request);
int module_pre_proxy(REQUEST *request);
int module_post_proxy(REQUEST *request);
int module_post_auth(REQUEST *request);

#endif /* RADIUS_MODULES_H */
