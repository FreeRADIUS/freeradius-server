/*
 * module.h	Interface to the RADIUS module system.
 *
 * Version:	$Id$
 *
 */

#include "conffile.h"

/*
 *	The types of the functions which are supported by each module.
 *	The functional parameters are defined here, so we don't have to
 *	edit each and every module when we decide to add another type
 *	of request handler.
 */
typedef int (*RLM_AUTHORIZE_FUNCP)(REQUEST *request, 
				   VALUE_PAIR **check_items,
				   VALUE_PAIR **reply_items);
typedef int (*RLM_AUTHENTICATE_FUNCP)(REQUEST *request,
				   VALUE_PAIR **check_items,
				   VALUE_PAIR **reply_items);
typedef int (*RLM_POST_AUTHENTICATE_FUNCP)(REQUEST *request);
typedef int (*RLM_PRE_ACCOUNTING_FUNCP)(REQUEST *request);
typedef int (*RLM_ACCOUNTING_FUNCP)(REQUEST *request);

/* Shouldn't need these anymore */
#define RLM_COMPONENT_AUTZ 0
#define RLM_COMPONENT_AUTH 1
#define RLM_COMPONENT_PREACCT 2
#define RLM_COMPONENT_ACCT 3
#define RLM_COMPONENT_COUNT 4 /* How many components are there */

typedef struct module_t {
	const char	*name;
	int	type;			/* reserved */
	int	(*init)(void);
	int	(*instantiate)(CONF_SECTION *mod_cs, void **instance);
	int	(*authorize)(void *instance, REQUEST *request, 
			VALUE_PAIR **check_items, VALUE_PAIR **reply_items);
	int	(*authenticate)(void *instance, REQUEST *request, 
			VALUE_PAIR **check_items, VALUE_PAIR **reply_items);
	int	(*preaccounting)(void *instance, REQUEST *request);
	int	(*accounting)(void *instance, REQUEST *request);
	int	(*detach)(void *instance);
 	int	(*destroy)(void);
} module_t;

enum {
	RLM_MODULE_REJECT = -2,	/* reject the request */
	RLM_MODULE_FAIL = -1,	/* module failed, don't reply */
	RLM_MODULE_OK = 0,	/* the module is OK, continue */
	RLM_MODULE_HANDLED = 1 	/* the module handled the request, so stop. */
};

int setup_modules(void);
int module_authorize(REQUEST *request);
int module_authenticate(int type, REQUEST *request);
int module_preacct(REQUEST *request);
int module_accounting(REQUEST *request);

