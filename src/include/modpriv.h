/* modpriv.h: Stuff needed by both modules.c and modcall.c, but should not be
 * accessed from anywhere else.
 *
 * Version: $Id$ */
#include "radiusd.h"
#include "modules.h"
#include "ltdl.h"

/*
 *	Keep track of which modules we've loaded.
 */
typedef struct module_list_t {
	struct module_list_t	*next;
	char			name[MAX_STRING_LEN];
	module_t		*module;
	lt_dlhandle		handle;
} module_list_t;

/*
 *	Per-instance data structure, to correlate the modules
 *	with the instance names (may NOT be the module names!), 
 *	and the per-instance data structures.
 */
typedef struct module_instance_t {
	struct module_instance_t *next;
	char			name[MAX_STRING_LEN];
	module_list_t		*entry;
	void                    *insthandle;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		*mutex;
#endif
} module_instance_t;

module_instance_t *find_module_instance(const char *instname);
