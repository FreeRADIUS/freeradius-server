/*
 * modules.c	Radius module support.
 *
 * Author:	Alan DeKok <aland@ox.org>
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<assert.h>

#include	"radiusd.h"
#include	"modules.h"
#include	"conffile.h"
#include	"ltdl.h"

/*
 *	Keep track of which modules we've loaded.
 */
typedef struct module_list_t {
	char			name[MAX_STRING_LEN];
	int			default_auth_type;
	module_t		*module;
	lt_dlhandle		handle;
	struct module_list_t	*next;
} module_list_t;

static module_list_t *module_list = NULL;

typedef struct module_instance_t {
	module_list_t		*entry;
	char			name[MAX_STRING_LEN];
        void                    *insthandle;
	struct module_instance_t *next;
} module_instance_t;

static module_instance_t *module_instance_list = NULL;

typedef struct config_module_t {
	module_instance_t	*instance;
#if HAVE_PTHREAD_H
	pthread_mutex_t		*mutex;
#endif
	struct config_module_t	*next;
} config_module_t;

typedef struct indexed_config_module_t {
	int idx;
	config_module_t *modulelist;
	struct indexed_config_module_t *next;
} indexed_config_module_t;

static config_module_t *authorize = NULL;
static indexed_config_module_t *authenticate = NULL;
static config_module_t *preacct = NULL;
static config_module_t *accounting = NULL;
static config_module_t *session = NULL;

static void config_list_free(config_module_t **cf)
{
	config_module_t	*c, *next;

	c = *cf;
	while (c) {
#if HAVE_PTHREAD_H
		if (c->mutex) {
			/*
			 *	The mutex MIGHT be locked...
			 *	we'll check for that later, I guess.
			 */
			pthread_mutex_destroy(c->mutex);
			free(c->mutex);
		}
#endif
		next = c->next;
		free(c);
		c = next;
	}
	*cf = NULL;
}

static void indexed_config_list_free(indexed_config_module_t **cf)
{
	indexed_config_module_t	*c, *next;

	c = *cf;
	while (c) {
		next = c->next;
		config_list_free(&c->modulelist);
		free(c);
		c = next;
	}
	*cf = NULL;
}

static void instance_list_free(module_instance_t **i)
{
	module_instance_t	*c, *next;

	c = *i;
	while (c) {
		next = c->next;
		if(c->entry->module->detach)
			(c->entry->module->detach)(c->insthandle);
		free(c);
		c = next;
	}
	*i = NULL;
}

static void module_list_free(void)
{
	module_list_t *ml, *next;

	indexed_config_list_free(&authenticate);
	config_list_free(&authorize);
	config_list_free(&preacct);
	config_list_free(&accounting);
	config_list_free(&session);

	instance_list_free(&module_instance_list);

	ml = module_list;
	while (ml) {
		next = ml->next;
		if (ml->module->destroy)
			(ml->module->destroy)();
		lt_dlclose(ml->handle);	/* ignore any errors */
		free(ml);
		ml = next;
	}

	module_list = NULL;
}

/*
 *  New Auth-Type's start at a large number, and go up from there.
 *
 *  We could do something more intelligent, but this should work almost
 *  all of the time.
 *
 * FIXME: move this to dict.c as dict_valadd() and dict_valdel()
 *        also clear value in module_list free (necessary?)
 */
static int new_authtype_value(const char *name)
{
  static int max_value = 32767;
  DICT_VALUE *old_value, *new_value;

  /*
   *  Check to see if it's already defined.
   *  If so, return the old value.
   */
  old_value = dict_valbyname(name);
  if (old_value) return old_value->value;

  /* Look for the predefined Auth-Type value */
  old_value = dict_valbyattr(PW_AUTHTYPE, 0);
  if (!old_value) return 0;	/* something WIERD is happening */

  /* allocate a new value */
  new_value = (DICT_VALUE *) malloc(sizeof(DICT_VALUE));
  if (!new_value) {
    radlog(L_ERR|L_CONS, "Out of memory\n");
    exit(1);
  }

  /* copy the old to the new */
  memcpy(new_value, old_value, sizeof(DICT_VALUE));
  old_value->next = new_value;

  /* set it up */
  strNcpy(new_value->name, name, sizeof(new_value->name));
  new_value->value = max_value++;

  return new_value->value;
}

/*
 *	Find a module on disk or in memory, and link to it.
 */
static module_list_t *linkto_module(module_list_t *head,
				  const char *module_name,
				  const char *cffilename, int cflineno)
{
	module_list_t	**last, *node;
	module_list_t	*new;
	void		*handle;
	const char	*error;

	while (head) {
		if (strcmp(head->name, module_name) == 0)
			return head;
		head = head->next;
	}

	last = &module_list;
	node = module_list;
	while (node) {
		last = &node->next;
		node = node->next;
	}

	/*
	 * Keep the handle around so we can dlclose() it.
	 * Also ensure that any further dependencies are exported,
	 * so that PAM can work.
	 *
	 * i.e. rlm_pam.so links to libpam.so, which in turn dlopen()'s
	 * pam_foo.so.  Without RTLD_GLOBAL, the functions in libpam.so
	 * won't get exported to pam_foo.so.
	 */
	handle = lt_dlopenext(module_name);
	if (handle == NULL) {
		radlog(L_ERR|L_CONS, "%s[%d] Failed to link to module '%s':"
		       " %s\n", cffilename, cflineno, module_name, lt_dlerror());
		return NULL;
	}

	/* make room for the module type */
	new = (module_list_t *) malloc(sizeof(module_list_t));
	if (new == NULL) {
		radlog(L_ERR|L_CONS, "%s[%d] Failed to allocate memory.\n",
		       cffilename, cflineno);
		lt_dlclose(handle);	/* ignore any errors */
		return NULL;
	}

	/* fill in the module structure */
	new->next = NULL;
	new->handle = handle;
	strNcpy(new->name, module_name, sizeof(new->name));
	
	/*
	 *	Link to the module's rlm_FOO{} module structure.
	 */
	new->module = (module_t *) lt_dlsym(new->handle, module_name);
	error = lt_dlerror();
	if (!new->module) {
		radlog(L_ERR|L_CONS, "%s[%d] Failed linking to "
		       "%s structure in %s: %s\n",
		       cffilename, cflineno,
		       module_name, cffilename, error);
		lt_dlclose(new->handle);	/* ignore any errors */
		free(new);
		return NULL;
	}
	
	/* If there's an authentication method, add a new Auth-Type */
	if (new->module->authenticate)
		new->default_auth_type =
			new_authtype_value(new->module->name);

	/* call the modules initialization */
	if (new->module->init &&
	    (new->module->init)() < 0) {
		radlog(L_ERR|L_CONS,
		       "%s[%d] Module initialization failed.\n",
		       cffilename, cflineno);
		lt_dlclose(new->handle);	/* ignore any errors */
		free(new);
		return NULL;
	}

	DEBUG("Module: Loaded %s ", new->module->name);

	*last = new;

	return new;
}

/*
 *	Find a module instance.
 */
static module_instance_t *find_module_instance(module_instance_t *head,
					       const char *instname)
{
	CONF_SECTION *cs, *inst_cs;
	const char *name1, *name2;
	module_instance_t *new;
	char module_name[256];

	/*
	 *	Look for a pre-existing module instance.
	 *	If found, return that.
	 */
	while (head) {
		if (strcmp(head->name, instname) == 0)
			return head;
		head = head->next;
	}

	/*
	 *	Instance doesn't exist yet. Try to find the
	 *	corresponding configuration section and create it.
	 */

	/*
	 *	Look for the 'modules' configuration section.
	 */
	cs = cf_section_find("modules");
	if (!cs) {
		radlog(L_ERR|L_CONS, "ERROR: Cannot find a 'modules' section in the configuration file.\n");
		return NULL;
	}

	/* Module instances are declared in the modules{} block and referenced
	 * later by their name, which is the name2 from the config section,
	 * or name1 if there was no name2. */

	for(inst_cs=cf_subsection_find_next(cs, NULL, NULL)
	    ; inst_cs ;
	    inst_cs=cf_subsection_find_next(cs, inst_cs, NULL)) {
                name1 = cf_section_name1(inst_cs);
                name2 = cf_section_name2(inst_cs);
		if ( (name2 && !strcmp(name2, instname)) ||
		     (!name2 && !strcmp(name1, instname)) )
			break;
	}
	if (!inst_cs) {
		radlog(L_ERR|L_CONS, "ERROR: Cannot find a configuration entry for module \"%s\".\n", instname);
		return NULL;
	}

	/*
	 *	Found the configuration entry.
	 */
	new = malloc(sizeof(*new));
	if (!new) {
		radlog(L_ERR|L_CONS, "Out of memory\n");
		exit(1);
	}
	
	/*
	 *	Link to the module by name: rlm_FOO
	 */
	snprintf(module_name, sizeof(module_name), "rlm_%s", name1);
	new->entry = linkto_module(module_list, module_name,
				   "radiusd.conf", cf_section_lineno(inst_cs));
	if (!new->entry) {
		free(new);
		/* linkto_module logs any errors */
		return NULL;
	}
	
	/*
	 *	No instance handle.
	 */
	new->insthandle = NULL;

	/*
	 *	Call the module's instantiation routine.
	 */
	if ((new->entry->module->instantiate) &&
	    ((new->entry->module->instantiate)(inst_cs,
					       &new->insthandle) < 0)) {
		radlog(L_ERR|L_CONS,
		       "radiusd.conf[%d]: %s: Module instantiation failed.\n",
		       cf_section_lineno(inst_cs), instname);
		free(new);
		return NULL;
	}
	
	/*
	 *	We're done.  Fill in the rest of the data structure,
	 *	and link it to the module instance list.
	 */
	strNcpy(new->name, instname, sizeof(new->name));
	new->next = module_instance_list;
	module_instance_list = new;

	DEBUG("Module: Instantiated %s (%s) ", name1, new->name);
	
	return new;
}

/*
 *	Add one entry at the end of the config_module_t list.
 */
static void add_to_list(config_module_t **head, module_instance_t *instance)
{
	config_module_t	*node = *head;
	config_module_t **last = head;

	while (node) {
		last = &node->next;
		node = node->next;
	}

	node = (config_module_t *) malloc(sizeof(config_module_t));
	if (!node) {
		radlog(L_ERR|L_CONS, "Out of memory\n");
		exit(1);
	}

	node->next = NULL;
	node->instance = instance;

#if HAVE_PTHREAD_H
	/*
	 *	If we're threaded, check if the module is thread-safe.
	 *
	 *	If it isn't, we create a mutex.
	 */
	if ((instance->entry->module->type & RLM_TYPE_THREAD_UNSAFE) != 0) {
		node->mutex = (pthread_mutex_t *) malloc(sizeof(pthread_mutex_t));
		if (!node->mutex) {
			radlog(L_ERR|L_CONS, "Out of memory\n");
			exit(1);
		}
		
		/*
		 *	Initialize the mutex.
		 */
		pthread_mutex_init(node->mutex, NULL);
	} else {
		/*
		 *	The module is thread-safe.  Don't give it a mutex.
		 */
		node->mutex = NULL;
	}

#endif	

	*last = node;
}

static indexed_config_module_t *new_sublist(indexed_config_module_t **head,
					    int idx)
{
	indexed_config_module_t	*node = *head;
	indexed_config_module_t **last = head;

	while (node) {
		if (node->idx == idx) {
			/* It is an error to try to create a sublist that
			 * already exists. */
			return NULL;
		}
		last = &node->next;
		node = node->next;
	}

	node = malloc(sizeof(*node));
	if (!node) {
		radlog(L_ERR|L_CONS, "Out of memory\n");
		exit(1);
	}

	node->next = NULL;
	node->modulelist = NULL;
	node->idx = idx;
	*last = node;
	return node;
}

static config_module_t *lookup_indexed_config(indexed_config_module_t *head,
					      int idx)
{
	indexed_config_module_t *p;
	for (p=head; p; p=p->next) {
		if(p->idx==idx)
			return p->modulelist;
	}
	return NULL;
}

static void load_authtype_subsection(CONF_SECTION *cs, const char *filename)
{
	module_instance_t *this;
	CONF_ITEM *modref;
        int modreflineno;
        const char *modrefname;
	int auth_type;
	indexed_config_module_t *auth_type_config;

	auth_type = new_authtype_value(cf_section_name2(cs));
	auth_type_config = new_sublist(&authenticate, auth_type);
	if (!auth_type_config) {
		radlog(L_ERR|L_CONS,
		       "%s[%d] authtype %s already configured - skipping",
		       filename, cf_section_lineno(cs), cf_section_name2(cs));
		return;
	}

	for(modref=cf_item_find_next(cs, NULL)
	    ; modref ;
	    modref=cf_item_find_next(cs, modref)) {

		if(cf_item_is_section(modref)) {
			CONF_SECTION *scs;
			scs = cf_itemtosection(modref);
			modreflineno = cf_section_lineno(scs);
			modrefname = cf_section_name1(scs);
		} else {
			CONF_PAIR *cp;
			cp = cf_itemtopair(modref);
			modreflineno = cf_pair_lineno(cp);
			modrefname = cf_pair_attr(cp);
		}

		this = find_module_instance(module_instance_list, modrefname);
		if (this == NULL) {
			/* find_module_instance logs any errors */
			exit(1);
		}

		if (!this->entry->module->authenticate) {
			radlog(L_ERR|L_CONS,
				"%s[%d] Module %s does not contain "
				"an 'authenticate' entry\n",
				filename, modreflineno,
			       this->entry->module->name);
			exit(1);
		}
		add_to_list(&auth_type_config->modulelist, this);
	}
}

static void load_indexed_module_section(CONF_SECTION *cs, int comp, const char *filename)
{
	module_instance_t *this;
	CONF_ITEM	*modref;
        int		modreflineno;
        const char	*modrefname;
	indexed_config_module_t *auth_type_config;

	/* This function does not yet need or want to handle anything but
	 * authtypes. */
	assert(comp == RLM_COMPONENT_AUTH);

	for(modref=cf_item_find_next(cs, NULL)
	    ; modref ;
	    modref=cf_item_find_next(cs, modref)) {

		if(cf_item_is_section(modref)) {
			CONF_SECTION *scs;
			scs = cf_itemtosection(modref);
			if (!strcmp(cf_section_name1(scs), "authtype")) {
				load_authtype_subsection(scs, filename);
				continue;
			}
			modreflineno = cf_section_lineno(scs);
			modrefname = cf_section_name1(scs);
		} else {
			CONF_PAIR *cp;
			cp = cf_itemtopair(modref);
			modreflineno = cf_pair_lineno(cp);
			modrefname = cf_pair_attr(cp);
		}

		this = find_module_instance(module_instance_list, modrefname);
		if (this == NULL) {
			/* find_module_instance logs any errors */
			exit(1);
		}

		if (!this->entry->module->authenticate) {
			radlog(L_ERR|L_CONS,
			       "%s[%d] Module %s does not contain "
			       "an 'authenticate' entry\n",
			       filename, modreflineno,
			       this->entry->module->name);
			exit(1);
		}
		auth_type_config = new_sublist(&authenticate,
					       this->entry->default_auth_type);
		if (!auth_type_config) {
			radlog(L_ERR|L_CONS,
			       "%s[%d] authtype %s already configured - skipping",
			       filename, modreflineno,
			       this->entry->module->name);
			continue;
		}
		add_to_list(&auth_type_config->modulelist, this);

  	}
}

static void load_module_section(CONF_SECTION *cs, int comp, const char *filename)
{
	module_instance_t *this;
	CONF_ITEM	*modref;
        int		modreflineno;
        const char	*modrefname;

	/* Authentication is special - it is not an ordered list but an
	 * associative array keyed on auth-type */
	if (comp == RLM_COMPONENT_AUTH) {
		load_indexed_module_section(cs, comp, filename);
		return;
	}

	for(modref=cf_item_find_next(cs, NULL)
	    ; modref ;
	    modref=cf_item_find_next(cs, modref)) {

		if(cf_item_is_section(modref)) {
			CONF_SECTION *scs;
			scs = cf_itemtosection(modref);
			modreflineno = cf_section_lineno(scs);
			modrefname = cf_section_name1(scs);
		} else {
			CONF_PAIR *cp;
			cp = cf_itemtopair(modref);
			modreflineno = cf_pair_lineno(cp);
			modrefname = cf_pair_attr(cp);
		}

		this = find_module_instance(module_instance_list, modrefname);
		if (this == NULL) {
			/* find_module_instance logs any errors */
			exit(1);
		}

		switch (comp) {
		case RLM_COMPONENT_AUTZ:
			if (!this->entry->module->authorize) {
				radlog(L_ERR|L_CONS,
					"%s[%d] Module %s does not contain "
					"an 'authorize' entry\n",
					filename, modreflineno,
					this->entry->module->name);
				exit(1);
			}
			add_to_list(&authorize, this);
			break;
		case RLM_COMPONENT_PREACCT:
			if (!this->entry->module->preaccounting) {
				radlog(L_ERR|L_CONS,
					"%s[%d] Module %s does not contain "
					"a 'preacct' entry\n",
					filename, modreflineno,
					this->entry->module->name);
				exit(1);
			}
			add_to_list(&preacct, this);
			break;
		case RLM_COMPONENT_ACCT:
			if (!this->entry->module->accounting) {
				radlog(L_ERR|L_CONS,
					"%s[%d] Module %s does not contain "
					"an 'accounting' entry\n",
					filename, modreflineno,
					this->entry->module->name);
				exit(1);
			}
			add_to_list(&accounting, this);
			break;
		case RLM_COMPONENT_SESS:
			if (!this->entry->module->checksimul) {
				radlog(L_ERR|L_CONS,
					"%s[%d] Module %s does not contain "
					"a 'checksimul' entry\n",
 					filename, modreflineno,
 					this->entry->module->name);
 				exit(1);
			}
			add_to_list(&session, this);
			break;
		default:
			radlog(L_ERR|L_CONS, "%s[%d] Unknown component %d.\n",
				filename, modreflineno, comp);
			exit(1);
		}
  	}
}

/*
 *	Parse the module config sections, and load
 *	and call each module's init() function.
 *
 *	Libtool makes your life a LOT easier, especially with libltdl.
 *	see: http://www.gnu.org/software/libtool/
 */
int setup_modules(void)
{
	const char	*control;
	int		comp;
	CONF_SECTION	*cs;
        const char *filename="radiusd.conf";

	/*
	 *	No current list of modules: Go initialize libltdl.
	 */
	if (!module_list) {
		if (lt_dlinit() != 0) {
			radlog(L_ERR|L_CONS, "Failed to initialize libraries: %s\n",
				lt_dlerror());
			exit(1); /* FIXME */
			
		}
		/*
		 *	Set the default list of preloaded symbols.
		 *	This is used to initialize libltdl's list of
		 *	preloaded modules. 
		 *
		 *	i.e. Static modules.
		 */
		LTDL_SET_PRELOADED_SYMBOLS();

		/*
		 *	Set the search path to ONLY our library directory.
		 *	This prevents the modules from being found from
		 *	any location on the disk.
		 */
		lt_dlsetsearchpath(radlib_dir);
		
		DEBUG2("modules: Library search path is %s",
		       lt_dlgetsearchpath());

	} else {
		module_list_free();
	}

	for (comp = 0; comp < RLM_COMPONENT_COUNT; ++comp) {
		switch(comp) {
		case RLM_COMPONENT_AUTH: control="authenticate"; break;
		case RLM_COMPONENT_AUTZ: control="authorize"; break;
		case RLM_COMPONENT_PREACCT: control="preacct"; break;
		case RLM_COMPONENT_ACCT: control="accounting"; break;
		case RLM_COMPONENT_SESS: control="session"; break;
		default: control="unknown";
		}
		
		cs = cf_section_find(control);
		if (!cs)
			continue;
		
		load_module_section(cs, comp, filename);
	}

	return 0;
}


/*
 *	Update the Stripped-User-Name attribute.
 */
static void update_username(REQUEST *request, char *newname)
{
	VALUE_PAIR *vp;

	/*
	 *	If there isn't a Stripped-User-Name attribute,
	 *	go add one, and make it the definitive user name.
	 */
	if (request->username->attribute != PW_STRIPPED_USER_NAME) {
		vp = paircreate(PW_STRIPPED_USER_NAME, PW_TYPE_STRING);
		if (!vp) {
			radlog(L_ERR|L_CONS, "no memory");
			exit(1);
		}
		DEBUG2("  authorize: Creating Stripped-User-Name of %s", newname);
		strcpy((char *)vp->strvalue, newname);
		vp->length = strlen((char *)vp->strvalue);
		pairadd(&request->packet->vps, vp);
		request->username = vp;
		return;
	}

	/*
	 *	There is one, update it in place.
	 */
	vp = request->username;
	DEBUG2("  authorize: Updating Stripped-User-Name from %s to %s",
	       vp->strvalue, newname);
	strcpy((char *)vp->strvalue, newname);
	vp->length = strlen((char *)vp->strvalue);
}

#if HAVE_PTHREAD_H
/*
 *	Lock the mutex for the module
 */
static void safe_lock(config_module_t *instance)
{
	if (instance->mutex) pthread_mutex_lock(instance->mutex);
}

/*
 *	Unlock the mutex for the module
 */
static void safe_unlock(config_module_t *instance)
{
	if (instance->mutex) pthread_mutex_unlock(instance->mutex);
}
#else
/*
 *	No threads: these functions become NULL's.
 */
#define safe_lock(foo)
#define safe_unlock(foo)
#endif

/*
 *	Call all authorization modules until one returns
 *	somethings else than RLM_MODULE_OK
 */
int module_authorize(REQUEST *request)
{
	config_module_t	*this;
	int		rcode = RLM_MODULE_OK;

	this = authorize;
	rcode = RLM_MODULE_OK;

	while (this && rcode == RLM_MODULE_OK) {
		DEBUG2("  authorize: %s", this->instance->entry->module->name);
		safe_lock(this);
		rcode = (this->instance->entry->module->authorize)(
			 this->instance->insthandle, request);
		safe_unlock(this);
		this = this->next;
	}

	/*
	 *	Before authenticating the user, update the
	 *	Stripped-User-Name attribute with any additions.
	 *
	 *	No name: nothing to add.
	 */
	if (request->username != NULL) {
		char newname[256];
		VALUE_PAIR *vp;

		/*
		 *	Try to add a prefix
		 */
		for (vp = request->config_items; vp != NULL; vp = vp->next) {
			switch (vp->attribute) {
			default:
				break;
				
			case PW_ADD_PREFIX:
				if ((size_t)(vp->length + request->username->length) > sizeof(vp->strvalue)) {
					DEBUG2("\"%s\"+\"%s\" too long",
					       vp->strvalue,
					       request->username->strvalue);
					continue;
				}
				strcpy(newname, (char *)vp->strvalue);
				strcat(newname, (char *)request->username->strvalue);
				update_username(request, newname);
				break;
				
			case PW_ADD_SUFFIX:
				if ((size_t)(vp->length + request->username->length) > sizeof(vp->strvalue)) {
					DEBUG2("\"%s\"+\"%s\" too long",
					       request->username->strvalue,
					       vp->strvalue);
					continue;
				}
				strcpy(newname,
					(char *)request->username->strvalue);
				strcat(newname, (char *)vp->strvalue);
				update_username(request, newname);
				break;
			}
		} /* over all configuration items */

		pairdelete(&request->config_items, PW_ADD_PREFIX);
		pairdelete(&request->config_items, PW_ADD_SUFFIX);
	}

	return rcode;
}

/*
 *	Authenticate a user/password with various methods.
 */
int module_authenticate(int auth_type, REQUEST *request)
{
	config_module_t	*this;
	int		rcode = RLM_MODULE_FAIL;

	/*
	 *  We MUST have a password, of SOME type!
	 */
	if (request->password == NULL) {
		return RLM_MODULE_FAIL;
	}

	this = lookup_indexed_config(authenticate, auth_type);

	while (this && rcode == RLM_MODULE_FAIL) {
		DEBUG2("  authenticate: %s",
			this->instance->entry->module->name);
		safe_lock(this);
		rcode = (this->instance->entry->module->authenticate)(
			this->instance->insthandle, request);
		safe_unlock(this);
		this = this->next;
	}
	return rcode;
}


/*
 *	Do pre-accounting for ALL configured sessions
 */
int module_preacct(REQUEST *request)
{
	config_module_t	*this;
	int		rcode;

	this = preacct;
	rcode = RLM_MODULE_OK;

	while (this && (rcode == RLM_MODULE_OK)) {
		DEBUG2("  preacct: %s", this->instance->entry->module->name);
		safe_lock(this);
		rcode = (this->instance->entry->module->preaccounting)
				(this->instance->insthandle, request);
		safe_unlock(this);
		this = this->next;
	}

	return rcode;
}

/*
 *	Do accounting for ALL configured sessions
 */
int module_accounting(REQUEST *request)
{
	config_module_t	*this;
	int		rcode;

	this = accounting;
	rcode = RLM_MODULE_OK;

	while (this && (rcode == RLM_MODULE_OK)) {
		DEBUG2("  accounting: %s", this->instance->entry->module->name);
		safe_lock(this);
		rcode = (this->instance->entry->module->accounting)
				(this->instance->insthandle, request);
		safe_unlock(this);
		this = this->next;
	}

	return rcode;
}

/*
 *	See if a user is already logged in.
 *
 *	Returns: 0 == OK, 1 == double logins, 2 == multilink attempt
 */
int module_checksimul(REQUEST *request, int maxsimul)
{
	config_module_t	*this;
	int		rcode;

	if(!session)
		return 0;

	if(!request->username)
		return 0;

	request->simul_count = 0;
	request->simul_max = maxsimul;
	request->simul_mpp = 1;

	this = session;
	rcode = RLM_MODULE_FAIL;

	while (this && (rcode == RLM_MODULE_FAIL)) {
		DEBUG2("  checksimul: %s", this->instance->entry->module->name);
		safe_lock(this);
		rcode = (this->instance->entry->module->checksimul)
				(this->instance->insthandle, request);
		safe_unlock(this);
		this = this->next;
	}

	if(rcode != RLM_MODULE_OK) {
		/* FIXME: Good spot for a *rate-limited* warning to the log */
		return 0;
	}

	return (request->simul_count < maxsimul) ? 0 : request->simul_mpp;
}

/*
 *	Module malloc() call, which does stuff if the malloc fails.
 *
 *	This call ALWAYS succeeds!
 */
void *rlm_malloc(size_t size)
{
	void *ptr = malloc(size);
	
	if (ptr == NULL) {
                radlog(L_ERR|L_CONS, "no memory");
		exit(1);
	}

	return ptr;
}
