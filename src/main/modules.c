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

#ifdef HAVE_DLFCN_H
#  include	<dlfcn.h>
#endif

#ifndef RTLD_GLOBAL
/*
 *	FreeBSD has libdl in it's Linux compatibility directory,
 *	but it doesn't define RTLD_GLOBAL.  Grr..
 */
#define RTLD_GLOBAL 0
#endif

#include	"radiusd.h"
#include	"modules.h"

#ifndef HAVE_DLOPEN
#include	"modules_static.h"
#endif

#define	RLM_AUTHORIZE		1
#define	RLM_AUTHENTICATE	2
#define RLM_ACCOUNTING		4

/*
 *	Keep track of which modules we've loaded
 */
typedef struct module_list_t {
	char			filename[MAX_STRING_LEN];
	int			auth_type;
	int			flags;		/* doing what, exactly? */
	module_t		*module;
#ifdef HAVE_DLOPEN
	void			*handle;
#endif
	struct module_list_t	*next;
} module_list_t;

static module_list_t *module_list = NULL;

typedef struct config_module_t {
	module_list_t		*entry;
	struct config_module_t	*next;
} config_module_t;

static config_module_t *authorize = NULL;
static config_module_t *authenticate = NULL;
static config_module_t *preacct = NULL;
static config_module_t *accounting = NULL;

static void config_list_free(config_module_t **cf)
{
	config_module_t	*c, *next;

	c = *cf;
	while (c) {
		next = c->next;
		free(c);
		c = next;
	}
	*cf = NULL;
}

static void module_list_free(void)
{
	module_list_t *ml, *next;

	ml = module_list;
	while (ml) {
		next = ml->next;
		if (ml->module->detach)
			(ml->module->detach)();
#ifdef HAVE_DLOPEN
		dlclose(ml->handle);	/* ignore any errors */
#endif
		free(ml);
		ml = next;
	}

	module_list = NULL;
	config_list_free(&authenticate);
	config_list_free(&authorize);
	config_list_free(&preacct);
	config_list_free(&accounting);
}


static module_list_t *find_module(module_list_t *head, char *filename)
{
	while (head) {
		if (strcmp(head->filename, filename) == 0)
			return head;
		head = head->next;
	}
	return NULL;
}


/*
 *	Add one entry at the end of the config_module_t list.
 */
static void add_to_list(config_module_t **head, module_list_t *entry)
{
	config_module_t	*node = *head;
	config_module_t **last = head;

	while (node) {
		last = &node->next;
		node = node->next;
	}

	node = (config_module_t *) malloc(sizeof(config_module_t));
	if (!node) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}

	node->next = NULL;
	node->entry = entry;
	*last = node;
}


/*
 *  New Auth-Type's start at a large number, and go up from there.
 *
 *  We could do something more intelligent, but this should work almost
 *  all of the time.
 *
 * FIXME: move this to dict.c as dict_valadd() and dict_valdel()
 *        also clear value in module_list free (nessecary?)
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
    fprintf(stderr, "Out of memory\n");
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
 *  Read the modules file, parse the structure into memory,
 *  and call each module's init() function.
 */
int read_modules_file(char *filename)
{
	FILE		*fp;
	module_list_t	*this;
	module_list_t	**last;
	char		*p, *q;
	char		buffer[1024];
	char		control[256];
	char		library[256];
	char		module_name[256];
	int		lineno = 0;
#ifdef HAVE_DLOPEN
	char		libraryfile[1024];
	void		*handle;
	const char	*error;
#else
	static_modules_t *sm;
#endif
	int		argc;			/* for calling the modules */
	char		*argv[32];

#ifndef HAVE_DLOPEN
	sm   = NULL;
#endif
	this = NULL; /* Shut up stupid gcc */

	if (module_list)
		module_list_free();

	/* read the modules file */
	fp = fopen(filename, "r");
	if (!fp)
		return 0;			/* no modules file, it's OK */

	last = &module_list;

	while (fgets(buffer, sizeof(buffer), fp)) {

	/*
	 *	Yes, we're missing one indenting TAB here.
	 *	It's yucky but otherwise it doesn't fit. That
	 *	ofcourse means that this function should
	 *	be split up....
	 */
	lineno++;
	if ((*buffer == '#') || (*buffer <= ' ')) 
		continue;

	/* split it up */
	if (sscanf(buffer, "%255s%255s", control, library) != 2) {
		fprintf(stderr, "[%s:%d] Parse error.\n",
			filename, lineno);
		exit(1); /* FIXME */
	}

	this = find_module(module_list, library);
	if (this == NULL) {
#ifdef HAVE_DLOPEN
		/*
		 * Keep the handle around so we can dlclose() it.
		 * Also ensure that any further dependencies are exported,
		 * so that PAM can work.
		 *
		 * i.e. rlm_pam.so links to libpam.so, which in turn dlopen()'s
		 * pam_foo.so.  Without RTLD_GLOBAL, the functions in libpam.so
		 * won't get exported to pam_foo.so.
		 */
		if (*library != '/')
			sprintf(libraryfile, "%.500s/%.500s",
				radius_dir, library);
		else
			strNcpy(libraryfile, library, sizeof(libraryfile));
#ifdef __OpenBSD__
		/* OpenBSD doesn't pay attention to the second value
		 * as of the present. It should be set to DL_LAZY for
		 * future compatibility
		 */
		handle = dlopen(libraryfile, DL_LAZY);
#else
		handle = dlopen(libraryfile, RTLD_NOW | RTLD_GLOBAL);
#endif

		if (handle == NULL) {
			fprintf(stderr, "[%s:%d] Failed to link to module %s:"
				" %s\n", filename, lineno, libraryfile, dlerror());
			exit(1); /* FIXME */
		}
#else /* HAVE_DLOPEN */
		/*
		 *	Find the module in the static module list.
		 */
		for (sm = static_modules; sm->keyword; sm++) {
			if (strcmp(sm->keyword, library) == 0)
	  			break;
		}
		if (sm == NULL || sm->keyword == NULL) {
		fprintf(stderr, "[%s:%d] Failed module link: no such module\n",
			filename, lineno);
			exit(1); /* FIXME */
		}
#endif /* HAVE_DLOPEN */

		/* make room for the module type */
		this = (module_list_t *) malloc(sizeof(module_list_t));
		if (this == NULL) {
			fprintf(stderr, "[%s:%d] Failed to allocate memory.\n",
				filename, lineno);
			exit(1);
		}

		/* fill in the module structure */
		this->next = NULL;
#ifdef HAVE_DLOPEN
		this->handle = handle;
#endif
		strNcpy(this->filename, library, sizeof(this->filename));

		/* find the structure name from the library name */
		p = strrchr(library, '/');
		q = module_name;
#ifdef MODULE_NEED_USCORE
		*(q++) = '_';
#endif
		if (p)
			strNcpy(q, p + 1, sizeof(module_name) - 1);
		else
			strNcpy(q, library, sizeof(module_name) - 1);
		p = strchr(module_name, '.');
		*p = '\0';

#ifdef HAVE_DLOPEN
		this->module = dlsym(this->handle, module_name);
		error = dlerror();
		if (!this->module) {
			fprintf(stderr, "[%s:%d] Failed linking to "
					"%s structure in %s: %s\n",
					filename, lineno, q,
					library, error);
			exit(1);
		}
#else
		this->module = sm->module;
#endif

		/* If there's an authentication method, add a new Auth-Type */
		if (this->module->authenticate)
			this->auth_type =
				new_authtype_value(this->module->name);

		/* split up the rest of the string into argv */
		p = strtok(buffer, " \t");  /* find name */
		if (p) p = strtok(NULL, " \t\r\n"); /* find library name */
		if (p) p = strtok(NULL, " \t\r\n"); /* find trailing stuff */

		argc = 0;
		while (p) {
			argv[argc++] = p;
			p = strtok(NULL, " \t\r\n");

			if (argc > 31) {
				fprintf(stderr, "[%s:%d]  Too many arguments "
						"to module.\n",
						filename, lineno);
				exit(1);
			}
		}
		argv[argc] = NULL;

		/* call the modules initialization */
		if (this->module->init &&
		    (this->module->init)(argc, argv) < 0) {
			fprintf(stderr,
			   "[%s:%d] Module initialization failed.\n",
				filename, lineno);
			exit(1);
		}
      
		DEBUG("Module: Loaded %s ", this->module->name);

		*last = this;
		last = &this->next;
	}

	if (strcmp(control, "authorize") == 0) {
		if (!this->module->authorize) {
			fprintf(stderr, "[%s:%d] Module %s does not contain "
					"an 'authorize' entry\n",
					filename, lineno, this->module->name);
			exit(1);
		}
		add_to_list(&authorize, this);
	} else if (strcmp(control, "authenticate") == 0) {
		if (!this->module->authenticate) {
			fprintf(stderr, "[%s:%d] Module %s does not contain "
					"an 'authenticate' entry\n",
					filename, lineno, this->module->name);
			exit(1);
		}
		add_to_list(&authenticate, this);
	} else if (strcmp(control, "preacct") == 0) {
		if (!this->module->preaccounting) {
			fprintf(stderr, "[%s:%d] Module %s does not contain "
					"a 'preacct' entry\n",
					filename, lineno, this->module->name);
			exit(1);
		}
		add_to_list(&preacct, this);
	} else if (strcmp(control, "accounting") == 0) {
		if (!this->module->accounting) {
			fprintf(stderr, "[%s:%d] Module %s does not contain "
					"an 'accounting' entry\n",
					filename, lineno, this->module->name);
			exit(1);
		}
		add_to_list(&accounting, this);
	} else {
		fprintf(stderr, "[%s:%d] Unknown control \"%s\".\n",
			filename, lineno, control);
		exit(1);
	}

  	} /* YUCK */

	fclose(fp);

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
			log(L_ERR|L_CONS, "no memory");
			exit(1);
		}
		DEBUG2("  authorize: Creating Stripped-User-Name of %s", newname);
		strcpy(vp->strvalue, newname);
		vp->length = strlen(vp->strvalue);
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
	strcpy(vp->strvalue, newname);
	vp->length = strlen(vp->strvalue);
}

/*
 *	Call all authorization modules until one returns
 *	somethings else than RLM_MODULE_OK
 */
int module_authorize(REQUEST *request,
		     VALUE_PAIR **check_items, VALUE_PAIR **reply_items)
{
	config_module_t	*this;
	int		rcode = RLM_MODULE_OK;

	this = authorize;
	rcode = RLM_MODULE_OK;

	while (this && rcode == RLM_MODULE_OK) {
		DEBUG2("  authorize: %s", this->entry->module->name);
		rcode = (this->entry->module->authorize)
			(request, check_items, reply_items);
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
				if ((vp->length + request->username->length) > sizeof(vp->strvalue)) {
					DEBUG2("\"%s\"+\"%s\" too long",
					       vp->strvalue,
					       request->username->strvalue);
					continue;
				}
				strcpy(newname, vp->strvalue);
				strcat(newname, request->username->strvalue);
				update_username(request, newname);
				break;
				
			case PW_ADD_SUFFIX:
				if ((vp->length + request->username->length) > sizeof(vp->strvalue)) {
					DEBUG2("\"%s\"+\"%s\" too long",
					       request->username->strvalue,
					       vp->strvalue);
					continue;
				}
				strcpy(newname, request->username->strvalue);
				strcat(newname, vp->strvalue);
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

	/*
	 *  We MUST have a password, of SOME type!
	 */
	if (request->password == NULL) {
		return RLM_MODULE_FAIL;
	}

	this = authenticate;
	while (this && this->entry->auth_type != auth_type)
		this = this->next;

	if (!this || !this->entry->module->authenticate) {
		/*
		 *	No such auth_type, or module auth_type not defined
		 */
		return RLM_MODULE_FAIL;
	}

	DEBUG2("  authenticate: %s", this->entry->module->name);
	return (this->entry->module->authenticate)(request);
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
		DEBUG2("  preacct: %s", this->entry->module->name);
		rcode = (this->entry->module->preaccounting)(request);
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
		DEBUG2("  accounting: %s", this->entry->module->name);
		rcode = (this->entry->module->accounting)(request);
		this = this->next;
	}

	return rcode;
}

