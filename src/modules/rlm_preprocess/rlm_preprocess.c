/*
 * rlm_preprocess.c
 *		Contains the functions for the "huntgroups" and "hints"
 *		files.
 *
 * Version:     $Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/time.h>
#include	<sys/stat.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<time.h>
#include	<ctype.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"
#include	"modules.h"

typedef struct rlm_preprocess_t {
	const char	*huntgroup_file;
	const char	*hints_file;
	PAIR_LIST	*huntgroups;
	PAIR_LIST	*hints;
	int		with_ascend_hack;
	int		ascend_channels_per_line;
	int		with_ntdomain_hack;
	int		with_specialix_jetstream_hack;
} rlm_preprocess_t;

static rlm_preprocess_t config;

static CONF_PARSER module_config[] = {
	{ "huntgroups",			PW_TYPE_STRING_PTR,
	  &config.huntgroup_file, 	"${raddbdir}/huntgroups" },
	{ "hints",			PW_TYPE_STRING_PTR,
	  &config.hints_file, 		"${raddbdir}/hints" },
	{ "with_ascend_hack",		PW_TYPE_BOOLEAN,
	  &config.with_ascend_hack,  	"no" },
	{ "ascend_channels_per_line",   PW_TYPE_INTEGER,
	  &config.ascend_channels_per_line,    "23" },

	{ "with_ntdomain_hack",		PW_TYPE_BOOLEAN,
	  &config.with_ntdomain_hack,  	"no" },
	{ "with_specialix_jetstream_hack",  PW_TYPE_BOOLEAN,
	  &config.with_specialix_jetstream_hack,  	"no" },

	{ NULL, -1, NULL, NULL }
};


/*
 *	dgreer --
 *	This hack changes Ascend's wierd port numberings
 *	to standard 0-??? port numbers so that the "+" works
 *	for IP address assignments.
 */
static void ascend_nasport_hack(VALUE_PAIR *nas_port, int channels_per_line)
{
	int service;
	int line;
	int channel;

	if (!nas_port) {
		return;
	}

	if (nas_port->lvalue > 9999) {
		service = nas_port->lvalue/10000; /* 1=digital 2=analog */
		line = (nas_port->lvalue - (10000 * service)) / 100;
		channel = nas_port->lvalue-((10000 * service)+(100 * line));
		nas_port->lvalue =
			(channel - 1) + (line - 1) * channels_per_line;
	}
}

/*
 *	Mangle username if needed, IN PLACE.
 */
static void rad_mangle(rlm_preprocess_t *data, REQUEST *request)
{
	VALUE_PAIR	*namepair;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	*tmp;

	/*
	 *	Get the username from the request
	 *	If it isn't there, then we can't mangle the request.
	 */
	request_pairs = request->packet->vps;
	namepair = pairfind(request_pairs, PW_USER_NAME);
	if ((namepair == NULL) || 
	    (namepair->length <= 0)) {
	  return;
	}

	if (data->with_ntdomain_hack) {
		char		*ptr;
		char		newname[MAX_STRING_LEN];

		/*
		 *	Windows NT machines often authenticate themselves as
		 *	NT_DOMAIN\username. Try to be smart about this.
		 *
		 *	FIXME: should we handle this as a REALM ?
		 */
		if ((ptr = strchr(namepair->strvalue, '\\')) != NULL) {
			strNcpy(newname, ptr + 1, sizeof(newname));
			/* Same size */
			strcpy(namepair->strvalue, newname);
			namepair->length = strlen(newname);
		}
	}

	if (data->with_specialix_jetstream_hack) {
		char		*ptr;

		/*
		 *	Specialix Jetstream 8500 24 port access server.
		 *	If the user name is 10 characters or longer, a "/"
		 *	and the excess characters after the 10th are
		 *	appended to the user name.
		 *
		 *	Reported by Lucas Heise <root@laonet.net>
		 */
		if ((strlen(namepair->strvalue) > 10) &&
		    (namepair->strvalue[10] == '/')) {
			for (ptr = namepair->strvalue + 11; *ptr; ptr++)
				*(ptr - 1) = *ptr;
			*(ptr - 1) = 0;
			namepair->length = strlen(namepair->strvalue);
		}
	}

	/*
	 *	Small check: if Framed-Protocol present but Service-Type
	 *	is missing, add Service-Type = Framed-User.
	 */
	if (pairfind(request_pairs, PW_FRAMED_PROTOCOL) != NULL &&
	    pairfind(request_pairs, PW_SERVICE_TYPE) == NULL) {
		tmp = paircreate(PW_SERVICE_TYPE, PW_TYPE_INTEGER);
		if (tmp) {
			tmp->lvalue = PW_FRAMED_USER;
			pairmove(&request_pairs, &tmp);
		}
	}
}

/*
 *	Compare the request with the "reply" part in the
 *	huntgroup, which normally only contains username or group.
 *	At least one of the "reply" items has to match.
 */
static int hunt_paircmp(VALUE_PAIR *request, VALUE_PAIR *check)
{
	VALUE_PAIR	*check_item = check;
	VALUE_PAIR	*tmp;
	int		result = -1;

	if (check == NULL) return 0;

	while (result != 0 && check_item != NULL) {

		tmp = check_item->next;
		check_item->next = NULL;

		result = paircmp(request, check_item, NULL);

		check_item->next = tmp;
		check_item = check_item->next;
	}

	return result;
}


/*
 *	Compare prefix/suffix
 */
static int presufcmp(VALUE_PAIR *check, char *name, char *rest)
{
	int		len, namelen;
	int		ret = -1;

#if 0 /* DEBUG */
	printf("Comparing %s and %s, check->attr is %d\n",
		name, check->strvalue, check->attribute);
#endif

	len = strlen((char *)check->strvalue);
	switch (check->attribute) {
		case PW_PREFIX:
			ret = strncmp(name, (char *)check->strvalue, len);
			if (ret == 0 && rest)
				strcpy(rest, name + len);
			break;
		case PW_SUFFIX:
			namelen = strlen(name);
			if (namelen < len)
				break;
			ret = strcmp(name + namelen - len,
				     (char *)check->strvalue);
			if (ret == 0 && rest) {
				strncpy(rest, name, namelen - len);
				rest[namelen - len] = 0;
			}
			break;
	}

	return ret;
}

/*
 *	Match a username with a wildcard expression.
 *	Is very limited for now.
 */
static int matches(char *name, PAIR_LIST *pl, char *matchpart)
{
	int len, wlen;
	int ret = 0;
	char *wild = pl->name;
	VALUE_PAIR *tmp;

	/*
	 *	We now support both:
	 *
	 *		DEFAULT	Prefix = "P"
	 *
	 *	and
	 *		P*
	 */
	if ((tmp = pairfind(pl->check, PW_PREFIX)) != NULL ||
	    (tmp = pairfind(pl->check, PW_SUFFIX)) != NULL) {

		if (strncmp(pl->name, "DEFAULT", 7) == 0 ||
		    strcmp(pl->name, name) == 0)
			return !presufcmp(tmp, name, matchpart);
	}

	/*
	 *	Shortcut if there's no '*' in pl->name.
	 */
	if (strchr(pl->name, '*') == NULL &&
	    (strncmp(pl->name, "DEFAULT", 7) == 0 ||
	     strcmp(pl->name, name) == 0)) {
		strcpy(matchpart, name);
		return 1;
	}

	/*
	 *	Normally, we should return 0 here, but we
	 *	support the old * stuff.
	 */
	len = strlen(name);
	wlen = strlen(wild);

	if (len == 0 || wlen == 0) return 0;

	if (wild[0] == '*') {
		wild++;
		wlen--;
		if (wlen <= len && strcmp(name + (len - wlen), wild) == 0) {
			strcpy(matchpart, name);
			matchpart[len - wlen] = 0;
			ret = 1;
		}
	} else if (wild[wlen - 1] == '*') {
		if (wlen <= len && strncmp(name, wild, wlen - 1) == 0) {
			strcpy(matchpart, name + wlen - 1);
			ret = 1;
		}
	}

	return ret;
}


/*
 *	Add hints to the info sent by the terminal server
 *	based on the pattern of the username.
 */
static int hints_setup(PAIR_LIST *hints, REQUEST *request)
{
	char		newname[MAX_STRING_LEN];
	char		*name;
	VALUE_PAIR	*add;
	VALUE_PAIR	*last;
	VALUE_PAIR	*tmp;
	PAIR_LIST	*i;
	int		do_strip;
	VALUE_PAIR *request_pairs;

	request_pairs = request->packet->vps;

	if (hints == NULL || request_pairs == NULL)
		return RLM_MODULE_NOOP;

	/* 
	 *	Check for valid input, zero length names not permitted 
	 */
	if ((tmp = pairfind(request_pairs, PW_USER_NAME)) == NULL)
		name = NULL;
	else
		name = (char *)tmp->strvalue;

	if (name == NULL || name[0] == 0)
		/*
		 *	No name, nothing to do.
		 */
		return RLM_MODULE_NOOP;

	for (i = hints; i; i = i->next) {
		if (matches(name, i, newname)) {
			DEBUG2("  hints: Matched %s at %d",
			       i->name, i->lineno);
			break;
		}
	}

	if (i == NULL) return RLM_MODULE_NOOP;

	add = paircopy(i->reply);

#if 0 /* DEBUG */
	printf("In hints_setup, newname is %s\n", newname);
#endif

	/*
	 *	See if we need to adjust the name.
	 */
	do_strip = 1;
	if ((tmp = pairfind(i->reply, PW_STRIP_USER_NAME)) != NULL
	     && tmp->lvalue == 0)
		do_strip = 0;
	if ((tmp = pairfind(i->check, PW_STRIP_USER_NAME)) != NULL
	     && tmp->lvalue == 0)
		do_strip = 0;

	if (do_strip) {
		tmp = pairfind(request_pairs, PW_STRIPPED_USER_NAME);
		if (tmp) {
			strcpy((char *)tmp->strvalue, newname);
			tmp->length = strlen((char *)tmp->strvalue);
		} else {
			/*
			 *	No Stripped-User-Name exists: add one.
			 */
			tmp = paircreate(PW_STRIPPED_USER_NAME, PW_TYPE_STRING);
			if (!tmp) {
				radlog(L_ERR|L_CONS, "no memory");
				exit(1);
			}
			strcpy((char *)tmp->strvalue, newname);
			tmp->length = strlen((char *)tmp->strvalue);
			pairadd(&request_pairs, tmp);
		}
		request->username = tmp;
	}

	/*
	 *	Now add all attributes to the request list,
	 *	except the PW_STRIP_USER_NAME one.
	 */
	pairdelete(&add, PW_STRIP_USER_NAME);
	for(last = request_pairs; last && last->next; last = last->next)
		;
	if (last) last->next = add;

	return RLM_MODULE_UPDATED;
}

/*
 *	See if the huntgroup matches. This function is
 *	tied to the "Huntgroup" keyword.
 */
static int huntgroup_cmp(void *instance, VALUE_PAIR *request, VALUE_PAIR *check,
			 VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	PAIR_LIST	*i;
	char		*huntgroup;
	rlm_preprocess_t *data = (rlm_preprocess_t *) instance;

	check_pairs = check_pairs; /* shut the compiler up */
	reply_pairs = reply_pairs;

	huntgroup = (char *)check->strvalue;

	for (i = data->huntgroups; i; i = i->next) {
		if (strcmp(i->name, huntgroup) != 0)
			continue;
		if (paircmp(request, i->check, NULL) == 0) {
			DEBUG2("  huntgroups: Matched %s at %d",
			       i->name, i->lineno);
			break;
		}
	}

	/*
	 *	paircmp() expects to see zero on match, so let's
	 *	keep it happy.
	 */
	if (i == NULL) {
		return -1;
	}
	return 0;
}


/*
 *	See if we have access to the huntgroup.
 */
static int huntgroup_access(PAIR_LIST *huntgroups, VALUE_PAIR *request_pairs)
{
	PAIR_LIST	*i;
	int		r = RLM_MODULE_OK;

	/*
	 *	We're not controlling access by huntgroups:
	 *	Allow them in.
	 */
	if (huntgroups == NULL)
		return RLM_MODULE_OK;

	for(i = huntgroups; i; i = i->next) {
		/*
		 *	See if this entry matches.
		 */
		if (paircmp(request_pairs, i->check, NULL) != 0)
			continue;

		/*
		 *	Now check for access.
		 */
		r = RLM_MODULE_REJECT;
		if (hunt_paircmp(request_pairs, i->reply) == 0) {
			r = RLM_MODULE_OK;
		}
		break;
	}

	return r;
}

/*
 *	If the NAS wasn't smart enought to add a NAS-IP-Address
 *	to the request, then add it ourselves.
 */
static void add_nas_attr(REQUEST *request)
{
	VALUE_PAIR *nas;

	nas = pairfind(request->packet->vps, PW_NAS_IP_ADDRESS);
	if (!nas) {
		nas = paircreate(PW_NAS_IP_ADDRESS, PW_TYPE_IPADDR);
		if (!nas) {
			radlog(L_ERR, "No memory");
			exit(1);
		}
		nas->lvalue = request->packet->src_ipaddr;
		pairadd(&request->packet->vps, nas);
	}

	/*
	 *	Add in a Client-IP-Address, to tell the user
	 *	the source IP of the request.  That is, the client,
	 *
	 *	Note that this MAY BE different from the NAS-IP-Address,
	 *	especially if the request is being proxied.
	 *
	 *	Note also that this is a server configuration item,
	 *	and will NOT make it to any packets being sent from
	 *	the server.
	 */
	nas = paircreate(PW_CLIENT_IP_ADDRESS, PW_TYPE_IPADDR);
	if (!nas) {
	  radlog(L_ERR, "No memory");
	  exit(1);
	}
	nas->lvalue = request->packet->src_ipaddr;
	pairadd(&request->packet->vps, nas);
}


/*
 *	Initialize.
 */
static int preprocess_instantiate(CONF_SECTION *conf, void **instance)
{
	int	rcode;
	rlm_preprocess_t *data;

	/*
	 *	Read this modules configuration data.
	 */
        if (cf_section_parse(conf, module_config) < 0) {
                return -1;
        }

	/*
	 *	Allocate room to put the module's instantiation data.
	 */
	data = (rlm_preprocess_t *) malloc(sizeof(*data));
	if (!data) {
		radlog(L_ERR|L_CONS, "Out of memory\n");
		return -1;
	}

	/*
	 *	Copy the configuration over to the instantiation.
	 */
	memcpy(data, &config, sizeof(*data));
	data->huntgroups = NULL;
	data->hints = NULL;
	config.huntgroup_file = NULL;
	config.hints_file = NULL;

	/*
	 *	Read the huntgroups file.
	 */
	rcode = pairlist_read(data->huntgroup_file, &(data->huntgroups), 0);
	if (rcode < 0) {
		radlog(L_ERR|L_CONS, "rlm_preprocess: Error reading %s",
		       data->huntgroup_file);
		return -1;
	}

	/*
	 *	Read the hints file.
	 */
	rcode = pairlist_read(data->hints_file, &(data->hints), 0);
	if (rcode < 0) {
		radlog(L_ERR|L_CONS, "rlm_preprocess: Error reading %s",
		       data->hints_file);
		return -1;
	}

	/*
	 *	Register the huntgroup comparison operation.
	 */
	paircompare_register(PW_HUNTGROUP_NAME, 0, huntgroup_cmp, data);

	/*
	 *	Save the instantiation data for later.
	 */
	*instance = data;

	return 0;
}

/*
 *	Preprocess a request.
 */
static int preprocess_authorize(void *instance, REQUEST *request)
{
	char buf[1024];
	rlm_preprocess_t *data = (rlm_preprocess_t *) instance;

	/*
	 *	Mangle the username, to get rid of stupid implementation
	 *	bugs.
	 */
	rad_mangle(data, request);

	if (data->with_ascend_hack) {
		/*
		 *	If we're using Ascend systems, hack the NAS-Port-Id
		 *	in place, to go from Ascend's weird values to something
		 *	approaching rationality.
		 */
		ascend_nasport_hack(pairfind(request->packet->vps,
					     PW_NAS_PORT_ID),
				    data->ascend_channels_per_line);
	}

	hints_setup(data->hints, request);
	
	/*
	 *	Note that we add the Request-Src-IP-Address to the request
	 *	structure BEFORE checking huntgroup access.  This allows
	 *	the Request-Src-IP-Address to be used for huntgroup
	 *	comparisons.
	 */
	add_nas_attr(request);

	if (huntgroup_access(data->huntgroups, request->packet->vps) != RLM_MODULE_OK) {
		radlog(L_AUTH, "No huntgroup access: [%s] (%s)",
		    request->username->strvalue,
		    auth_name(buf, sizeof(buf), request, 1));
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK; /* Meaning: try next authorization module */
}

/*
 *	Preprocess a request before accounting
 */
static int preprocess_preaccounting(void *instance, REQUEST *request)
{
	int r;
	rlm_preprocess_t *data = (rlm_preprocess_t *) instance;

	/*
	 *  Ensure that we have the SAME user name for both
	 *  authentication && accounting.
	 */
	rad_mangle(data, request);
	r = hints_setup(data->hints, request);

	/*
	 *  Ensure that we log the NAS IP Address in the packet.
	 */
	add_nas_attr(request);

	return r;
}

/*
 *      Clean up the module's instance.
 */
static int preprocess_detach(void *instance)
{
	rlm_preprocess_t *data = (rlm_preprocess_t *) instance;

	paircompare_unregister(PW_HUNTGROUP_NAME, huntgroup_cmp);
	pairlist_free(&(data->huntgroups));
	pairlist_free(&(data->hints));

	free((char *) data->huntgroup_file);
	free((char *) data->hints_file);
	free(data);

	return 0;
}

/* globally exported name */
module_t rlm_preprocess = {
	"preprocess",
	0,			/* type: reserved */
	NULL,			/* initialization */
	preprocess_instantiate,	/* instantiation */
	preprocess_authorize,	/* authorization */
	NULL,			/* authentication */
	preprocess_preaccounting, /* pre-accounting */
	NULL,			/* accounting */
	NULL,			/* checksimul */
	preprocess_detach,	/* detach */
	NULL,			/* destroy */
};

