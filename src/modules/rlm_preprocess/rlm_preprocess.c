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


/* FIXME: should this stuff be instance data? */
static PAIR_LIST	*huntgroups;
static PAIR_LIST	*hints;

#ifdef WITH_ASCEND_HACK
/*
 *	dgreer --
 *	This hack changes Ascend's wierd port numberings
 *	to standard 0-??? port numbers so that the "+" works
 *	for IP address assignments.
 */
static void ascend_nasport_hack(VALUE_PAIR *nas_port)
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
			(channel - 1) + (line - 1) * ASCEND_CHANNELS_PER_LINE;
	}
}
#endif

/*
 *	Mangle username if needed, IN PLACE.
 */
static void rad_mangle(REQUEST *request)
{
	VALUE_PAIR	*namepair;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	*tmp;
#ifdef WITH_NTDOMAIN_HACK
	char		newname[MAX_STRING_LEN];
#endif
#if defined(WITH_NTDOMAIN_HACK) || defined(WITH_SPECIALIX_JETSTREAM_HACK)
	char		*ptr;
#endif

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

#ifdef WITH_NTDOMAIN_HACK
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
#endif /* WITH_NTDOMAIN_HACK */

#ifdef WITH_SPECIALIX_JETSTREAM_HACK
	/*
	 *	Specialix Jetstream 8500 24 port access server.
	 *	If the user name is 10 characters or longer, a "/"
	 *	and the excess characters after the 10th are
	 *	appended to the user name.
	 *
	 *	Reported by Lucas Heise <root@laonet.net>
	 */
	if (strlen(namepair->strvalue) > 10 && namepair->strvalue[10] == '/') {
		for (ptr = namepair->strvalue + 11; *ptr; ptr++)
			*(ptr - 1) = *ptr;
		*(ptr - 1) = 0;
		namepair->length = strlen(namepair->strvalue);
	}
#endif

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

#if 0
	/*
	 *	FIXME: find some substitute for this, or
	 *	drop the log_auth_detail option all together.
	 */
	if (log_auth_detail)
		rad_accounting_orig(request, -1, "detail.auth");
#endif
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
			ret = strncmp(name, check->strvalue, len);
			if (ret == 0 && rest)
				strcpy(rest, name + len);
			break;
		case PW_SUFFIX:
			namelen = strlen(name);
			if (namelen < len)
				break;
			ret = strcmp(name + namelen - len, check->strvalue);
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
static int hints_setup(REQUEST *request)
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
		return RLM_MODULE_OK;

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
		return RLM_MODULE_OK;

	for (i = hints; i; i = i->next) {
		if (matches(name, i, newname)) {
			DEBUG2("  hints: Matched %s at %d",
			       i->name, i->lineno);
			break;
		}
	}

	if (i == NULL) return RLM_MODULE_OK;

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
			strcpy(tmp->strvalue, newname);
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
			strcpy(tmp->strvalue, newname);
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

	return RLM_MODULE_OK;
}

/*
 *	See if the huntgroup matches. This function is
 *	tied to the "Huntgroup" keyword.
 */
static int huntgroup_cmp(VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	PAIR_LIST	*i;
	char		*huntgroup;

	check_pairs = check_pairs; /* shut the compiler up */
	reply_pairs = reply_pairs;

	huntgroup = (char *)check->strvalue;

	for (i = huntgroups; i; i = i->next) {
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
static int huntgroup_access(VALUE_PAIR *request_pairs)
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
	 *	Add in a Request-Src-IP-Address, to tell the user
	 *	the source IP of the request.  That is, the client,
	 *	but Client-IP-Address is too close to the old
	 *	Client-FOO names, which I KNOW would confuse a lot
	 *	of people.
	 *
	 *	Note that this MAY BE different from the NAS-IP-Address,
	 *	especially if the request is being proxied.
	 *
	 *	Note also that this is a server configuration item,
	 *	and will NOT make it to any packets being sent from
	 *	the server.
	 */
	nas = paircreate(PW_REQUEST_SRC_IP_ADDRESS, PW_TYPE_IPADDR);
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
static int preprocess_init(void)
{
	int	rcode;
	char	buffer[256];

	pairlist_free(&huntgroups);
	pairlist_free(&hints);

	sprintf(buffer, "%s/%s", radius_dir, RADIUS_HUNTGROUPS);
	rcode = pairlist_read(buffer, &huntgroups, 0);
	if (rcode < 0) {
		return -1;
	}

	sprintf(buffer, "%s/%s", radius_dir, RADIUS_HINTS);
	rcode = pairlist_read(buffer, &hints, 0);
	if (rcode < 0) {
		return -1;
	}

	paircompare_register(PW_HUNTGROUP_NAME, 0, huntgroup_cmp);

	return 0;
}

/*
 *	Preprocess a request.
 */
static int preprocess_authorize(void *instance, REQUEST *request,
	VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
	char buf[1024];

	instance = instance;

	check_pairs = check_pairs; /* shut the compiler up */
	reply_pairs = reply_pairs;

	/*
	 *	Mangle the username, to get rid of stupid implementation
	 *	bugs.
	 */
	rad_mangle(request);

#ifdef WITH_ASCEND_HACK
	/*
	 *	If we're using Ascend systems, hack the NAS-Port-Id
	 *	in place, to go from Ascend's weird values to something
	 *	approaching rationality.
	 */
	ascend_nasport_hack(pairfind(request->packet->vps, PW_NAS_PORT_ID));
#endif

	hints_setup(request);
	
	/*
	 *	Note that we add the Request-Src-IP-Address to the request
	 *	structure BEFORE checking huntgroup access.  This allows
	 *	the Request-Src-IP-Address to be used for huntgroup
	 *	comparisons.
	 */
	add_nas_attr(request);

	if (huntgroup_access(request->packet->vps) != RLM_MODULE_OK) {
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
	instance = instance;
	/*
	 *  Ensure that we have the SAME user name for both
	 *  authentication && accounting.
	 */
	rad_mangle(request);
	hints_setup(request);

	/*
	 *  Ensure that we log the NAS IP Address in the packet.
	 */
	add_nas_attr(request);

	return RLM_MODULE_OK;
}

/*
 *      Clean up.
 */
static int preprocess_destroy(void)
{
	paircompare_unregister(PW_HUNTGROUP_NAME, huntgroup_cmp);
	pairlist_free(&huntgroups);
	pairlist_free(&hints);

	return 0;
}

/* globally exported name */
module_t rlm_preprocess = {
	"preprocess",
	0,				/* type: reserved */
	preprocess_init,		/* initialization */
	NULL,				/* instantiation */
	preprocess_authorize,		/* authorization */
	NULL,				/* authentication */
	preprocess_preaccounting,	/* pre-accounting */
	NULL,				/* accounting */
	NULL,				/* detach */
	preprocess_destroy,		/* destroy */
};

