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


static PAIR_LIST	*huntgroups;
static PAIR_LIST	*hints;

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

	len = strlen(check->strvalue);
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
static int hints_setup(VALUE_PAIR *request_pairs)
{
	char		newname[MAX_STRING_LEN];
	char		*name;
	VALUE_PAIR	*add;
	VALUE_PAIR	*last;
	VALUE_PAIR	*tmp;
	PAIR_LIST	*i;
	int		do_strip;

	if (hints == NULL || request_pairs == NULL)
		return RLM_AUTZ_OK;

	/* 
	 *	Check for valid input, zero length names not permitted 
	 */
	if ((tmp = pairfind(request_pairs, PW_USER_NAME)) == NULL)
		name = NULL;
	else
		name = tmp->strvalue;

	if (name == NULL || name[0] == 0)
		/*
		 *	No name, nothing to do.
		 */
		return RLM_AUTZ_OK;

	for (i = hints; i; i = i->next) {
		if (matches(name, i, newname)) {
			DEBUG2("  hints: Matched %s at %d",
			       i->name, i->lineno);
			break;
		}
	}

	if (i == NULL) return RLM_AUTZ_OK;

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
		tmp = pairfind(request_pairs, PW_USER_NAME);
		if (tmp) {
			strcpy(tmp->strvalue, newname);
			tmp->length = strlen(tmp->strvalue);
		}
	}

	/*
	 *	Now add all attributes to the request list,
	 *	except the PW_STRIP_USER_NAME one.
	 */
	pairdelete(&add, PW_STRIP_USER_NAME);
	for(last = request_pairs; last && last->next; last = last->next)
		;
	if (last) last->next = add;

	return RLM_AUTZ_OK;
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

	huntgroup = check->strvalue;

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
	int		r = 1;

	if (huntgroups == NULL)
		return RLM_AUTZ_REJECT;

	for(i = huntgroups; i; i = i->next) {
		/*
		 *	See if this entry matches.
		 */
		if (paircmp(request_pairs, i->check, NULL) != 0)
			continue;

		/*
		 *	Now check for access.
		 */
		r = RLM_AUTZ_REJECT;
		if (hunt_paircmp(request_pairs, i->reply) == 0) {
			r = RLM_AUTZ_OK;
		}
		break;
	}

	return r;
}

/*
 *	Initialize.
 */
static int preprocess_init(int argc, char **argv)
{
	char	buffer[256];

	pairlist_free(&huntgroups);
	pairlist_free(&hints);

	sprintf(buffer, "%s/%s", radius_dir, RADIUS_HUNTGROUPS);
	huntgroups = pairlist_read(buffer, 0);
	sprintf(buffer, "%s/%s", radius_dir, RADIUS_HINTS);
	hints	   = pairlist_read(buffer, 0);

	paircompare_register(PW_HUNTGROUP_NAME, 0, huntgroup_cmp);

	return 0;
}

/*
 *	Preprocess a request.
 */
static int preprocess_authorize(REQUEST *request, char *name,
	VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
	hints_setup(request->packet->vps);
	if (huntgroup_access(request->packet->vps) != RLM_AUTZ_OK) {
		log(L_AUTH, "No huntgroup access: [%s] (%s)",
			request->username, auth_name(request, 1));
		return RLM_AUTZ_REJECT;
	}

	return RLM_AUTZ_NOTFOUND; /* Meaning: try next autorization module */
}

/*
 *	Preprocess a request before accounting
 */
static int preprocess_accounting(REQUEST *request)
{
	hints_setup(request->packet->vps);

	return RLM_ACCT_OK;
}

/*
 *      Clean up.
 */
static int preprocess_detach(void)
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
	preprocess_authorize,		/* authorization */
	NULL,				/* authentication */
	preprocess_accounting,		/* accounting */
	preprocess_detach,		/* detach */
};

