/*
 * valuepair.c	Functions to handle VALUE_PAIRs
 *
 * Version:	@(#)valuepair.c  1.00  19-Jul-1999  miquels@cistron.nl
 *
 */

char valuepair_sccsid[] =
"@(#)radius.c 	1.00 Copyright 1998-1999 Cistron Internet Services B.V.";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/time.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<time.h>
#include	<ctype.h>

#include	"libradius.h"

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif


static char *months[] = {
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec" };


/*
 *	Create a new valuepair.
 */
VALUE_PAIR *paircreate(int attr, int type)
{
	VALUE_PAIR	*vp;
	DICT_ATTR	*da;

	if ((vp = malloc(sizeof(VALUE_PAIR))) == NULL)
		return NULL;
	memset(vp, 0, sizeof(VALUE_PAIR));
	vp->attribute = attr;
	vp->type = type;
	if ((da = dict_attrbyvalue(attr)) != NULL)
		strcpy(vp->name, da->name);
	else
		sprintf(vp->name, "Attr-%d", attr);
	switch (vp->type) {
		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
		case PW_TYPE_DATE:
			vp->length = 4;
			break;
		default:
			vp->length = 0;
			break;
	}

	return vp;
}

/*
 *	Release the memory used by a list of attribute-value
 *	pairs.
 */
void pairfree(VALUE_PAIR *pair)
{
	VALUE_PAIR	*next;

	while(pair != NULL) {
		next = pair->next;
		free(pair);
		pair = next;
	}
}


/*
 *	Find the pair with the matching attribute
 */
VALUE_PAIR * pairfind(VALUE_PAIR *first, int attr)
{
	while(first && first->attribute != attr)
		first = first->next;
	return first;
}


/*
 *	Delete the pair(s) with the matching attribute
 */
void pairdelete(VALUE_PAIR **first, int attr)
{
	VALUE_PAIR *i, *next, *last = NULL;

	for(i = *first; i; i = next) {
		next = i->next;
		if (i->attribute == attr) {
			if (last)
				last->next = next;
			else
				*first = next;
			free(i);
		} else
			last = i;
	}
}

/*
 *	Add a pair at the end of a VALUE_PAIR list.
 */
void pairadd(VALUE_PAIR **first, VALUE_PAIR *new)
{
	VALUE_PAIR *i;

	new->next = NULL;
	if (*first == NULL) {
		*first = new;
		return;
	}
	for(i = *first; i->next; i = i->next)
		;
	i->next = new;
}

/*
 *	Copy just a certain type of pairs.
 */
VALUE_PAIR *paircopy2(VALUE_PAIR *vp, int attr)
{
	VALUE_PAIR	*first, *n, *last;

	first = NULL;
	last = NULL;

	while (vp) {
		if (attr >= 0 && vp->attribute != attr) {
			vp = vp->next;
			continue;
		}
		if ((n = (VALUE_PAIR *)malloc(sizeof(VALUE_PAIR))) == NULL)
			return first;
		memcpy(n, vp, sizeof(VALUE_PAIR));
		n->next = NULL;
		if (last == NULL)
			first = n;
		else
			last->next = n;
		last = n;
		vp = vp->next;
	}
	return first;
}


/*
 *	Copy a pairlist.
 */
VALUE_PAIR *paircopy(VALUE_PAIR *vp)
{
	return paircopy2(vp, -1);
}


/*
 *	Move attributes from one list to the other
 *	if not already present.
 */
void pairmove(VALUE_PAIR **to, VALUE_PAIR **from)
{
	VALUE_PAIR *tailto, *i, *next;
	VALUE_PAIR *tailfrom = NULL;
	int has_password = 0;

	if (*to == NULL) {
		*to = *from;
		*from = NULL;
		return;
	}

	/*
	 *	First, see if there are any passwords here, and
	 *	point "tailto" to the end of the "to" list.
	 */
	tailto = *to;
	for(i = *to; i; i = i->next) {
		if (i->attribute == PW_PASSWORD ||
		/*
		 *	FIXME: this seems to be needed with PAM support
		 *	to keep it around the Auth-Type = Pam stuff.
		 *	Perhaps we should only do this if Auth-Type = Pam?
		 */
#ifdef WITH_PAM
		    i->attribute == PAM_AUTH_ATTR ||
#endif
		    i->attribute == PW_CRYPT_PASSWORD)
			has_password = 1;
		tailto = i;
	}

	/*
	 *	Loop over the "from" list.
	 */
	for(i = *from; i; i = next) {
		next = i->next;
		/*
		 *	If there was a password in the "to" list,
		 *	do not move any other password from the
		 *	"from" to the "to" list.
		 */
		if (has_password &&
		    (i->attribute == PW_PASSWORD ||
#ifdef WITH_PAM
		     i->attribute == PAM_AUTH_ATTR ||
#endif
		     i->attribute == PW_CRYPT_PASSWORD)) {
			tailfrom = i;
			continue;
		}
		/*
		 *	If the attribute is already present in "to",
		 *	do not move it from "from" to "to". We make
		 *	an exception for "Hint" which can appear multiple
		 *	times, and we never move "Fall-Through".
		 */
		if (i->attribute == PW_FALL_THROUGH ||
		    (i->attribute != PW_HINT && i->attribute != PW_FRAMED_ROUTE
		     && pairfind(*to, i->attribute) != 0)) {
			tailfrom = i;
			continue;
		}
		if (tailfrom)
			tailfrom->next = next;
		else
			*from = next;
		tailto->next = i;
		i->next = NULL;
		tailto = i;
	}
}

/*
 *	Move one kind of attributes from one list to the other
 */
void pairmove2(VALUE_PAIR **to, VALUE_PAIR **from, int attr)
{
	VALUE_PAIR *to_tail, *i, *next;
	VALUE_PAIR *iprev = NULL;

	/*
	 *	Find the last pair in the "to" list and put it in "to_tail".
	 */
	if (*to != NULL) {
		to_tail = *to;
		for(i = *to; i; i = i->next)
			to_tail = i;
	} else
		to_tail = NULL;

	for(i = *from; i; i = next) {
		next = i->next;

		if (i->attribute != attr) {
			iprev = i;
			continue;
		}

		/*
		 *	Remove the attribute from the "from" list.
		 */
		if (iprev)
			iprev->next = next;
		else
			*from = next;

		/*
		 *	Add the attribute to the "to" list.
		 */
		if (to_tail)
			to_tail->next = i;
		else
			*to = i;
		to_tail = i;
		i->next = NULL;
	}
}


/*
 *	Sort of strtok/strsep function.
 */
static char *mystrtok(char **ptr, char *sep)
{
	char	*res;

	if (**ptr == 0)
		return NULL;
	while (**ptr && strchr(sep, **ptr))
		(*ptr)++;
	if (**ptr == 0)
		return NULL;
	res = *ptr;
	while (**ptr && strchr(sep, **ptr) == NULL)
		(*ptr)++;
	if (**ptr != 0)
		*(*ptr)++ = 0;
	return res;
}

/*
 *	Turn printable string into time_t
 */
static time_t gettime(char *valstr)
{
	int		i;
	time_t		t;
	struct tm	*tm;
	char		buf[32];
	char		*p;
	char		*y, *m, *d;

	time(&t);
	tm = localtime(&t);

	strncpy(buf, valstr, sizeof(buf));
	buf[sizeof(buf) - 1] = 0;
	for (p = buf; *p; p++)
		if (isupper(*p)) *p = tolower(*p);

	p = buf;
	d = mystrtok(&p, " \t");
	m = mystrtok(&p, " \t");
	y = mystrtok(&p, " \t");
	if (!y || !m || !d) return 0;

	for (i = 0; i < 12; i++) {
		if (strncmp(months[i], y, 3) == 0) {
			tm->tm_mon = i;
			i = 13;
		}
	}
	tm->tm_mday = atoi(m);
	tm->tm_year = atoi(y);
	if (tm->tm_year >= 1900) tm->tm_year -= 1900;

	return mktime(tm);
}

/*
 *	Create a VALUE_PAIR from an ASCII attribute and value.
 */
VALUE_PAIR *pairmake(char *attribute, char *value, int operator)
{
	DICT_ATTR	*da;
	DICT_VALUE	*dval;
	VALUE_PAIR	*vp;
	char		*p, *s;

	if ((da = dict_attrbyname(attribute)) == NULL) {
		librad_log("unknown attribute %s", attribute);
		return NULL;
	}

	if ((vp = (VALUE_PAIR *)malloc(sizeof(VALUE_PAIR))) == NULL) {
		librad_log("out of memory");
		return NULL;
	}

	memset(vp, 0, sizeof(VALUE_PAIR));
	vp->attribute = da->attr;
	vp->type = da->type;
	vp->operator = (operator == 0) ? T_OP_EQ : operator;
	strcpy(vp->name, da->name);

	/*
	 *	Even for integers, dates and ip addresses we
	 *	keep the original string in vp->strvalue.
	 */
	strncpy(vp->strvalue, value, MAX_STRING_LEN);
	vp->strvalue[MAX_STRING_LEN - 1] = 0;

	switch(da->type) {
		case PW_TYPE_STRING:
			vp->length = strlen(value);
			break;
		case PW_TYPE_IPADDR:
			/*
			 *	FIXME: complain if hostname
			 *	cannot be resolved, or resolve later!
			 */
			if ((p = strrchr(value, '+')) != NULL && !p[1]) {
				*p = 0;
				vp->addport = 1;
			} else
				p = NULL;
			vp->lvalue = librad_dodns ? ip_getaddr(value) :
						    ip_addr(value);
			vp->length = 4;
			if (p) *p = '+';
			break;
		case PW_TYPE_INTEGER:
			/*
			 *	For PW_NAS_PORT_ID, allow a
			 *	port range instead of just a port.
			 */
			if (vp->attribute == PW_NAS_PORT_ID) {
				for(s = value; *s; s++)
					if (!isdigit(*s)) break;
				if (*s) {
					vp->type = PW_TYPE_STRING;
					vp->length = strlen(value);
					break;
				}
			}
			if (isdigit(*value)) {
				vp->lvalue = atoi(value);
				vp->length = 4;
			}
			else if ((dval = dict_valbyname(value)) == NULL) {
				free(vp);
				librad_log("unknown value %s", value);
				return NULL;
			}
			else {
				vp->lvalue = dval->value;
				vp->length = 4;
			}
			break;

		case PW_TYPE_DATE:
			if ((vp->lvalue = gettime(value)) == (time_t)-1) {
				free(vp);
				librad_log("failed to get time");
				return NULL;
			}
			vp->length = 4;
			break;
		default:
			free(vp);
			librad_log("unknown attribute type");
			return NULL;
	}
	return vp;
}

/*
 *	Read a valuepair from a buffer, and advance pointer.
 *	Sets *eol to 1 if end of line was encountered.
 */
VALUE_PAIR *pairread(char **ptr, int *eol)
{
	char		buf[64];
	char		attr[64];
	char		value[256];
	char		*p;
	int		token, t;

	*eol = 0;

	/* Get attribute. */
	gettoken(ptr, attr, sizeof(attr));
	if (attr[0] == 0) {
		librad_log("No token read");
		return NULL;
	}

	/* Now we should have an '=' here. */
	token = gettoken(ptr, buf, sizeof(buf));
	if (token < T_EQSTART || token > T_EQEND) {
		librad_log("expecting '='");
		return NULL;
	}

	/* Read value. */
	gettoken(ptr, value, sizeof(value));
	if (value[0] == 0) {
		librad_log("failed to get value");
		return NULL;
	}

	/*
	 *	Peek at the next token. Must be T_EOL or T_COMMA.
	 */
	p = *ptr;
	t = gettoken(&p, buf, sizeof(buf));
	if (t != T_EOL && t != T_COMMA) {
		librad_log("Expected end of line or comma");
		return NULL;
	}

	if (t == T_COMMA) {
		*ptr = p;
		/*
		 *	HACK: should peek again, taking shortcut :)
		 */
		if (*p == 0)
			*eol = 1;
	} else {
		*eol = 1;
	}

	return pairmake(attr, value, token);
}

/*
 *	Read one line of attribute/value pairs. This might contain
 *	multiple pairs seperated by comma's.
 */
int userparse(char *buffer, VALUE_PAIR **first_pair)
{
	VALUE_PAIR	*vp;
	char		*p;
	int		eol = 0;

	/*
	 *	We allow an empty line.
	 */
	if (buffer[0] == 0)
		return 0;

	p = buffer;
	do {
		if ((vp = pairread(&p, &eol)) == NULL)
			return -1;
		pairadd(first_pair, vp);
	} while (!eol);

	return 0;
}

