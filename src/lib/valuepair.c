/*
 * valuepair.c	Functions to handle VALUE_PAIRs
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/types.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>

#include	"libradius.h"

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#if HAVE_REGEX_H
#  include	<regex.h>
#endif

#include	"missing.h"

static const char *months[] = {
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec" };


/*
 *	Create a new valuepair.
 */
VALUE_PAIR *paircreate(int attr, int type)
{
	VALUE_PAIR	*vp;
	DICT_ATTR	*da;

	if ((vp = malloc(sizeof(VALUE_PAIR))) == NULL) {
		librad_log("out of memory");
		return NULL;
	}
	memset(vp, 0, sizeof(VALUE_PAIR));
	vp->attribute = attr;
	vp->operator = T_OP_EQ;
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
 *	pairs, and sets the pair pointer to NULL.
 */
void pairfree(VALUE_PAIR **pair_ptr)
{
	VALUE_PAIR	*next, *pair;

	if (!pair_ptr) return;
	pair = *pair_ptr;

	while (pair != NULL) {
		next = pair->next;
		free(pair);
		pair = next;
	}

	*pair_ptr = NULL;
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
	VALUE_PAIR *i, *next;
	VALUE_PAIR **last = first;

	for(i = *first; i; i = next) {
		next = i->next;
		if (i->attribute == attr) {
			*last = next;
			free(i);
		} else {
			last = &i->next;
		}
	}
}

/*
 *	Add a pair at the end of a VALUE_PAIR list.
 */
void pairadd(VALUE_PAIR **first, VALUE_PAIR *add)
{
	VALUE_PAIR *i;

	if (*first == NULL) {
		*first = add;
		return;
	}
	for(i = *first; i->next; i = i->next)
		;
	i->next = add;
}

/*
 *	Copy just a certain type of pairs.
 */
VALUE_PAIR *paircopy2(VALUE_PAIR *vp, int attr)
{
	VALUE_PAIR	*first, *n, **last;

	first = NULL;
	last = &first;

	while (vp) {
		if (attr >= 0 && vp->attribute != attr) {
			vp = vp->next;
			continue;
		}
		if ((n = (VALUE_PAIR *)malloc(sizeof(VALUE_PAIR))) == NULL) {
			librad_log("out of memory");
			return first;
		}
		memcpy(n, vp, sizeof(VALUE_PAIR));
		n->next = NULL;
		*last = n;
		last = &n->next;
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
	VALUE_PAIR **tailto, *i, *j, *next;
	VALUE_PAIR *tailfrom = NULL;
	VALUE_PAIR *found;
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
	tailto = to;
	for(i = *to; i; i = i->next) {
		if (i->attribute == PW_PASSWORD ||
		    i->attribute == PW_CRYPT_PASSWORD)
			has_password = 1;
		tailto = &i->next;
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
		    (i->attribute != PW_HINT && i->attribute != PW_FRAMED_ROUTE)) {
		  
			found = pairfind(*to, i->attribute);
			switch (i->operator) {

			  /*
			   *  If a similar attribute is found,
			   *  delete it.
			   */
			case T_OP_SUB:		/* -= */
				if (found) {
					if (!i->strvalue[0] ||
					    (strcmp((char *)found->strvalue,
						    (char *)i->strvalue) == 0)){
						pairdelete(to, found->attribute);
						
						/*
						 *	'tailto' may have been
						 *	deleted...
						 */
						tailto = to;
						for(j = *to; j; j = j->next) {
							tailto = &j->next;
						}
					}
				}
				tailfrom = i;
				continue;
				break;
				
/* really HAVE_REGEX_H */
#if 0 
				/*
				 *  Attr-Name =~ "s/find/replace/"
				 *
				 *  Very bad code.  Barely working,
				 *  if at all.
				 */

			case T_OP_REG_EQ:
			  if (found &&
			      (i->strvalue[0] == 's')) {
			    regex_t		reg;
			    regmatch_t		match[1];

			    char *str;
			    char *p, *q;

			    p = i->strvalue + 1;
			    q = strchr(p + 1, *p);
			    if (!q || (q[strlen(q) - 1] != *p)) {
			      tailfrom = i;
			      continue;
			    }
			    str = strdup(i->strvalue + 2);
			    q = strchr(str, *p);
			    *(q++) = '\0';
			    q[strlen(q) - 1] = '\0';
			    
			    regcomp(&reg, str, 0);
			    if (regexec(&reg, found->strvalue,
					1, match, 0) == 0) {
			      fprintf(stderr, "\"%s\" will have %d to %d replaced with %s\n",
				      found->strvalue, match[0].rm_so,
				      match[0].rm_eo, q);

			    }
			    regfree(&reg);
			    free(str);
			  }
			  tailfrom = i;	/* don't copy it over */
			  continue;
			  break;
#endif
			case T_OP_EQ:		/* = */
				if (found) {
					tailfrom = i;
					continue; /* with the loop */
				}
				break;

			  /*
			   *  If a similar attribute is found,
			   *  replace it with the new one.  Otherwise,
			   *  add the new one to the list.
			   */
			case T_OP_SET:		/* := */
				if (found) {
					pairdelete(to, found->attribute);
					/*
					 *	'tailto' may have been
					 *	deleted...
					 */
					tailto = to;
					for(j = *to; j; j = j->next) {
						tailto = &j->next;
					}
				}
				break;
				

			   /*
			    *  Add the new element to the list, even
			    *  if similar ones already exist.
			    */
			default:
			case T_OP_ADD:		/* += */
				break;
			}
		
		}
		if (tailfrom)
			tailfrom->next = next;
		else
			*from = next;
		
		/*
		 *	If ALL of the 'to' attributes have been deleted,
		 *	then ensure that the 'tail' is updated to point
		 *	to the head.
		 */
		if (!*to) {
			tailto = to;
		}
		*tailto = i;
		if (i) {
			i->next = NULL;
			tailto = &i->next;
		}
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
static char *mystrtok(char **ptr, const char *sep)
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
 *	Returns -1 on error, 0 on OK.
 */
static int gettime(const char *valstr, time_t *lvalue)
{
	int		i;
	time_t		t;
	struct tm	*tm;
	char		buf[64];
	char		*p;
	char		*year, *month, *day;

	time(&t);
	tm = localtime(&t);

	strNcpy(buf, valstr, sizeof(buf));
	for (p = buf; *p; p++)
		if (isupper(*p)) *p = tolower(*p);

	p = buf;
	day = mystrtok(&p, " \t");
	month = mystrtok(&p, " \t");
	year = mystrtok(&p, " \t");
	if (!year || !month || !day) return -1;

	tm->tm_mon = 12;
	for (i = 0; i < 12; i++) {
		if (strncmp(months[i], month, 3) == 0) {
			tm->tm_mon = i;
			break;
		}
	}

	/* month not found? */
	if (tm->tm_mon == 12) return -1;

	tm->tm_mday = atoi(day);
	tm->tm_year = atoi(year);
	if (tm->tm_year >= 1900) tm->tm_year -= 1900;

	*lvalue = mktime(tm);
	return 0;
}

/*
 *	Create a VALUE_PAIR from an ASCII attribute and value.
 */
VALUE_PAIR *pairmake(const char *attribute, const char *value, int operator)
{
	DICT_ATTR	*da;
	DICT_VALUE	*dval;
	VALUE_PAIR	*vp;
	char		*p, *s=0;
	const char	*cp, *cs;

	if ((da = dict_attrbyname(attribute)) == NULL) {
		librad_log("Unknown attribute %s", attribute);
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
	vp->next = NULL;

	/*
	 *	Even for integers, dates and ip addresses we
	 *	keep the original string in vp->strvalue.
	 */
	strNcpy((char *)vp->strvalue, value, MAX_STRING_LEN);

	switch(da->type) {
		case PW_TYPE_STRING:
			vp->length = strlen(value);
			if (vp->length >= MAX_STRING_LEN) {
			  vp->length = MAX_STRING_LEN - 1;
			}
			break;
		case PW_TYPE_IPADDR:
			/*
			 *	FIXME: complain if hostname
			 *	cannot be resolved, or resolve later!
			 */
			if ((p = strrchr(value, '+')) != NULL && !p[1]) {
				cs = s = strdup(value);
				p = strrchr(s, '+');
				*p = 0;
				vp->addport = 1;
			} else {
				p = NULL;
				cs = value;
			}
			vp->lvalue = librad_dodns ? ip_getaddr(cs) :
						    ip_addr(cs);
			vp->length = 4;
			if (s) free(s);
			break;
		case PW_TYPE_INTEGER:
			/*
			 * 	If it starts with a digit, it must
			 * 	be a number (or a range).
			 *
			 *	Note that ALL integers are unsigned!
			 */
			if (isdigit(*value)) {
				vp->lvalue = atoi(value);
				vp->length = 4;
			}
			/*
			 *	Look for the named value for the given
			 *	attribute.
			 */
			else if ((dval = dict_valbyname(da->attr, value)) == NULL) {
               			free(vp);
				librad_log("Unknown value %s for attribute %s",
					   value, vp->name);
				return NULL;
			}
			else {
				vp->lvalue = dval->value;
				vp->length = 4;
			}
			break;

		case PW_TYPE_DATE:
			if (gettime(value, (time_t *)&vp->lvalue) < 0) {
				free(vp);
				librad_log("failed to parse time string "
					   "\"%s\"", value);
				return NULL;
			}
			vp->length = 4;
			break;
		case PW_TYPE_ABINARY:
#ifdef ASCEND_BINARY
			/*
			 *	Special case to convert filter to binary
			 */
		  	if ( filterBinary( vp, value ) < 0 ) {
			  librad_log("failed to parse Ascend binary attribute: %s",
				     librad_errstr);
			  free(vp);
			  return NULL;
			}
			break;
			/*
			 *	If Ascend binary is NOT defined,
			 *	then fall through to raw octets, so that
			 *	the user can at least make them by hand...
			 */
#endif
			/* raw octets: 0x01020304... */
		case PW_TYPE_OCTETS:
		  vp->length = 0;
		  if (strncasecmp(value, "0x", 2) == 0) {
		    u_char *us;
		    cp = value + 2;
		    us = vp->strvalue;
		    while (*cp && vp->length < MAX_STRING_LEN) {
		      unsigned int tmp;

		      if (sscanf(cp, "%02x", &tmp) != 1) break;
		      cp += 2;
		      *(us++) = tmp;
		      vp->length++;
		    }
		    *us = '\0';
		  }
		  break;

		default:
			free(vp);
			librad_log("unknown attribute type %d", da->type);
			return NULL;
	}
	return vp;
}

/*
 *	Read a valuepair from a buffer, and advance pointer.
 *	Sets *eol to T_EOL if end of line was encountered.
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
	token = gettoken(ptr, attr, sizeof(attr));

	/*  If it's a comment, then exit, as we haven't read a pair */
	if (token == T_HASH) {
		*eol = token;
		return NULL;
	}

	/*  It's not a comment, so it MUST be an attribute */
	if ((token == T_EOL) ||
	    (attr[0] == 0)) {
		librad_log("No token read where we expected an attribute name");
		return NULL;
	}

	/* Now we should have an '=' here. */
	token = gettoken(ptr, buf, sizeof(buf));
	if (token < T_EQSTART || token > T_EQEND) {
		librad_log("expecting '='");
		return NULL;
	}

	/* Read value.  Note that empty string values are allowed */
	t = gettoken(ptr, value, sizeof(value));
	if (t == T_EOL) {
		librad_log("failed to get value");
		return NULL;
	}

	/*
	 *	Peek at the next token. Must be T_EOL, T_COMMA, or T_HASH
	 */
	p = *ptr;
	t = gettoken(&p, buf, sizeof(buf));
	if (t != T_EOL && t != T_COMMA && t != T_HASH) {
		librad_log("Expected end of line or comma");
		return NULL;
	}

	*eol = t;
	if (t == T_COMMA) {
		*ptr = p;
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
	int		last_token = 0;
	int		previous_token;

	/*
	 *	We allow an empty line.
	 */
	if (buffer[0] == 0)
		return 0;

	p = buffer;
	do {
		previous_token = last_token;
		if ((vp = pairread(&p, &last_token)) == NULL) {
			return -1;
		}
		pairadd(first_pair, vp);
	} while (*p && (last_token == T_COMMA));

	/*
	 *	Don't tell the caller that there was a comment.
	 */
	if (last_token == T_HASH) {
		return previous_token;
	}

	/*
	 *	And return the last token which we read.
	 */
	return last_token;
}

