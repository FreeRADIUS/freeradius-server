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
	if ((da = dict_attrbyvalue(attr)) != NULL) {
		strcpy(vp->name, da->name);
	} else if (VENDOR(attr) == 0) {
		sprintf(vp->name, "Attr-%u", attr);
	} else {
		sprintf(vp->name, "Vendor-%u-Attr-%u",
			VENDOR(attr), attr & 0xffff);
	}
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
				/*
				 *  FIXME: Tunnel attributes with
				 *  different tags are different
				 *  attributes.
				 */
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
			case T_OP_ADD: /* += */
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


		/*
		 *	If the attribute to move is NOT a VSA, then it
		 *	ignores any attributes which do not match exactly.
		 */
		if ((attr != PW_VENDOR_SPECIFIC) &&
		    (i->attribute != attr)) {
			iprev = i;
			continue;
		}

		/*
		 *	If the attribute to move IS a VSA, then it ignores
		 *	any non-VSA attribute.
		 */
		if ((attr == PW_VENDOR_SPECIFIC) &&
		    (VENDOR(i->attribute) == 0)) {
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
	struct tm	*tm, s_tm;
	char		buf[64];
	char		*p;
	char		*f[3];

	time(&t);
	tm = localtime_r(&t, &s_tm);

	strNcpy(buf, valstr, sizeof(buf));

	p = buf;
	f[0] = mystrtok(&p, " \t");
	f[1] = mystrtok(&p, " \t");
	f[2] = mystrtok(&p, " \t");
	if (!f[0] || !f[1] || !f[2]) return -1;

	/*
	 *  The month is text, which allows us to find it easily.
	 */
	tm->tm_mon = 12;
	for (i = 0; i < 3; i++) {
		if (isalpha( (int) *f[i])) {	
			/*
			 *  Bubble the month to the front of the list
			 */
			p = f[0];
			f[0] = f[i];
			f[i] = p;

			for (i = 0; i < 12; i++) {
				if (strncasecmp(months[i], f[0], 3) == 0) {
					tm->tm_mon = i;
					break;
				}
			}
		}
	}

	/* month not found? */
	if (tm->tm_mon == 12) return -1;

	/*
	 *  The year may be in f[1], or in f[2]
	 */
	tm->tm_year = atoi(f[1]);
	tm->tm_mday = atoi(f[2]);

	if (tm->tm_year >= 1900) {
		tm->tm_year -= 1900;

	} else {
		/*
		 *  We can't use 2-digit years any more, they make it
		 *  impossible to tell what's the day, and what's the year.
		 */
		if (tm->tm_mday < 1900) return -1;

		/*
		 *  Swap the year and the day.
		 */
		i = tm->tm_year;
		tm->tm_year = tm->tm_mday - 1900;
		tm->tm_mday = i;
	}

	/*
	 *  If the day is out of range, die.
	 */
	if ((tm->tm_mday < 1) || (tm->tm_mday > 31)) {
		return -1;
	}

	/*
	 *  Returns -1 on error.
	 */
	t = mktime(tm);
	if (t == (time_t) -1) return -1;

	*lvalue = t;

	return 0;
}

/*
 *  Parse a string value into a given VALUE_PAIR
 */
VALUE_PAIR *pairparsevalue(VALUE_PAIR *vp, const char *value)
{
	char		*p, *s=0;
	const char	*cp, *cs;
	DICT_VALUE	*dval;

	/*
	 *	Even for integers, dates and ip addresses we
	 *	keep the original string in vp->strvalue.
	 */
	strNcpy((char *)vp->strvalue, value, sizeof(vp->strvalue));
	vp->length = strlen(vp->strvalue);

	switch(vp->type) {
		case PW_TYPE_STRING:
			/*
			 *	Already handled above.
			 */
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
				vp->flags.addport = 1;
			} else {
				p = NULL;
				cs = value;
			}
			vp->lvalue = librad_dodns ? ip_getaddr(cs) :
						    ip_addr(cs);
			if (s) free(s);
			vp->length = 4;
			break;
		case PW_TYPE_INTEGER:
			/*
			 * 	If it starts with a digit, it must
			 * 	be a number (or a range).
			 *
			 *	Note that ALL integers are unsigned!
			 */
			if (isdigit((int) *value)) {
				vp->lvalue = (uint32_t) strtoul(value, NULL, 10);
				vp->length = 4;
			}
			/*
			 *	Look for the named value for the given
			 *	attribute.
			 */
			else if ((dval = dict_valbyname(vp->attribute, value)) == NULL) {
				librad_log("Unknown value %s for attribute %s",
					   value, vp->name);
				return NULL;
			} else {
				vp->lvalue = dval->value;
				vp->length = 4;
			}
			break;

		case PW_TYPE_DATE:
			if (gettime(value, (time_t *)&vp->lvalue) < 0) {
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
			if (strncasecmp(value, "0x", 2) == 0) {
				u_char *us;
				cp = value + 2;
				us = vp->strvalue;
				vp->length = 0;

				while (*cp && vp->length < MAX_STRING_LEN) {
					unsigned int tmp;
					
					if (sscanf(cp, "%02x", &tmp) != 1) {
						librad_log("Non-hex characters at %c%c", cp[0], cp[1]);
						return NULL;
					}

					cp += 2;
					*(us++) = tmp;
					vp->length++;
				}
				*us = '\0';
			}
			break;

			/*
			 *  Anything else.
			 */
		default:
			librad_log("unknown attribute type %d", vp->type);
			return NULL;
	}

	return vp;
}

/*
 *	Create a VALUE_PAIR from an ASCII attribute and value.
 */
VALUE_PAIR *pairmake(const char *attribute, const char *value, int operator)
{
	DICT_ATTR	*da;
	VALUE_PAIR	*vp;
	char            *tc, *ts;
	signed char     tag;
	int             found_tag;
#ifdef HAVE_REGEX_H
	int		res;
	regex_t		cre;
#endif

	/*
	 *    Check for tags in 'Attribute:Tag' format.
	 */
	found_tag = 0;
	tag = 0;

	ts = strrchr( attribute, ':' );
	if (ts && ts[1]) {
	         /* Colon found with something behind it */
	         if (ts[1] == '*' && ts[2] == 0) {
		         /* Wildcard tag for check items */
		         tag = TAG_ANY;
			 *ts = 0;
		 } else if ((ts[1] >= '0') && (ts[1] <= '9')) {
		         /* It's not a wild card tag */
		         tag = strtol(ts + 1, &tc, 0);
			 if (tc && !*tc && TAG_VALID_ZERO(tag))
				 *ts = 0;
			 else tag = 0;
		 } else {
			 librad_log("Invalid tag for attribute %s", attribute);
			 return NULL;
		 }
		 found_tag = 1;
	}

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
	vp->flags = da->flags;
	vp->next = NULL;

	/*      Check for a tag in the 'Merit' format of:
	 *      :Tag:Value.  Print an error if we already found
	 *      a tag in the Attribute.
	 */

	if (value && (*value == ':' && da->flags.has_tag)) {
	        /* If we already found a tag, this is invalid */
	        if(found_tag) {
		        free(vp);
			librad_log("Duplicate tag %s for attribute %s",
				   value, vp->name);
			DEBUG("Duplicate tag %s for attribute %s\n",
				   value, vp->name);
			return NULL;

		}
	        /* Colon found and attribute allows a tag */
	        if (value[1] == '*' && value[2] == ':') {
		       /* Wildcard tag for check items */
		       tag = TAG_ANY;
		       value += 3;
		} else {
	               /* Real tag */
		       tag = strtol(value + 1, &tc, 0);
		       if (tc && *tc==':' && TAG_VALID_ZERO(tag))
			    value = tc + 1;
		       else tag = 0;
		}
		found_tag = 1;
	}	
	
	if (found_tag) {
	  vp->flags.tag = tag;
	}

	switch (vp->operator) {
	default:
		break;

		/*
		 *      For =* and !* operators, the value is irrelevant
		 *      so we return now.
		 */
	case T_OP_CMP_TRUE:
	case T_OP_CMP_FALSE:
		vp->strvalue[0] = '\0';
		vp->length = 0;
	        return vp;
		break;

		/*
		 *	Regular expression comparison of integer attributes
		 *	does a STRING comparison of the names of their
		 *	integer attributes.
		 */
	case T_OP_REG_EQ:	/* =~ */
	case T_OP_REG_NE:	/* !~ */
		if (vp->type == PW_TYPE_INTEGER) {
			return vp;
		}
#ifdef HAVE_REGEX_H
		/*
		 *	Regular expression match with no regular
		 *	expression is wrong.
		 */
		if (!value) {
			pairfree(&vp);
			return NULL;
		}

		res = regcomp(&cre, value, REG_EXTENDED|REG_NOSUB);
		if (res != 0) {
			char	msg[128];

			regerror(res, &cre, msg, sizeof(msg));               
			librad_log("Illegal regular expression in attribute: %s: %s",
				vp->name, msg);
			free(vp);
			return NULL;
		}
		regfree(&cre);
#else
		librad_log("Regelar expressions not enabled in this build, error in attribute %s",
				vp->name);
		free(vp);
		return NULL;
#endif
	}

	if (value && (pairparsevalue(vp, value) == NULL)) {
		free(vp);
		return NULL;
	}

	return vp;
}

/*
 *	Read a valuepair from a buffer, and advance pointer.
 *	Sets *eol to T_EOL if end of line was encountered.
 */
VALUE_PAIR *pairread(char **ptr, LRAD_TOKEN *eol)
{
	char		buf[64];
	char		attr[64];
	char		value[256];
	char		*p;
	LRAD_TOKEN	token, t, xlat;
	VALUE_PAIR	*vp;

	*eol = 0;

	/* Get attribute. */
	token = gettoken(ptr, attr, sizeof(attr));

	/*  If it's a comment, then exit, as we haven't read a pair */
	if (token == T_HASH) {
		*eol = token;
		librad_log("Read a comment instead of a token");
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
	xlat = gettoken(ptr, value, sizeof(value));
	if (xlat == T_EOL) {
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

	switch (xlat) {
		/*
		 *	Make the full pair now.
		 */
	default:
		vp = pairmake(attr, value, token);
		break;

		/*
		 *	Mark the pair to be allocated later.
		 */
	case T_BACK_QUOTED_STRING:
		vp = pairmake(attr, NULL, token);
		if (!vp) return vp;
		
		vp->flags.do_xlat = 1;
		strNcpy(vp->strvalue, value, sizeof(vp->strvalue));
		vp->length = 0;
		break;
	}
	
	return vp;
}

/*
 *	Read one line of attribute/value pairs. This might contain
 *	multiple pairs seperated by comma's.
 */
LRAD_TOKEN userparse(char *buffer, VALUE_PAIR **first_pair)
{
	VALUE_PAIR	*vp;
	char		*p;
	LRAD_TOKEN	last_token = T_INVALID;
	LRAD_TOKEN	previous_token;

	/*
	 *	We allow an empty line.
	 */
	if (buffer[0] == 0)
		return T_EOL;

	p = buffer;
	do {
		previous_token = last_token;
		if ((vp = pairread(&p, &last_token)) == NULL) {
			return T_INVALID;
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

