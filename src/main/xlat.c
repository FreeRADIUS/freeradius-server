/*
 * xlat.c	Translate strings.  This is the first version of xlat 
 * 		incorporated to RADIUS
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

static const char rcsid[] = 
"$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>

#include	"radiusd.h"

struct xlat_cmp {
	char module[MAX_STRING_LEN];
	int length;
	void *instance;
	RAD_XLAT_FUNC do_xlat;
	struct xlat_cmp *next;
};

static struct xlat_cmp *cmp = NULL;

/*
 *      Register an xlat function.
 */
int xlat_register(const char *module, RAD_XLAT_FUNC func, void *instance)
{
	struct xlat_cmp      *c;

	if (module == NULL || strlen(module) == 0){
		DEBUG("xlat_register: Invalid module name");
		return -1;
	}

	xlat_unregister(module, func);

	c = rad_malloc(sizeof(struct xlat_cmp));

	c->do_xlat = func;
	strncpy(c->module, module, MAX_STRING_LEN);
	c->length = strlen(c->module);
	c->instance = instance;
	c->next = cmp;
	cmp = c;

	return 0;
}

/*
 *      Unregister an xlat function.
 */
void xlat_unregister(const char *module, RAD_XLAT_FUNC func)
{
	struct xlat_cmp      *c, *last;

	last = NULL;
	for (c = cmp; c; c = c->next) {
		if (strncmp(c->module,module,c->length) == 0 && c->do_xlat == func)
			break;
		last = c;
	}

	if (c == NULL) return;

	if (last != NULL)
		last->next = c->next;
	else
		cmp = c->next;

	free(c);
}

/*
 * find the appropriate registered xlat function.
 */
static struct xlat_cmp *find_xlat_func(const char *module)
{
	struct xlat_cmp *c;

	for (c = cmp; c; c = c->next){
		if (strncmp(c->module,module,c->length) == 0 && *(module+c->length) == ':')
			break;
	}

	return c;
}


/*
   Convert the value on a VALUE_PAIR to string
*/
static int valuepair2str(char * out,int outlen,VALUE_PAIR * pair,
			 int type, RADIUS_ESCAPE_STRING func)
{
	char buffer[MAX_STRING_LEN * 4];

	if (pair != NULL) {
		vp_prints_value(buffer, sizeof(buffer), pair, 0);
		return func(out, outlen, buffer);
	}

	switch (type) {
	case PW_TYPE_STRING :
		strNcpy(out,"_",outlen);
		break;
	case PW_TYPE_INTEGER :
		strNcpy(out,"0",outlen);
		break;
	case PW_TYPE_IPADDR :
		strNcpy(out,"?.?.?.?",outlen);
		break;
	case PW_TYPE_DATE :
		strNcpy(out,"0",outlen);
		break;
	default :
		strNcpy(out,"unknown_type",outlen);
	}
	return strlen(out);
}

/*
 *	Decode an attribute name from a particular RADIUS_PACKET
 *	into a string.
 */
static int decode_attr_packet(const char *from, char **to, int freespace,
			      RADIUS_PACKET *packet,
			      RADIUS_ESCAPE_STRING func)

{
	DICT_ATTR *tmpda;
	VALUE_PAIR *vp;
	
	tmpda = dict_attrbyname(from);
	if (!tmpda) return 0;

	/*
	 *	See if the VP is defined.
	 */
	vp = pairfind(packet->vps, tmpda->attr);
	if (vp) {
		*to += valuepair2str(*to, freespace, vp,
				     tmpda->type, func);
		return 1;
	}

	/*
	 *	Non-protocol attributes.
	 */
	switch (tmpda->attr) {
		case PW_PACKET_TYPE:
		{
			DICT_VALUE *dval;

			dval = dict_valbyattr(tmpda->attr, packet->code);
			if (dval) {
				snprintf(*to, freespace, "%s", dval->name);
			} else {
				snprintf(*to, freespace, "%d", packet->code);
			}
			*to += strlen(*to);
			return 1;
		}
		break;

		default:
			break;
	}

	return 0;
}

/*
 * Decode an attribute name from a particular VALUE_PAIR*
 * into a string.
 */
static int decode_attr_vps(const char *from, char **to, int freespace,
			      VALUE_PAIR *vps,
			      RADIUS_ESCAPE_STRING func)

{
	DICT_ATTR *tmpda;
	VALUE_PAIR *vp;
	
	tmpda = dict_attrbyname(from);
	if (!tmpda) return 0;

	/*
	 *	See if the VP is defined.
	 */
	vp = pairfind(vps, tmpda->attr);
	if (vp) {
		*to += valuepair2str(*to, freespace, vp,
				     tmpda->type, func);
		return 1;
	}

	return 0;
}

/*
 *  Decode an attribute name into a string.
 */
static void decode_attribute(const char **from, char **to, int freespace,
			     int *open, REQUEST *request,
			     RADIUS_ESCAPE_STRING func)
{
	DICT_ATTR *tmpda;
	VALUE_PAIR *tmppair;
	char attrname[256];
	const char *p;
	char *q, *pa;
	int stop=0, found=0;
	int openbraces = *open;
	struct xlat_cmp *c;

	p = *from;
	q = *to;
	pa = &attrname[0];

	*q = '\0';

	/* 
	 * Skip the '{' at the front of 'p' 
	 * Increment open braces 
	 */ 
	p++;
	openbraces++;

	/*
	 *  Copy over the rest of the string.
	 */
	while ((*p) && (!stop)) {
		switch(*p) {
			/*
			 *  Allow braces inside things, too.
			 */
			case '\\':
				p++; /* skip it */
				*pa++ = *p++;
				break;

			case '{':
				openbraces++;
				*pa++ = *p++;
				break;
				
			case '}':
				openbraces--;
				if (openbraces == *open) {
					p++;
					stop=1;
				} else {
					*pa++ = *p++;
				}
				break;

				/*
				 *  Attr-Name1:-Attr-Name2
				 *
				 *  Use Attr-Name1, and if not found,
				 *  use Attr-Name2.
				 */
			case ':':
				if (p[1] == '-') {
					p += 2;
					stop = 1;
					break;
				}
				/* else FALL-THROUGH */

			default:
				*pa++ = *p++;
				break;
		}
	}
	*pa = '\0';

	/*
	 *	Find an attribute from the reply.
	 */
	if (strncasecmp(attrname,"reply:",6) == 0) {
		found = decode_attr_packet(&attrname[6], &q, freespace,
					   request->reply, func);

		/*
		 *	Find an attribute from the request.
		 */
	} else if (strncasecmp(attrname,"request:",8) == 0) {
		found = decode_attr_packet(&attrname[8], &q, freespace,
					   request->packet, func);

		/*
		 *	Find an attribute from the config items.
		 */
	} else if (strncasecmp(attrname,"check:",6) == 0) {
		found = decode_attr_vps(&attrname[6], &q, freespace,
					   request->config_items, func);

		/*
		 *	Find an attribute from the proxy request.
		 */
	} else if ((strncasecmp(attrname,"proxy-request:",14) == 0) &&
		   (request->proxy_reply != NULL)) {
		found = decode_attr_packet(&attrname[14], &q, freespace,
					   request->proxy, func);

		/*
		 *	Find an attribute from the proxy reply.
		 */
	} else if ((strncasecmp(attrname,"proxy-reply:",12) == 0) &&
		   (request->proxy_reply != NULL)) {
		found = decode_attr_packet(&attrname[12], &q, freespace,
					   request->proxy_reply, func);

		/*
		 *	Find a string from a registered function.
		 */
	} else if ((c = find_xlat_func(attrname)) != NULL) {
		DEBUG("radius_xlat: Running registered xlat function of module %s for string \'%s\'",
		      c->module, attrname+ c->length + 1);
		q += c->do_xlat(c->instance, request, attrname+(c->length+1), q, freespace, func);
		found = 1;

		/*
		 *	Nothing else, it MUST be a bare attribute name.
		 */
	} else if (decode_attr_packet(&attrname[6], &q, freespace, request->reply, func)) {
		found = 1;
	} else {
		/*
		 *	No attribute by that name, return an error.
		 */
		DEBUG2("WARNING: Attempt to use unknown xlat function or attribute in string %%{%s}", attrname);
	}

	/*
	 * Skip to last '}' if attr is found
	 * The rest of the stuff within the braces is
	 * useless if we found what we need
	 */
	if (found) {
		while((*p != '\0') && (openbraces > 0)) {
			switch (*p) {
			default:
				break;

				/*
				 *  Ensure that escaped braces are allowed.
				 */
			case '\\':
				p++; /* skip the escaped character */
				break;

				/*
				 *  Bare brace
				 */
			case '{':
				openbraces++;
				break;

			case '}':
				openbraces--;
				break;
			}
			p++;	/* skip the character */
		}
	}

	*open = openbraces;
	*from = p;
	*to = q;
}

/*
 *  If the caller doesn't pass xlat an escape function, then
 *  we use this one.  It simplifies the coding, as the check for
 *  func == NULL only happens once.
 */
static int xlat_copy(char *out, int outlen, const char *in)
{
	int len = 0;

	while (*in) {
		/*
		 *  Truncate, if too much.
		 */
		if (len >= outlen) {
			break;
		}

		/*
		 *  Copy data.
		 *
		 *  FIXME: Do escaping of bad stuff!
		 */
		*out = *in;

		out++;
		in++;
		len++;
	}

	*out = '\0';
	return len;
}

/*
 *	Replace %<whatever> in a string.
 *
 *	See 'doc/variables.txt' for more information.
 */
int radius_xlat(char *out, int outlen, const char *fmt,
		REQUEST *request, RADIUS_ESCAPE_STRING func)
{
	int i, c,freespace;
	const char *p;
	char *q;
	VALUE_PAIR *tmp;
	struct tm *TM, s_TM;
	char tmpdt[40]; /* For temporary storing of dates */
	int openbraces=0;

	/*
	 *  Ensure that we always have an escaping function.
	 */
	if (func == NULL) {
		func = xlat_copy;
	}

	q = out;
	p = fmt;
	while (*p) {
		/* Calculate freespace in output */
		freespace = outlen - (q - out);
		if (freespace <= 1)
			break;
		c = *p;

		if ((c != '%') && (c != '$') && (c != '\\')) {
			/*
			 * We check if we're inside an open brace.  If we are
			 * then we assume this brace is NOT literal, but is
			 * a closing brace and apply it 
			 */
			if((c == '}') && openbraces) {
				openbraces--;
				p++; /* skip it */
				continue;
			}
			*q++ = *p++;
			continue;
		}

		if (*++p == '\0') break;

		if (c == '\\') {
			switch(*p) {
			case '\\':
				*q++ = *p;
				break;
			case 't':
				*q++ = '\t';
				break;
			case 'n':
				*q++ = '\n';
				break;
			default:
				*q++ = c;
				*q++ = *p;
				break;
			}
			p++;
		} else if (c == '$') switch(*p) {
			case '{': /* Attribute by Name */
				decode_attribute(&p, &q, freespace, &openbraces, request, func);
				break;
			default:
				*q++ = c;
				*q++ = *p++;
				break;

		} else if (c == '%') switch(*p) {
			case '{':
				decode_attribute(&p, &q, freespace, &openbraces, request, func);
				break;

			case '%':
				*q++ = *p++;
				break;
			case 'a': /* Protocol: */
				q += valuepair2str(q,freespace,pairfind(request->reply->vps,PW_FRAMED_PROTOCOL),PW_TYPE_INTEGER, func);
				p++;
				break;
			case 'c': /* Callback-Number */
				q += valuepair2str(q,freespace,pairfind(request->reply->vps,PW_CALLBACK_NUMBER),PW_TYPE_STRING, func);
				p++;
				break;
			case 'd': /* request day */
				TM = localtime_r(&request->timestamp, &s_TM);
				strftime(tmpdt,sizeof(tmpdt),"%d",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				p++;
				break;
			case 'f': /* Framed IP address */
				q += valuepair2str(q,freespace,pairfind(request->reply->vps,PW_FRAMED_IP_ADDRESS),PW_TYPE_IPADDR, func);
				p++;
				break;
			case 'i': /* Calling station ID */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_CALLING_STATION_ID),PW_TYPE_STRING, func);
				p++;
				break;
			case 'l': /* request timestamp */
				snprintf(tmpdt, sizeof(tmpdt), "%lu",request->timestamp);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				p++;
				break;
			case 'm': /* request month */
				TM = localtime_r(&request->timestamp, &s_TM);
				strftime(tmpdt,sizeof(tmpdt),"%m",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				p++;
				break;
			case 'n': /* NAS IP address */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_NAS_IP_ADDRESS),PW_TYPE_IPADDR, func);
				p++;
				break;
			case 'p': /* Port number */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_NAS_PORT),PW_TYPE_INTEGER, func);
				p++;
				break;
			case 's': /* Speed */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_CONNECT_INFO),PW_TYPE_STRING, func);
				p++;
				break;
			case 't': /* request timestamp */
				ctime_r(&request->timestamp, q);
				q += strlen(q);
				p++;
				break;
			case 'u': /* User name */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_USER_NAME),PW_TYPE_STRING, func);
				p++;
				break;
			case 'A': /* radacct_dir */
				strNcpy(q,radacct_dir,freespace-1);
				q += strlen(q);
				p++;
				break;
			case 'C': /* ClientName */
				strNcpy(q,client_name(request->packet->src_ipaddr),freespace-1);
				q += strlen(q);
				p++;
				break;
			case 'D': /* request date */
				TM = localtime_r(&request->timestamp, &s_TM);
				strftime(tmpdt,sizeof(tmpdt),"%Y%m%d",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				p++;
				break;
			case 'H': /* request hour */
				TM = localtime_r(&request->timestamp, &s_TM);
				strftime(tmpdt,sizeof(tmpdt),"%H",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				p++;
				break;
			case 'L': /* radlog_dir */
				strNcpy(q,radlog_dir,freespace-1);
				q += strlen(q);
				p++;
				break;
			case 'M': /* MTU */
				q += valuepair2str(q,freespace,pairfind(request->reply->vps,PW_FRAMED_MTU),PW_TYPE_INTEGER, func);
				p++;
				break;
			case 'R': /* radius_dir */
				strNcpy(q,radius_dir,freespace-1);
				q += strlen(q);
				p++;
				break;
			case 'S': /* request timestamp in SQL format*/
				TM = localtime_r(&request->timestamp, &s_TM);
				strftime(tmpdt,sizeof(tmpdt),"%Y-%m-%d %H:%M:%S",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				p++;
				break;
			case 'T': /* request timestamp */
				TM = localtime_r(&request->timestamp, &s_TM);
				strftime(tmpdt,sizeof(tmpdt),"%Y-%m-%d-%H.%M.%S.000000",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				p++;
				break;
			case 'U': /* Stripped User name */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_STRIPPED_USER_NAME),PW_TYPE_STRING, func);
				p++;
				break;
			case 'V': /* Request-Authenticator */
				if (request->packet->verified)
					strNcpy(q,"Verified",freespace-1);
				else
					strNcpy(q,"None",freespace-1);
				q += strlen(q);
				p++;
				break;
			case 'Y': /* request year */
				TM = localtime_r(&request->timestamp, &s_TM);
				strftime(tmpdt,sizeof(tmpdt),"%Y",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				p++;
				break;
			case 'Z': /* Full request pairs except password */
				tmp = request->packet->vps;
				while (tmp && (freespace > 3)) {
					if (tmp->attribute != PW_PASSWORD) {
						*q++ = '\t';
						i = vp_prints(q,freespace-2,tmp);
						q += i;
						freespace -= (i+2);
						*q++ = '\n';
					}
					tmp = tmp->next;
				}
				p++;
				break;
			default:
				DEBUG2("WARNING: Unknown variable '%%%c': See 'doc/variables.txt'", *p);
				if (freespace > 2) {
					*q++ = '%';
					*q++ = *p++;
				}
				break;
		}
	}
	*q = '\0';

	DEBUG2("radius_xlat:  '%s'", out);

	return strlen(out);
}
