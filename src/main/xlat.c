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

/*
   Convert the value on a VALUE_PAIR to string
*/
static int valuepair2str(char * out,int outlen,VALUE_PAIR * pair,
			 int type, RADIUS_ESCAPE_STRING func)
{
	char buffer[MAX_STRING_LEN * 4];

	if (pair != NULL) {
		if (func) {
			vp_prints_value(buffer, sizeof(buffer), pair, 0);
			return func(out, outlen, buffer);
		} else {
			return vp_prints_value(out, outlen, pair, 0);
		}
	} else {
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
}

/*
 *  Decode an attribute name into a string.
 */
static void decode_attribute(const char **from, char **to, int freespace, int *open, REQUEST *request, RADIUS_ESCAPE_STRING func)
{

	DICT_ATTR *tmpda;
	VALUE_PAIR *tmppair;
	char attrname[256];
	const char *p;
	char *q, *pa;
	int stop=0, found=0;
	int openbraces = *open;

	p = *from;
	q = *to;
	pa = &attrname[0];

	/* 
	 * Skip the '}' at the front of 'p' 
	 * Increment open braces 
	 */ 
	p++;
	openbraces++;

	while ((*p) && (!stop)) {
		switch(*p) {
			case '}':
				openbraces--;
				stop=1;
				p++;
				break;

			case ':':
				if(*(p+1) && (*(p+1) == '-')) {
					p+=2;
					stop=1;
					break;
				}
				/* else FALL-THROUGH */

			default:
				*pa++ = *p++;
				break;
		}
	}
	*pa = '\0';

	if (strncasecmp(attrname,"reply:",6) == 0) {
		if((tmpda = dict_attrbyname(&attrname[6])) && 
				(tmppair = pairfind(request->reply->vps, tmpda->attr))) {
			q += valuepair2str(q,freespace,tmppair,tmpda->type, func);
			found = 1;
		}
	} else if (strncasecmp(attrname,"request:",8) == 0) {
		if((tmpda = dict_attrbyname(&attrname[8])) && 
				(tmppair = pairfind(request->packet->vps, tmpda->attr))) {
			q += valuepair2str(q,freespace,tmppair,tmpda->type, func);
			found = 1;
		}
	} else {
		if((tmpda = dict_attrbyname(attrname)) && 
				(tmppair = pairfind(request->packet->vps,tmpda->attr))) {
			q += valuepair2str(q,freespace,tmppair,tmpda->type, func);
			found = 1;
		}
	} 

	/*
	 * Skip to last '}' if attr is found
	 * The rest of the stuff within the braces is
	 * useless if we found what we need
	 */
	if(found) {
		while((*p != '\0') && (openbraces > 0)) {
			if(*p == '}') 
				openbraces--;
			if (openbraces > 0)
				p++;
		}
	} else {
		openbraces--;
		if (*p != '\0') {
			p--;
			decode_attribute(&p, &q, freespace, &openbraces, request, func);
		}
	}

	*open = openbraces;
	*from = p;
	*to = q;

}


/*
 *	Replace %<whatever> in a string.
 *
 *	%a	 Protocol (SLIP/PPP)
 *	%c	 Callback-Number
 *	%d	 request day (DD)
 *	%f	 Framed IP address
 *	%i	 Calling Station ID
 *	%l	 request timestamp
 *	%m	 request month (MM)
 *	%n	 NAS IP address
 *	%p	 Port number
 *	%s	 Speed (PW_CONNECT_INFO)
 *	%t	 request in ctime format
 *	%u	 User name
 *	%A	 radacct_dir
 *	%C	 clientname
 *	%D	 request date (YYYYMMDD)
 *	%L	 radlog_dir
 *	%M	 MTU
 *	%R	 radius_dir
 *	%S	 request timestamp in database format (w/ spaces)
 *	%T	 request timestamp in database format
 *	%U	 Stripped User name
 *	%V	 Request-Authenticator (Verified/None)
 *	%Y	 request year (YYYY)
 *	%Z	 All request attributes except password (must have big buffer)
 *	${AttributeName}		Corresponding value for AttributeName in request
 *	${request:AttributeName}	Corresponding value for AttributeName in request
 *	${reply:AttributeName}		Corresponding value for AttributeName in reply
 */

int radius_xlat(char *out, int outlen, const char *fmt,
		REQUEST *request, RADIUS_ESCAPE_STRING func)
{
	int i, c,freespace;
	const char *p;
	char *q;
	VALUE_PAIR *tmp;
	struct tm * TM;
	char tmpdt[40]; /* For temporary storing of dates */
	int openbraces=0;

	q = out;
	for (p = fmt; *p ; p++) {
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
				continue;
			}
			*q++ = *p;
			continue;
		}
		if (*++p == '\0') break;
		if (c == '\\') switch(*p) {
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
		} else if (c == '$') switch(*p) {
			case '{': /* Attribute by Name */
				decode_attribute(&p, &q, freespace, &openbraces, request, func);
			default:
				*q++ = c;
				*q++ = *p;
				break;

		} else if (c == '%') switch(*p) {
			case '{':
				decode_attribute(&p, &q, freespace, &openbraces, request, func);
				break;

			case '%':
				*q++ = *p;
				break;
			case 'a': /* Protocol: */
				q += valuepair2str(q,freespace,pairfind(request->reply->vps,PW_FRAMED_PROTOCOL),PW_TYPE_INTEGER, func);
				break;
			case 'c': /* Callback-Number */
				q += valuepair2str(q,freespace,pairfind(request->reply->vps,PW_CALLBACK_NUMBER),PW_TYPE_STRING, func);
				break;
			case 'd': /* request year */
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%d",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				break;
			case 'f': /* Framed IP address */
				q += valuepair2str(q,freespace,pairfind(request->reply->vps,PW_FRAMED_IP_ADDRESS),PW_TYPE_IPADDR, func);
				break;
			case 'i': /* Calling station ID */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_CALLING_STATION_ID),PW_TYPE_STRING, func);
				break;
			case 'l': /* request timestamp */
				snprintf(tmpdt, sizeof(tmpdt), "%ld",request->timestamp);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				break;
			case 'm': /* request month */
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%m",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				break;
			case 'n': /* NAS IP address */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_NAS_IP_ADDRESS),PW_TYPE_IPADDR, func);
				break;
			case 'p': /* Port number */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_NAS_PORT_ID),PW_TYPE_INTEGER, func);
				break;
			case 's': /* Speed */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_CONNECT_INFO),PW_TYPE_STRING, func);
				break;
			case 't': /* request timestamp */
				strNcpy(q,ctime(&request->timestamp),freespace);
				q += strlen(q);
				break;
			case 'u': /* User name */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_USER_NAME),PW_TYPE_STRING, func);
				break;
			case 'A': /* radacct_dir */
				strNcpy(q,radacct_dir,freespace-1);
				q += strlen(q);
				break;
			case 'C': /* ClientName */
				strNcpy(q,client_name(request->packet->src_ipaddr),freespace-1);
				q += strlen(q);
				break;
			case 'D': /* request date */
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%Y%m%d",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				break;
			case 'L': /* radlog_dir */
				strNcpy(q,radlog_dir,freespace-1);
				q += strlen(q);
				break;
			case 'M': /* MTU */
				q += valuepair2str(q,freespace,pairfind(request->reply->vps,PW_FRAMED_MTU),PW_TYPE_INTEGER, func);
				break;
			case 'R': /* radius_dir */
				strNcpy(q,radius_dir,freespace-1);
				q += strlen(q);
				break;
			case 'S': /* request timestamp in SQL format*/
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%Y-%m-%d %H:%M:%S",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				break;
			case 'T': /* request timestamp */
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%Y-%m-%d-%H.%M.%S.000000",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				break;
			case 'U': /* Stripped User name */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_STRIPPED_USER_NAME),PW_TYPE_STRING, func);
				break;
			case 'V': /* Request-Authenticator */
				if (request->packet->verified)
					strNcpy(q,"Verified",freespace-1);
				else
					strNcpy(q,"None",freespace-1);
				q += strlen(q);
				break;
			case 'Y': /* request year */
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%Y",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
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
				break;
			default:
				*q++ = '%';
				*q++ = *p;
				break;
		}
	}
	*q = '\0';

	DEBUG2("radius_xlat:  '%s'", out);

	return strlen(out);
}
