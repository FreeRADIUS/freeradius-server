/*
 * xlat.c	Translate strings.
 *
 * Version:	$Id$
 *
 *		This is the first version of xlat incorporated to RADIUS
 */

static const char rcsid[] = 
"$Id$";

#include	"autoconf.h"

#include	<sys/types.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>

#include	"radiusd.h"

/*
   Convert the value on a VALUE_PAIR to string
*/
static int valuepair2str(char * out,int outlen,VALUE_PAIR * pair,int type)
{
   if (pair)
	 return vp_prints_value(out,outlen,pair,0);
   else {
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
  Returns a string with value of Attribute
*/
static int valuebyname(char * out,int outlen,VALUE_PAIR * request, char * attrname)
{
	DICT_ATTR * da;

	da = dict_attrbyname(attrname);
	if (da) {
	  return (valuepair2str(out,outlen,pairfind(request,da->attr),da->type));
	} else {
	  *out = '\0';
	  return 0;
	}
}


/*
 *	Based on radius_xlat from exec.c
 *	After testing will replace the radius_xlat
 *
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
 *	%t	 MTU
 *	%u	 User name
 *	%y	 request year (YY)
 *	%A	 radacct_dir
 *	%C	 clientname
 *	%D	 request date (YYYYMMDD)
 *	%I	 request in ctime format
 *	%L	 radlog_dir
 *	%R	 radius_dir
 *	%T	 request timestamp in database format
 *	%U	 Stripped User name
 *	%V	 Request-Authenticator (Verified/None)
 *	%Y	 request year (YYYY)
 *	%Z	 All request attributes except password (must have big buffer)
 *	${AttributeName}		Corresponding value for AttributeName in request
 *	${request:AttributeName}	Corresponding value for AttributeName in request
 *	${reply:AttributeName}		Corresponding value for AttributeName in reply
 */

int radius_xlat2(char * out,int outlen, const char *fmt, REQUEST * request, VALUE_PAIR *reply)
{
	char attrname[128];
	char *pa;
	int i, c,freespace;
	const char *p;
	char *q;
	VALUE_PAIR *tmp;
	struct tm * TM;
	char tmpdt[40]; /* For temporary storing of dates */

	q = out;
	for (p = fmt; *p ; p++) {
	/* Calculate freespace in output */
	freespace = outlen - ((int)q-(int)out);
		if (freespace <= 1)
		  break;
		c = *p;
		if ((c != '%') && (c != '$') && (c != '\\')) {
			*q++ = *p;
			continue;
		}
		if (*++p == 0) break;
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
				pa = &attrname[0];
				p++;
				while (*p && (*p != '}')) {
				  *pa++ = *p++;
				}
				*pa = '\0';
				if (strncasecmp(attrname,"reply:",6) == 0) {
				  q += valuebyname(q,freespace,reply,&attrname[6]);
				} else if (strncasecmp(attrname,"request:",8) == 0) {
				  q += valuebyname(q,freespace,request->packet->vps,&attrname[8]);
				} else {
				  q += valuebyname(q,freespace,request->packet->vps,attrname);
				}
				break;
			default:
				*q++ = c;
				*q++ = *p;
				break;
		} else if (c == '%') switch(*p) {
			case '%':
				*q++ = *p;
				break;
			case 'a': /* Protocol: */
				q += valuepair2str(q,freespace,pairfind(reply,PW_FRAMED_PROTOCOL),PW_TYPE_INTEGER);
				break;
			case 'c': /* Callback-Number */
				q += valuepair2str(q,freespace,pairfind(reply,PW_CALLBACK_NUMBER),PW_TYPE_STRING);
				break;
			case 'd': /* request year */
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%d",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				break;
			case 'f': /* Framed IP address */
				q += valuepair2str(q,freespace,pairfind(reply,PW_FRAMED_IP_ADDRESS),PW_TYPE_IPADDR);
				break;
			case 'i': /* Calling station ID */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_CALLING_STATION_ID),PW_TYPE_STRING);
				break;
			case 'l': /* request timestamp */
				sprintf(tmpdt,"%ld",request->timestamp);
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
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_NAS_IP_ADDRESS),PW_TYPE_IPADDR);
				break;
			case 'p': /* Port number */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_NAS_PORT_ID),PW_TYPE_INTEGER);
				break;
			case 's': /* Speed */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_CONNECT_INFO),PW_TYPE_STRING);
				break;
			case 't': /* MTU */
				q += valuepair2str(q,freespace,pairfind(reply,PW_FRAMED_MTU),PW_TYPE_INTEGER);
				break;
			case 'u': /* User name */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_USER_NAME),PW_TYPE_STRING);
				break;
			case 'y': /* request year */
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%y",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
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
			case 'I': /* request timestamp */
				strNcpy(q,ctime(&request->timestamp),freespace);
				q += strlen(q);
				break;
			case 'L': /* radlog_dir */
				strNcpy(q,radlog_dir,freespace-1);
				q += strlen(q);
				break;
			case 'R': /* radius_dir */
				strNcpy(q,radius_dir,freespace-1);
				q += strlen(q);
				break;
			case 'T': /* request timestamp */
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%Y-%m-%d-%H.%M.%S.000000",TM);
				strNcpy(q,tmpdt,freespace);
				q += strlen(q);
				break;
			case 'U': /* Stripped User name */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_STRIPPED_USER_NAME),PW_TYPE_STRING);
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

	return strlen(out);
}
