/*
 * xlat.c	Translate strings.
 *
 * Version: @(#)xlat.c	1.0  20-Sep-1999  ivanfm@ecodigit.com.br
 *
 *
 * This is the first version of xlat incorporated to RADIUS
 */

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/time.h>
#include	<sys/file.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<fcntl.h>
#include	<time.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<signal.h>
#include	<errno.h>
#include	<sys/wait.h>

#include	"libradius.h"
#include	"radiusd.h"

/*
   Convert the value on a VALUE_PAIR to string
*/
int valuepair2str(char * buffer,VALUE_PAIR * pair,int type)
{
   DICT_VALUE * dv;
   switch (type) {
	  case PW_TYPE_STRING :
		if (pair) {
		  strcpy(buffer,pair->strvalue);
		} else {
		  strcpy(buffer,"_");
		}
		break;
	  case PW_TYPE_INTEGER :
		if (pair) {
			 dv = dict_valbyattr(pair->attribute,pair->lvalue);
			 if (dv) {
			   strcpy(buffer,dv->name);
			 } else {
			   sprintf(buffer,"%d",pair->lvalue);
			}
		} else {
		  strcpy(buffer,"0");
		}
		break;
	  case PW_TYPE_IPADDR :
		if (pair) {
		  ip_ntoa(buffer, pair->lvalue);
		} else {
		  strcpy(buffer,"?.?.?.?");
		}
		break;
	  case PW_TYPE_DATE :
		if (pair) {
		  sprintf(buffer,"%d",pair->lvalue);
		} else {
		  strcpy(buffer,"0");
		}
		break;
	  default :
		strcpy(buffer,"unknown_type");
	}
   return strlen(buffer);
}

/*
  Returns a string with value of Attribute
*/
int valuebyname(char * buffer,VALUE_PAIR * request, char * attrname)
{
	DICT_ATTR * da;

	da = dict_attrbyname(attrname);
	if (da) {
	  return (valuepair2str(buffer,pairfind(request,da->attr),da->type));
	} else {
	  *buffer = '\0';
	  return 0;
	}
}


/*
 *	Based on radius_xlat from exec.c
 *	After testing will replace the radius_xlat
 *
 *	Replace %<whatever> in a string.
 *
 *	%p	 Port number
 *	%n	 NAS IP address
 *	%f	 Framed IP address
 *	%u	 User name
 *	%c	 Callback-Number
 *	%t	 MTU
 *	%a	 Protocol (SLIP/PPP)
 *	%s	 Speed (PW_CONNECT_INFO)
 *	%i	 Calling Station ID
 *	%C	 clientname
 *	%R	 radius_dir
 *	%A	 radacct_dir
 *	%L	 radlog_dir
 *	%T	 request timestamp in database format
 *	%D	 request date (YYYYMMDD)
 *	${AttributeName}		   Corresponding value for AttributeName in request
 *	${request:AttributeName}   Corresponding value for AttributeName in request
 *	${reply:AttributeName}	   Corresponding value for AttributeName in reply
 */

char * radius_xlat2(char *str, REQUEST * request, VALUE_PAIR *reply)
{
	static char buf[4096];
	char attrname[128];
	char *pa;
	int n, i, c;
	char *p;
	char *q;
	VALUE_PAIR *tmp;
	struct tm * TM;

	q = buf;
	for (p = str; *p; p++) {
		c = *p;
		if ((c != '%') && (c != '$')) {
			*q++ = *p;
			continue;
		}
		if (*++p == 0) break;
		if (c == '$') switch(*p) {
			case '{': /* Attribute by Name */
				pa = &attrname[0];
				p++;
				while (*p && (*p != '}')) {
				  *pa++ = *p++;
				}
				*pa = '\0';
				if (strnicmp(attrname,"reply:",6) == 0) {
				  q += valuebyname(q,reply,&attrname[6]);
				} else if (strnicmp(attrname,"request:",8) == 0) {
				  q += valuebyname(q,request->packet->vps,&attrname[8]);
				} else {
				  q += valuebyname(q,request->packet->vps,attrname);
				}
				break;
			default:
				*q++ = c;
				*q++ = *p;
				break;
		}
		else if (c == '%') switch(*p) {
			case '%':
				*q++ = *p;
				break;
			case 'f': /* Framed IP address */
				q += valuepair2str(q,pairfind(reply,PW_FRAMED_IP_ADDRESS),PW_TYPE_IPADDR);
				break;
			case 'n': /* NAS IP address */
				q += valuepair2str(q,pairfind(request->packet->vps,PW_NAS_IP_ADDRESS),PW_TYPE_IPADDR);
				break;
			case 't': /* MTU */
				q += valuepair2str(q,pairfind(reply,PW_FRAMED_MTU),PW_TYPE_INTEGER);
				break;
			case 'p': /* Port number */
				q += valuepair2str(q,pairfind(request->packet->vps,PW_NAS_PORT_ID),PW_TYPE_INTEGER);
				break;
			case 'u': /* User name */
				q += valuepair2str(q,pairfind(request->packet->vps,PW_USER_NAME),PW_TYPE_STRING);
				break;
			case 'i': /* Calling station ID */
				q += valuepair2str(q,pairfind(request->packet->vps,PW_CALLING_STATION_ID),PW_TYPE_STRING);
				break;
			case 'c': /* Callback-Number */
				q += valuepair2str(q,pairfind(reply,PW_CALLBACK_NUMBER),PW_TYPE_STRING);
				break;
			case 'a': /* Protocol: */
				q += valuepair2str(q,pairfind(reply,PW_FRAMED_PROTOCOL),PW_TYPE_INTEGER);
				break;
			case 's': /* Speed */
				q += valuepair2str(q,pairfind(request->packet->vps,PW_CONNECT_INFO),PW_TYPE_STRING);
				break;
			case 'C': /* ClientName */
				strcpy(q,client_name(request->packet->src_ipaddr));
				i = strlen(q); q += i;
				break;
			case 'R': /* radius_dir */
				strcpy(q,radius_dir);
				i = strlen(q); q += i;
				break;
			case 'A': /* radius_dir */
				strcpy(q,radacct_dir);
				i = strlen(q); q += i;
				break;
			case 'L': /* radlog_dir */
				strcpy(q,radlog_dir);
				i = strlen(q); q += i;
				break;
			case 'D': /* request date */
				TM = localtime(&request->timestamp);
				q += strftime(q,100,"%Y%m%d",TM);
				break;
			case 'T': /* request timestamp */
				TM = localtime(&request->timestamp);
				q += strftime(q,100,"%Y-%m-%d-%H.%M.%S.000000",TM);
				break;
			default:
				*q++ = '%';
				*q++ = *p;
				break;
		}
	}
/*
	This routine make translations of strings, but can have larger results
	If this check is need we can make a wrapper to do this truncation
*/
/*
	if (i >= MAX_STRING_LEN)
		i = MAX_STRING_LEN - 1;
*/
	*q = 0;

	return buf;
}


