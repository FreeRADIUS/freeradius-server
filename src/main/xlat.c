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
char * valuepair2str(VALUE_PAIR * pair,int type)
{
   static char buffer[256];
   DICT_VALUE * dv;
   switch (type)
	{
	  case PW_TYPE_STRING :
		if (pair)
		  strcpy(buffer,pair->strvalue);
		else
		  strcpy(buffer,"_");
		break;
	  case PW_TYPE_INTEGER :
		if (pair)
		  {
			 dv = dict_valbyattr(pair->attribute,pair->lvalue);
			 if (dv)
			   strcpy(buffer,dv->name);
			 else
			   sprintf(buffer,"%d",pair->lvalue);
		  }
		else
		  strcpy(buffer,"0");
		break;
	  case PW_TYPE_IPADDR :
		if (pair)
		  ip_ntoa(buffer, pair->lvalue);
		else
		  strcpy(buffer,"?.?.?.?");
		break;
	  case PW_TYPE_DATE :
		if (pair)
		  sprintf(buffer,"%d",pair->lvalue);
		else
		  strcpy(buffer,"0");
		break;
	  default :
		strcpy(buffer,"unknown_type");
	}
   return (&buffer[0]);
}

/*
  Returns a string with value of Attribute
*/
char * valuebyname(VALUE_PAIR * request, char * attrname)
{
	DICT_ATTR * da;
	static char buffer;

	da = dict_attrbyname(attrname);
	if (da)
	  {
		 return (valuepair2str(pairfind(request,da->attr),da->type));
	  }
	else
	  {
		buffer = '\0';
		return (&buffer);
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
 *	%{AttributeName}   Corresponding value for AttributeName in request
 *	%{!AttributeName}  Corresponding value for AttributeName in reply
 */

char * radius_xlat2(char *str, REQUEST * request, VALUE_PAIR *reply)
{
    static char buf[4096];
	char attrname[128];
	char *pa;
	int n, i = 0, c;
	char *p;
	VALUE_PAIR *tmp;
	struct tm * TM;

	for (p = str; *p; p++) {
		c = *p;
		if ((c != '%') && (c != '$')) {
			buf[i++] = *p;
			continue;
		}
		if (*++p == 0) break;
		if (c == '$') switch(*p) {
			case '{': /* Attribute by Name */
				pa = &attrname[0];
				p++;
				while (*p && (*p != '}'))
				  {
					*pa++ = *p++;
				  }
				*pa = '\0';
				if (attrname[0] == '!')
				  strcpy(buf+i,valuebyname(reply,attrname));
				else
				  strcpy(buf+i,valuebyname(request->packet->vps,attrname));
				i += strlen(buf + i);
				break;
			default:
				buf[i++] = c;
				buf[i++] = *p;
				break;
		}
		else if (c == '%') switch(*p) {
			case '%':
				buf[i++] = *p;
				break;
			case 'f': /* Framed IP address */
				strcpy(buf+i,valuepair2str(pairfind(reply,PW_FRAMED_IP_ADDRESS),PW_TYPE_IPADDR));
				i += strlen(buf + i);
				break;
			case 'n': /* NAS IP address */
				strcpy(buf+i,valuepair2str(pairfind(request->packet->vps,PW_NAS_IP_ADDRESS),PW_TYPE_IPADDR));
				i += strlen(buf + i);
				break;
			case 't': /* MTU */
				strcpy(buf+i,valuepair2str(pairfind(reply,PW_FRAMED_MTU),PW_TYPE_INTEGER));
				i += strlen(buf + i);
				break;
			case 'p': /* Port number */
				strcpy(buf+i,valuepair2str(pairfind(request->packet->vps,PW_NAS_PORT_ID),PW_TYPE_INTEGER));
				i += strlen(buf + i);
				break;
			case 'u': /* User name */
				strcpy(buf+i,valuepair2str(pairfind(request->packet->vps,PW_USER_NAME),PW_TYPE_STRING));
				i += strlen(buf + i);
				break;
			case 'i': /* Calling station ID */
				strcpy(buf+i,valuepair2str(pairfind(request->packet->vps,PW_CALLING_STATION_ID),PW_TYPE_STRING));
				i += strlen(buf + i);
				break;
			case 'c': /* Callback-Number */
				strcpy(buf+i,valuepair2str(pairfind(reply,PW_CALLBACK_NUMBER),PW_TYPE_STRING));
				i += strlen(buf + i);
				break;
			case 'a': /* Protocol: */
				strcpy(buf+i,valuepair2str(pairfind(reply,PW_FRAMED_PROTOCOL),PW_TYPE_INTEGER));
				i += strlen(buf + i);
				break;
			case 's': /* Speed */
				strcpy(buf+i,valuepair2str(pairfind(request->packet->vps,PW_CONNECT_INFO),PW_TYPE_STRING));
				i += strlen(buf + i);
				break;
			case 'C': /* ClientName */
				strcpy(buf+i,client_name(request->packet->src_ipaddr));
				i += strlen(buf + i);
				break;
			case 'R': /* radius_dir */
				strcpy(buf+i,radius_dir);
				i += strlen(buf + i);
				break;
			case 'A': /* radius_dir */
				strcpy(buf+i,radacct_dir);
				i += strlen(buf + i);
				break;
			case 'L': /* radlog_dir */
				strcpy(buf+i,radlog_dir);
				i += strlen(buf + i);
				break;
			case 'D': /* request date */
				TM = localtime(&request->timestamp);
				TM->tm_year += 1900;
				TM->tm_mon += 1;
				sprintf(buf+i,"%4.4d%2.2d%2.2d",
						TM->tm_year,
						TM->tm_mon,
						TM->tm_mday);
				i += strlen(buf + i);
				break;
			case 'T': /* request timestamp */
				TM = localtime(&request->timestamp);
				TM->tm_year += 1900;
				TM->tm_mon += 1;
				sprintf(buf+i,"%4.4d-%2.2d-%2.2d-%2.2d.%2.2d.%2.2d.000000",
						TM->tm_year,
						TM->tm_mon,
						TM->tm_mday,
						TM->tm_hour,
						TM->tm_min,
						TM->tm_sec);
				i += strlen(buf + i);
				break;
			default:
				buf[i++] = '%';
				buf[i++] = *p;
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
	buf[i++] = 0;

	return buf;
}


