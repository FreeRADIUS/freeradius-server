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
int valuepair2str(char * out,int outlen,VALUE_PAIR * pair,int type)
{
   if (pair)
	 return vp_prints_value(out,outlen,pair,0);
   else {
	 switch (type) {
	   case PW_TYPE_STRING :
		  strncpy(out,"_",outlen-1);
		  break;
	   case PW_TYPE_INTEGER :
		  strncpy(out,"0",outlen-1);
		  break;
	   case PW_TYPE_IPADDR :
		  strncpy(out,"?.?.?.?",outlen-1);
		  break;
	   case PW_TYPE_DATE :
		  strncpy(out,"0",outlen-1);
		  break;
	   default :
		  strncpy(out,"unknown_type",outlen-1);
	 }
	 out[outlen-1] = '\0';
	 return strlen(out);
   }
}

/*
  Returns a string with value of Attribute
*/
int valuebyname(char * out,int outlen,VALUE_PAIR * request, char * attrname)
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
 *	%p	 Port number
 *	%n	 NAS IP address
 *	%f	 Framed IP address
 *	%u	 User name
 *	%c	 Callback-Number
 *	%t	 MTU
 *	%a	 Protocol (SLIP/PPP)
 *	%s	 Speed (PW_CONNECT_INFO)
 *	%i	 Calling Station ID
 *  %V   Request-Authenticator (Verified/None)
 *  %C   clientname
 *	%R	 radius_dir
 *	%A	 radacct_dir
 *	%L	 radlog_dir
 *	%T	 request timestamp in database format
 *	%D	 request date (YYYYMMDD)
 *  %I   request in ctime format
 *  %Z   All request attributes except password (must have big buffer)
 *	${AttributeName}		   Corresponding value for AttributeName in request
 *	${request:AttributeName}   Corresponding value for AttributeName in request
 *	${reply:AttributeName}	   Corresponding value for AttributeName in reply
 */

int radius_xlat2(char * out,int outlen, char *str, REQUEST * request, VALUE_PAIR *reply)
{
	char attrname[128];
	char *pa;
	int n, i, c,freespace;
	char *p;
	char *q;
	VALUE_PAIR *tmp;
	struct tm * TM;
    char tmpdt[40]; /* For temporary storing of dates */

	q = out;
	for (p = str; *p ; p++) {
        /* Calculate freespace in output */
        freespace = outlen - ((int)q-(int)out);
		if (freespace <= 1)
		  break;
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
				  q += valuebyname(q,freespace,reply,&attrname[6]);
				} else if (strnicmp(attrname,"request:",8) == 0) {
				  q += valuebyname(q,freespace,request->packet->vps,&attrname[8]);
				} else {
				  q += valuebyname(q,freespace,request->packet->vps,attrname);
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
				q += valuepair2str(q,freespace,pairfind(reply,PW_FRAMED_IP_ADDRESS),PW_TYPE_IPADDR);
				break;
			case 'n': /* NAS IP address */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_NAS_IP_ADDRESS),PW_TYPE_IPADDR);
				break;
			case 't': /* MTU */
				q += valuepair2str(q,freespace,pairfind(reply,PW_FRAMED_MTU),PW_TYPE_INTEGER);
				break;
			case 'p': /* Port number */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_NAS_PORT_ID),PW_TYPE_INTEGER);
				break;
			case 'u': /* User name */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_USER_NAME),PW_TYPE_STRING);
				break;
			case 'i': /* Calling station ID */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_CALLING_STATION_ID),PW_TYPE_STRING);
				break;
			case 'c': /* Callback-Number */
				q += valuepair2str(q,freespace,pairfind(reply,PW_CALLBACK_NUMBER),PW_TYPE_STRING);
				break;
			case 'a': /* Protocol: */
				q += valuepair2str(q,freespace,pairfind(reply,PW_FRAMED_PROTOCOL),PW_TYPE_INTEGER);
				break;
			case 's': /* Speed */
				q += valuepair2str(q,freespace,pairfind(request->packet->vps,PW_CONNECT_INFO),PW_TYPE_STRING);
				break;
			case 'C': /* ClientName */
                strncpy(q,client_name(request->packet->src_ipaddr),freespace-1);
                i = strlen(q); q[i] = '\0'; q += i;
                break;
			case 'R': /* radius_dir */
                strncpy(q,radius_dir,freespace-1);
                i = strlen(q); q[i] = '\0'; q += i;
                break;
			case 'A': /* radacct_dir */
                strncpy(q,radacct_dir,freespace-1);
                i = strlen(q); q[i] = '\0'; q += i;
                break;
			case 'L': /* radlog_dir */
                strncpy(q,radlog_dir,freespace-1);
                i = strlen(q); q[i] = '\0'; q += i;
                break;
            case 'V': /* Request-Authenticator */
                if (request->packet->verified)
                    strncpy(q,"Verified",freespace-1);
                else
                    strncpy(q,"None",freespace-1);
                i = strlen(q); q[i] = '\0'; q += i;
                break;
            case 'D': /* request date */
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%Y%m%d",TM);
				strncpy(q,tmpdt,freespace);
                i = strlen(q); q[i] = '\0'; q += i;
				break;
			case 'T': /* request timestamp */
				TM = localtime(&request->timestamp);
				strftime(tmpdt,sizeof(tmpdt),"%Y-%m-%d-%H.%M.%S.000000",TM);
				strncpy(q,tmpdt,freespace);
                i = strlen(q); q[i] = '\0'; q += i;
                break;
            case 'I': /* request timestamp */
                strncpy(q,ctime(&request->timestamp),freespace);
                i = strlen(q); q[i] = '\0'; q += i;
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
/*
	This routine make translations of strings, but can have larger results
	If this check is need we can make a wrapper to do this truncation
*/
/*
	if (i >= MAX_STRING_LEN)
		i = MAX_STRING_LEN - 1;
*/
	*q = 0;

	return strlen(out);
}

/*
 * print a string passing by the radius_xlat2
 *
 */
void printf_xlat(char *str, REQUEST * request, VALUE_PAIR *reply)
{
  char * p;
  p = malloc(4096);
  radius_xlat2(p,4096,str,request,reply);
  printf("%s",p);
  free(p);
}

