/*
 * rlm_ippool_tool.c
 *
 * Version:  $Id$
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
 * Copyright 2003  FreeRADIUS Project, http://www.freeradius.org/
 * Copyright 2003  Edwin Groothuis, edwin@mavetju.org
 * Permission from Edwin Groothuis for release under GPL is archived here:
 * http://lists.cistron.nl/archives/freeradius-devel/2003/09/frm00247.html
 *
 */

/*
 The original license follows. This license applies to the tarball at
 http://www.mavetju.org/unix/general.php

 Copyright 2003 by Edwin Groothuis, edwin@mavetju.org
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <gdbm.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int active=0;

int aflag=0;
int cflag=0;
int rflag=0;
int vflag=0;
int nflag=0;

typedef struct ippool_info {
    uint32_t        ipaddr;
    char            active;
    char            cli[32];
	char			extra;
} ippool_info;


#define MAX_NAS_NAME_SIZE 64
typedef struct ippool_key {
    char nas[MAX_NAS_NAME_SIZE];
    unsigned int port;
} ippool_key;

#define MATCH_IP(ip1,ip2) ((ip1)==NULL || strcmp((ip1),(ip2))==0)
#define MATCH_ACTIVE(info) ((info).active==1 || !aflag)

void addip(char *sessiondbname,char *indexdbname,char *ipaddress, char* NASname, char*NASport);
void viewdb(char *sessiondbname,char *indexdbname,char *ipaddress);
void usage(char *argv0);

void addip(char *sessiondbname,char *indexdbname,char *ipaddress, char* NASname, char*NASport) {
    GDBM_FILE sessiondb;
    GDBM_FILE indexdb;
    datum key_datum,data_datum,save_datum;
	datum nextkey;
    ippool_key key;
    ippool_info entry;
    struct in_addr ipaddr;
    int num=0;
	int mppp=0;
    int mode=GDBM_WRITER;
    signed int rcode;
	char *cli = NULL;
	int delete = 0;
	int port;
	int extra = 0;
	int found = 0;

    sessiondb=gdbm_open(sessiondbname,512,mode,0,NULL);
    indexdb=gdbm_open(indexdbname,512,mode,0,NULL);

	if (inet_aton(ipaddress, &ipaddr) == 0)
	{
		printf("rlm_ippool_tool: Unable to convert IP address '%s'\n", ipaddress);
		return;
	}

    if (sessiondb==NULL)
	{
		printf("rlm_ippool_tool: Unable to open DB '%s'\n", sessiondbname);
		return;
	}

    if (indexdb==NULL)
	{
		printf("rlm_ippool_tool: Unable to open DB '%s'\n", indexdbname);
		return;
	}

	port = strtoul(NASport,NULL,0);

	/* Basically from rlm_ippool.c */

	memset(key.nas,0,MAX_NAS_NAME_SIZE);
	strncpy(key.nas,NASname,MAX_NAS_NAME_SIZE -1 );
	key.port = port;
	key_datum.dptr = (char *) &key;
	key_datum.dsize = sizeof(ippool_key);

	data_datum = gdbm_fetch(sessiondb, key_datum);
	if (data_datum.dptr != NULL){
		found = 1;
		memcpy(&entry,data_datum.dptr, sizeof(ippool_info));
		free(data_datum.dptr);
		if (entry.active){
			printf("rlm_ippool_tool: Deleting stale entry for ip/port %s/%u",
					ipaddress, port);
			entry.active = 0;
			save_datum.dptr = key_datum.dptr;
			save_datum.dsize = key_datum.dsize;

			data_datum.dptr = (char*) &entry;
			data_datum.dsize = sizeof(ippool_info);

			rcode = gdbm_store(sessiondb, key_datum, data_datum, GDBM_REPLACE);
			if (rcode < 0) {
				printf("rlm_ippool_tool: Failed storing data to %s: %s\n",
					sessiondbname, gdbm_strerror(gdbm_errno));
				gdbm_close(indexdb);
				gdbm_close(sessiondb);
				return;
			}

			key_datum.dptr = (char *) &entry.ipaddr;
			key_datum.dsize = sizeof(uint32_t);
			data_datum = gdbm_fetch(indexdb, key_datum);
			if (data_datum.dptr != NULL) {
				memcpy(&num, data_datum.dptr, sizeof(int));
				free(data_datum.dptr);
				if (num > 0) {
					num--;
					data_datum.dptr = (char *) &num;
					data_datum.dsize = sizeof(int);
					rcode = gdbm_store(indexdb, key_datum, data_datum, GDBM_REPLACE);
					if (rcode < 0) {
						printf("rlm_ippool_tool: Failed storing data to %s: %s\n",
							indexdbname, gdbm_strerror(gdbm_errno));
						gdbm_close(indexdb);
						gdbm_close(sessiondb);
						return;
					}
					if (num > 0 && entry.extra == 1) {
						gdbm_delete(sessiondb, save_datum);
					}
				}
			}
		}
	}
	key_datum.dptr = NULL;

	if (cli != NULL){
		key_datum = gdbm_firstkey(sessiondb);
		while(key_datum.dptr){
			data_datum = gdbm_fetch(sessiondb, key_datum);
			if (data_datum.dptr){
				memcpy(&entry,data_datum.dptr, sizeof(ippool_info));
				free(data_datum.dptr);
				/*
		 		* If we find an entry for the same caller-id and nas with active=1
		 		* then we use that for multilink (MPPP) to work properly.
		 		*/
				if (strcmp(entry.cli,cli) == 0 && entry.active){
					memcpy(&key,key_datum.dptr,sizeof(ippool_key));
					if (!strcmp(key.nas,NASname)){
						mppp = 1;
						break;
					}
				}
			}
			nextkey = gdbm_nextkey(sessiondb, key_datum);
			free(key_datum.dptr);
			key_datum = nextkey;
		}
	}

	if (key_datum.dptr == NULL) {
		key_datum = gdbm_firstkey(sessiondb);
		while (key_datum.dptr) {
			data_datum = gdbm_fetch(sessiondb, key_datum);
			if (data_datum.dptr != NULL) {
				memcpy(&entry, data_datum.dptr, sizeof(ippool_info));
				free(data_datum.dptr);

				if (entry.active == 0 && entry.ipaddr == ipaddr.s_addr) {
					datum tmp;
					tmp.dptr = (char *) &entry.ipaddr;
					tmp.dsize = sizeof(uint32_t);
					data_datum = gdbm_fetch(indexdb, tmp);
					if (data_datum.dptr){
						memcpy(&num, data_datum.dptr, sizeof(int));
						free(data_datum.dptr);
						if (num == 0){
							delete = 1;
							break;
						}
					} else {
						delete = 1;
						break;
					}
				}
			}
			nextkey = gdbm_nextkey(sessiondb, key_datum);
			free(key_datum.dptr);
			key_datum = nextkey;
		}
	}

	if (key_datum.dptr){
		if (found && ! mppp){
			datum key_datum_tmp,data_datum_tmp;
			ippool_key key_tmp;
			memset(key_tmp.nas,0,MAX_NAS_NAME_SIZE);
			strncpy(key_tmp.nas,NASname,MAX_NAS_NAME_SIZE - 1);
			key_tmp.port=port;
			key_datum_tmp.dptr = (char *) &key_tmp;
			key_datum_tmp.dsize = sizeof(ippool_key);

			data_datum_tmp = gdbm_fetch(sessiondb, key_datum_tmp);
			if (data_datum_tmp.dptr != NULL) {
				rcode = gdbm_store(sessiondb, key_datum, data_datum_tmp, GDBM_REPLACE);
				if (rcode < 0) {
					printf("rlm_ippool_tool: Failed storing data to %s: %s\n",
						sessiondbname, gdbm_strerror(gdbm_errno));
						gdbm_close(indexdb);
						gdbm_close(sessiondb);
					return;
				}
				free(data_datum_tmp.dptr);
			}
		} else {
			if (delete)
				gdbm_delete(sessiondb, key_datum);
			else {
				if (mppp)
					extra = 1;
//				if (!mppp)
//					printf("Error in if statements!!!\n");
			}
		}
		free(key_datum.dptr);
		entry.active=1;
		if (extra)
			entry.extra=1;
		data_datum.dptr = (char *) &entry;
		data_datum.dsize = sizeof(ippool_info);
		memset(key.nas,0,MAX_NAS_NAME_SIZE);
		strncpy(key.nas,NASname,MAX_NAS_NAME_SIZE -1 );
		key.port = port;
		key_datum.dptr = (char *) &key;
		key_datum.dsize = sizeof(ippool_key);
		printf("rlm_ippool_tool: Allocating ip to nas/port: %s/%u\n",key.nas,key.port);
		rcode = gdbm_store(sessiondb, key_datum, data_datum, GDBM_REPLACE);
		if (rcode < 0) {
			printf("rlm_ippool_tool: Failed storing data to %s: %s\n",
				sessiondbname, gdbm_strerror(gdbm_errno));
			gdbm_close(indexdb);
			gdbm_close(sessiondb);
			return;
		}

		/* Increase the ip index count */
		key_datum.dptr = (char *) &entry.ipaddr;
		key_datum.dsize = sizeof(uint32_t);
		data_datum = gdbm_fetch(indexdb, key_datum);
		if (data_datum.dptr){
			memcpy(&num,data_datum.dptr,sizeof(int));
			free(data_datum.dptr);
		} else
			num = 0;
		num++;
		printf("rlm_ippool_tool: num: %d\n",num);
		data_datum.dptr = (char *) &num;
		data_datum.dsize = sizeof(int);
		rcode = gdbm_store(indexdb, key_datum, data_datum, GDBM_REPLACE);
		if (rcode < 0) {
			printf("rlm_ippool_tool: Failed storing data to %s: %s\n",
				indexdbname, gdbm_strerror(gdbm_errno));
			gdbm_close(indexdb);
			gdbm_close(sessiondb);
			return;
		}

		printf("rlm_ippool_tool: Allocated ip %s to client on nas %s,port %u\n",
				ipaddress, key.nas,port);

	}
    gdbm_close(indexdb);
    gdbm_close(sessiondb);
}

void viewdb(char *sessiondbname,char *indexdbname,char *ipaddress) {
    GDBM_FILE sessiondb;
    GDBM_FILE indexdb;
    datum key_datum,keynext_datum,data_datum,save_datum;
    ippool_key key;
    ippool_info info;
    struct in_addr ipaddr;
    int num;
    char *ip;
    int mode=GDBM_READER;
    int rcode;

    if (rflag) mode=GDBM_WRITER;
    sessiondb=gdbm_open(sessiondbname,512,mode,0,NULL);
    indexdb=gdbm_open(indexdbname,512,mode,0,NULL);

    if (sessiondb==NULL || indexdb==NULL) return;

    key_datum=gdbm_firstkey(sessiondb);
    while (key_datum.dptr) {
	keynext_datum=gdbm_nextkey(sessiondb,key_datum);
	if (key_datum.dsize==sizeof(struct ippool_key)) {
	    memcpy(&key,key_datum.dptr,sizeof(struct ippool_key));

	    data_datum=gdbm_fetch(sessiondb,key_datum);
	    if (data_datum.dptr!=NULL) {

		memcpy(&info,data_datum.dptr,sizeof(struct ippool_info));
		memcpy(&ipaddr,&info.ipaddr,4);
		ip=inet_ntoa(ipaddr);

		if (info.active) active++;
		if (vflag && MATCH_IP(ipaddress,ip) && MATCH_ACTIVE(info))
		    printf("NAS:%s port:0x%x - ",key.nas,key.port);
		if (!vflag && aflag && info.active && MATCH_IP(ipaddress,ip))
		    printf("%s\n",ip);
		else if (vflag && MATCH_IP(ipaddress,ip) && MATCH_ACTIVE(info))
		    printf("ipaddr:%s active:%d cli:%s",
			inet_ntoa(ipaddr),info.active,info.cli);

		//
		// algorythm copied from rlm_ippool.c:
		// - set active to zero
		// - set number of sessions to zero
		//
		if (rflag && MATCH_IP(ipaddress,ip)) {
		    info.active=0;
			save_datum.dptr = key_datum.dptr;
			save_datum.dsize = key_datum.dsize;
		    data_datum.dptr = (char *) &info;
		    data_datum.dsize = sizeof(ippool_info);
		    rcode=gdbm_store(sessiondb,key_datum,data_datum,GDBM_REPLACE);
		    if (rcode < 0) {
				printf("Failed to update %s: %s\n",ip,gdbm_strerror(gdbm_errno));
				gdbm_close(indexdb);
				gdbm_close(sessiondb);
				return;
			}
		    key_datum.dptr=(char *)&info.ipaddr;
		    key_datum.dsize = sizeof(uint32_t);
		    data_datum=gdbm_fetch(indexdb,key_datum);
		    if (data_datum.dptr!=NULL) {
				memcpy(&num, data_datum.dptr, sizeof(int));
				if (num>0) {
					num--;
					data_datum.dptr = (char *) &num;
					data_datum.dsize = sizeof(int);
					rcode = gdbm_store(indexdb, key_datum, data_datum, GDBM_REPLACE);
					if (rcode < 0) {
						printf("Failed to update %s: %s\n",ip,gdbm_strerror(gdbm_errno));
						gdbm_close(indexdb);
						gdbm_close(sessiondb);
						return;
					}
					if (num > 0 && info.extra == 1) {
						gdbm_delete(sessiondb, save_datum);
					}
				}
		    }
		}

		key_datum.dptr=(char *)&info.ipaddr;
		key_datum.dsize = sizeof(uint32_t);
		data_datum=gdbm_fetch(indexdb,key_datum);
		if (data_datum.dptr!=NULL) {
		    memcpy(&num, data_datum.dptr, sizeof(int));
		    if (vflag && MATCH_IP(ipaddress,ip) && MATCH_ACTIVE(info))
			printf(" num:%d",num);
		}
		if (vflag && MATCH_IP(ipaddress,ip) && MATCH_ACTIVE(info))
		    printf("\n");
	    } else
		if (vflag && ipaddress==NULL)
		    printf("NAS:%s port:0x%x\n",key.nas,key.port);
	}
	key_datum=keynext_datum;
    }
    gdbm_close(indexdb);
    gdbm_close(sessiondb);
}

void usage(char *argv0) {
    printf("Usage: %s [-a] [-c] [-v] <session-db> <index-db> [ipaddress]\n",argv0);
    printf("-a: print all active entries\n");
    printf("-c: report number of active entries\n");
    printf("-r: remove active entries\n");
    printf("-v: verbose report of all entries\n");
    printf("If an ipaddress is specified then that address is used to\n");
    printf("limit the actions or output.\n");
    printf("Usage: %s -n  <session-db> <index-db> <ipaddress> <nasIP> <nasPort>\n",argv0);
    printf("-n: Mark the entry nasIP/nasPort as having ipaddress\n");
    exit(0);
}

int main(int argc,char **argv) {
    int ch;
    char *argv0=argv[0];

    while ((ch=getopt(argc,argv,"acrvn"))!=-1)
	switch (ch) {
	case 'a': aflag++;break;
	case 'c': cflag++;break;
	case 'r': rflag++;break;
	case 'v': vflag=1;break;
	case 'n': nflag=1;break;
	default: usage(argv0);
	}
    argc -= optind;
    argv += optind;

    if ((argc==2 || argc==3) && !nflag) {
		viewdb(argv[0],argv[1],argv[2]);
		if (cflag) printf("%d\n",active);
	} else
		if (argc==5 && nflag)
			addip(argv[0],argv[1],argv[2],argv[3],argv[4]);
		else
			usage(argv0);
    return 0;
}
