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
 * Copyright 2003  Edwin Groothuis, edwin@mavetju.org
 * Permission from Edwin Groothuis for release under GPL is archived here:
 * http://lists.cistron.nl/archives/freeradius-devel/2003/09/frm00247.html
 *
 */

// The original license follows. This license applies to the tarball at
// http://www.mavetju.org/unix/general.php

// Copyright 2003 by Edwin Groothuis, edwin@mavetju.org
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <gdbm.h>
#include <unistd.h>

int active=0;

int aflag=0;
int cflag=0;
int rflag=0;
int vflag=0;

typedef struct ippool_info {
    uint32_t        ipaddr;
    char            active;
    char            cli[32];
} ippool_info;


#define MAX_NAS_NAME_SIZE 64
typedef struct ippool_key {
    char nas[MAX_NAS_NAME_SIZE];
    int port;
} ippool_key;

#define MATCH_IP(ip1,ip2) ((ip1)==NULL || strcmp((ip1),(ip2))==0)
#define MATCH_ACTIVE(info) ((info).active==1 || !aflag)

void viewdb(char *sessiondbname,char *indexdbname,char *ipaddress) {
    GDBM_FILE sessiondb;
    GDBM_FILE indexdb;
    datum key_datum,keynext_datum,data_datum;
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
		    data_datum.dptr = (char *) &info;
		    data_datum.dsize = sizeof(ippool_info);
		    rcode=gdbm_store(sessiondb,key_datum,data_datum,GDBM_REPLACE);
		    if (rcode < 0)
			printf("Failed to update %s: %s\n",ip,gdbm_strerror(gdbm_errno));
		    key_datum.dptr=(char *)&info.ipaddr;
		    key_datum.dsize = sizeof(uint32_t);
		    data_datum=gdbm_fetch(indexdb,key_datum);
		    if (data_datum.dptr!=NULL) {
			memcpy(&num, data_datum.dptr, sizeof(int));
			if (num>0) {
			    num=0;
			    data_datum.dptr = (char *) &num;
			    data_datum.dsize = sizeof(int);
			    rcode = gdbm_store(indexdb, key_datum, data_datum, GDBM_REPLACE);
			    if (rcode < 0)
				printf("Failed to update %s: %s\n",ip,gdbm_strerror(gdbm_errno));
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
    printf("If an ipaddress is specified then only that address is used to\n");
    printf("limit the actions or output to that address only.\n");
    exit(0);
}

int main(int argc,char **argv) {
    int ch;
    char *argv0=argv[0];

    while ((ch=getopt(argc,argv,"acrv"))!=-1)
	switch (ch) {
	case 'a': aflag++;break;
	case 'c': cflag++;break;
	case 'r': rflag++;break;
	case 'v': vflag=1;break;
	default: usage(argv0);
	}
    argc -= optind;
    argv += optind;

    if (argc!=2 && argc!=3)
	usage(argv0);
    else
	viewdb(argv[0],argv[1],argv[2]);
    if (cflag) printf("%d\n",active);
    return 0;
}
