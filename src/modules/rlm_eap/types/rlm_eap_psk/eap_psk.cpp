/* $Id$ */

/*
 * eap_psk.cpp
 *
 * Implementation of the EAP-PSK packet management
 *
 * 
 * Copyright (C) France Télécom R&D (DR&D/MAPS/NSS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */


#include <stdio.h>
#include <stdlib.h>

#include "eap_psk.h"


/*
 *
 *  PSK Packet Format in EAP 
 *  --- ------ ------ -- ---
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |   Identifier  |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |   Data
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */


int pskConvertHex(char *inbytes, char *outstr, int numbytes)
{
	int i;
	char buildstr[1024], tempstr[10];

	memset(buildstr, 0, 1024);

	for (i=0;i<numbytes;i++)
	{
		sprintf((char *)tempstr, "%02X",(unsigned char)inbytes[i]);
		strcat((char *)buildstr, (char *)tempstr);
	}
	strcpy(outstr, (char *)buildstr);

	return 1;
}


int pskHex2Bin(const char *hex, unsigned char *bin, int numbytes) {
    int len = strlen(hex);
    char c;
    int i;
    unsigned char v;
    for (i = 0; i < numbytes; i++) {
        c = hex[2*i];
        if (c >= '0' && c <= '9') {
            v = c - '0';
        } else if (c >= 'A' && c <= 'F') {
	  v = c - 'A' + 10;
        } else if (c >= 'a' && c <= 'f') {
	  v = c - 'a' + 10;
        } else {
	  //v = 0;
	  return 0; // non hexa character
        }
        v <<= 4;
        c = hex[2*i + 1];
        if (c >= '0' && c <= '9') {
	  v += c - '0';
        } else if (c >= 'A' && c <= 'F') {
	  v += c - 'A' + 10;
        } else if (c >= 'a' && c <= 'f') {
	  v += c - 'a' + 10;
        } else {
	  //v = 0;
	  return 0; // non hexa character
        }
        bin[i] = v;
    }
    return 1;
}


int pskGetRandomBytes(void *buf, int nbytes){
  FILE *fptr=NULL;
  int written=0;
  
  if((fptr = fopen("/dev/urandom","r")) == NULL) {
    radlog(L_ERR,"pskGetRandomBytes: urandom device not accessible");
    return 0;
  }
  
  if((written = fread(buf,1,nbytes,fptr)) != nbytes) {
    radlog(L_ERR,"pskGetRandomBytes: number not generated");
    return 0;
  }	 
  
  fclose(fptr);
  
  return 1;
}
