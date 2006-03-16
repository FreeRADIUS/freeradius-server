/* $Id$ */


/*
 * userinfo.c
 *
 * Implementation of the user management
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "userinfo.h"
#include "eap_psk_ssm.h"
#include "eap_psk.h"  //hex2Bin()



userinfo_t*   pskGetUserInfo(char* path, char* peerID)
{
    FILE*       fp;
    char        buff[1024]; //FIXME: give the buffer a proper size 
                            //when we know more about ID length
    userinfo_t* uinfo = NULL;
    int         found = 0;
    char*       AK = NULL;
    char*       KDK = NULL;
	int res;

    fp = fopen(path, "r");
    if (fp == NULL)
	{
	    radlog(L_ERR, "pskGetUserInfo: failed to open PSK users file");
	    return NULL;
	}
    
    while (!found && fgets(buff, sizeof(buff), fp)) 
	{
	  unsigned int     i = 0;

	    // ignore comments
	    if (buff[0] == '#')
		continue;

	    // read this login name
	    while (! isspace(buff[i]))
		i++;
	    
	    // is it the one we looking for?
	    if ((i != strlen(peerID)) 
		|| (strncmp(peerID, buff, i) != 0))
		continue;
	    else
		found = 1;
	    
	    // skip spaces 
	    while (isspace(buff[i]))
		i++;
	    
	    // prepare to store user info
	    uinfo = (userinfo_t*) malloc(sizeof(userinfo_t));
	    if (uinfo == NULL)
		{
		    radlog(L_ERR, "pskGetUserInfo: out of memory");
		    return NULL;
		}

	    //get AK  
	    AK = strndup(buff + i, PSK_AK_STRLEN);
            if (AK == NULL) {
                radlog(L_ERR, "pskGetUserInfo: out of memory");
				free(uinfo);
				return NULL;
	    }
	    //FIXME: shouldnt we check the key size?
	    /*
	      else if (strlen(AK) != 32) {
	      log();
	      return NULL;
	      }
	    */
	    res=pskHex2Bin(AK, &(uinfo->AK),PSK_AK_SIZE);

		if(!res)
		{
			radlog(L_ERR, "pskGetUserInfo: the key isn't in hexadecimal format");
			free(uinfo);
			free(AK);
			return NULL;
		}
	   	   
	    //get KDK
	    KDK = strndup(buff + i + PSK_AK_STRLEN, PSK_KDK_STRLEN);
	    if (KDK == NULL) {
			radlog(L_ERR, "psk_get_user_info: out of memory");
			free(uinfo);
			free(AK);
			return NULL;
	    }
	    //FIXME: shouldnt we check the key size?
	    /*
	      else if (strlen(KDK) != 32) { 
	      log();
	      return NULL;
	      }             
	    */
	    res=pskHex2Bin(KDK, &(uinfo->KDK),PSK_KDK_SIZE);

		if(!res)
		{
			radlog(L_ERR, "pskGetUserInfo: the key isn't in hexadecimal format");
			free(uinfo);
			free(AK);
			free(KDK);
			return NULL;
		}
	   
	    free(AK);
	    free(KDK);
	}
   
    
    // if user was not found, NULL is returned
    fclose(fp);
    return uinfo;
}

