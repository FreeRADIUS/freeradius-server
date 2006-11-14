/* $Id$ */


/*
 * userinfo.h
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
 * Copyright 2006 The FreeRADIUS server project
 *
 */

#ifndef __USERINFO_H__
#define __USERINFO_H__

#include <freeradius-devel/ident.h>
RCSIDH(userinfo_h, "$Id$")


#include "eap_psk_ssm.h" // PSK_AK/KDK_SIZE




#if defined(__cplusplus)
extern "C"
{
#endif

typedef struct s_userinfo {
    //    char*          name;
    unsigned char  AK[PSK_AK_SIZE];
    unsigned char  KDK[PSK_KDK_SIZE];
    //    s_userinfo*  next;
} userinfo_t;




#define   ASCII_PER_BYTE     2
#define   PSK_AK_STRLEN      (PSK_AK_SIZE*ASCII_PER_BYTE)
#define   PSK_KDK_STRLEN     (PSK_KDK_SIZE*ASCII_PER_BYTE)




userinfo_t*  pskGetUserInfo(char*  filename, char*  peerID);

//int        psk_user_free(); //A VOIR

#if defined(__cplusplus)
}
#endif

#endif /*__USERINFO_H__*/
