/*
 * valid.c
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <syslog.h>
#include "smblib-priv.h"
#include "valid.h"

SMB_Handle_Type SMB_Connect_Server(void *, char *, char *);

int Valid_User(char *USERNAME,char *PASSWORD,char *SERVER,char *BACKUP, char *DOMAIN)
{
  char *SMB_Prots[] = {"PC NETWORK PROGRAM 1.0",
			    "MICROSOFT NETWORKS 1.03",
			    "MICROSOFT NETWORKS 3.0",
			    "LANMAN1.0",
			    "LM1.2X002",
			    "Samba",
			    "NT LM 0.12",
			    "NT LANMAN 1.0",
			    NULL};
  SMB_Handle_Type con;

  SMB_Init();
  con = SMB_Connect_Server(NULL, SERVER, DOMAIN);
  if (con == NULL) { /* Error ... */
   con = SMB_Connect_Server(NULL, BACKUP, DOMAIN);
   if (con == NULL) {
   	return(NTV_SERVER_ERROR);
   }
  }
  if (SMB_Negotiate(con, SMB_Prots) < 0) { /* An error */
    SMB_Discon(con,0);
    return(NTV_PROTOCOL_ERROR);
  }
  /* Test for a server in share level mode do not authenticate against it */
  if (con -> Security == 0)
    {
      SMB_Discon(con,0);
      return(NTV_PROTOCOL_ERROR);
    }

  if (SMB_Logon_Server(con, USERNAME, PASSWORD) < 0) {
    SMB_Discon(con,0);
    return(NTV_LOGON_ERROR);
  }

  SMB_Discon(con,0);
  return(NTV_NO_ERROR);
}
