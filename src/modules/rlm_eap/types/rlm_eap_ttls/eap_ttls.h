/*
 * eap_ttls.h 
 *
 * Version:     $Id$
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
 * Copyright 2003 Alan DeKok <aland@freeradius.org>
 */
#ifndef _EAP_TTLS_H
#define _EAP_TTLS_H

#include "rlm_eap_tls.h"

typedef struct ttls_tunnel_t {
	VALUE_PAIR	*username;
	VALUE_PAIR	*state;
	int		authenticated;
	int		default_eap_type;
	int		copy_request_to_tunnel;
	int		use_tunneled_reply;
} ttls_tunnel_t;

/*
 *	Process the TTLS portion of an EAP-TTLS request.
 */
int eapttls_process(EAP_HANDLER *handler, tls_session_t *tls_session);

#endif /* _EAP_TTLS_H */
