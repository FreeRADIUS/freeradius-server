/*
 * rlm_pap.h    Local Header file.
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
 * Copyright 2012  Matthew Newton <matthew@newtoncomputing.co.uk>
 * Copyright 2012  The FreeRADIUS server project
 */

#ifndef _RLM_PAP_H
#define _RLM_PAP_H

/*
 * PAP auth functions
 */

static int pap_auth_clear(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_crypt(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_md5(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_smd5(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_sha(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_ssha(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_nt(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_lm(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_ns_mta_md5(REQUEST *, VALUE_PAIR *, char *);

#endif /*_RLM_PAP_H*/
