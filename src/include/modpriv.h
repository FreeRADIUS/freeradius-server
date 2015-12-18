/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef _FR_MODPRIV_H
#define _FR_MODPRIV_H
/**
 * $Id$
 *
 * @file modpriv.h
 * @brief Stuff needed by both modules.c and modcall.c, but should not be
 *	accessed from anywhere else.
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(modpriv_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#ifndef HAVE_DLFCN_H
#error FreeRADIUS needs either libltdl, or a working dlopen()
#else
#include <dlfcn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void *lt_dlhandle;

lt_dlhandle lt_dlopenext(char const *name);
void *lt_dlsym(lt_dlhandle handle, char const *symbol);
int lt_dlclose(lt_dlhandle handle);
char const *lt_dlerror(void);

/*
 *	Keep track of which modules we've loaded.
 */
typedef struct module_dlhandle_t {
	char const		*name;
	module_t const		*module;
	lt_dlhandle		dlhandle;
} module_dlhandle_t;

typedef struct fr_module_hup_t fr_module_hup_t;

/*
 *	Per-instance data structure, to correlate the modules
 *	with the instance names (may NOT be the module names!),
 *	and the per-instance data structures.
 */
typedef struct module_instance_t {
	char const		*name;
	module_dlhandle_t		*entry;
	void			*insthandle;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		*mutex;
#endif
	CONF_SECTION		*cs;
	time_t			last_hup;
	bool			instantiated;
	bool			force;
	rlm_rcode_t		code;
	fr_module_hup_t	       	*mh;
} module_instance_t;

module_instance_t	*module_instantiate(CONF_SECTION *modules, char const *askedname);
module_instance_t	*module_instantiate_method(CONF_SECTION *modules, char const *askedname, rlm_components_t *method);
module_instance_t	*module_find(CONF_SECTION *modules, char const *askedname);
int			module_sibling_section_find(CONF_SECTION **out, CONF_SECTION *module, char const *name);
int			module_hup_module(CONF_SECTION *cs, module_instance_t *node, time_t when);

#ifdef __cplusplus
}
#endif

#endif	/* _FR_MODPRIV_H */
