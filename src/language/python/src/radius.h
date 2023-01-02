/*
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
 */

/**
 * $Id$
 *
 * @file src/radius.h
 * @brief Python bindings for major FreeRADIUS libraries
 *
 * @copyright Network RADIUS SAS(legal@networkradius.com)
 * @author 2023 Jorge Pereira (jpereira@freeradius.org)
 */

RCSIDH(pyfr_radius_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <pythread.h>

extern PyObject *pyfr_ErrorRadius;

typedef struct {
    PyObject_HEAD
    char *auth_host;  //!< auth host
    char *auth_port;  //!< auth host port
} pyfr_radius_ctx_t;

PyTypeObject *pyfr_radius_register(void);

#ifdef __cplusplus
}
#endif
