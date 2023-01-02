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
 * @file src/pyfr.h
 * @brief Python bindings for major FreeRADIUS libraries
 *
 * @copyright Network RADIUS SAS(legal@networkradius.com)
 * @author 2023 Jorge Pereira (jpereira@freeradius.org)
 */
RCSIDH(pyfr_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dict_priv.h>
#include <freeradius-devel/util/version.h>

#define PYFR_TYPE_FLAGS Py_TPFLAGS_HAVE_GC
#define PYFR_SINGLE_FILE
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <pythread.h>
#include <structmember.h>

#if !(PY_MAJOR_VERSION >= 3 && PY_MINOR_VERSION >= 10) /* At least 3.10.x */ 
    #error "We expect Python >= 3.10.x"
#endif

#if defined(PYFR_SINGLE_FILE)
# define PYFR_INTERNAL static
#else
# define PYFR_INTERNAL
#endif

typedef struct {
    PyObject_HEAD
    PyObject *error;
    bool util_loaded;
    bool radius_loaded;

    TALLOC_CTX *autofree;

    char *raddb_dir; //!< Path to raddb directory
    char *dict_dir;  //!< The location for loading dictionaries
    char *lib_dir;   //!< The location for loading libraries
} pyfr_mod_state_t;

pyfr_mod_state_t *pyfr_get_mod_state(void);

DIAG_OFF(unused-macros)
#define DEBUG(fmt, ...)     if (fr_log_fp && (fr_debug_lvl > 1)) fr_fprintf(fr_log_fp , "** DEBUG: pyfr: %s:%d %s(): "fmt "\n", __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#define DEBUG2(fmt, ...)    if (fr_log_fp && (fr_debug_lvl > 2)) fr_fprintf(fr_log_fp , "** DEBUG2: pyfr: %s:%d %s(): "fmt "\n", __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#define DEBUG3(fmt, ...)    if (fr_log_fp && (fr_debug_lvl > 3)) fr_fprintf(fr_log_fp , "** DEBUG3: pyfr: %s:%d %s(): "fmt "\n", __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#define INFO(fmt, ...)      if (fr_log_fp && (fr_debug_lvl > 0)) fr_fprintf(fr_log_fp , "** INFO: pyfr: %s:%d %s(): "fmt "\n", __FILE__, __LINE__, __func__, ## __VA_ARGS__)
DIAG_ON(unused-macros)

#ifndef NDEBUG
#   define pyfr_ErrorObject_as_strerror(pyErrorObj) PyErr_Format(pyErrorObj, "%s:%d %s(): %s", __FILE__, __LINE__, __func__, fr_strerror())
#else
#   define pyfr_ErrorObject_as_strerror(pyErrorObj) PyErr_SetString(pyErrorObj, fr_strerror())
#endif

#ifdef __cplusplus
}
#endif
