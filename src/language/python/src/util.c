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
 * @file src/util.c
 * @brief Python bindings for major FreeRADIUS libraries
 *
 * @copyright Network RADIUS SAS(legal@networkradius.com)
 * @author 2023 Jorge Pereira (jpereira@freeradius.org)
 */

RCSID("$Id$")

#include "src/pyfr.h"
#include "src/util.h"

#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/protocol/radius/freeradius.internal.h>

PyObject *pyfr_ErrorUtil = NULL;

fr_dict_t const *dict_freeradius;
fr_dict_t const *dict_radius;

extern fr_dict_autoload_t pyfr_dict[];
fr_dict_autoload_t pyfr_dict[] = {
    { .out = &dict_freeradius, .proto = "freeradius" },
    { .out = &dict_radius, .proto = "radius" },
    { NULL }
};

PYFR_INTERNAL int pyfr_util_init(UNUSED PyObject *self, UNUSED PyObject *args, UNUSED PyObject *kwds)
{
    pyfr_mod_state_t *state = pyfr_get_mod_state();

    if (state->util_loaded) return 0;

    DEBUG3("Initialising libfreeradius-util");

    /*
     *  Initialize the DL infrastructure, which is used by the
     *  config file parser.
     */
    if (state->lib_dir && dl_search_global_path_set(state->lib_dir) < 0) {
        pyfr_ErrorObject_as_strerror(pyfr_ErrorUtil);
        goto error;
    }

    /* Load the dictionary */
    if (!fr_dict_global_ctx_init(NULL, true, state->dict_dir)) {
        pyfr_ErrorObject_as_strerror(pyfr_ErrorUtil);
        goto error;
    }

    if (fr_dict_autoload(pyfr_dict) < 0) {
        pyfr_ErrorObject_as_strerror(pyfr_ErrorUtil);
        goto error;
    }

    if (fr_dict_read(fr_dict_unconst(dict_freeradius), state->raddb_dir, FR_DICTIONARY_FILE) == -1) {
        fr_log_perror(&default_log, L_ERR, __FILE__, __LINE__, NULL, "fr_dict_read() Failed to initialize the dictionaries");
        PyErr_Format(pyfr_ErrorUtil, "fr_dict_read() Failed initialising the dictionaries");
        goto error;
    }

    if (fr_dict_read(fr_dict_unconst(dict_radius), state->raddb_dir, FR_DICTIONARY_FILE) == -1) {
        fr_log_perror(&default_log, L_ERR, __FILE__, __LINE__, NULL, "fr_dict_read() Failed to initialize the dictionaries");
        PyErr_Format(pyfr_ErrorUtil, "fr_dict_read() Failed initialising the dictionaries");
        goto error;
    }

    state->util_loaded = true;

    return 1;

error:
    return -1;
}

PYFR_INTERNAL PyObject *pyfr_util_new(PyTypeObject *type, UNUSED PyObject *args, UNUSED PyObject *kwargs)
{
    pyfr_util_ctx_t *ctx = PyObject_New(pyfr_util_ctx_t, type);
    pyfr_mod_state_t *state = pyfr_get_mod_state();

    DEBUG2("raddb_dir='%s', dict_dir='%s', lib_dir='%s'", state->raddb_dir, state->dict_dir, state->lib_dir);

    return (PyObject *)ctx;
}

PYFR_INTERNAL void pyfr_util_dealloc(PyObject *self)
{
    pyfr_util_ctx_t *ctx = (pyfr_util_ctx_t *)self;

    if (fr_dict_autofree(pyfr_dict) < 0) pyfr_ErrorObject_as_strerror(pyfr_ErrorUtil);

    PyObject_Del(ctx);
}

PYFR_INTERNAL PyObject *pyfr_util_dict_attr_by_oid(UNUSED PyObject *self, PyObject *args)
{
    PyObject             *obj;
    const char           *oid;
    fr_dict_attr_t const *da;
    char                  flags_str[256];
    char                  oid_str[512];
    char                  oid_num[16];
    pyfr_mod_state_t     *state = pyfr_get_mod_state();

    if (!PyArg_ParseTuple(args, "s", &oid)) return NULL;

    DEBUG3("Looking for \"%s\" in dict RADIUS", oid);

    da = fr_dict_attr_by_oid(state->autofree, fr_dict_root(dict_radius), oid);
    if (!da) {
        PyErr_Format(pyfr_ErrorUtil, "OID '%s' not found", oid);
        return NULL;
    }

    if (fr_dict_attr_oid_print(&FR_SBUFF_OUT(oid_str, sizeof(oid_str)), NULL, da, false) <= 0) {
        PyErr_SetString(pyfr_ErrorUtil, "OID string too long");
        return NULL;
    }

    if (fr_dict_attr_oid_print(&FR_SBUFF_OUT(oid_num, sizeof(oid_num)), NULL, da, true) <= 0) {
        PyErr_SetString(pyfr_ErrorUtil, "OID string too long");
        return NULL;
    }

    fr_dict_attr_flags_print(&FR_SBUFF_OUT(flags_str, sizeof(flags_str)), dict_radius, da->type, &da->flags);

    obj = Py_BuildValue("{s:s, s:s, s:s, s:i, s:s, s:s, s:N, s:N, s:N, s:N, s:N, s:N, s:s}",
                         "oid.string", oid_str,
                         "oid.numeric", oid_num,
                         "name", da->name,
                         "id", da->attr,
                         "type", fr_type_to_str(da->type),
                         "flags", flags_str,
                         "is_root", PyBool_FromLong(da->flags.is_root),
                         "is_raw", PyBool_FromLong(da->flags.is_raw),
                         "is_alias", PyBool_FromLong(da->flags.is_alias),
                         "is_internal", PyBool_FromLong(da->flags.internal),
                         "has_value", PyBool_FromLong(da->flags.has_value),
                         "virtual", PyBool_FromLong(da->flags.virtual),
                         "parent.type", fr_type_to_str(da->parent->type)
    );

    if (!obj) {
        PyErr_SetString(pyfr_ErrorUtil, "Problems in Py_BuildValue()");
        return NULL;
    }

    return obj;
}

PYFR_INTERNAL PyMemberDef pyfr_util_members[] = {
    { NULL }  /* Sentinel */
};

/* List of functions defined in this module */
PYFR_INTERNAL PyMethodDef pyfr_util_methods[] = {
    {
        "dict_attr_by_oid", pyfr_util_dict_attr_by_oid, METH_VARARGS,
        "Resolve an attribute using an OID string."
    },

    { NULL }
};

PYFR_INTERNAL PyTypeObject pyfr_util_types = {
    PyVarObject_HEAD_INIT(NULL, 0) "pyfr.Util",                  /* tp_name */
    sizeof(pyfr_util_ctx_t),                                     /* tp_basicsize */
    0,                                                           /* tp_itemsize */
    pyfr_util_dealloc,                                           /* tp_dealloc */
    0,                                                           /* tp_print */
    0,                                                           /* tp_getattr */
    0,                                                           /* tp_setattr */
    0,                                                           /* tp_reserved */
    0,                                                           /* tp_repr */
    0,                                                           /* tp_as_number */
    0,                                                           /* tp_as_sequence */
    0,                                                           /* tp_as_mapping */
    0,                                                           /* tp_hash  */
    0,                                                           /* tp_call */
    0,                                                           /* tp_str */
    0,                                                           /* tp_getattro */
    0,                                                           /* tp_setattro */
    0,                                                           /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,                    /* tp_flags*/
    "Object to use libfreeradius-util library.",                 /* tp_doc */
    0,                                                           /* tp_traverse */
    0,                                                           /* tp_clear */
    0,                                                           /* tp_richcompare */
    0,                                                           /* tp_weaklistoffset */
    0,                                                           /* tp_iter */
    0,                                                           /* tp_iternext */
    pyfr_util_methods,                                           /* tp_methods */
    pyfr_util_members,                                           /* tp_members */
    0,                                                           /* tp_getset */
    0,                                                           /* tp_base */
    0,                                                           /* tp_dict */
    0,                                                           /* tp_descr_get */
    0,                                                           /* tp_descr_set */
    0,                                                           /* tp_dictoffset */
    pyfr_util_init,                                              /* tp_init */
    0,                                                           /* tp_alloc */
    pyfr_util_new,                                               /* tp_new */
};

PyTypeObject *pyfr_util_register(void)
{
    DEBUG2("Loading pyfr.Util");

    return &pyfr_util_types;
}
