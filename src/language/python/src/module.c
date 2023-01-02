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
 * @file src/module.c
 * @brief Python bindings for major FreeRADIUS libraries
 *
 * @copyright Network RADIUS SAS(legal@networkradius.com)
 * @author 2023 Jorge Pereira (jpereira@freeradius.org)
 */
RCSID("$Id$")

#include "pyfr.h"
#include "src/version.h"
#include "src/util.h"     // pyfr.Util.*   ~> libfreeradius-util*
#include "src/radius.h"   // pyfr.Radius.* ~> libfreeradius-radius*

PYFR_INTERNAL char const *pyfr_version = STRINGIFY(PYFR_VERSION_MAJOR) "." STRINGIFY(PYFR_VERSION_MINOR) "." STRINGIFY(PYFR_VERSION_INCRM);
PYFR_INTERNAL char const *pyfr_version_build = PYFR_VERSION_BUILD();

PYFR_INTERNAL char const *libfreeradius_version = STRINGIFY(RADIUSD_VERSION_MAJOR) "." STRINGIFY(RADIUSD_VERSION_MINOR) "." STRINGIFY(RADIUSD_VERSION_INCRM);
PYFR_INTERNAL char const *libfreeradius_version_build = RADIUSD_VERSION_BUILD("libfreeradius");

/* Singleton settings */
pyfr_mod_state_t *pyfr_get_mod_state(void) {
    static pyfr_mod_state_t _state = { 0 };

    return &_state;
}

PyObject *pyfr_ErrorObject = NULL;

PYFR_INTERNAL int pyfr_register_consts(PyObject *m)
{
    struct pyfr_consts_s {
        const char *key, *var;
    } pyfr_consts[] = {
        { "LOGDIR", LOGDIR },
        { "LIBDIR", LIBDIR },
        { "RADDBDIR", RADDBDIR },
        { "RUNDIR", RUNDIR },
        { "SBINDIR", SBINDIR },
        { "RADIR", RADIR },
        { "DICTDIR", DICTDIR },
        { NULL, NULL }
    };
    uint8_t i = 0;

    PyModule_AddStringConstant(m, "version", pyfr_version);
    PyModule_AddStringConstant(m, "version_build", pyfr_version_build);
    PyModule_AddStringConstant(m, "libfreeradius_version", libfreeradius_version);
    PyModule_AddStringConstant(m, "libfreeradius_version_build", libfreeradius_version_build);

    for (; pyfr_consts[i].key; i++) PyModule_AddStringConstant(m, pyfr_consts[i].key, pyfr_consts[i].var);

    return 1;
}

/* Bootstrap all modules */
PYFR_INTERNAL int pyfr_register_modules(PyObject *m)
{
    uint8_t i = 0;
    struct pyfr_mods_s {
        char const *name;
        PyTypeObject *(*mod_register)(void);
        char const *err_name;
        PyObject **err_obj;
    } pyfr_mods[] = {
        { "Util", pyfr_util_register, "pyfr_ErrorUtil", &pyfr_ErrorUtil },
        { "Radius", pyfr_radius_register, "pyfr_ErrorRadius", &pyfr_ErrorRadius },
        { NULL }
    };

    for (; pyfr_mods[i].name; i++) {
        PyTypeObject *type_obj;
        char *err_name;

        /* Setup the Module */
        type_obj = pyfr_mods[i].mod_register();
        if (!type_obj) return 0;
        
        if (PyType_Ready(type_obj) < 0) return 0;
        Py_INCREF(type_obj);
        PyModule_AddObject(m, pyfr_mods[i].name, (PyObject *)type_obj);

        /* Setup the Exception */
        err_name = talloc_asprintf(NULL, "pyfr.%s", pyfr_mods[i].err_name);
        *pyfr_mods[i].err_obj = PyErr_NewException(err_name, NULL, NULL);
        Py_INCREF(*pyfr_mods[i].err_obj);
        PyModule_AddObject(m, pyfr_mods[i].err_name, *pyfr_mods[i].err_obj);

        talloc_free(err_name);
    }

    return 1;
}

PYFR_INTERNAL int pyfr_bootstrap_libfreeradius(UNUSED PyObject *m)
{
	pyfr_mod_state_t *s = pyfr_get_mod_state();

	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_atexit_global_setup();

#ifndef NDEBUG
    s->autofree = talloc_autofree_context();

    if (fr_fault_setup(s->autofree, getenv("PANIC_ACTION"), "pyfr") < 0) {
        PyErr_SetString(PyExc_RuntimeError, fr_strerror());
        goto error;
    }
#endif

	talloc_set_log_stderr();

    /*
     *  Always log to stdout
     */
    // TODO: these attributes should be a Python const
    default_log.dst = L_DST_STDOUT;
    default_log.fd = STDOUT_FILENO;
    default_log.print_level = false;

    if (fr_log_init_legacy(&default_log, false) < 0) {
        pyfr_ErrorObject_as_strerror(pyfr_ErrorObject);
        goto error;
    }

    /*
     *  Mismatch between the binary and the libraries it depends on
     */
    if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
        pyfr_ErrorObject_as_strerror(pyfr_ErrorObject);
        goto error;
    }

    fr_strerror_clear();    /* Clear the error buffer */

    return 1;

error:
    if (talloc_free(s->autofree) < 0) fr_perror("pyfr");

    s->autofree = NULL;

    /*
     *  Ensure our atexit handlers run before any other
     *  atexit handlers registered by third party libraries.
     */
    fr_atexit_global_trigger_all();

    return 0;
}

PYFR_INTERNAL PyObject *pyfr_PyFR(PyObject *self, PyObject *args, PyObject *kwargs)
{
    pyfr_mod_state_t *state = pyfr_get_mod_state();
    const char * const keywords[] = { "raddb_dir", "dict_dir", "lib_dir", "debug_lvl", NULL};
    char *raddb_dir = NULL, *dict_dir = NULL, *lib_dir = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|sssi", UNCONST(char **, keywords), &raddb_dir, &dict_dir, &lib_dir, &fr_debug_lvl)) return NULL;
 
    DEBUG2("raddb_dir='%s', dict_dir='%s', lib_dir='%s'", raddb_dir, dict_dir, lib_dir);

#define _SET_VAR(var, dflt)  state->var = talloc_strdup(NULL, (var && strlen(var)) > 0 ? var : dflt)

    _SET_VAR(raddb_dir, RADDBDIR);
    _SET_VAR(dict_dir, DICTDIR);
    _SET_VAR(lib_dir, LIBDIR);

    /*
     *  It's easier having two sets of flags to set the
     *  verbosity of library calls and the verbosity of
     *  library.
     */
    fr_debug_lvl = 0;
    fr_log_fp = stdout; // TODO: Move to some API settings.

    return (PyObject *)self;
}

PYFR_INTERNAL PyObject *pyfr_set_raddb_dir(PyObject *self, PyObject *args)
{
    char *raddb_dir = NULL;

    if (PyArg_ParseTuple(args, "s", &raddb_dir)) {
        pyfr_mod_state_t *state = pyfr_get_mod_state();

        DEBUG3("raddb_dir='%s'", raddb_dir);

        state->raddb_dir = talloc_strdup(NULL, (raddb_dir && strlen(raddb_dir) > 0) ? raddb_dir : RADDBDIR);
    }

    return (PyObject *)self;
}

PYFR_INTERNAL PyObject *pyfr_set_dict_dir(PyObject *self, PyObject *args)
{
    char *dict_dir = NULL;

    if (PyArg_ParseTuple(args, "s", &dict_dir)) {
        pyfr_mod_state_t *state = pyfr_get_mod_state();

        DEBUG3("dict_dir='%s'", dict_dir);

        state->dict_dir = talloc_strdup(NULL, (dict_dir && strlen(dict_dir) > 0) ? dict_dir : DICTDIR);
    }

    return (PyObject *)self;
}

PYFR_INTERNAL PyObject *pyfr_set_lib_dir(PyObject *self, PyObject *args)
{
    char *lib_dir = NULL;

    if (PyArg_ParseTuple(args, "s", &lib_dir)) {
        pyfr_mod_state_t *state = pyfr_get_mod_state();

        DEBUG3("lib_dir='%s'", lib_dir);

        state->lib_dir = talloc_strdup(NULL, (lib_dir && strlen(lib_dir) > 0) ? lib_dir : LIBDIR);
    }

    return (PyObject *)self;
}

PYFR_INTERNAL PyObject *pyfr_set_debug_level(PyObject *self, PyObject *args)
{
    if (PyArg_ParseTuple(args, "i", &fr_debug_lvl)) DEBUG3("fr_debug_lvl='%d'", fr_debug_lvl);

    return (PyObject *)self;
}

PYFR_INTERNAL PyObject *pyfr_version_info(UNUSED PyObject *self, UNUSED PyObject *args)
{
    PyObject *ret = NULL;
    PyObject *tmp;

    ret = PyTuple_New((Py_ssize_t)4); /* (pyfr_version, git_hash, arch, built) */
    if (ret == NULL) goto error;

#define SET(i, v) \
        tmp = (v); if (tmp == NULL) goto error; PyTuple_SET_ITEM(ret, i, tmp)
    SET(0, PyUnicode_FromString(pyfr_version));
    SET(1, PyUnicode_FromString(PYFR_VERSION_COMMIT_STRING));
    SET(2, PyUnicode_FromString(HOSTINFO));
    SET(3, PyUnicode_FromString(_PYFR_VERSION_BUILD_TIMESTAMP));
#undef SET

    return ret;

error:
    Py_XDECREF(ret);
    return NULL;
}

PYFR_INTERNAL void pyfr_mod_free(UNUSED void *unused) {

#ifndef NDEBUG
    talloc_free(pyfr_get_mod_state()->autofree);
#endif

    /*
     *  Ensure our atexit handlers run before any other
     *  atexit handlers registered by third party libraries.
     */
    fr_atexit_global_trigger_all();
}

/* List of functions defined in this module */
PYFR_INTERNAL PyMethodDef pyfr_methods[] = {
    { "PyFR",             (PyCFunction)pyfr_PyFR,            METH_VARARGS | METH_KEYWORDS, NULL },
    { "set_raddb_dir",    (PyCFunction)pyfr_set_raddb_dir,   METH_VARARGS, NULL },
    { "set_dict_dir",     (PyCFunction)pyfr_set_dict_dir,    METH_VARARGS, NULL },
    { "set_lib_dir",      (PyCFunction)pyfr_set_lib_dir,     METH_VARARGS, NULL },
    { "set_debug_level",  (PyCFunction)pyfr_set_debug_level, METH_VARARGS, NULL },
    { "get_version_info", (PyCFunction)pyfr_version_info,    METH_NOARGS,  NULL },
    { NULL, NULL, 0, NULL }
};

PYFR_INTERNAL PyModuleDef pyfr_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "pyfr",
    .m_doc = "Python bindings for miscellaneous FreeRADIUS functions.",
    .m_size = -1,
    .m_methods = pyfr_methods,
    .m_traverse = NULL,
    .m_clear = NULL,
    .m_free = pyfr_mod_free
};

PyMODINIT_FUNC PyInit_pyfr(void);
PyMODINIT_FUNC PyInit_pyfr(void)
{
    PyObject *m;

    m = PyModule_Create(&pyfr_module);
    if (!m) return NULL;
    
    /* Add error object to the module */
    pyfr_ErrorObject = PyErr_NewException("pyfr.ErrorObject", PyExc_RuntimeError, NULL);
    if (pyfr_ErrorObject) {
        Py_INCREF(pyfr_ErrorObject);
        PyModule_AddObject(m, "ErrorObject", pyfr_ErrorObject);
    }

    /* Load some consts like version and default paths */
    if (!pyfr_register_consts(m)) goto error;

    /* then, let's call everything needed by libfreeradius* */
    if (!pyfr_bootstrap_libfreeradius(m)) goto error;

    /* Bootstrap all modules */
    if (!pyfr_register_modules(m)) goto error;

    return m;

error:
    if (!PyErr_Occurred()) PyErr_SetString(PyExc_ImportError, "pyfr module load failed");

    Py_XDECREF(pyfr_ErrorObject);
    Py_CLEAR(pyfr_ErrorObject);
    Py_DECREF(m);

    return NULL;
}
