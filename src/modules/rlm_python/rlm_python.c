/*
 * rlm_python.c
 *
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
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2002  Miguel A.L. Paraz <mparaz@mparaz.com>
 * Copyright 2002  Imperium Technology, Inc.
 */

#include <Python.h>

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

#define Pyx_BLOCK_THREADS       {PyGILState_STATE __gstate = PyGILState_Ensure();
#define Pyx_UNBLOCK_THREADS     PyGILState_Release(__gstate);}



static const char rcsid[] = "$Id$";

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */

struct rlm_python_t {
        char    *mod_instantiate;
        char    *mod_authorize;
        char    *mod_authenticate;
        char    *mod_preacct;
        char    *mod_accounting;
        char    *mod_checksimul;
        char    *mod_detach;

        /* Names of functions */
        char    *func_instantiate;
        char    *func_authorize;
        char    *func_authenticate;
        char    *func_preacct;
        char    *func_accounting;
        char    *func_checksimul;
        char    *func_detach;

        PyObject *pModule_instantiate;
        PyObject *pModule_authorize;
        PyObject *pModule_authenticate;
        PyObject *pModule_preacct;
        PyObject *pModule_accounting;
        PyObject *pModule_checksimul;
        PyObject *pModule_detach;

        /* Functions */
        PyObject *pFunc_instantiate;
        PyObject *pFunc_authorize;
        PyObject *pFunc_authenticate;
        PyObject *pFunc_preacct;
        PyObject *pFunc_accounting;
        PyObject *pFunc_checksimul;
        PyObject *pFunc_detach;
};


/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static CONF_PARSER module_config[] = {
  { "mod_instantiate",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, mod_instantiate), NULL,  NULL},
  { "func_instantiate",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, func_instantiate), NULL,  NULL},

  { "mod_authorize",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, mod_authorize), NULL,  NULL},
  { "func_authorize",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, func_authorize), NULL,  NULL},

  { "mod_authenticate",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, mod_authenticate), NULL,  NULL},
  { "func_authenticate",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, func_authenticate), NULL,  NULL},

  { "mod_preacct",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, mod_preacct), NULL,  NULL},
  { "func_preacct",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, func_preacct), NULL,  NULL},

  { "mod_accounting",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, mod_accounting), NULL,  NULL},
  { "func_accounting",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, func_accounting), NULL,  NULL},

  { "mod_checksimul",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, mod_checksimul), NULL,  NULL},
  { "func_checksimul",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, func_checksimul), NULL,  NULL},

  { "mod_detach",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, mod_detach), NULL,  NULL},
  { "func_detach",  PW_TYPE_STRING_PTR,
    offsetof(struct rlm_python_t, func_detach), NULL,  NULL},


  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

static struct {
        const char*     name;
        int             value;
} radiusd_constants[] = {
        { "L_DBG",              L_DBG                   },
        { "L_AUTH",             L_AUTH                  },
        { "L_INFO",             L_INFO                  },
        { "L_ERR",              L_ERR                   },
        { "L_PROXY",            L_PROXY                 },
        { "L_CONS",             L_CONS                  },
        { "RLM_MODULE_REJECT",  RLM_MODULE_REJECT       },
        { "RLM_MODULE_FAIL",    RLM_MODULE_FAIL         },
        { "RLM_MODULE_OK",      RLM_MODULE_OK           },
        { "RLM_MODULE_HANDLED", RLM_MODULE_HANDLED      },
        { "RLM_MODULE_INVALID", RLM_MODULE_INVALID      },
        { "RLM_MODULE_USERLOCK",RLM_MODULE_USERLOCK     },
        { "RLM_MODULE_NOTFOUND",RLM_MODULE_NOTFOUND     },
        { "RLM_MODULE_NOOP",    RLM_MODULE_NOOP         },
        { "RLM_MODULE_UPDATED", RLM_MODULE_UPDATED      },
        { "RLM_MODULE_NUMCODES",RLM_MODULE_NUMCODES     },
        { NULL, 0 },
};


/* Let assume that radiusd module is only one since we have only one intepreter */

static PyObject *radiusd_module = NULL;

/*
 * radiusd Python functions
 */

/* radlog wrapper */
static PyObject *python_radlog(const PyObject *module, PyObject *args) {
    int status;
    char *msg;

    if (!PyArg_ParseTuple(args, "is", &status, &msg)) {
	return NULL;
    }

    radlog(status, "%s", msg);
    Py_INCREF(Py_None);

    return Py_None;
}

static PyMethodDef radiusd_methods[] = {
    {"radlog", (PyCFunction) &python_radlog, METH_VARARGS, "freeradius radlog()."},
    {NULL, NULL, 0, NULL}
};

static void python_error() {
    PyObject        *pType = NULL;
    PyObject        *pValue = NULL;
    PyObject        *pTraceback = NULL;
    PyObject        *pStr1 = NULL;
    PyObject        *pStr2 = NULL;

    Pyx_BLOCK_THREADS

    PyErr_Fetch(&pType, &pValue, &pTraceback);
    if (pType == NULL || pValue == NULL)
        goto failed;
    if ((pStr1 = PyObject_Str(pType)) == NULL || (pStr2 = PyObject_Str(pValue)) == NULL)
        goto failed;
    radlog(L_ERR, "rlm_python:EXCEPT:%s: %s", PyString_AsString(pStr1), PyString_AsString(pStr2));

failed:
    Py_XDECREF(pStr1);
    Py_XDECREF(pStr2);
    Py_XDECREF(pType);
    Py_XDECREF(pValue);
    Py_XDECREF(pTraceback);

    Pyx_UNBLOCK_THREADS
}

static int python_init()
{
    int i;

    Py_SetProgramName("radiusd");

    Py_Initialize();

    PyEval_InitThreads(); // This also grabs a lock

    if ((radiusd_module = Py_InitModule3("radiusd", radiusd_methods, "FreeRADIUS Module.")) == NULL)
        goto failed;

    for (i = 0; radiusd_constants[i].name; i++)
        if ((PyModule_AddIntConstant(radiusd_module, radiusd_constants[i].name, radiusd_constants[i].value)) < 0)
            goto failed;

    PyEval_ReleaseLock(); // Drop lock grabbed by InitThreads

    radlog(L_DBG, "python_init done");

    return 0;

failed:
    python_error();
    Py_Finalize();
    return -1;
}

static int python_destroy() {
    Pyx_BLOCK_THREADS
    Py_XDECREF(radiusd_module);
    Py_Finalize();
    Pyx_UNBLOCK_THREADS

    return 0;
}

static void python_vptuple(VALUE_PAIR **vpp, PyObject *pValue, const char *funcname) {
        int             i;
        int             tuplesize;
        VALUE_PAIR      *vp;

        /* If the Python function gave us None for the tuple, then just return. */
        if (pValue == Py_None)
                return;

        if (!PyTuple_CheckExact(pValue)) {
                radlog(L_ERR, "rlm_python:%s: non-tuple passed", funcname);
                return;
        }
        /* Get the tuple tuplesize. */
        tuplesize = PyTuple_GET_SIZE(pValue);
        for (i = 0; i < tuplesize; i++) {
                PyObject *pTupleElement = PyTuple_GET_ITEM(pValue, i);
                PyObject *pStr1;
                PyObject *pStr2;
                int pairsize;
                const char *s1;
                const char *s2;

                if (!PyTuple_CheckExact(pTupleElement)) {
                        radlog(L_ERR, "rlm_python:%s: tuple element %d is not a tuple", funcname, i);
                        continue;
                }
                /* Check if it's a pair */
                if ((pairsize = PyTuple_GET_SIZE(pTupleElement)) != 2) {
                        radlog(L_ERR, "rlm_python:%s: tuple element %d is a tuple of size %d. Must be 2", funcname, i, pairsize);
                        continue;
                }
                pStr1 = PyTuple_GET_ITEM(pTupleElement, 0);
                pStr2 = PyTuple_GET_ITEM(pTupleElement, 1);
                if ((!PyString_CheckExact(pStr1)) || (!PyString_CheckExact(pStr2))) {
                        radlog(L_ERR, "rlm_python:%s: tuple element %d must be as (str, str)", funcname, i);
                        continue;
                }
                s1 = PyString_AsString(pStr1);
                s2 = PyString_AsString(pStr2);
                /* xxx Might need to support other T_OP */
                vp = pairmake(s1, s2, T_OP_EQ);
                if (vp != NULL) {
                        pairadd(vpp, vp);
                        radlog(L_DBG, "rlm_python:%s: '%s' = '%s'", funcname, s1, s2);
                } else {
                        radlog(L_DBG, "rlm_python:%s: Failed: '%s' = '%s'", funcname, s1, s2);
                }
        }
}


/* This is the core Python function that the others wrap around.
 * Pass the value-pair print strings in a tuple.
 * xxx We're not checking the errors. If we have errors, what do we do?
 */

static int python_function(REQUEST *request, PyObject *pFunc, const char *funcname) {
        char            buf[1024];
        VALUE_PAIR      *vp;
        PyObject        *pRet = NULL;
        PyObject        *pArgs = NULL;
        int             tuplelen;
        int             ret;

	PyGILState_STATE gstate;

        /* Return with "OK, continue" if the function is not defined. */
        if (pFunc == NULL)
                return RLM_MODULE_OK;

        /* Default return value is "OK, continue" */
        ret = RLM_MODULE_OK;

        /* We will pass a tuple containing (name, value) tuples
         * We can safely use the Python function to build up a tuple,
         * since the tuple is not used elsewhere.
         *
         * Determine the size of our tuple by walking through the packet.
         * If request is NULL, pass None.
         */
        tuplelen = 0;
        if (request != NULL) {
                for (vp = request->packet->vps; vp; vp = vp->next)
                        tuplelen++;
        }

        gstate = PyGILState_Ensure();

        if (tuplelen == 0) {
                Py_INCREF(Py_None);
                pArgs = Py_None;
        } else {
                int     i = 0;
                if ((pArgs = PyTuple_New(tuplelen)) == NULL)
                        goto failed;
                for (vp = request->packet->vps; vp != NULL; vp = vp->next, i++) {
                        PyObject *pPair;
                        PyObject *pStr;
                        /* The inside tuple has two only: */
                        if ((pPair = PyTuple_New(2)) == NULL)
                                goto failed;
                        /* Put the tuple inside the container */
                        PyTuple_SET_ITEM(pArgs, i, pPair);
                        /* The name. logic from vp_prints, lib/print.c */
                        if (vp->flags.has_tag)
                                snprintf(buf, sizeof(buf), "%s:%d", vp->name, vp->flags.tag);
                        else
                                strcpy(buf, vp->name);
                        if ((pStr = PyString_FromString(buf)) == NULL)
                                goto failed;
                        PyTuple_SET_ITEM(pPair, 0, pStr);
                        vp_prints_value(buf, sizeof(buf), vp, 1);
                        if ((pStr = PyString_FromString(buf)) == NULL)
                                goto failed;
                        PyTuple_SET_ITEM(pPair, 1, pStr);
                }
        }

        /* Call Python function. */
        pRet = PyObject_CallFunctionObjArgs(pFunc, pArgs, NULL);

	if (pRet == NULL)
                goto failed;

        if (request == NULL)
                goto okay;
        /* The function returns either:
         *  1. tuple containing the integer return value,
         *  then the integer reply code (or None to not set),
         *  then the string tuples to build the reply with.
         *  (returnvalue, (p1, s1), (p2, s2))
         *
         *  2. the function return value alone
         *
         *  3. None - default return value is set
         *
         * xxx This code is messy!
         */
        if (PyTuple_CheckExact(pRet)) {
                PyObject *pTupleInt;

                if (PyTuple_GET_SIZE(pRet) != 3) {
                        radlog(L_ERR, "rlm_python:%s: tuple must be (return, replyTuple, configTuple)", funcname);
                        goto failed;
                }
                pTupleInt = PyTuple_GET_ITEM(pRet, 0);
                if (!PyInt_CheckExact(pTupleInt)) {
                        radlog(L_ERR, "rlm_python:%s: first tuple element not an integer", funcname);
                        goto failed;
                }
                /* Now have the return value */
                ret = PyInt_AsLong(pTupleInt);
                /* Reply item tuple */
                python_vptuple(&request->reply->vps, PyTuple_GET_ITEM(pRet, 1), funcname);
                /* Config item tuple */
                python_vptuple(&request->config_items, PyTuple_GET_ITEM(pRet, 2), funcname);
        } else
        if (PyInt_CheckExact(pRet)) {
                /* Just an integer */
                ret = PyInt_AsLong(pRet);
        } else
        if (pRet == Py_None) {
                /* returned 'None', return value defaults to "OK, continue." */
                ret = RLM_MODULE_OK;
        } else {
                /* Not tuple or None */
                radlog(L_ERR, "rlm_python:%s: function did not return a tuple or None", funcname);
                goto failed;
        }
        if (ret == RLM_MODULE_REJECT && request != NULL)
                pairfree(&request->reply->vps);
okay:
        Py_DECREF(pArgs);
        Py_DECREF(pRet);
	PyGILState_Release(gstate);
        return ret;
failed:
        python_error();
        Py_XDECREF(pArgs);
        Py_XDECREF(pRet);
        PyGILState_Release(gstate);

        return -1;
}

/*
 * Import a user module and load a function from it
 */

static int python_load_function(char *module, const char *func, PyObject **pModule, PyObject **pFunc) {
        const char      funcname[] = "python_load_function";
        PyGILState_STATE gstate;

        *pFunc = NULL;
        *pModule = NULL;
        gstate = PyGILState_Ensure();

        if (module != NULL && func != NULL) {
                if ((*pModule = PyImport_ImportModule(module)) == NULL) {
                        radlog(L_ERR, "rlm_python:%s: module '%s' is not found", funcname, module);
                        goto failed;
                }
                if ((*pFunc = PyObject_GetAttrString(*pModule, func)) == NULL) {
                        radlog(L_ERR, "rlm_python:%s: function '%s.%s' is not found", funcname, module, func);
                        goto failed;
                }
                if (!PyCallable_Check(*pFunc)) {
                        radlog(L_ERR, "rlm_python:%s: function '%s.%s' is not callable", funcname, module, func);
                        goto failed;
                }
        }
	PyGILState_Release(gstate);
        return 0;
failed:
        python_error();
        radlog(L_ERR, "rlm_python:%s: failed to import python function '%s.%s'", funcname, module, func);
        Py_XDECREF(*pFunc);
        *pFunc = NULL;
        Py_XDECREF(*pModule);
        PyGILState_Release(gstate);
        *pModule = NULL;
        return -1;
}

static void python_objclear(PyObject **ob) {
        if (*ob != NULL) {
		Pyx_BLOCK_THREADS
                Py_DECREF(*ob);
                Pyx_UNBLOCK_THREADS
                *ob = NULL;
        }
}

static void python_instance_clear(struct rlm_python_t *data) {
        python_objclear(&data->pFunc_instantiate);
        python_objclear(&data->pFunc_authorize);
        python_objclear(&data->pFunc_authenticate);
        python_objclear(&data->pFunc_preacct);
        python_objclear(&data->pFunc_accounting);
        python_objclear(&data->pFunc_checksimul);
        python_objclear(&data->pFunc_detach);

        python_objclear(&data->pModule_instantiate);
        python_objclear(&data->pModule_authorize);
        python_objclear(&data->pModule_authenticate);
        python_objclear(&data->pModule_preacct);
        python_objclear(&data->pModule_accounting);
        python_objclear(&data->pModule_checksimul);
        python_objclear(&data->pModule_detach);
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 *
 */

static int python_instantiate(CONF_SECTION *conf, void **instance) {
        struct rlm_python_t    *data = NULL;

        /*
         *      Set up a storage area for instance data
         */
        if ((data = malloc(sizeof(*data))) == NULL)
                return -1;
        bzero(data, sizeof(*data));

        /*
         *      If the configuration parameters can't be parsed, then
         *      fail.
         */
        if (cf_section_parse(conf, data, module_config) < 0) {
                free(data);
                return -1;
        }

        /*
         * Import user modules.
         */
        if (python_load_function(data->mod_instantiate,
                                data->func_instantiate,
                                &data->pModule_instantiate,
                                &data->pFunc_instantiate) < 0)
                goto failed;

        if (python_load_function(data->mod_authenticate,
                                data->func_authenticate,
                                &data->pModule_authenticate,
                                &data->pFunc_authenticate) < 0)
                goto failed;

        if (python_load_function(data->mod_authorize,
                                data->func_authorize,
                                &data->pModule_authorize,
                                &data->pFunc_authorize) < 0)
                goto failed;

        if (python_load_function(data->mod_preacct,
                                data->func_preacct,
                                &data->pModule_preacct,
                                &data->pFunc_preacct) < 0)
                goto failed;

        if (python_load_function(data->mod_accounting,
                                data->func_accounting,
                                &data->pModule_accounting,
                                &data->pFunc_accounting) < 0)
                goto failed;

        if (python_load_function(data->mod_checksimul,
                                data->func_checksimul,
                                &data->pModule_checksimul,
                                &data->pFunc_checksimul) < 0)
                goto failed;

        if (python_load_function(data->mod_detach,
                                data->func_detach,
                                &data->pModule_detach,
                                &data->pFunc_detach) < 0)
                goto failed;

        *instance = data;
        /* Call the instantiate function.  No request.  Use the return value. */

        return python_function(NULL, data->pFunc_instantiate, "instantiate");
failed:
        python_error();
        python_instance_clear(data);
        return -1;
}

static int python_detach(void *instance) {
        struct rlm_python_t    *data = (struct rlm_python_t *) instance;
        int             ret;

        ret = python_function(NULL, data->pFunc_detach, "detach");

        python_instance_clear(data);

        free(data);
        return ret;
}


/* Wrapper functions */
static int python_authorize(void *instance, REQUEST *request)
{
    return python_function(request,
			   ((struct rlm_python_t *)instance)->pFunc_authorize,
			   "authorize");
}

static int python_authenticate(void *instance, REQUEST *request)
{
    return python_function(
	request,
	((struct rlm_python_t *)instance)->pFunc_authenticate,
	"authenticate");
}

static int python_preacct(void *instance, REQUEST *request)
{
    return python_function(
	request,
	((struct rlm_python_t *)instance)->pFunc_preacct,
	"preacct");
}

static int python_accounting(void *instance, REQUEST *request)
{
    return python_function(
	request,
	((struct rlm_python_t *)instance)->pFunc_accounting,
	"accounting");
}

static int python_checksimul(void *instance, REQUEST *request)
{
    return python_function(
	request,
	((struct rlm_python_t *)instance)->pFunc_checksimul,
	"checksimul");
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_python = {
	"python",
	RLM_TYPE_THREAD_SAFE,		/* type */
	python_init,			/* initialization */
	python_instantiate,		/* instantiation */
	{
		python_authenticate,	/* authentication */
		python_authorize,	/* authorization */
		python_preacct,		/* preaccounting */
		python_accounting,	/* accounting */
		python_checksimul,	/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
	python_detach,			/* detach */
	python_destroy,				/* destroy */
};
