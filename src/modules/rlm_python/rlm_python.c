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

static const char rcsid[] = "$Id$";

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_python_t {
    /* Config section */

    /* Names of modules */
    char
        *mod_instantiate,
        *mod_authorize,
	*mod_authenticate,
	*mod_preacct,
	*mod_accounting,
	*mod_checksimul,
	*mod_detach,

    /* Names of functions */
        *func_instantiate,
        *func_authorize,
	*func_authenticate,
	*func_preacct,
	*func_accounting,
	*func_checksimul,
	*func_detach;


    /* End Config section */


    /* Python objects for modules */
    PyObject
        *pModule_builtin,
        *pModule_instantiate,
        *pModule_authorize,
	*pModule_authenticate,
	*pModule_preacct,
	*pModule_accounting,
	*pModule_checksimul,
	*pModule_detach,


	/* Functions */

	*pFunc_instantiate,
	*pFunc_authorize,
	*pFunc_authenticate,
	*pFunc_preacct,
	*pFunc_accounting,
	*pFunc_checksimul,
	*pFunc_detach;

} rlm_python_t;

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
    offsetof(rlm_python_t, mod_instantiate), NULL,  NULL},
  { "func_instantiate",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, func_instantiate), NULL,  NULL},

  { "mod_authorize",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, mod_authorize), NULL,  NULL},
  { "func_authorize",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, func_authorize), NULL,  NULL},

  { "mod_authenticate",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, mod_authenticate), NULL,  NULL},
  { "func_authenticate",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, func_authenticate), NULL,  NULL},

  { "mod_preacct",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, mod_preacct), NULL,  NULL},
  { "func_preacct",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, func_preacct), NULL,  NULL},

  { "mod_accounting",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, mod_accounting), NULL,  NULL},
  { "func_accounting",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, func_accounting), NULL,  NULL},

  { "mod_checksimul",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, mod_checksimul), NULL,  NULL},
  { "func_checksimul",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, func_checksimul), NULL,  NULL},

  { "mod_detach",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, mod_detach), NULL,  NULL},
  { "func_detach",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t, func_detach), NULL,  NULL},


  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 * radiusd Python functions
 */

/* radlog wrapper */
static PyObject *radlog_py(const PyObject *self, PyObject *args) {
    int status;
    char *msg;

    if (!PyArg_ParseTuple(args, "is", &status, &msg)) {
	return NULL;
    }

    radlog(status, msg);
    return Py_None;
}

static PyMethodDef radiusd_methods[] = {
    {"radlog", (PyCFunction)radlog_py, METH_VARARGS, "freeradius radlog()."},
    {NULL, NULL, 0, NULL}
};

/*
 *	Do any per-module initialization.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	Try to avoid putting too much stuff in here - it's better to
 *	do it in instantiate() where it is not global.
 */
static int python_init(void)
{
    /*
     * Initialize Python interpreter. Fatal error if this fails.
     */
    Py_Initialize();

    radlog(L_DBG, "python_init done");

    return 0;
}

/* Extract string representation of Python error. */
static void python_error(void) {
    PyObject *pType, *pValue, *pTraceback, *pStr1, *pStr2;

    PyErr_Fetch(&pType, &pValue, &pTraceback);
    pStr1 = PyObject_Str(pType);
    pStr2 = PyObject_Str(pValue);

    radlog(L_ERR, "%s: %s\n",
	   PyString_AsString(pStr1), PyString_AsString(pStr2));
}

/* Tuple to value pair conversion */
static void add_vp_tuple(VALUE_PAIR **vpp, PyObject *pValue,
			 const char *function_name) {
    int i, outertuplesize;
    VALUE_PAIR	*vp;

    /* If the Python function gave us None for the tuple, then just return. */
    if (pValue == Py_None) {
	return;
    }

    if (!PyTuple_Check(pValue)) {
	radlog(L_ERR, "%s: non-tuple passed", function_name);
    }

    /* Get the tuple size. */
    outertuplesize = PyTuple_Size(pValue);

    for (i = 0; i < outertuplesize; i++) {
	PyObject *pTupleElement = PyTuple_GetItem(pValue, i);

	if ((pTupleElement != NULL) &&
	    (PyTuple_Check(pTupleElement))) {

	    /* Check if it's a pair */
	    int tuplesize;

	    if ((tuplesize = PyTuple_Size(pTupleElement)) != 2) {
		radlog(L_ERR, "%s: tuple element %d is a tuple "
		       " of size %d. must be 2\n", function_name,
		       i, tuplesize);
	    }
	    else {
		PyObject *pString1, *pString2;

		pString1 = PyTuple_GetItem(pTupleElement, 0);
		pString2 = PyTuple_GetItem(pTupleElement, 1);

		/* xxx PyString_Check does not compile here */
		if  ((pString1 != NULL) &&
		     (pString2 != NULL) &&
		     PyObject_TypeCheck(pString1,&PyString_Type) &&
		     PyObject_TypeCheck(pString2,&PyString_Type)) {


		    const char *s1, *s2;

		    /* pairmake() will convert and find any
		     * errors in the pair.
		     */

		    s1 = PyString_AsString(pString1);
		    s2 = PyString_AsString(pString2);

		    if ((s1 != NULL) && (s2 != NULL)) {
			radlog(L_DBG, "%s: %s = %s ",
			       function_name, s1, s2);

			/* xxx Might need to support other T_OP */
			vp = pairmake(s1, s2, T_OP_EQ);
			if (vp != NULL) {
			    pairadd(vpp, vp);
			    radlog(L_DBG, "%s: s1, s2 OK\n",
				   function_name);
			}
			else {
			    radlog(L_DBG, "%s: s1, s2 FAILED\n",
				   function_name);
			}
		    }
		    else {
			radlog(L_ERR, "%s: string conv failed\n",
			       function_name);
		    }

		}
		else {
		    radlog(L_ERR, "%s: tuple element %d must be "
			   "(string, string)", function_name, i);
		}
	    }
	}
	else {
	    radlog(L_ERR, "%s: tuple element %d is not a tuple\n",
		   function_name, i);
	}
    }

}

/* This is the core Python function that the others wrap around.
 * Pass the value-pair print strings in a tuple.
 * xxx We're not checking the errors. If we have errors, what do we do?
 */

static int python_function(REQUEST *request,
			   PyObject *pFunc, const char *function_name)
{
#define BUF_SIZE 1024

    char buf[BUF_SIZE];		/* same size as vp_print buffer */

    VALUE_PAIR	*vp;

    PyObject *pValue, *pValuePairContainer, **pValueHolder, **pValueHolderPtr;
    int i, n_tuple, return_value;

    /* Return with "OK, continue" if the function is not defined. */
    if (pFunc == NULL) {
	return RLM_MODULE_OK;
    }

    /* Default return value is "OK, continue" */
    return_value = RLM_MODULE_OK;

    /* We will pass a tuple containing (name, value) tuples
     * We can safely use the Python function to build up a tuple,
     * since the tuple is not used elsewhere.
     *
     * Determine the size of our tuple by walking through the packet.
     * If request is NULL, pass None.
     */
    n_tuple = 0;

    if (request != NULL) {
	for (vp = request->packet->vps; vp; vp = vp->next) {
	    n_tuple++;
	}
    }

    /* Create the tuple and a holder for the pointers, so that we can
     * decref more efficiently later without the overhead of reading
     * the tuple.
     *
     * We use malloc() instead of the Python memory allocator since we
     * are not embedded.
     */

    if (NULL == (pValueHolder = pValueHolderPtr =
		 malloc(sizeof(PyObject *) * n_tuple))) {

	radlog(L_ERR, "%s: malloc of %d bytes failed\n",
	       function_name, sizeof(PyObject *) * n_tuple);

	return -1;
    }

    if (n_tuple == 0) {
	pValuePairContainer = Py_None;
    }
    else {
	pValuePairContainer = PyTuple_New(n_tuple);

	i = 0;
	for (vp = request->packet->vps; vp; vp = vp->next) {
	    PyObject *pValuePair, *pString1, *pString2;

	    /* The inside tuple has two only: */
	    pValuePair = PyTuple_New(2);

	    /* The name. logic from vp_prints, lib/print.c */
	    if (vp->flags.has_tag) {
		snprintf(buf, BUF_SIZE, "%s:%d", vp->name, vp->flags.tag);
	    }
	    else {
		strcpy(buf, vp->name);
	    }

	    pString1 = PyString_FromString(buf);
	    PyTuple_SetItem(pValuePair, 0, pString1);


	    /* The value. Use delimiter - don't know what that means */
	    vp_prints_value(buf, sizeof(buf), vp, 1);
	    pString2 = PyString_FromString(buf);
	    PyTuple_SetItem(pValuePair, 1, pString2);

	    /* Put the tuple inside the container */
	    PyTuple_SetItem(pValuePairContainer, i++, pValuePair);

	    /* Store the pointer in our malloc() storage */
	    *pValueHolderPtr++ = pValuePair;
	}
    }


    /* Call Python function.
     */

    if (pFunc && PyCallable_Check(pFunc)) {
	PyObject *pArgs;

	/* call the function with a singleton tuple containing the
	 * container tuple.
	 */

	if ((pArgs = PyTuple_New(1)) == NULL) {
	    radlog(L_ERR, "%s: could not create tuple", function_name);
	    return -1;
	}
	if ((PyTuple_SetItem(pArgs, 0, pValuePairContainer)) != 0) {
	    radlog(L_ERR, "%s: could not set tuple item", function_name);
	    return -1;
	}

	if ((pValue = PyObject_CallObject(pFunc, pArgs)) == NULL) {
	    radlog(L_ERR, "%s: function call failed", function_name);
	    python_error();
	    return -1;
	}

	/* The function returns either:
	 *  1. tuple containing the integer return value,
	 *  then the integer reply code (or None to not set),
	 *  then the string tuples to build the reply with.
	 *     (returnvalue, (p1, s1), (p2, s2))
	 *
	 *  2. the function return value alone
	 *
	 *  3. None - default return value is set
	 *
	 * xxx This code is messy!
	 */

	if (PyTuple_Check(pValue)) {
	    PyObject *pTupleInt;

	    if (PyTuple_Size(pValue) != 3) {
		radlog(L_ERR, "%s: tuple must be " \
		       "(return, replyTuple, configTuple)",
		       function_name);

	    }
	    else {
		pTupleInt = PyTuple_GetItem(pValue, 0);

		if ((pTupleInt == NULL) || !PyInt_Check(pTupleInt)) {
		    radlog(L_ERR, "%s: first tuple element not an integer",
			   function_name);
		}
		else {
		    /* Now have the return value */
		    return_value = PyInt_AsLong(pTupleInt);

		    /* Reply item tuple */
		    add_vp_tuple(&request->reply->vps,
				 PyTuple_GetItem(pValue, 1), function_name);

		    /* Config item tuple */
		    add_vp_tuple(&request->config_items,
				 PyTuple_GetItem(pValue, 2), function_name);
		}
	    }
	}
	else if (PyInt_Check(pValue)) {
	    /* Just an integer */
	    return_value = PyInt_AsLong(pValue);
	}
	else if (pValue == Py_None) {
	    /* returned 'None', return value defaults to "OK, continue." */
	    return_value = RLM_MODULE_OK;
	}
	else {
	    /* Not tuple or None */
	    radlog(L_ERR, "%s function did not return a tuple or None\n",
		   function_name);
	}


	/* Decrease reference counts for the argument and return tuple */
	Py_DECREF(pArgs);
	Py_DECREF(pValue);
    }

    /* Decrease reference count for the tuples passed, the
     * container tuple, and the return value.
     */

    pValueHolderPtr = pValueHolder;
    i = n_tuple;
    while (i--) {
	/* Can't write as pValueHolderPtr since Py_DECREF is a macro */
	Py_DECREF(*pValueHolderPtr);
	pValueHolderPtr++;
    }
    free(pValueHolder);
    Py_DECREF(pValuePairContainer);

    /* pDict and pFunc are borrowed and must not be Py_DECREF-ed */

    /* Free pairs if we are rejecting.
     * xxx Shouldn't the core do that?
     */

    if ((return_value == RLM_MODULE_REJECT) && (request != NULL)) {
	pairfree(&(request->reply->vps));
    }

    /* Return the specified by the Python module */
    return return_value;
}


static struct varlookup {
	const char*	name;
	int		value;
} constants[] = {
	{ "L_DBG",		L_DBG			},
	{ "L_AUTH",		L_AUTH			},
	{ "L_INFO",		L_INFO			},
	{ "L_ERR",		L_ERR			},
	{ "L_PROXY",		L_PROXY			},
	{ "L_CONS",		L_CONS			},
	{ "RLM_MODULE_REJECT",	RLM_MODULE_REJECT	},
	{ "RLM_MODULE_FAIL",	RLM_MODULE_FAIL		},
	{ "RLM_MODULE_OK",	RLM_MODULE_OK		},
	{ "RLM_MODULE_HANDLED",	RLM_MODULE_HANDLED	},
	{ "RLM_MODULE_INVALID",	RLM_MODULE_INVALID	},
	{ "RLM_MODULE_USERLOCK",RLM_MODULE_USERLOCK	},
	{ "RLM_MODULE_NOTFOUND",RLM_MODULE_NOTFOUND	},
	{ "RLM_MODULE_NOOP",	RLM_MODULE_NOOP		},
	{ "RLM_MODULE_UPDATED",	RLM_MODULE_UPDATED	},
	{ "RLM_MODULE_NUMCODES",RLM_MODULE_NUMCODES	},
	{ NULL, 0 },
};

/*
 * Import a user module and load a function from it
 */
static int load_python_function(const char* module, const char* func,
				PyObject** pyModule, PyObject** pyFunc) {

    if ((module==NULL) || (func==NULL)) {
	*pyFunc=NULL;
	*pyModule=NULL;
    } else {
	PyObject *pName;

	pName = PyString_FromString(module);
	Py_INCREF(pName);
	*pyModule = PyImport_Import(pName);
	Py_DECREF(pName);
	if (*pyModule != NULL) {
	    PyObject *pDict;

	    pDict = PyModule_GetDict(*pyModule);
	    /* pDict: borrowed reference */

	    *pyFunc = PyDict_GetItemString(pDict, func);
	    /* pFunc: Borrowed reference */
	} else {
	    python_error();

	    radlog(L_ERR, "Failed to import python module \"%s\"\n", module);
	    return -1;
	}
    }

    return 0;
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
static int python_instantiate(CONF_SECTION *conf, void **instance)
{
    rlm_python_t *data;
    PyObject *module;
    int idx;

    /*
	 *	Set up a storage area for instance data
	 */
    data = rad_malloc(sizeof(*data));
    if (!data) {
      return -1;
    }
    memset(data, 0, sizeof(*data));

    /*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
    if (cf_section_parse(conf, data, module_config) < 0) {
	free(data);
	return -1;
    }


    /*
     * Setup our 'radiusd' module.
     */

    /* Code */
    if ((module = data->pModule_builtin =
	 Py_InitModule3("radiusd", radiusd_methods,
			"FreeRADIUS Module.")) == NULL) {

	radlog(L_ERR, "Python Py_InitModule3 failed");
	free(data);
	return -1;
    }

    /*
     * Load constants into module
     */
    for (idx=0; constants[idx].name; idx++)
	if ((PyModule_AddIntConstant(module, constants[idx].name, constants[idx].value)) == -1) {

	    radlog(L_ERR, "Python AddIntConstant failed");
	}


    /*
     * Import user modules.
     */

    if (load_python_function(data->mod_instantiate, data->func_instantiate,
		&data->pModule_instantiate, &data->pFunc_instantiate)==-1) {
	/* TODO: check if we need to cleanup data */
	return -1;
    }

    if (load_python_function(data->mod_authenticate, data->func_authenticate,
		&data->pModule_authenticate, &data->pFunc_authenticate)==-1) {
	/* TODO: check if we need to cleanup data */
	return -1;
    }

    if (load_python_function(data->mod_authorize, data->func_authorize,
		&data->pModule_authorize, &data->pFunc_authorize)==-1) {
	/* TODO: check if we need to cleanup data */
	return -1;
    }

    if (load_python_function(data->mod_preacct, data->func_preacct,
		&data->pModule_preacct, &data->pFunc_preacct)==-1) {
	/* TODO: check if we need to cleanup data */
	return -1;
    }

    if (load_python_function(data->mod_accounting, data->func_accounting,
		&data->pModule_accounting, &data->pFunc_accounting)==-1) {
	/* TODO: check if we need to cleanup data */
	return -1;
    }

    if (load_python_function(data->mod_checksimul, data->func_checksimul,
		&data->pModule_checksimul, &data->pFunc_checksimul)==-1) {
	/* TODO: check if we need to cleanup data */
	return -1;
    }

    if (load_python_function(data->mod_detach, data->func_detach,
		&data->pModule_detach, &data->pFunc_detach)==-1) {
	/* TODO: check if we need to cleanup data */
	return -1;
    }

    *instance=data;

    /* Call the instantiate function.  No request.  Use the return value. */
    return python_function(NULL, data->pFunc_instantiate, "instantiate");
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


static int python_detach(void *instance)
{
    int return_value;

    /* Default return value is failure */
    return_value = -1;

    if (((rlm_python_t *)instance)->pFunc_detach &&
	PyCallable_Check(((rlm_python_t *)instance)->pFunc_detach)) {

	PyObject *pArgs, *pValue;

	/* call the function with an empty tuple */

	pArgs = PyTuple_New(0);
	pValue = PyObject_CallObject(((rlm_python_t *)instance)->pFunc_detach,
				     pArgs);

	if (pValue == NULL) {
	    python_error();
	    return -1;
	}
	else {
	    if (!PyInt_Check(pValue)) {
		radlog(L_ERR, "detach: return value not an integer");
	    }
	    else {
		return_value = PyInt_AsLong(pValue);
	    }
	}

	/* Decrease reference counts for the argument and return tuple */
	Py_DECREF(pArgs);
	Py_DECREF(pValue);
    }

    free(instance);

#if 0
    /* xxx test delete module object so it will be reloaded later.
     * xxx useless since we can't SIGHUP reliably, anyway.
     */
    PyObject_Del(((struct rlm_python_t *)instance)->pModule_accounting);
#endif

    radlog(L_DBG, "python_detach done");

    /* Return the specified by the Python module */
    return return_value;
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
	NULL,				/* destroy */
};
