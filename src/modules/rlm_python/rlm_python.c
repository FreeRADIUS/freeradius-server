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
 */

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

#include <Python.h>

#if 0
static const char rcsid[] = "$Id$";
#endif

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_python_t {
    /* Config section */
    char		*mod_authorize;  /* Name of authorization module */
    char		*func_authorize; /* Name of authorization function */
    /* End Config section */

    /* xxx To keep things simple, all functions should initially be
     * xxx in one module.
     */

    PyObject *pModule, *pFunc_authorize;
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

#if 0
static CONF_PARSER module_config[] = {
  { "integer", PW_TYPE_INTEGER,    offsetof(rlm_python_t,value), NULL,   "1" },
  { "boolean", PW_TYPE_BOOLEAN,    offsetof(rlm_python_t,boolean), NULL, "no"},
  { "string",  PW_TYPE_STRING_PTR, offsetof(rlm_python_t,string), NULL,  NULL},
  { "ipaddr",  PW_TYPE_IPADDR,     offsetof(rlm_python_t,ipaddr), NULL,  "*" },

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

#else

static CONF_PARSER module_config[] = {
  { "mod_authorize",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t,mod_authorize), NULL,  NULL},
  { "func_authorize",  PW_TYPE_STRING_PTR,
    offsetof(rlm_python_t,func_authorize), NULL,  NULL},

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};
#endif


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
     * Initialize Python interpreter
     */
    Py_Initialize();

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
 */
static int python_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_python_t *data;
	PyObject *pName;
	
	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}
	
	*instance = data;

	pName = PyString_FromString(data->mod_authorize);

	/* Import module */
	data->pModule = PyImport_Import(pName);
	if (data->pModule != NULL) {
	    PyObject *pDict;

	    pDict = PyModule_GetDict(data->pModule);
	    /* pDict: borrowed reference */

	    data->pFunc_authorize =
		PyDict_GetItemString(pDict, data->func_authorize);
	    /* pFunc: Borrowed reference */
	}
	else {
	    /* xxx Change this to dump error message to log xxx */
	    PyErr_Print();

	    radlog(L_ERR, "Failed to load \"%s\"\n", data->mod_authorize);
	    return -1;
	}

	/* xxx Should we check if function is callable now?
	 * xxx or later when it is used, since it can change...
	 */ 

	
	return 0;
}

/* Pass the value-pair print strings in a tuple.
   xxx We're not checking the errors. If we have errors, what do we do?
*/
static int python_authorize(void *instance, REQUEST *request)
{
    VALUE_PAIR	*vp;
    char buf[1024];		/* same size as vp_print buffer */
    PyObject *pValue, *pValuePairContainer, **pValueHolder, **pValueHolderPtr;
    int i, n_tuple, return_value;
    
#define inst ((struct rlm_python_t *)instance)

    /* Default return value is failure */
    return_value = -1;

    /* We will pass a tuple containing (name, value) tuples 
     * We can safely use the Python function to build up a tuple,
     * since the tuple is not used elsewhere.
     *
     * Determine the size of our tuple by walking through the packet.
     */
    n_tuple = 0;

    for (vp = request->packet->vps; vp; vp = vp->next) {
	n_tuple++;
    }
	
    /* Create the tuple and a holder for the pointers, so that we can
     * decref more efficiently later without the overhead of reading
     * the tuple.
     */
    pValuePairContainer = PyTuple_New(n_tuple);
    if (NULL == (pValueHolder = pValueHolderPtr =
		 malloc(sizeof(PyObject *) * n_tuple))) {
	
	radlog(L_ERR, "malloc of %d bytes failed\n",
	       sizeof(PyObject *) * n_tuple);
	
	return -1;
    }
    
    i = 0;
    for (vp = request->packet->vps; vp; vp = vp->next) {
	PyObject *pValuePair, *pString1, *pString2;
	
	/* The inside tuple has two only: */
	pValuePair = PyTuple_New(2);
	
	/* The name. logic from vp_prints, lib/print.c */
	if (vp->flags.has_tag) {
	    sprintf(buf, "%s:%d", vp->name, vp->flags.tag);
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
    
    /* Call Python function.
     * xxx need to make visible wrappers for functions such as radlog
     */
    
    if (inst->pFunc_authorize && PyCallable_Check(inst->pFunc_authorize)) {
	PyObject *pArgs;
	
	/* xxx this should have error checking xxx */
	
	/* call the function with a singleton tuple containing the
	 * value-pair container tuple.
	 */
	pArgs = PyTuple_New(1);
	PyTuple_SetItem(pArgs, 0, pValuePairContainer);
	
	pValue = PyObject_CallObject(inst->pFunc_authorize, pArgs);
	
	if (pValue == NULL) {
	    PyErr_Print();
	    return -1;
	}

	/* Returns a tuple for the function return value,
	 * then the strings to build the reply with. */
	if (PyTuple_Check(pValue)) {
	    PyObject *pTupleInt;
	    int n;

	    n = PyTuple_Size(pValue);


	    if (n == 0) {
		radlog(L_ERR, "tuple must have at least one element");
	    }
	    else if (pTupleInt = PyTuple_GetItem(pValue, 0),
		     !PyInt_Check(pTupleInt)) {
		radlog(L_ERR, "first tuple element not an integer");
	    }
	    else {
		return_value = PyInt_AsLong(pTupleInt);
		
		
		
		for (i = 1; i < n; i++) {
		    PyObject *pTupleElement = PyTuple_GetItem(pValue, i);
		    
		    if (PyTuple_Check(pTupleElement)) {
			/* Check if it's a pair */
			int m;
			
			if ((m = PyTuple_Size(pTupleElement)) != 2) {
			    radlog(L_ERR, "tuple element %d is a tuple "
				   " of size %d. must be 2\n", i, m);
			}
			else {
			    PyObject *pString1, *pString2;
			    
			    pString1 = PyTuple_GetItem(pTupleElement, 0);
			    pString2 = PyTuple_GetItem(pTupleElement, 1);

			    if (PyString_Check(pString1) &&
				PyString_Check(pString2)) {
				char *s1, *s2;
				
				/* pairmake() will convert and find any
				 * errors in the pair.
				 */

				s1 = PyString_AsString(pString1);
				s2 = PyString_AsString(pString2);

				radlog(L_DBG, "python: %s = %s ", s1, s2);

				vp = pairmake(s1, s2, T_OP_EQ);
				if (vp != NULL) {
				    pairadd(&request->packet->vps, vp);
				    radlog(L_DBG, "OK\n");
				}
				else {
				    radlog(L_DBG, "FAILED\n");
				}

			    }
			    else {
				radlog(L_ERR, "tuple element %d must be "
				       "(string, string)", i);
			    }
			}
		    }
		    else {
			radlog(L_ERR, "tuple element %d is not a tuple\n", i);
		    }
		}
	    }
	}
	else {
	    /* Not a tuple */
	    radlog(L_ERR, "authorize function did not return a tuple\n");
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

    
    /* Return the specified by the Python module */
    return return_value;
}



static int python_detach(void *instance)
{
	free(instance);
	return 0;
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
#if 0
		python_authenticate,	/* authentication */
#else
		NULL,
#endif	      
		python_authorize,	/* authorization */
#if 0	    

		python_preacct,	/* preaccounting */
		python_accounting,	/* accounting */
		python_checksimul	/* checksimul */
#else
		NULL,
		NULL,
		NULL,
#endif		
	},
	python_detach,			/* detach */
	NULL,				/* destroy */
};
