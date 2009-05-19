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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2002  Miguel A.L. Paraz <mparaz@mparaz.com>
 * Copyright 2002  Imperium Technology, Inc.
 * - rewritten by Paul P. Komkoff Jr <i@stingr.net>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <Python.h>

#define Pyx_BLOCK_THREADS    {PyGILState_STATE __gstate = PyGILState_Ensure();
#define Pyx_UNBLOCK_THREADS   PyGILState_Release(__gstate);}

/*
 *	TODO: The only needed thing here is function. Anything else is
 *	required for initialization only. I will remove it, putting a
 *	symbolic constant here instead.
 */
struct py_function_def {
	PyObject *module;
	PyObject *function;
	
	char     *module_name;
	char     *function_name;
}; 

struct rlm_python_t {
	struct py_function_def 
		instantiate,
		authorize,
		authenticate,
		preacct,
		accounting,
		checksimul,
		pre_proxy,
		post_proxy,
		post_auth,
#ifdef WITH_COA
		recv_coa,
		send_coa,
#endif
		detach;
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

#define A(x) { "mod_" #x, PW_TYPE_STRING_PTR, offsetof(struct rlm_python_t, x.module_name), NULL, NULL }, \
  { "func_" #x, PW_TYPE_STRING_PTR, offsetof(struct rlm_python_t, x.function_name), NULL, NULL },

  A(instantiate)
  A(authorize)
  A(authenticate)
  A(preacct)
  A(accounting)
  A(checksimul)
  A(pre_proxy)
  A(post_proxy)
  A(post_auth)
#ifdef WITH_COA
  A(recv_coa)
  A(send_coa)
#endif
  A(detach)

#undef A

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

static struct {
  const char *name;
  int  value;
} radiusd_constants[] = {

#define A(x) { #x, x },

  A(L_DBG)
  A(L_AUTH)
  A(L_INFO)
  A(L_ERR)
  A(L_PROXY)
  A(L_CONS)
  A(RLM_MODULE_REJECT)
  A(RLM_MODULE_FAIL)
  A(RLM_MODULE_OK)
  A(RLM_MODULE_HANDLED)
  A(RLM_MODULE_INVALID)
  A(RLM_MODULE_USERLOCK)
  A(RLM_MODULE_NOTFOUND)
  A(RLM_MODULE_NOOP)
  A(RLM_MODULE_UPDATED)
  A(RLM_MODULE_NUMCODES)

#undef A

  { NULL, 0 },
};


/*
 *	Let assume that radiusd module is only one since we have only
 *	one intepreter
 */

static PyObject *radiusd_module = NULL;

/*
 *	radiusd Python functions
 */

/* radlog wrapper */
static PyObject *python_radlog(UNUSED PyObject *module, PyObject *args)
{
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
	{ "radlog", &python_radlog, METH_VARARGS, 
	  "radiusd.radlog(level, msg)\n\n" \
	  "Print a message using radiusd logging system. level should be one of the\n" \
	  "constants L_DBG, L_AUTH, L_INFO, L_ERR, L_PROXY, L_CONS\n"
	},
	{ NULL, NULL, 0, NULL },
};


static void python_error(void)
{
	PyObject 
		*pType = NULL,
		*pValue = NULL,
		*pTraceback = NULL,
		*pStr1 = NULL,
		*pStr2 = NULL;
	
	Pyx_BLOCK_THREADS

	PyErr_Fetch(&pType, &pValue, &pTraceback);
	if (pType == NULL || pValue == NULL)
		goto failed;
	if (((pStr1 = PyObject_Str(pType)) == NULL) ||
	    ((pStr2 = PyObject_Str(pValue)) == NULL))
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

static int python_init(void)
{
	int i;

	if (radiusd_module) return 0;
	
	Py_SetProgramName("radiusd");
	Py_Initialize();
	PyEval_InitThreads(); /* This also grabs a lock */
	
	if ((radiusd_module = Py_InitModule3("radiusd", radiusd_methods, 
					     "FreeRADIUS Module.")) == NULL)
		goto failed;
	
	for (i = 0; radiusd_constants[i].name; i++)
		if ((PyModule_AddIntConstant(radiusd_module,
					     radiusd_constants[i].name, 
					     radiusd_constants[i].value)) < 0)
			goto failed;
	
	PyEval_ReleaseLock(); /* Drop lock grabbed by InitThreads */
	
	radlog(L_DBG, "python_init done");
	return 0;
	
 failed:
	python_error();
	Py_XDECREF(radiusd_module);
	radiusd_module = NULL;
	Py_Finalize();
	return -1;
}

#if 0

static int python_destroy(void)
{
	Pyx_BLOCK_THREADS
	Py_XDECREF(radiusd_module);
	Py_Finalize();
	Pyx_UNBLOCK_THREADS
	return 0;
}

/*
 *	This will need reconsidering in a future. Maybe we'll need to
 *	have our own reference counting for radiusd_module
 */
#endif

/* TODO: Convert this function to accept any iterable objects? */

static void python_vptuple(VALUE_PAIR **vpp, PyObject *pValue,
			   const char *funcname)
{
        int             i;
        int             tuplesize;
        VALUE_PAIR      *vp;

        /*
	 *	If the Python function gave us None for the tuple,
	 *	then just return.
	 */
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


/*
 *	This is the core Python function that the others wrap around.
 *	Pass the value-pair print strings in a tuple.
 *
 *	FIXME: We're not checking the errors. If we have errors, what
 *	do we do?
 */
static int python_populate_vptuple(PyObject *pPair, VALUE_PAIR *vp)
{
	PyObject *pStr = NULL;
	char buf[1024];
	
	/* Look at the vp_print_name? */
	
	if (vp->flags.has_tag)
		pStr = PyString_FromFormat("%s:%d", vp->name, vp->flags.tag);
	else
		pStr = PyString_FromString(vp->name);
	
	if (pStr == NULL)
		goto failed;
	
	PyTuple_SET_ITEM(pPair, 0, pStr);
	
	vp_prints_value(buf, sizeof(buf), vp, 1);
	
	if ((pStr = PyString_FromString(buf)) == NULL)
		goto failed;
	PyTuple_SET_ITEM(pPair, 1, pStr);
	
	return 0;
	
 failed:
	return -1;
}

static int python_function(REQUEST *request, PyObject *pFunc,
			   const char *funcname)
{
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
	
	/*
	 *	We will pass a tuple containing (name, value) tuples
	 *	We can safely use the Python function to build up a
	 *	tuple, since the tuple is not used elsewhere.
	 *
	 *	Determine the size of our tuple by walking through the packet.
	 *	If request is NULL, pass None.
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
		int i = 0;
		if ((pArgs = PyTuple_New(tuplelen)) == NULL)
			goto failed;

		for (vp = request->packet->vps;
		     vp != NULL;
		     vp = vp->next, i++) {
			PyObject *pPair;
			
			/* The inside tuple has two only: */
			if ((pPair = PyTuple_New(2)) == NULL)
				goto failed;
			
			if (python_populate_vptuple(pPair, vp) == 0) {
				/* Put the tuple inside the container */
				PyTuple_SET_ITEM(pArgs, i, pPair);
			} else {
				Py_INCREF(Py_None);
				PyTuple_SET_ITEM(pArgs, i, Py_None);
				Py_DECREF(pPair);
			}
		}
	}
	
	/* Call Python function. */
	pRet = PyObject_CallFunctionObjArgs(pFunc, pArgs, NULL);
	
	if (pRet == NULL)
		goto failed;
	
	if (request == NULL)
		goto okay;

	/*
	 *	The function returns either:
	 *  1. (returnvalue, replyTuple, configTuple), where
	 *   - returnvalue is one of the constants RLM_*
	 *   - replyTuple and configTuple are tuples of string
	 *      tuples of size 2
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
		python_vptuple(&request->reply->vps,
			       PyTuple_GET_ITEM(pRet, 1), funcname);
		/* Config item tuple */
		python_vptuple(&request->config_items,
			       PyTuple_GET_ITEM(pRet, 2), funcname);

	} else if (PyInt_CheckExact(pRet)) {
		/* Just an integer */
		ret = PyInt_AsLong(pRet);

	} else if (pRet == Py_None) {
		/* returned 'None', return value defaults to "OK, continue." */
		ret = RLM_MODULE_OK;
	} else {
		/* Not tuple or None */
		radlog(L_ERR, "rlm_python:%s: function did not return a tuple or None", funcname);
		goto failed;
	}

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
 *	Import a user module and load a function from it
 */

static int python_load_function(struct py_function_def *def)
{
	const char *funcname = "python_load_function";
	PyGILState_STATE gstate;
	
	gstate = PyGILState_Ensure();
	
	if (def->module_name != NULL && def->function_name != NULL) {
		if ((def->module = PyImport_ImportModule(def->module_name)) == NULL) {
			radlog(L_ERR, "rlm_python:%s: module '%s' is not found", funcname, def->module_name);
			goto failed;
		}
		
		if ((def->function = PyObject_GetAttrString(def->module, def->function_name)) == NULL) {
			radlog(L_ERR, "rlm_python:%s: function '%s.%s' is not found", funcname, def->module_name, def->function_name);
			goto failed;
		}
		
		if (!PyCallable_Check(def->function)) {
			radlog(L_ERR, "rlm_python:%s: function '%s.%s' is not callable", funcname, def->module_name, def->function_name);
			goto failed;
		}
	}
	PyGILState_Release(gstate);
	return 0;
	
 failed:
	python_error();
	radlog(L_ERR, "rlm_python:%s: failed to import python function '%s.%s'", funcname, def->module_name, def->function_name);
	Py_XDECREF(def->function);
	def->function = NULL;
	Py_XDECREF(def->module);
	def->module = NULL;
	PyGILState_Release(gstate);
	return -1;
}


static void python_objclear(PyObject **ob)
{
	if (*ob != NULL) {
		Pyx_BLOCK_THREADS
		Py_DECREF(*ob);
		Pyx_UNBLOCK_THREADS
	        *ob = NULL;
	}
}

static void free_and_null(char **p)
{
	if (*p != NULL) {
		free(*p);
		*p = NULL;
	}
}

static void python_funcdef_clear(struct py_function_def *def)
{
	python_objclear(&def->function);
	python_objclear(&def->module);
	free_and_null(&def->function_name);
	free_and_null(&def->module_name);
}

static void python_instance_clear(struct rlm_python_t *data)
{
#define A(x) python_funcdef_clear(&data->x)
	
	A(instantiate);
	A(authorize);
	A(authenticate);
	A(preacct);
	A(accounting);
	A(checksimul);
	A(detach);

#undef A
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
        struct rlm_python_t    *data = NULL;

        /*
         *      Set up a storage area for instance data
         */
        if ((data = malloc(sizeof(*data))) == NULL)
                return -1;
        memset(data, 0, sizeof(*data));

        if (python_init() != 0) {
		free(data);
		return -1;
        }

        /*
         *      If the configuration parameters can't be parsed, then
         *      fail.
         */
        if (cf_section_parse(conf, data, module_config) < 0) {
                free(data);
                return -1;
        }

#define A(x) if (python_load_function(&data->x) < 0) goto failed

        A(instantiate);
        A(authenticate);
        A(authorize);
        A(preacct);
        A(accounting);
        A(checksimul);
        A(pre_proxy);
        A(post_proxy);
        A(post_auth);
#ifdef WITH_COA
        A(recv_coa);
        A(send_coa);
#endif
        A(detach);

#undef A

        *instance = data;

        /*
	 *	Call the instantiate function.  No request.  Use the
	 *	return value.
	 */
	return python_function(NULL, data->instantiate.function,
			       "instantiate");
 failed:
        python_error();
        python_instance_clear(data);
        free(data);
        return -1;
}

static int python_detach(void *instance)
{
        struct rlm_python_t    *data = (struct rlm_python_t *) instance;
        int             ret;
	
        ret = python_function(NULL, data->detach.function, "detach");
	
        python_instance_clear(data);
	
        free(data);
        return ret;
}

#define A(x) static int python_##x(void *instance, REQUEST *request) { \
  return python_function(request, ((struct rlm_python_t *)instance)->x.function, #x); \
}

A(authenticate)
A(authorize)
A(preacct)
A(accounting)
A(checksimul)
A(pre_proxy)
A(post_proxy)
A(post_auth)
#ifdef WITH_COA
A(recv_coa)
A(send_coa)
#endif

#undef A

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
	RLM_MODULE_INIT,
	"python",
	RLM_TYPE_THREAD_SAFE,		/* type */
	python_instantiate,		/* instantiation */
        python_detach,
	{
		python_authenticate,	/* authentication */
		python_authorize,	/* authorization */
		python_preacct,		/* preaccounting */
		python_accounting,	/* accounting */
		python_checksimul,	/* checksimul */
		python_pre_proxy,	/* pre-proxy */
		python_post_proxy,	/* post-proxy */
		python_post_auth	/* post-auth */
#ifdef WITH_COA
		, python_recv_coa,
		python_send_coa
#endif
	}
};
