/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_python.c
 * @brief Translates requests between the server an a python interpreter.
 *
 * @note Rewritten by Paul P. Komkoff Jr <i@stingr.net>.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2002  Miguel A.L. Paraz <mparaz@mparaz.com>
 * @copyright 2002  Imperium Technology, Inc.
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <Python.h>
#include <dlfcn.h>

#ifdef HAVE_PTHREAD_H
#define Pyx_BLOCK_THREADS    {PyGILState_STATE __gstate = PyGILState_Ensure();
#define Pyx_UNBLOCK_THREADS   PyGILState_Release(__gstate);}
#else
#define Pyx_BLOCK_THREADS
#define Pyx_UNBLOCK_THREADS
#endif

/*
 *	TODO: The only needed thing here is function. Anything else is
 *	required for initialization only. I will remove it, putting a
 *	symbolic constant here instead.
 */
struct py_function_def {
	PyObject	*module;
	PyObject	*function;

	char const	*module_name;
	char const	*function_name;
};

typedef struct rlm_python_t {
	void		*libpython;
	PyThreadState	*main_thread_state;
	char const	*python_path;

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
} rlm_python_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static CONF_PARSER module_config[] = {

#define A(x) { FR_CONF_OFFSET("mod_" #x, PW_TYPE_STRING, rlm_python_t, x.module_name) }, \
	{ FR_CONF_OFFSET("func_" #x, PW_TYPE_STRING, rlm_python_t, x.function_name) },

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

	{ FR_CONF_OFFSET("python_path", PW_TYPE_STRING, rlm_python_t, python_path) },
	CONF_PARSER_TERMINATOR
};

static struct {
	char const *name;
	int  value;
} radiusd_constants[] = {

#define A(x) { #x, x },

	A(L_DBG)
	A(L_AUTH)
	A(L_INFO)
	A(L_ERR)
	A(L_PROXY)
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
 *	This allows us to initialise PyThreadState on a per thread basis
 */
fr_thread_local_setup(PyThreadState *, local_thread_state)	/* macro */


/*
 *	Let assume that radiusd module is only one since we have only
 *	one intepreter
 */

static PyObject *radiusd_module = NULL;

/*
 *	radiusd Python functions
 */

/* radlog wrapper */
static PyObject *mod_radlog(UNUSED PyObject *module, PyObject *args)
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
	{ "radlog", &mod_radlog, METH_VARARGS,
	  "radiusd.radlog(level, msg)\n\n" \
	  "Print a message using radiusd logging system. level should be one of the\n" \
	  "constants L_DBG, L_AUTH, L_INFO, L_ERR, L_PROXY\n"
	},
	{ NULL, NULL, 0, NULL },
};


static void mod_error(void)
{
	PyObject *pType = NULL, *pValue = NULL, *pTraceback = NULL, *pStr1 = NULL, *pStr2 = NULL;

	/* This will be called with the GIL lock held */

	PyErr_Fetch(&pType, &pValue, &pTraceback);
	if (!pType || !pValue)
		goto failed;
	if (((pStr1 = PyObject_Str(pType)) == NULL) ||
	    ((pStr2 = PyObject_Str(pValue)) == NULL))
		goto failed;

	ERROR("rlm_python:EXCEPT:%s: %s", PyString_AsString(pStr1), PyString_AsString(pStr2));

failed:
	Py_XDECREF(pStr1);
	Py_XDECREF(pStr2);
	Py_XDECREF(pType);
	Py_XDECREF(pValue);
	Py_XDECREF(pTraceback);
}

static int mod_init(rlm_python_t *inst)
{
	int i;
	static char name[] = "radiusd";

	if (radiusd_module) return 0;

	/*
	 *	Explicitly load libpython, so symbols will be available to lib-dynload modules
	 */
	inst->libpython = dlopen("libpython" STRINGIFY(PY_MAJOR_VERSION) "." STRINGIFY(PY_MINOR_VERSION) ".so",
				 RTLD_NOW | RTLD_GLOBAL);
	if (!inst->libpython) {
		WARN("Failed loading libpython symbols into global symbol table: %s", dlerror());
	}

	Py_SetProgramName(name);
#ifdef HAVE_PTHREAD_H
	Py_InitializeEx(0);				/* Don't override signal handlers */
	PyEval_InitThreads(); 				/* This also grabs a lock */
	inst->main_thread_state = PyThreadState_Get();	/* We need this for setting up thread local stuff */
#endif
	if (inst->python_path) {
		char *path;

		memcpy(&path, &inst->python_path, sizeof(path));
		PySys_SetPath(path);
	}

	if ((radiusd_module = Py_InitModule3("radiusd", radiusd_methods,
					     "FreeRADIUS Module")) == NULL)
		goto failed;

	for (i = 0; radiusd_constants[i].name; i++) {
		if ((PyModule_AddIntConstant(radiusd_module, radiusd_constants[i].name,
					     radiusd_constants[i].value)) < 0) {
			goto failed;
		}
	}

#ifdef HAVE_PTHREAD_H
	PyThreadState_Swap(NULL);	/* We have to swap out the current thread else we get deadlocks */
	PyEval_ReleaseLock();		/* Drop lock grabbed by InitThreads */
#endif
	DEBUG("mod_init done");
	return 0;

failed:
	Py_XDECREF(radiusd_module);

#ifdef HAVE_PTHREAD_H
	PyEval_ReleaseLock();
#endif

	Pyx_BLOCK_THREADS
	mod_error();
	Pyx_UNBLOCK_THREADS

	radiusd_module = NULL;

	Py_Finalize();
	return -1;
}

#if 0

static int mod_destroy(void)
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

static void mod_vptuple(TALLOC_CTX *ctx, VALUE_PAIR **vps, PyObject *pValue,
			char const *funcname)
{
	int	     i;
	int	     tuplesize;
	VALUE_PAIR      *vp;

	/*
	 *	If the Python function gave us None for the tuple,
	 *	then just return.
	 */
	if (pValue == Py_None)
		return;

	if (!PyTuple_CheckExact(pValue)) {
		ERROR("rlm_python:%s: non-tuple passed", funcname);
		return;
	}
	/* Get the tuple tuplesize. */
	tuplesize = PyTuple_GET_SIZE(pValue);
	for (i = 0; i < tuplesize; i++) {
		PyObject *pTupleElement = PyTuple_GET_ITEM(pValue, i);
		PyObject *pStr1;
		PyObject *pStr2;
		PyObject *pOp;
		int pairsize;
		char const *s1;
		char const *s2;
		long op;

		if (!PyTuple_CheckExact(pTupleElement)) {
			ERROR("rlm_python:%s: tuple element %d is not a tuple", funcname, i);
			continue;
		}
		/* Check if it's a pair */

		pairsize = PyTuple_GET_SIZE(pTupleElement);
		if ((pairsize < 2) || (pairsize > 3)) {
			ERROR("rlm_python:%s: tuple element %d is a tuple of size %d. Must be 2 or 3.", funcname, i, pairsize);
			continue;
		}

		if (pairsize == 2) {
			pStr1	= PyTuple_GET_ITEM(pTupleElement, 0);
			pStr2	= PyTuple_GET_ITEM(pTupleElement, 1);
			op	= T_OP_EQ;
		} else {
			pStr1	= PyTuple_GET_ITEM(pTupleElement, 0);
			pStr2	= PyTuple_GET_ITEM(pTupleElement, 2);
			pOp	= PyTuple_GET_ITEM(pTupleElement, 1);
			op	= PyInt_AsLong(pOp);
		}

		if ((!PyString_CheckExact(pStr1)) || (!PyString_CheckExact(pStr2))) {
			ERROR("rlm_python:%s: tuple element %d must be as (str, str)", funcname, i);
			continue;
		}
		s1 = PyString_AsString(pStr1);
		s2 = PyString_AsString(pStr2);
		vp = fr_pair_make(ctx, vps, s1, s2, op);
		if (vp != NULL) {
			DEBUG("rlm_python:%s: '%s' = '%s'", funcname, s1, s2);
		} else {
			DEBUG("rlm_python:%s: Failed: '%s' = '%s'", funcname, s1, s2);
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
static int mod_populate_vptuple(PyObject *pPair, VALUE_PAIR *vp)
{
	PyObject *pStr = NULL;
	char buf[1024];

	/* Look at the fr_pair_fprint_name? */

	if (vp->da->flags.has_tag)
		pStr = PyString_FromFormat("%s:%d", vp->da->name, vp->tag);
	else
		pStr = PyString_FromString(vp->da->name);

	if (!pStr)
		goto failed;

	PyTuple_SET_ITEM(pPair, 0, pStr);

	fr_pair_value_snprint(buf, sizeof(buf), vp, '"');

	if ((pStr = PyString_FromString(buf)) == NULL)
		goto failed;
	PyTuple_SET_ITEM(pPair, 1, pStr);

	return 0;

failed:
	return -1;
}

#ifdef HAVE_PTHREAD_H
/** Cleanup any thread local storage on pthread_exit()
 */
static void do_python_cleanup(void *arg)
{
	PyThreadState	*my_thread_state = arg;

	PyEval_AcquireLock();
	PyThreadState_Swap(NULL);	/* Not entirely sure this is needed */
	PyThreadState_Clear(my_thread_state);
	PyThreadState_Delete(my_thread_state);
	PyEval_ReleaseLock();
}
#endif

static rlm_rcode_t do_python(rlm_python_t *inst, REQUEST *request, PyObject *pFunc, char const *funcname, bool worker)
{
	vp_cursor_t	cursor;
	VALUE_PAIR      *vp;
	PyObject	*pRet = NULL;
	PyObject	*pArgs = NULL;
	int		tuplelen;
	int		ret;

	PyGILState_STATE gstate;
	PyThreadState	*prev_thread_state = NULL;	/* -Wuninitialized */
	memset(&gstate, 0, sizeof(gstate));		/* -Wuninitialized */

	/* Return with "OK, continue" if the function is not defined. */
	if (!pFunc)
		return RLM_MODULE_NOOP;

#ifdef HAVE_PTHREAD_H
	gstate = PyGILState_Ensure();
	if (worker) {
		PyThreadState *my_thread_state;
		my_thread_state = fr_thread_local_init(local_thread_state, do_python_cleanup);
		if (!my_thread_state) {
			my_thread_state = PyThreadState_New(inst->main_thread_state->interp);
			RDEBUG3("Initialised new thread state %p", my_thread_state);
			if (!my_thread_state) {
				REDEBUG("Failed initialising local PyThreadState on first run");
				PyGILState_Release(gstate);
				return RLM_MODULE_FAIL;
			}

			ret = fr_thread_local_set(local_thread_state, my_thread_state);
			if (ret != 0) {
				REDEBUG("Failed storing PyThreadState in TLS: %s", fr_syserror(ret));
				PyThreadState_Clear(my_thread_state);
				PyThreadState_Delete(my_thread_state);
				PyGILState_Release(gstate);
				return RLM_MODULE_FAIL;
			}
		}
		RDEBUG3("Using thread state %p", my_thread_state);
		prev_thread_state = PyThreadState_Swap(my_thread_state);	/* Swap in our local thread state */
	}
#endif

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
		for (vp = fr_cursor_init(&cursor, &request->packet->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			tuplelen++;
		}
	}

	if (tuplelen == 0) {
		Py_INCREF(Py_None);
		pArgs = Py_None;
	} else {
		int i = 0;
		if ((pArgs = PyTuple_New(tuplelen)) == NULL) {
			ret = RLM_MODULE_FAIL;
			goto finish;
		}

		for (vp = fr_cursor_init(&cursor, &request->packet->vps);
		     vp;
		     vp = fr_cursor_next(&cursor), i++) {
			PyObject *pPair;

			/* The inside tuple has two only: */
			if ((pPair = PyTuple_New(2)) == NULL) {
				ret = RLM_MODULE_FAIL;
				goto finish;
			}

			if (mod_populate_vptuple(pPair, vp) == 0) {
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

	if (!pRet) {
		ret = RLM_MODULE_FAIL;
		goto finish;
	}

	if (!request)
		goto finish;

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
			ERROR("rlm_python:%s: tuple must be (return, replyTuple, configTuple)", funcname);
			ret = RLM_MODULE_FAIL;
			goto finish;
		}

		pTupleInt = PyTuple_GET_ITEM(pRet, 0);
		if (!PyInt_CheckExact(pTupleInt)) {
			ERROR("rlm_python:%s: first tuple element not an integer", funcname);
			ret = RLM_MODULE_FAIL;
			goto finish;
		}
		/* Now have the return value */
		ret = PyInt_AsLong(pTupleInt);
		/* Reply item tuple */
		mod_vptuple(request->reply, &request->reply->vps,
			    PyTuple_GET_ITEM(pRet, 1), funcname);
		/* Config item tuple */
		mod_vptuple(request, &request->config,
			    PyTuple_GET_ITEM(pRet, 2), funcname);

	} else if (PyInt_CheckExact(pRet)) {
		/* Just an integer */
		ret = PyInt_AsLong(pRet);

	} else if (pRet == Py_None) {
		/* returned 'None', return value defaults to "OK, continue." */
		ret = RLM_MODULE_OK;
	} else {
		/* Not tuple or None */
		ERROR("rlm_python:%s: function did not return a tuple or None", funcname);
		ret = RLM_MODULE_FAIL;
		goto finish;
	}

finish:
	Py_XDECREF(pArgs);
	Py_XDECREF(pRet);

#ifdef HAVE_PTHREAD_H
	if (worker) {
		PyThreadState_Swap(prev_thread_state);
	}
	PyGILState_Release(gstate);
#endif

	return ret;
}

/*
 *	Import a user module and load a function from it
 */

static int mod_load_function(struct py_function_def *def)
{
	char const *funcname = "mod_load_function";
	PyGILState_STATE gstate;

	gstate = PyGILState_Ensure();

	if (def->module_name != NULL && def->function_name != NULL) {
		if ((def->module = PyImport_ImportModule(def->module_name)) == NULL) {
			ERROR("rlm_python:%s: module '%s' is not found", funcname, def->module_name);
			goto failed;
		}

		if ((def->function = PyObject_GetAttrString(def->module, def->function_name)) == NULL) {
			ERROR("rlm_python:%s: function '%s.%s' is not found", funcname, def->module_name, def->function_name);
			goto failed;
		}

		if (!PyCallable_Check(def->function)) {
			ERROR("rlm_python:%s: function '%s.%s' is not callable", funcname, def->module_name, def->function_name);
			goto failed;
		}
	}
	PyGILState_Release(gstate);
	return 0;

failed:
	mod_error();
	ERROR("rlm_python:%s: failed to import python function '%s.%s'", funcname, def->module_name, def->function_name);
	Py_XDECREF(def->function);
	def->function = NULL;
	Py_XDECREF(def->module);
	def->module = NULL;
	PyGILState_Release(gstate);
	return -1;
}


static void mod_objclear(PyObject **ob)
{
	if (*ob != NULL) {
		Pyx_BLOCK_THREADS
		Py_DECREF(*ob);
		Pyx_UNBLOCK_THREADS
		*ob = NULL;
	}
}

static void mod_funcdef_clear(struct py_function_def *def)
{
	mod_objclear(&def->function);
	mod_objclear(&def->module);
}

static void mod_instance_clear(rlm_python_t *inst)
{
#define A(x) mod_funcdef_clear(&inst->x)

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
static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	rlm_python_t *inst = instance;

	if (mod_init(inst) != 0) {
		return -1;
	}

#define A(x) if (mod_load_function(&inst->x) < 0) goto failed

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

	/*
	 *	Call the instantiate function.  No request.  Use the
	 *	return value.
	 */
	return do_python(inst, NULL, inst->instantiate.function, "instantiate", false);
failed:
	Pyx_BLOCK_THREADS
	mod_error();
	Pyx_UNBLOCK_THREADS
	mod_instance_clear(inst);
	return -1;
}

static int mod_detach(void *instance)
{
	rlm_python_t *inst = instance;
	int	     ret;

	/*
	 *	Master should still have no thread state
	 */
	ret = do_python(inst, NULL, inst->detach.function, "detach", false);

	mod_instance_clear(inst);
	dlclose(inst->libpython);

	return ret;
}

#define A(x) static rlm_rcode_t CC_HINT(nonnull) mod_##x(void *instance, REQUEST *request) { \
		return do_python((rlm_python_t *) instance, request, ((rlm_python_t *)instance)->x.function, #x, true);\
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
extern module_t rlm_python;
module_t rlm_python = {
	.magic		= RLM_MODULE_INIT,
	.name		= "python",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_python_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_SESSION]		= mod_checksimul,
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
		[MOD_POST_AUTH]		= mod_post_auth,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_recv_coa,
		[MOD_SEND_COA]		= mod_send_coa
#endif
	}
};
