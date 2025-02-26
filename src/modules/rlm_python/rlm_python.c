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
 * @copyright 2000,2006,2015-2016  The FreeRADIUS server project
 * @copyright 2002  Miguel A.L. Paraz <mparaz@mparaz.com>
 * @copyright 2002  Imperium Technology, Inc.
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_python - "

#include "config.h"
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <Python.h>
#include <frameobject.h> /* Python header not pulled in by default. */
#include <dlfcn.h>
#ifdef HAVE_DL_ITERATE_PHDR
#include <link.h>
#endif

#define LIBPYTHON_LINKER_NAME \
	"libpython" STRINGIFY(PY_MAJOR_VERSION) "." STRINGIFY(PY_MINOR_VERSION) LT_SHREXT

static uint32_t		python_instances = 0;
static void		*python_dlhandle;

static PyThreadState	*main_interpreter;	//!< Main interpreter (cext safe)
static PyObject		*main_module;		//!< Pthon configuration dictionary.

/** Specifies the module.function to load for processing a section
 *
 */
typedef struct python_func_def {
	PyObject	*module;		//!< Python reference to module.
	PyObject	*function;		//!< Python reference to function in module.

	char const	*module_name;		//!< String name of module.
	char const	*function_name;		//!< String name of function in module.
} python_func_def_t;

/** An instance of the rlm_python module
 *
 */
typedef struct rlm_python_t {
	char const	*name;			//!< Name of the module instance
	PyThreadState	*sub_interpreter;	//!< The main interpreter/thread used for this instance.
	char const	*python_path;		//!< Path to search for python files in.

#if PY_VERSION_HEX > 0x03050000
	wchar_t		*wide_name;		//!< Special wide char encoding of radiusd name.
#endif
	PyObject	*module;		//!< Local, interpreter specific module, containing
						//!< FreeRADIUS functions.
	bool		cext_compat;		//!< Whether or not to create sub-interpreters per module
						//!< instance.

	python_func_def_t
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

	PyObject	*pythonconf_dict;	//!< Configuration parameters defined in the module
						//!< made available to the python script.
	bool 		pass_all_vps;		//!< Pass all VPS lists (request, reply, config, state, proxy_req, proxy_reply)
	bool 		pass_all_vps_dict;		//!< Pass all VPS lists as a dictionary rather than a tuple
} rlm_python_t;

/** Tracks a python module inst/thread state pair
 *
 * Multiple instances of python create multiple interpreters and each
 * thread must have a PyThreadState per interpreter, to track execution.
 */
typedef struct python_thread_state {
	PyThreadState		*state;		//!< Module instance/thread specific state.
	rlm_python_t		*inst;		//!< Module instance that created this thread state.
} python_thread_state_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static CONF_PARSER module_config[] = {

#define A(x) { "mod_" #x, FR_CONF_OFFSET(PW_TYPE_STRING, rlm_python_t, x.module_name), NULL }, \
	{ "func_" #x, FR_CONF_OFFSET(PW_TYPE_STRING, rlm_python_t, x.function_name), NULL },

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

	{ "python_path", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_python_t, python_path), NULL },
	{ "cext_compat", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_python_t, cext_compat), "yes" },
	{ "pass_all_vps", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_python_t, pass_all_vps), "no" },
	{ "pass_all_vps_dict", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_python_t, pass_all_vps_dict), "no" },

	CONF_PARSER_TERMINATOR
};

static struct {
	char const *name;
	int  value;
} radiusd_constants[] = {

#define A(x) { #x, x },

	A(L_DBG)
	A(L_WARN)
	A(L_AUTH)
	A(L_INFO)
	A(L_ERR)
	A(L_PROXY)
	A(L_ACCT)
	A(L_DBG_WARN)
	A(L_DBG_ERR)
	A(L_DBG_WARN_REQ)
	A(L_DBG_ERR_REQ)
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
fr_thread_local_setup(rbtree_t *, local_thread_state)	/* macro */

/*
 *	radiusd Python functions
 */

/** Allow radlog to be called from python
 *
 */
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

static PyMethodDef module_methods[] = {
	{ "radlog", &mod_radlog, METH_VARARGS,
	  "radiusd.radlog(level, msg)\n\n" \
	  "Print a message using radiusd logging system. level should be one of the\n" \
	  "constants L_DBG, L_AUTH, L_INFO, L_ERR, L_PROXY\n"
	},
	{ NULL, NULL, 0, NULL },
};

/** Print out the current error
 *
 * Must be called with a valid thread state set
 */
static void python_error_log(void)
{
	PyObject *p_type = NULL, *p_value = NULL, *p_traceback = NULL, *p_str_1 = NULL, *p_str_2 = NULL;

	PyErr_Fetch(&p_type, &p_value, &p_traceback);
	PyErr_NormalizeException(&p_type, &p_value, &p_traceback);
	if (!p_type || !p_value) goto failed;

	if (((p_str_1 = PyObject_Str(p_type)) == NULL) || ((p_str_2 = PyObject_Str(p_value)) == NULL)) goto failed;

	ERROR("%s (%s)", PyString_AsString(p_str_1), PyString_AsString(p_str_2));

	if (p_traceback != Py_None) {
		PyTracebackObject *ptb = (PyTracebackObject*)p_traceback;
		size_t fnum = 0;

		for (; ptb != NULL; ptb = ptb->tb_next, fnum++) {
			PyFrameObject *cur_frame = ptb->tb_frame;

			ERROR("[%ld] %s:%d at %s()",
				fnum,
				PyString_AsString(cur_frame->f_code->co_filename),
				PyFrame_GetLineNumber(cur_frame),
				PyString_AsString(cur_frame->f_code->co_name)
			);
		}
	}

failed:
	Py_XDECREF(p_str_1);
	Py_XDECREF(p_str_2);
	Py_XDECREF(p_type);
	Py_XDECREF(p_value);
	Py_XDECREF(p_traceback);
}

static void mod_vptuple(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR **vps, PyObject *pValue,
			char const *funcname, char const *list_name)
{
	int	     i;
	int	     tuplesize;
	vp_tmpl_t       dst;
	VALUE_PAIR      *vp;
	REQUEST         *current = request;

	memset(&dst, 0, sizeof(dst));

	/*
	 *	If the Python function gave us None for the tuple,
	 *	then just return.
	 */
	if (pValue == Py_None || pValue == NULL) return;

	if (!PyTuple_CheckExact(pValue)) {
		ERROR("%s - non-tuple passed to %s", funcname, list_name);
		return;
	}
	/* Get the tuple tuplesize. */
	tuplesize = PyTuple_GET_SIZE(pValue);
	for (i = 0; i < tuplesize; i++) {
		PyObject 	*pTupleElement = PyTuple_GET_ITEM(pValue, i);
		PyObject 	*pStr1;
		PyObject 	*pStr2;
		PyObject 	*pOp;
		int		pairsize;
		char const	*s1;
		char const	*s2;
		FR_TOKEN	op = T_OP_EQ;

		if (!PyTuple_CheckExact(pTupleElement)) {
			ERROR("%s - Tuple element %d of %s is not a tuple", funcname, i, list_name);
			continue;
		}
		/* Check if it's a pair */

		pairsize = PyTuple_GET_SIZE(pTupleElement);
		if ((pairsize < 2) || (pairsize > 3)) {
			ERROR("%s - Tuple element %d of %s is a tuple of size %d. Must be 2 or 3",
			      funcname, i, list_name, pairsize);
			continue;
		}

		pStr1 = PyTuple_GET_ITEM(pTupleElement, 0);
		pStr2 = PyTuple_GET_ITEM(pTupleElement, pairsize-1);

		if ((!PyString_CheckExact(pStr1)) || (!PyString_CheckExact(pStr2))) {
			ERROR("%s - Tuple element %d of %s must be as (str, str)",
			      funcname, i, list_name);
			continue;
		}
		s1 = PyString_AsString(pStr1);
		s2 = PyString_AsString(pStr2);

		if (pairsize == 3) {
			pOp = PyTuple_GET_ITEM(pTupleElement, 1);
			if (PyString_CheckExact(pOp)) {
				if (!(op = fr_str2int(fr_tokens, PyString_AsString(pOp), 0))) {
					ERROR("%s - Invalid operator %s:%s %s %s, falling back to '='",
					      funcname, list_name, s1, PyString_AsString(pOp), s2);
					op = T_OP_EQ;
				}
			} else if (PyInt_Check(pOp)) {
				op	= PyInt_AsLong(pOp);
				if (!fr_int2str(fr_tokens, op, NULL)) {
					ERROR("%s - Invalid operator %s:%s %i %s, falling back to '='",
					      funcname, list_name, s1, op, s2);
					op = T_OP_EQ;
				}
			} else {
				ERROR("%s - Invalid operator type for %s:%s ? %s, using default '='",
				      funcname, list_name, s1, s2);
			}
		}

		if (tmpl_from_attr_str(&dst, s1, REQUEST_CURRENT, PAIR_LIST_REPLY, false, false) <= 0) {
			ERROR("%s - Failed to find attribute %s:%s", funcname, list_name, s1);
			continue;
		}

		if (radius_request(&current, dst.tmpl_request) < 0) {
			ERROR("%s - Attribute name %s:%s refers to outer request but not in a tunnel, skipping...",
			      funcname, list_name, s1);
			continue;
		}

		if (!(vp = fr_pair_afrom_da(ctx, dst.tmpl_da))) {
			ERROR("%s - Failed to create attribute %s:%s", funcname, list_name, s1);
			continue;
		}

		vp->op = op;
		vp->tag = dst.tmpl_tag;

		if (fr_pair_value_from_str(vp, s2, -1) < 0) {
			DEBUG("%s - Failed: '%s:%s' %s '%s'", funcname, list_name, s1,
			      fr_int2str(fr_tokens, op, "="), s2);
		} else {
			DEBUG("%s - '%s:%s' %s '%s'", funcname, list_name, s1,
			      fr_int2str(fr_tokens, op, "="), s2);
		}

		radius_pairmove(current, vps, vp, false);
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

	if (vp->da->flags.has_tag) {
		pStr = PyString_FromFormat("%s:%d", vp->da->name, vp->tag);
	} else {
		pStr = PyString_FromString(vp->da->name);
	}

	if (!pStr) return -1;

	PyTuple_SET_ITEM(pPair, 0, pStr);

	vp_prints_value(buf, sizeof(buf), vp, '\0');	/* Python doesn't need any escaping */

	pStr = PyString_FromString(buf);
	if (pStr == NULL) return -1;

	PyTuple_SET_ITEM(pPair, 1, pStr);

	return 0;
}

/*
 * This function generates a tuple representing a given VPS and inserts it into
 * the indicated position in the tuple pArgs.
 * Returns false on error.
 */
static bool mod_populate_vps(PyObject* pArgs, const int pos, VALUE_PAIR *vps)
{
	PyObject *vps_tuple = NULL;
	int tuplelen = 0;
	int i = 0;
	vp_cursor_t	cursor;
	VALUE_PAIR 	*vp;

	/* If vps is NULL, return None */
	if (vps == NULL) {
		Py_INCREF(Py_None);
		PyTuple_SET_ITEM(pArgs, pos, Py_None);
		return true;
	}

	/*
	 *	We will pass a tuple containing (name, value) tuples
	 *	We can safely use the Python function to build up a
	 *	tuple, since the tuple is not used elsewhere.
	 *
	 *	Determine the size of our tuple by walking through the vps.
	 */
	for (vp = fr_cursor_init(&cursor, &vps); vp; vp = fr_cursor_next(&cursor))
		tuplelen++;

	if ((vps_tuple = PyTuple_New(tuplelen)) == NULL) goto error;

	for (vp = fr_cursor_init(&cursor, &vps); vp; vp = fr_cursor_next(&cursor), i++) {
		PyObject *pPair = NULL;

		/* The inside tuple has two only: */
		if ((pPair = PyTuple_New(2)) == NULL) goto error;

		if (mod_populate_vptuple(pPair, vp) == 0) {
			/* Put the tuple inside the container */
			PyTuple_SET_ITEM(vps_tuple, i, pPair);
		} else {
			Py_INCREF(Py_None);
			PyTuple_SET_ITEM(vps_tuple, i, Py_None);
			Py_DECREF(pPair);
		}
	}
	PyTuple_SET_ITEM(pArgs, pos, vps_tuple);
	return true;

error:
	Py_XDECREF(vps_tuple);
	return false;
}

static rlm_rcode_t do_python_single(REQUEST *request, PyObject *pFunc, char const *funcname, bool pass_all_vps, bool pass_all_vps_dict)
{
	PyObject	*pRet = NULL;
	PyObject	*pArgs = NULL;
	PyObject 	*pDictInput = NULL;
	int		ret;
	int 		i;

	/* Default return value is "OK, continue" */
	ret = RLM_MODULE_OK;

	/*
	 * pArgs is a 6-tuple with (Request, Reply, Config, State, Proxy-Request, Proxy-Reply)
	 * If some list is not available, NONE is used instead
	 */
	if ((pArgs = PyTuple_New(6)) == NULL) {
		ret = RLM_MODULE_FAIL;
		goto finish;
	}

	/* If there is a request, fill in the first 4 attribute lists */
	if (request != NULL) {
		if (!mod_populate_vps(pArgs, 0, request->packet->vps) ||
		    !mod_populate_vps(pArgs, 1, request->reply->vps) ||
		    !mod_populate_vps(pArgs, 2, request->config) ||
		    !mod_populate_vps(pArgs, 3, request->state)) {
			ret = RLM_MODULE_FAIL;
			goto finish;
		}

		/* fill proxy vps */
		if (request->proxy) {
			if (!mod_populate_vps(pArgs, 4, request->proxy->vps)) {
				ret = RLM_MODULE_FAIL;
				goto finish;
			}
		} else {
			mod_populate_vps(pArgs, 4, NULL);
		}

		/* fill proxy_reply vps */
		if (request->proxy_reply) {
			if (!mod_populate_vps(pArgs, 5, request->proxy_reply->vps)) {
				ret = RLM_MODULE_FAIL;
				goto finish;
			}
		} else {
			mod_populate_vps(pArgs, 5, NULL);
		}

	}
	/* If there is no request, set all the elements to None */
	else for (i = 0; i < 6; i++) mod_populate_vps(pArgs, i, NULL);

	/*
	 * Call Python function. If pass_all_vps_dict is true, a dictionary with the
	 * appropriate "request", "reply"... keys is passed as argument to the
	 * module callback.
	 * Else, if pass_all_vps is true, a 6-tuple representing
	 * (Request, Reply, Config, State, Proxy-Request, Proxy-Reply) is passed.
	 * Otherwise, a tuple representing just the request is used.
	 */
	if (pass_all_vps_dict) {
		pDictInput = PyDict_New();
		if (pDictInput == NULL ||
		    PyDict_SetItemString(pDictInput, "request", PyTuple_GET_ITEM(pArgs, 0)) ||
		    PyDict_SetItemString(pDictInput, "reply", PyTuple_GET_ITEM(pArgs, 1)) ||
		    PyDict_SetItemString(pDictInput, "config", PyTuple_GET_ITEM(pArgs, 2)) ||
		    PyDict_SetItemString(pDictInput, "session-state", PyTuple_GET_ITEM(pArgs, 3)) ||
		    PyDict_SetItemString(pDictInput, "proxy-request", PyTuple_GET_ITEM(pArgs, 4)) ||
		    PyDict_SetItemString(pDictInput, "proxy-reply", PyTuple_GET_ITEM(pArgs, 5))) {
			ret = RLM_MODULE_FAIL;
			goto finish;
		}
		pRet = PyObject_CallFunctionObjArgs(pFunc, pDictInput, NULL);
	}
	else if (pass_all_vps)
		pRet = PyObject_CallFunctionObjArgs(pFunc, pArgs, NULL);
	else
		pRet = PyObject_CallFunctionObjArgs(pFunc, PyTuple_GET_ITEM(pArgs, 0), NULL);

	if (!pRet) {
		ret = RLM_MODULE_FAIL;
		goto finish;
	}

	if (!request) {
		// check return code at module instantiation time
		if (PyInt_CheckExact(pRet)) ret = PyInt_AsLong(pRet);
		goto finish;
	}

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
		int tuple_size = PyTuple_GET_SIZE(pRet);

		if (tuple_size < 2 || tuple_size > 3) {
			ERROR("%s - Tuple must be (return, updateDict) or (return, replyTuple, configTuple)", funcname);
			ret = RLM_MODULE_FAIL;
			goto finish;
		}

		pTupleInt = PyTuple_GET_ITEM(pRet, 0);
		if (!PyInt_CheckExact(pTupleInt)) {
			ERROR("%s - First tuple element not an integer", funcname);
			ret = RLM_MODULE_FAIL;
			goto finish;
		}
		/* Now have the return value */
		ret = PyInt_AsLong(pTupleInt);

		/* process updateDict */
		if (tuple_size == 2) {
			PyObject *updateDict = PyTuple_GET_ITEM(pRet, 1);
			if (!PyDict_CheckExact(updateDict)) {
				ERROR("%s - updateDict is not a dictionary", funcname);
				ret = RLM_MODULE_FAIL;
				goto finish;
			}
			mod_vptuple(request->reply, request, &request->reply->vps,
				    PyDict_GetItemString(updateDict, "reply"), funcname, "reply");
			mod_vptuple(request, request, &request->config,
				    PyDict_GetItemString(updateDict, "config"), funcname, "config");
			mod_vptuple(request->packet, request, &request->packet->vps,
				    PyDict_GetItemString(updateDict, "request"), funcname, "request");
			mod_vptuple(request->state_ctx, request, &request->state,
				    PyDict_GetItemString(updateDict, "session-state"), funcname, "session-state");
#ifdef WITH_PROXY
			if (request->proxy)
				mod_vptuple(request->proxy, request, &request->proxy->vps,
					    PyDict_GetItemString(updateDict, "proxy-request"), funcname, "proxy-request");
			if (request->proxy_reply)
				mod_vptuple(request->proxy_reply, request, &request->proxy_reply->vps,
					    PyDict_GetItemString(updateDict, "proxy-reply"), funcname, "proxy-reply");
#endif
			/*
			 *	Update cached copies
			 */
			request->username = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
			request->password = fr_pair_find_by_num(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY);
			if (!request->password)
				request->password = fr_pair_find_by_num(request->packet->vps, PW_CHAP_PASSWORD, 0, TAG_ANY);
		}

		/* process replyTuple and configTuple */
		else if (tuple_size == 3) {
			/* Reply item tuple */
			mod_vptuple(request->reply, request, &request->reply->vps,
				    PyTuple_GET_ITEM(pRet, 1), funcname, "reply");
			/* Config item tuple */
			mod_vptuple(request, request, &request->config,
				    PyTuple_GET_ITEM(pRet, 2), funcname, "config");
		}
	} else if (PyInt_CheckExact(pRet)) {
		/* Just an integer */
		ret = PyInt_AsLong(pRet);

	} else if (pRet == Py_None) {
		/* returned 'None', return value defaults to "OK, continue." */
		ret = RLM_MODULE_OK;
	} else {
		/* Not tuple or None */
		ERROR("%s - Function did not return a tuple or None", funcname);
		ret = RLM_MODULE_FAIL;
		goto finish;
	}


finish:
	Py_XDECREF(pArgs);
	Py_XDECREF(pRet);
	Py_XDECREF(pDictInput);

	return ret;
}

static void python_interpreter_free(PyThreadState *interp)
{
	PyEval_AcquireLock();
	PyThreadState_Swap(interp);
	Py_EndInterpreter(interp);
	PyEval_ReleaseLock();
}

/** Destroy a thread state
 *
 * @param thread to destroy.
 * @return 0
 */
static int _python_thread_free(python_thread_state_t *thread)
{
	PyEval_RestoreThread(thread->state);	/* Swap in our local thread state */
	PyThreadState_Clear(thread->state);
	PyEval_SaveThread();

	PyThreadState_Delete(thread->state);	/* Don't need to hold lock for this */

	return 0;
}

/** Callback for rbtree delete walker
 *
 */
static void _python_thread_entry_free(void *arg)
{
	talloc_free(arg);
}

/** Cleanup any thread local storage on pthread_exit()
 *
 * @param arg The thread currently exiting.
 */
static void _python_thread_tree_free(void *arg)
{
	rad_assert(arg == local_thread_state);

	rbtree_t *tree = talloc_get_type_abort(arg, rbtree_t);
	rbtree_free(tree);	/* Needs to be this not talloc_free to execute delete walker */

	local_thread_state = NULL;	/* Prevent double free in unittest env */
}

/** Compare instance pointers
 *
 */
static int _python_inst_cmp(const void *a, const void *b)
{
	python_thread_state_t const *a_p = a, *b_p = b;

	if (a_p->inst < b_p->inst) return -1;
	if (a_p->inst > b_p->inst) return +1;
	return 0;
}

/** Thread safe call to a python function
 *
 * Will swap in thread state specific to module/thread.
 */
static rlm_rcode_t do_python(rlm_python_t *inst, REQUEST *request, PyObject *pFunc, char const *funcname)
{
	int			ret;
	rbtree_t		*thread_tree;
	python_thread_state_t	*this_thread;
	python_thread_state_t	find;

	/*
	 *	It's a NOOP if the function wasn't defined
	 */
	if (!pFunc) return RLM_MODULE_NOOP;

	/*
	 *	Check to see if we've got a thread state tree
	 *	If not, create one.
	 */
	thread_tree = fr_thread_local_init(local_thread_state, _python_thread_tree_free);
	if (!thread_tree) {
		thread_tree = rbtree_create(NULL, _python_inst_cmp, _python_thread_entry_free, 0);
		if (!thread_tree) {
			RERROR("Failed allocating thread state tree");
			return RLM_MODULE_FAIL;
		}

		ret = fr_thread_local_set(local_thread_state, thread_tree);
		if (ret != 0) {
			talloc_free(thread_tree);
			return RLM_MODULE_FAIL;
		}
	}

	find.inst = inst;
	/*
	 *	Find the thread state associated with this instance
	 *	and this thread, or create a new thread state.
	 */
	this_thread = rbtree_finddata(thread_tree, &find);
	if (!this_thread) {
		PyThreadState *state;

		state = PyThreadState_New(inst->sub_interpreter->interp);

		RDEBUG3("Initialised new thread state %p", state);
		if (!state) {
			REDEBUG("Failed initialising local PyThreadState on first run");
			return RLM_MODULE_FAIL;
		}

		this_thread = talloc(NULL, python_thread_state_t);
		this_thread->inst = inst;
		this_thread->state = state;
		talloc_set_destructor(this_thread, _python_thread_free);

		if (!rbtree_insert(thread_tree, this_thread)) {
			RERROR("Failed inserting thread state into TLS tree");
			talloc_free(this_thread);

			return RLM_MODULE_FAIL;
		}
	}
	RDEBUG3("Using thread state %p", this_thread->state);

	PyEval_RestoreThread(this_thread->state);	/* Swap in our local thread state */
	ret = do_python_single(request, pFunc, funcname, inst->pass_all_vps, inst->pass_all_vps_dict);
	if (ret == RLM_MODULE_FAIL) python_error_log();
	PyEval_SaveThread();

	return ret;
}

#define MOD_FUNC(x) \
static rlm_rcode_t CC_HINT(nonnull) mod_##x(void *instance, REQUEST *request) { \
	return do_python((rlm_python_t *) instance, request, ((rlm_python_t *)instance)->x.function, #x);\
}

MOD_FUNC(authenticate)
MOD_FUNC(authorize)
MOD_FUNC(preacct)
MOD_FUNC(accounting)
MOD_FUNC(checksimul)
MOD_FUNC(pre_proxy)
MOD_FUNC(post_proxy)
MOD_FUNC(post_auth)
#ifdef WITH_COA
MOD_FUNC(recv_coa)
MOD_FUNC(send_coa)
#endif
static void python_obj_destroy(PyObject **ob)
{
	if (*ob != NULL) {
		Py_DECREF(*ob);
		*ob = NULL;
	}
}

static void python_function_destroy(python_func_def_t *def)
{
	python_obj_destroy(&def->function);
	python_obj_destroy(&def->module);
}

/** Import a user module and load a function from it
 *
 */
static int python_function_load(char const *name, python_func_def_t *def)
{
	if (!def->module_name && !def->function_name) return 0; /* Just not set, it's fine */

	if (!def->module_name) {
		ERROR("Once you have set the 'func_%s = %s', you should set 'mod_%s = ...' too.",
					name, def->function_name, name);
		return -1;
	}

	if (!def->function_name) {
		ERROR("Once you have set the 'mod_%s = %s', you should set 'func_%s = ...' too.",
					name, def->module_name, name);
		return -1;
	}

	def->module = PyImport_ImportModule(def->module_name);
	if (!def->module) {
		ERROR("%s - Module '%s' not found", __func__, def->module_name);

	error:
		python_error_log();
		ERROR("%s - Failed to import python function '%s.%s'",
		      __func__, def->module_name, def->function_name);
		Py_XDECREF(def->function);
		def->function = NULL;
		Py_XDECREF(def->module);
		def->module = NULL;

		return -1;
	}

	def->function = PyObject_GetAttrString(def->module, def->function_name);
	if (!def->function) {
		ERROR("%s - Function '%s.%s' is not found", __func__, def->module_name, def->function_name);
		goto error;
	}

	if (!PyCallable_Check(def->function)) {
		ERROR("%s - Function '%s.%s' is not callable", __func__, def->module_name, def->function_name);
		goto error;
	}

	return 0;
}

/*
 *	Parse a configuration section, and populate a dict.
 *	This function is recursively called (allows to have nested dicts.)
 */
static void python_parse_config(CONF_SECTION *cs, int lvl, PyObject *dict)
{
	int		indent_section = (lvl + 1) * 4;
	int		indent_item = (lvl + 2) * 4;
	CONF_ITEM	*ci = NULL;

	if (!cs || !dict) return;

	DEBUG("%*s%s {", indent_section, " ", cf_section_name1(cs));

	while ((ci = cf_item_find_next(cs, ci))) {
		/*
		 *  This is a section.
		 *  Create a new dict, store it in current dict,
		 *  Then recursively call python_parse_config with this section and the new dict.
		 */
		if (cf_item_is_section(ci)) {
			CONF_SECTION *sub_cs = cf_item_to_section(ci);
			char const *key = cf_section_name1(sub_cs); /* dict key */
			PyObject *sub_dict, *pKey;

			if (!key) continue;

			pKey = PyString_FromString(key);
			if (!pKey) continue;

			if (PyDict_Contains(dict, pKey)) {
				WARN("rlm_python: Ignoring duplicate config section '%s'", key);
				continue;
			}

			if (!(sub_dict = PyDict_New())) {
				WARN("rlm_python: Unable to create subdict for config section '%s'", key);
			}

			(void)PyDict_SetItem(dict, pKey, sub_dict);

			python_parse_config(sub_cs, lvl + 1, sub_dict);
		} else if (cf_item_is_pair(ci)) {
			CONF_PAIR *cp = cf_item_to_pair(ci);
			char const  *key = cf_pair_attr(cp); /* dict key */
			char const  *value = cf_pair_value(cp); /* dict value */
			PyObject *pKey, *pValue;

			if (!key || !value) continue;

			pKey = PyString_FromString(key);
			pValue = PyString_FromString(value);
			if (!pKey || !pValue) continue;

			/*
			 *  This is an item.
			 *  Store item attr / value in current dict.
			 */
			if (PyDict_Contains(dict, pKey)) {
				WARN("rlm_python: Ignoring duplicate config item '%s'", key);
				continue;
			}

			(void)PyDict_SetItem(dict, pKey, pValue);

			DEBUG("%*s%s = %s", indent_item, " ", key, value);
		}
	}

	DEBUG("%*s}", indent_section, " ");
}

#ifdef HAVE_DL_ITERATE_PHDR
static int dlopen_libpython_cb(struct dl_phdr_info *info,
					UNUSED size_t size, void *data)
{
	const char *pattern = "/" LIBPYTHON_LINKER_NAME;
	char **ppath = (char **)data;

	if (strstr(info->dlpi_name, pattern) != NULL) {
		if (*ppath != NULL) {
			talloc_free(*ppath);
			*ppath = NULL;
			return EEXIST;
		} else {
			*ppath = talloc_strdup(NULL, info->dlpi_name);
			if (*ppath == NULL) {
				return errno;
			}
		}
	}
	return 0;
}

/* Dlopen the already linked libpython */
static void *dlopen_libpython(int flags)
{
	char *path = NULL;
	int rc;
	void *handle;

	/* Find the linked libpython path */
	rc = dl_iterate_phdr(dlopen_libpython_cb, &path);
	if (rc != 0) {
		WARN("Failed searching for libpython "
			"among linked libraries: %s", strerror(rc));
		return NULL;
	} else if (path == NULL) {
		WARN("Libpython is not found among linked libraries");
		return NULL;
	}

	/* Dlopen the found library */
	handle = dlopen(path, flags);
	if (handle == NULL) {
		WARN("Failed loading %s: %s", path, dlerror());
	}
	talloc_free(path);
	return handle;
}
#else	/* ! HAVE_DL_ITERATE_PHDR */
/* Dlopen libpython by its linker name (bare soname) */
static void *dlopen_libpython(int flags)
{
	const char *name = LIBPYTHON_LINKER_NAME;
	void *handle;
	handle = dlopen(name, flags);
	if (handle == NULL) {
		WARN("Failed loading %s: %s", name, dlerror());
	}
	return handle;
}
#endif	/* ! HAVE_DL_ITERATE_PHDR */

/** Initialises a separate python interpreter for this module instance
 *
 */
static int python_interpreter_init(rlm_python_t *inst, CONF_SECTION *conf)
{
	int i;
	bool locked = false;

	/*
	 *	Explicitly load libpython, so symbols will be available to lib-dynload modules
	 */
	if (python_instances == 0) {
		INFO("Python version: %s", Py_GetVersion());

		python_dlhandle = dlopen_libpython(RTLD_NOW | RTLD_GLOBAL);
		if (!python_dlhandle) WARN("Failed loading libpython symbols into global symbol table");

#if PY_VERSION_HEX > 0x03050000
		{
			inst->wide_name = Py_DecodeLocale(main_config.name, strlen(main_config.name));
			Py_SetProgramName(inst->wide_name);		/* The value of argv[0] as a wide char string */
		}
#else
		{
			char *name;

			memcpy(&name, &main_config.name, sizeof(name));
			Py_SetProgramName(name);		/* The value of argv[0] as a wide char string */
		}
#endif

		Py_InitializeEx(0);			/* Don't override signal handlers - noop on subs calls */
		PyEval_InitThreads(); 			/* This also grabs a lock (which we then need to release) */
		main_interpreter = PyThreadState_Get();	/* Store reference to the main interpreter */
		locked = true;
	}
	rad_assert(PyEval_ThreadsInitialized());

	/*
	 *	Increment the reference counter
	 */
	python_instances++;

	/*
	 *	This sets up a separate environment for each python module instance
	 *	These will be destroyed on Py_Finalize().
	 */
	if (!inst->cext_compat) {
		inst->sub_interpreter = Py_NewInterpreter();
	} else {
		inst->sub_interpreter = main_interpreter;
	}

	if (!locked) PyEval_AcquireThread(inst->sub_interpreter);
	PyThreadState_Swap(inst->sub_interpreter);

	/*
	 *	Due to limitations in Python, sub-interpreters don't work well
	 *	with Python C extensions if they use GIL lock functions.
	 */
	if (!inst->cext_compat || !main_module) {
		CONF_SECTION *cs;

		/*
		 *	Set the python search path
		 *
		 *	The path buffer does not appear to be dup'd
		 *	so its lifetime should really be bound to
		 *	the lifetime of the module.
		 */
		if (inst->python_path) {
			char *p, *path;
			PyObject *sys = PyImport_ImportModule("sys");
			PyObject *sys_path = PyObject_GetAttrString(sys, "path");

			memcpy(&p, &inst->python_path, sizeof(path));

			for (path = strtok(p, ":"); path != NULL; path = strtok(NULL, ":")) {
				PyList_Append(sys_path, PyString_FromString(path));
			}

			PyObject_SetAttrString(sys, "path", sys_path);
			Py_DecRef(sys);
			Py_DecRef(sys_path);
		}

		/*
		 *	Initialise a new module, with our default methods
		 */
		inst->module = Py_InitModule3("radiusd", module_methods, "FreeRADIUS python module");
		if (!inst->module) {
		error:
			python_error_log();
			PyEval_SaveThread();
			return -1;
		}

		/*
		 *	Py_InitModule3 returns a borrowed ref, the actual
		 *	module is owned by sys.modules, so we also need
		 *	to own the module to prevent it being freed early.
		 */
		Py_IncRef(inst->module);

		if (inst->cext_compat) main_module = inst->module;

		for (i = 0; radiusd_constants[i].name; i++) {
			if ((PyModule_AddIntConstant(inst->module, radiusd_constants[i].name,
						     radiusd_constants[i].value)) < 0)
				goto error;
		}

		/*
		 *	Convert a FreeRADIUS config structure into a python
		 *	dictionary.
		 */
		inst->pythonconf_dict = PyDict_New();
		if (!inst->pythonconf_dict) {
			ERROR("Unable to create python dict for config");
			python_error_log();
			return -1;
		}

		/*
		 *	Add module configuration as a dict
		 */
		if (PyModule_AddObject(inst->module, "config", inst->pythonconf_dict) < 0) goto error;

		cs = cf_section_sub_find(conf, "config");
		if (cs) python_parse_config(cs, 0, inst->pythonconf_dict);
	} else {
		inst->module = main_module;
		Py_IncRef(inst->module);
		inst->pythonconf_dict = PyObject_GetAttrString(inst->module, "config");
		Py_IncRef(inst->pythonconf_dict);
	}

	PyEval_SaveThread();

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
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_python_t	*inst = instance;
	int		code = 0;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	/*
	 *	Load the python code required for this module instance
	 */
	if (python_interpreter_init(inst, conf) < 0) return -1;

	/*
	 *	Switch to our module specific main thread
	 */
	PyEval_RestoreThread(inst->sub_interpreter);

	/*
	 *	Process the various sections
	 */
#define PYTHON_FUNC_LOAD(_x) if (python_function_load(#_x, &inst->_x) < 0) goto error
	PYTHON_FUNC_LOAD(instantiate);
	PYTHON_FUNC_LOAD(authenticate);
	PYTHON_FUNC_LOAD(authorize);
	PYTHON_FUNC_LOAD(preacct);
	PYTHON_FUNC_LOAD(accounting);
	PYTHON_FUNC_LOAD(checksimul);
	PYTHON_FUNC_LOAD(pre_proxy);
	PYTHON_FUNC_LOAD(post_proxy);
	PYTHON_FUNC_LOAD(post_auth);
#ifdef WITH_COA
	PYTHON_FUNC_LOAD(recv_coa);
	PYTHON_FUNC_LOAD(send_coa);
#endif
	PYTHON_FUNC_LOAD(detach);

	/*
	 *	Call the instantiate function only if the function and module is set.
	 */
	if (inst->instantiate.module_name && inst->instantiate.function_name) {
		code = do_python_single(NULL, inst->instantiate.function, "instantiate", inst->pass_all_vps, inst->pass_all_vps_dict);
		if (code == RLM_MODULE_FAIL) {
		error:
			python_error_log();	/* Needs valid thread with GIL */
			PyEval_SaveThread();
			return -1;
		}
	}
	PyEval_SaveThread();

	return 0;
}

static int mod_detach(void *instance)
{
	rlm_python_t *inst = instance;
	int	     ret;

	/*
	 *	Call module destructor
	 */
	PyEval_RestoreThread(inst->sub_interpreter);

	ret = do_python_single(NULL, inst->detach.function, "detach", inst->pass_all_vps, inst->pass_all_vps_dict);
	if (ret == RLM_MODULE_FAIL) python_error_log();

#define PYTHON_FUNC_DESTROY(_x) python_function_destroy(&inst->_x)
	PYTHON_FUNC_DESTROY(instantiate);
	PYTHON_FUNC_DESTROY(authorize);
	PYTHON_FUNC_DESTROY(authenticate);
	PYTHON_FUNC_DESTROY(preacct);
	PYTHON_FUNC_DESTROY(accounting);
	PYTHON_FUNC_DESTROY(checksimul);
	PYTHON_FUNC_DESTROY(detach);

	Py_DecRef(inst->pythonconf_dict);
	Py_DecRef(inst->module);

	PyEval_SaveThread();

	/*
	 *	Force cleaning up of threads if this is *NOT* a worker
	 *	thread, which happens if this is being called from
	 *	unittest framework, and probably with the server running
	 *	in debug mode.
	 */
	rbtree_free(local_thread_state);
	local_thread_state = NULL;

	/*
	 *	Only destroy if it's a subinterpreter
	 */
	if (!inst->cext_compat) python_interpreter_free(inst->sub_interpreter);

	if ((--python_instances) == 0) {
		PyThreadState_Swap(main_interpreter); /* Swap to the main thread */
		Py_Finalize();
		dlclose(python_dlhandle);

#if PY_VERSION_HEX > 0x03050000
		if (inst->wide_name) PyMem_RawFree(inst->wide_name);
#endif
	}


	return ret;
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
extern module_t rlm_python;
module_t rlm_python = {
	.magic		= RLM_MODULE_INIT,
	.name		= "python",
	.type		= RLM_TYPE_THREAD_UNSAFE,
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
