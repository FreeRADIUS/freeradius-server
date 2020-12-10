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
 * @copyright 2000,2006,2015-2016 The FreeRADIUS server project
 * @copyright 2002 Miguel A.L. Paraz (mparaz@mparaz.com)
 * @copyright 2002 Imperium Technology, Inc.
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_python (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/lsan.h>

#include <Python.h>
#include <frameobject.h> /* Python header not pulled in by default. */
#include <libgen.h>
#include <dlfcn.h>

/** Specifies the module.function to load for processing a section
 *
 */
typedef struct {
	PyObject	*module;		//!< Python reference to module.
	PyObject	*function;		//!< Python reference to function in module.

	char const	*module_name;		//!< String name of module.
	char const	*function_name;		//!< String name of function in module.
} python_func_def_t;

/** An instance of the rlm_python module
 *
 */
typedef struct {
	char const	*name;			//!< Name of the module instance
	PyThreadState	*interpreter;		//!< The interpreter used for this instance of rlm_python.
	char const	*python_path;		//!< Path to search for python files in.
	bool		python_path_include_conf_dir;	//!< Include the directory of the current
							///< rlm_python module config in the python path.
	bool		python_path_include_default;	//!< Include the default python path
							///< in the python path.
	PyObject	*module;		//!< Local, interpreter specific module.

	python_func_def_t
	instantiate,
	authorize,
	authenticate,
	preacct,
	accounting,
	post_auth,
	detach;

	PyObject	*pythonconf_dict;	//!< Configuration parameters defined in the module
						//!< made available to the python script.
} rlm_python_t;

/** Tracks a python module inst/thread state pair
 *
 * Multiple instances of python create multiple interpreters and each
 * thread must have a PyThreadState per interpreter, to track execution.
 */
typedef struct {
	PyThreadState	*state;			//!< Module instance/thread specific state.
} rlm_python_thread_t;

static void		*python_dlhandle;
static PyThreadState	*global_interpreter;	//!< Our first interpreter.

static rlm_python_t	*current_inst;		//!< Used for communication with inittab functions.
static CONF_SECTION	*current_conf;		//!< Used for communication with inittab functions.
static char		*default_path;		//!< The default python path.

/*
 *	As of Python 3.8 the GIL will be per-interpreter
 *	If there are still issues with CEXTs,
 *	multiple interpreters and the GIL at that point
 *	users can build rlm_python against Python 3.8
 *	and the horrible hack of using a single interpreter
 *	for all instances of rlm_python will no longer be
 *	required.
 *
 *	As Python 3.x module initialisation is significantly
 *	different than Python 2.x initialisation,
 *	it'd be a pain to retain the cext_compat for
 *	Python 3 and as Python 3 users have the option of
 *	using as version of Python which fixes the underlying
 *	issue, we only support using a global interpreter
 *	for Python 2.7 and below.
 */

/*
 *	A mapping of configuration file names to internal variables.
 */
static CONF_PARSER module_config[] = {

#define A(x) { FR_CONF_OFFSET("mod_" #x, FR_TYPE_STRING, rlm_python_t, x.module_name), .dflt = "${.module}" }, \
	{ FR_CONF_OFFSET("func_" #x, FR_TYPE_STRING, rlm_python_t, x.function_name) },

	A(instantiate)
	A(authorize)
	A(authenticate)
	A(preacct)
	A(accounting)
	A(post_auth)
	A(detach)

#undef A

	{ FR_CONF_OFFSET("python_path", FR_TYPE_STRING, rlm_python_t, python_path) },
	{ FR_CONF_OFFSET("python_path_include_conf_dir", FR_TYPE_BOOL, rlm_python_t, python_path_include_conf_dir), .dflt = "yes" },
	{ FR_CONF_OFFSET("python_path_include_default", FR_TYPE_BOOL, rlm_python_t, python_path_include_default), .dflt = "yes" },

	CONF_PARSER_TERMINATOR
};

static struct {
	char const *name;
	int  value;
} freeradius_constants[] = {

#define A(x) { #x, x },

	A(L_DBG)
	A(L_WARN)
	A(L_INFO)
	A(L_ERR)
	A(L_WARN)
	A(L_DBG_WARN)
	A(L_DBG_ERR)
	A(L_DBG_WARN_REQ)
	A(L_DBG_ERR_REQ)
	A(RLM_MODULE_REJECT)
	A(RLM_MODULE_FAIL)
	A(RLM_MODULE_OK)
	A(RLM_MODULE_HANDLED)
	A(RLM_MODULE_INVALID)
	A(RLM_MODULE_DISALLOW)
	A(RLM_MODULE_NOTFOUND)
	A(RLM_MODULE_NOOP)
	A(RLM_MODULE_UPDATED)
	A(RLM_MODULE_NUMCODES)

#undef A

	{ NULL, 0 },
};

/*
 *	radiusd Python functions
 */

/** Allow fr_log to be called from python
 *
 */
static PyObject *mod_log(UNUSED PyObject *module, PyObject *args)
{
	int status;
	char *msg;

	if (!PyArg_ParseTuple(args, "is", &status, &msg)) {
		Py_RETURN_NONE;
	}

	fr_log(&default_log, status, __FILE__, __LINE__, "%s", msg);

	Py_RETURN_NONE;
}

static PyMethodDef module_methods[] = {
	{ "log", &mod_log, METH_VARARGS,
	  "freeradius.log(level, msg)\n\n" \
	  "Print a message using the freeradius daemon's logging system. level should be one of the\n" \
	  "following constants L_DBG, L_WARN, L_INFO, L_ERR, L_DBG_WARN, L_DBG_ERR, L_DBG_WARN_REQ, L_DBG_ERR_REQ\n"
	},
	{ NULL, NULL, 0, NULL },
};

/** Print out the current error
 *
 * Must be called with a valid thread state set
 */
static void python_error_log(const rlm_python_t *inst, request_t *request)
{
	PyObject *p_type = NULL, *p_value = NULL, *p_traceback = NULL, *p_str_1 = NULL, *p_str_2 = NULL;

	PyErr_Fetch(&p_type, &p_value, &p_traceback);
	PyErr_NormalizeException(&p_type, &p_value, &p_traceback);
	if (!p_type || !p_value) goto failed;

	if (((p_str_1 = PyObject_Str(p_type)) == NULL) || ((p_str_2 = PyObject_Str(p_value)) == NULL)) goto failed;

	ROPTIONAL(RERROR, ERROR, "%s (%s)", PyUnicode_AsUTF8(p_str_1), PyUnicode_AsUTF8(p_str_2));

	if (p_traceback != Py_None) {
		PyTracebackObject *ptb = (PyTracebackObject*)p_traceback;
		size_t fnum = 0;

		while (ptb != NULL) {
			PyFrameObject *cur_frame = ptb->tb_frame;

			ROPTIONAL(RERROR, ERROR, "[%ld] %s:%d at %s()",
				fnum,
				PyUnicode_AsUTF8(cur_frame->f_code->co_filename),
				PyFrame_GetLineNumber(cur_frame),
				PyUnicode_AsUTF8(cur_frame->f_code->co_name)
			);

			ptb = ptb->tb_next;
			fnum++;
		}
	}

failed:
	Py_XDECREF(p_str_1);
	Py_XDECREF(p_str_2);
	Py_XDECREF(p_type);
	Py_XDECREF(p_value);
	Py_XDECREF(p_traceback);
}

static int tuple_to_list(TALLOC_CTX *ctx, request_t *request, const char *list_name, fr_pair_list_t *list, PyObject *tuple)
{
	int         i;
	Py_ssize_t  tuple_len;
	tmpl_t      *dst;
	fr_pair_t   *vp;
	request_t   *current = request;

	/*
	 *	If the Python function gave us None for the tuple,
	 *	then just return.
	 */
	if (!tuple || tuple == Py_None) return 0;

	if (!PyTuple_CheckExact(tuple)) {
		RERROR("non-tuple passed to %s", list_name);
		return -1;
	}

	/* Get the tuple tuple_len. */
	tuple_len = PyTuple_GET_SIZE(tuple);
	for (i = 0; i < tuple_len; i++) {
		PyObject 	*p_tuple_element = PyTuple_GET_ITEM(tuple, i);
		PyObject 	*p_str_1;
		PyObject 	*p_str_2;
		Py_ssize_t	pair_len;
		char const	*s1;
		char const	*s2;

		if (!PyTuple_CheckExact(p_tuple_element)) {
			RERROR("Tuple element %d of %s is not a tuple", i, list_name);
			return -1;
		}

		/* Check if it's a pair like (Attr, Value) */
		pair_len = PyTuple_GET_SIZE(p_tuple_element);
		if (pair_len != 2) {
			RERROR("Tuple element %d of %s is a tuple of size %zu. Must be 2",
					i, list_name, pair_len);
			return -1;
		}

		p_str_1 = PyTuple_GET_ITEM(p_tuple_element, 0);
		p_str_2 = PyTuple_GET_ITEM(p_tuple_element, pair_len - 1);
		if ((!PyUnicode_CheckExact(p_str_1)) || (!PyUnicode_CheckExact(p_str_2))) {
			RERROR("Tuple element %d of %s must be as (str, str)",
					i, list_name);
			return -1;
		}

		s1 = PyUnicode_AsUTF8(p_str_1);
		s2 = PyUnicode_AsUTF8(p_str_2);

		if (tmpl_afrom_attr_str(ctx, NULL, &dst, s1,
					&(tmpl_rules_t){
						.prefix = TMPL_ATTR_REF_PREFIX_NO,
						.dict_def = request->dict,
						.list_def = PAIR_LIST_REPLY
					}) <= 0) {
			RERROR("Failed to find attribute %s.%s", list_name, s1);
			return -1;
		}

		if (radius_request(&current, tmpl_request(dst)) < 0) {
			RDEBUG2("Attribute name %s.%s refers to outer request but not in a tunnel, skipping...",
					list_name, s1);
			talloc_free(dst);
			continue;
		}

		MEM(vp = fr_pair_afrom_da(ctx, tmpl_da(dst)));
		talloc_free(dst);

		vp->op = T_OP_EQ;
		if (fr_pair_value_from_str(vp, s2, -1, '\0', false) < 0) {
			RERROR("Failed: '%s.%s' = '%s'", list_name, s1, s2);
			return -1;
		}

		RDEBUG2("Update '%s.%s' = '%s'", list_name, s1, s2);

		radius_pairmove(current, list, &vp, false);
	}

	return 0;
}

static void mod_update_tuple_to_list(TALLOC_CTX *ctx, request_t *request, fr_pair_list_t *list,
                                    PyObject *update_dict, const char *funcname, char const *list_name)
{
	PyObject *p_tuple;

	if (!PyDict_CheckExact(update_dict)) {
		RERROR("%s - Expected '%s' as a dict with tuples. e.g: foo['%s']=((attr,val), (attrN,valN))",
			funcname, list_name, list_name);
		return;
	}

	p_tuple = PyDict_GetItemString(update_dict, list_name);
	if (p_tuple == Py_None) return;

	RDEBUG3("%s - Calling tuple_to_list()", funcname);

	if (tuple_to_list(ctx, request, list_name, list, p_tuple) < 0) {
		RERROR("%s - Failed tuple_to_list() %s", funcname, list_name);
	}
}

/*
 *	This is the core Python function that the others wrap around.
 *	Pass the value-pair print strings in a tuple.
 */
static int pair_to_tuple(rlm_python_t const *inst, request_t *request, PyObject *p_pair, fr_pair_t *vp)
{
	PyObject *attribute = NULL;
	PyObject *value = NULL;

	/* Look at the fr_pair_fprint_name? */
	attribute = PyUnicode_FromString(vp->da->name);
	if (!attribute) return -1;

	switch (vp->vp_type) {
	case FR_TYPE_STRING:
		value = PyUnicode_FromStringAndSize(vp->vp_strvalue, vp->vp_length);
		break;

	case FR_TYPE_OCTETS:
		value = PyBytes_FromStringAndSize((char const *)vp->vp_octets, vp->vp_length);
		break;

	case FR_TYPE_BOOL:
		value = PyBool_FromLong(vp->vp_bool);
		break;

	case FR_TYPE_UINT8:
		value = PyLong_FromUnsignedLong(vp->vp_uint8);
		break;

	case FR_TYPE_UINT16:
		value = PyLong_FromUnsignedLong(vp->vp_uint16);
		break;

	case FR_TYPE_UINT32:
		value = PyLong_FromUnsignedLong(vp->vp_uint32);
		break;

	case FR_TYPE_UINT64:
		value = PyLong_FromUnsignedLongLong(vp->vp_uint64);
		break;

	case FR_TYPE_INT8:
		value = PyLong_FromLong(vp->vp_int8);
		break;

	case FR_TYPE_INT16:
		value = PyLong_FromLong(vp->vp_int16);
		break;

	case FR_TYPE_INT32:
		value = PyLong_FromLong(vp->vp_int32);
		break;

	case FR_TYPE_INT64:
		value = PyLong_FromLongLong(vp->vp_int64);
		break;

	case FR_TYPE_FLOAT32:
		value = PyFloat_FromDouble((double) vp->vp_float32);
		break;

	case FR_TYPE_FLOAT64:
		value = PyFloat_FromDouble(vp->vp_float64);
		break;

	case FR_TYPE_SIZE:
		value = PyLong_FromSize_t(vp->vp_size);
		break;

	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_DATE:
	case FR_TYPE_IFID:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_ETHERNET:
	{
		ssize_t slen;
		char buffer[256];

		slen = fr_value_box_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), &vp->data, NULL);
		if (slen < 0) {
		error:
			RERROR("Failed marshalling %pP to Python value", vp);
			python_error_log(inst, request);
			Py_XDECREF(attribute);
			return -1;
		}
		value = PyUnicode_FromStringAndSize(buffer, (size_t)slen);
	}
		break;

	case FR_TYPE_NON_VALUES:
		fr_assert(0);
		return -1;
	}

	if (value == NULL) goto error;

	PyTuple_SET_ITEM(p_pair, 0, attribute);
	PyTuple_SET_ITEM(p_pair, 1, value);

	return 0;
}

static int list_to_tuple(rlm_python_t const *inst, request_t *request, PyObject **p_tuple, fr_pair_list_t *list)
{
	PyObject    *p_our_tuple = NULL;
	int         tuplelen = 0;
	int         i = 0;
	fr_cursor_t cursor;
	fr_pair_t   *vp;

	if (!list) return -1;

	/*
	 *	We will pass a tuple containing (name, value) tuples
	 *	We can safely use the Python function to build up a
	 *	tuple, since the tuple is not used elsewhere.
	 *
	 *	Determine the size of our tuple by walking through the list.
	 */
	for (vp = fr_cursor_init(&cursor, list); vp; vp = fr_cursor_next(&cursor)) tuplelen++;

	if ((p_our_tuple = PyTuple_New(tuplelen)) == NULL) goto error;

	for (vp = fr_cursor_init(&cursor, list); vp; vp = fr_cursor_next(&cursor), i++) {
		PyObject *p_pair = NULL;

		/* The inside tuple has two only: */
		if ((p_pair = PyTuple_New(2)) == NULL) goto error;

		if (pair_to_tuple(inst, request, p_pair, vp) == 0) {
			/* Put the tuple inside the container */
			PyTuple_SET_ITEM(p_our_tuple, i, p_pair);
		} else {
			Py_DECREF(p_pair);
			goto error;
		}
	}

	*p_tuple = p_our_tuple;

	return 0;

error:
	Py_XDECREF(p_our_tuple);
	return -1;
}

/*
 * This function generates a tuple representing a given VPS and inserts it into
 * the indicated dict position in the p_dict.
 * Returns false on error.
 */
static bool mod_load_list_to_tuple(rlm_python_t const *inst, request_t *request, PyObject *p_dict,
                                   fr_pair_list_t *list, char const *list_name)
{
	PyObject *p_tuple = NULL;

	if (list_to_tuple(inst, request, &p_tuple, list) < 0) {
		/* If vps is NULL, return None */
		Py_INCREF(Py_None);
		PyDict_SetItemString(p_dict, list_name, Py_None);
		return false;
	}

	/* Add into p["list_name"] dict */
	PyDict_SetItemString(p_dict, list_name, p_tuple);

	return true;
}

static unlang_action_t do_python_single(rlm_rcode_t *p_result,
					rlm_python_t const *inst, request_t *request, PyObject *p_func, char const *funcname)
{
	PyObject    *p_ret = NULL;
	PyObject    *p_dict = NULL;
	PyObject    *p_tuple_int = NULL;
	PyObject    *p_update_dict = NULL;
	rlm_rcode_t rcode = RLM_MODULE_OK; /* Default return value is "OK, continue" */

	/*
	 * p_dict is a 4-dict indexed by (Request, Reply, Control and State) names within tuples.
	 *
	 * e.g:
	 *
	 * p = dict()
	 * p["foo"] = ((attr1,val1), (attrN, valN))
	 * p["bar"] = ((attr1,val1), (attrN, valN))
	 *
	 * If some list is not available, NONE is used instead
	 */
	p_dict = PyDict_New();
	if (!p_dict) {
		ERROR("%s - Memory cannot be allocated for PyDict_New()", funcname);
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	/*
	 * Fill in the first 4 attribute lists, or set all the elements to None.
	 */
#define LOAD_LIST_TO_TUPLE(_list_name, _vps)\
	mod_load_list_to_tuple(inst, request, p_dict, (request ? _vps : NULL), _list_name)

	LOAD_LIST_TO_TUPLE("request", &request->request_pairs);
	LOAD_LIST_TO_TUPLE("reply", &request->reply_pairs);
	LOAD_LIST_TO_TUPLE("control", &request->control_pairs);
	LOAD_LIST_TO_TUPLE("session-state", &request->state_pairs);

	p_ret = PyObject_CallFunctionObjArgs(p_func, p_dict, NULL);
	if (!p_ret) {
		python_error_log(inst, request); /* Needs valid thread with GIL */
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	if (!request) {
		/* check return code at module instantiation time */
		if (PyNumber_Check(p_ret)) rcode = PyLong_AsLong(p_ret);
		goto finish;
	}

	/*
	 *	The function returns either:
	 *
	 *  1. (returnvalue, updateDict), where
	 *
	 *   - returnvalue is one of the constants RLM_*
	 *   - updateDict are dicts of tuples indexed by the name (e.g: "request", "reply", "control" or "session-state")
	 *     with tuple of string tuples of size 2
	 *
	 *  2. the function return value alone
	 *
	 *  3. None - default return value is set
	 */
	if (PyTuple_CheckExact(p_ret)) {
		int tuple_size;

		tuple_size = PyTuple_GET_SIZE(p_ret);
		if (tuple_size != 2) {
			ERROR("%s - Tuple must be (return, updateDict)", funcname);
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		p_tuple_int = PyTuple_GET_ITEM(p_ret, 0);
		if (!PyNumber_Check(p_tuple_int)) {
			ERROR("%s - First tuple element not an integer", funcname);
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		/* Now have the return value */
		rcode = PyLong_AsLong(p_tuple_int);

		/* process updateDict */
		p_update_dict = PyTuple_GET_ITEM(p_ret, 1);
		if (!PyDict_CheckExact(p_update_dict)) {
			ERROR("%s - updateDict is not dictionary", funcname);
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

#define UPDATE_TUPLE_TO_LIST(_ctx, _list_name, _vps) \
		mod_update_tuple_to_list(_ctx, request, _vps, p_update_dict, funcname, _list_name)

		UPDATE_TUPLE_TO_LIST(request->packet, "request", &request->request_pairs);
		UPDATE_TUPLE_TO_LIST(request->reply, "reply", &request->reply_pairs);
		UPDATE_TUPLE_TO_LIST(request, "control", &request->control_pairs);
		UPDATE_TUPLE_TO_LIST(request->state_ctx, "session-state", &request->state_pairs);

	} else if (PyNumber_Check(p_ret)) {
		/* Just an integer */
		rcode = PyLong_AsLong(p_ret);
	} else if (p_ret == Py_None) {
		/* returned 'None', return value defaults to "OK, continue." */
		rcode = RLM_MODULE_OK;
	} else {
		/* Not tuple or None */
		ERROR("%s - Function did not return a tuple or None", funcname);
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

finish:
	if (rcode == RLM_MODULE_FAIL) python_error_log(inst, request);

	Py_XDECREF(p_ret);
	Py_XDECREF(p_dict);
	Py_XDECREF(p_tuple_int);
	Py_XDECREF(p_update_dict);

	RETURN_MODULE_RCODE(rcode);
}

/** Thread safe call to a python function
 *
 * Will swap in thread state specific to module/thread.
 */
static unlang_action_t do_python(rlm_rcode_t *p_result, rlm_python_t const *inst, rlm_python_thread_t *this_thread,
			     	 request_t *request, PyObject *p_func, char const *funcname)
{
	rlm_rcode_t		rcode;

	/*
	 *	It's a NOOP if the function wasn't defined
	 */
	if (!p_func) RETURN_MODULE_NOOP;

	RDEBUG3("Using thread state %p/%p", inst, this_thread->state);

	PyEval_RestoreThread(this_thread->state);	/* Swap in our local thread state */
	do_python_single(&rcode, inst, request, p_func, funcname);
	(void)fr_cond_assert(PyEval_SaveThread() == this_thread->state);

	RETURN_MODULE_RCODE(rcode);
}

#define MOD_FUNC(x) \
static unlang_action_t CC_HINT(nonnull) mod_##x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) \
{ \
	rlm_python_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_python_t); \
	rlm_python_thread_t *thread = talloc_get_type_abort(mctx->thread, rlm_python_thread_t); \
	return do_python(p_result, inst, thread, request, inst->x.function, #x);\
}

MOD_FUNC(authenticate)
MOD_FUNC(authorize)
MOD_FUNC(preacct)
MOD_FUNC(accounting)
MOD_FUNC(post_auth)

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
static int python_function_load(rlm_python_t *inst, python_func_def_t *def)
{
	char const *funcname = "python_function_load";

	if (def->module_name == NULL || def->function_name == NULL) return 0;

	LSAN_DISABLE(def->module = PyImport_ImportModule(def->module_name));
	if (!def->module) {
		ERROR("%s - Module '%s' load failed", funcname, def->module_name);
	error:
		python_error_log(inst, NULL);
		Py_XDECREF(def->function);
		def->function = NULL;
		Py_XDECREF(def->module);
		def->module = NULL;

		return -1;
	}

	def->function = PyObject_GetAttrString(def->module, def->function_name);
	if (!def->function) {
		ERROR("%s - Function '%s.%s' is not found", funcname, def->module_name, def->function_name);
		goto error;
	}

	if (!PyCallable_Check(def->function)) {
		ERROR("%s - Function '%s.%s' is not callable", funcname, def->module_name, def->function_name);
		goto error;
	}

	return 0;
}

/*
 *	Parse a configuration section, and populate a dict.
 *	This function is recursively called (allows to have nested dicts.)
 */
static int python_parse_config(rlm_python_t *inst, CONF_SECTION *cs, int lvl, PyObject *dict)
{
	int		indent_section = (lvl * 4);
	int		indent_item = (lvl + 1) * 4;
	int		ret = 0;
	CONF_ITEM	*ci = NULL;

	if (!cs || !dict) return -1;

	DEBUG("%*s%s {", indent_section, " ", cf_section_name1(cs));

	while ((ci = cf_item_next(cs, ci))) {
		/*
		 *  This is a section.
		 *  Create a new dict, store it in current dict,
		 *  Then recursively call python_parse_config with this section and the new dict.
		 */
		if (cf_item_is_section(ci)) {
			CONF_SECTION	*sub_cs = cf_item_to_section(ci);
			char const	*key = cf_section_name1(sub_cs); /* dict key */
			PyObject	*sub_dict, *p_key;

			p_key = PyUnicode_FromString(key);
			if (!p_key) {
				ERROR("Failed converting config key \"%s\" to python string", key);
				return -1;
			}

			if (PyDict_Contains(dict, p_key)) {
				WARN("Ignoring duplicate config section '%s'", key);
				continue;
			}

			MEM(sub_dict = PyDict_New());
			(void)PyDict_SetItem(dict, p_key, sub_dict);

			ret = python_parse_config(inst, sub_cs, lvl + 1, sub_dict);
			if (ret < 0) break;
		} else if (cf_item_is_pair(ci)) {
			CONF_PAIR	*cp = cf_item_to_pair(ci);
			char const	*key = cf_pair_attr(cp); /* dict key */
			char const	*value = cf_pair_value(cp); /* dict value */
			PyObject	*p_key, *p_value;

			if (!value) {
				WARN("Skipping \"%s\" as it has no value", key);
				continue;
			}

			p_key = PyUnicode_FromString(key);
			p_value = PyUnicode_FromString(value);
			if (!p_key) {
				ERROR("Failed converting config key \"%s\" to python string", key);
				return -1;
			}
			if (!p_value) {
				ERROR("Failed converting config value \"%s\" to python string", value);
				return -1;
			}

			/*
			 *  This is an item.
			 *  Store item attr / value in current dict.
			 */
			if (PyDict_Contains(dict, p_key)) {
				WARN("Ignoring duplicate config item '%s'", key);
				continue;
			}

			(void)PyDict_SetItem(dict, p_key, p_value);

			DEBUG("%*s%s = \"%s\"", indent_item, " ", key, value);
		}
	}

	DEBUG("%*s}", indent_section, " ");

	return ret;
}

/** Make the current instance's config available within the module we're initialising
 *
 */
static int python_module_import_config(rlm_python_t *inst, CONF_SECTION *conf, PyObject *module)
{
	CONF_SECTION *cs;

	/*
	 *	Convert a FreeRADIUS config structure into a python
	 *	dictionary.
	 */
	inst->pythonconf_dict = PyDict_New();
	if (!inst->pythonconf_dict) {
		ERROR("Unable to create python dict for config");
	error:
		Py_XDECREF(inst->pythonconf_dict);
		inst->pythonconf_dict = NULL;
		python_error_log(inst, NULL);
		return -1;
	}

	cs = cf_section_find(conf, "config", NULL);
	if (cs) {
		DEBUG("Inserting \"config\" section into python environment as radiusd.config");
		if (python_parse_config(inst, cs, 0, inst->pythonconf_dict) < 0) goto error;
	}

	/*
	 *	Add module configuration as a dict
	 */
	if (PyModule_AddObject(module, "config", inst->pythonconf_dict) < 0) goto error;

	return 0;
}

/** Import integer constants into the module we're initialising
 *
 */
static int python_module_import_constants(rlm_python_t *inst, PyObject *module)
{
	size_t i;

	for (i = 0; freeradius_constants[i].name; i++) {
		if ((PyModule_AddIntConstant(module, freeradius_constants[i].name, freeradius_constants[i].value)) < 0) {
			ERROR("Failed adding constant to module");
			python_error_log(inst, NULL);
			return -1;
		}
	}

	return 0;
}

static char *python_path_build(TALLOC_CTX *ctx, rlm_python_t *inst, CONF_SECTION *conf)
{
	char *path;

	MEM(path = talloc_strdup(ctx, ""));
	if (inst->python_path) {
		MEM(path = talloc_asprintf_append_buffer(path, "%s:", inst->python_path));
	}
	if (inst->python_path_include_conf_dir) {
		char const *imutable;
		char *mutable;

		imutable = cf_filename(conf);
		memcpy(&mutable, &imutable, sizeof(mutable));

		MEM(path = talloc_asprintf_append_buffer(path, "%s:", dirname(mutable)));
	}
	if (inst->python_path_include_default) {
		MEM(path = talloc_asprintf_append_buffer(path, "%s:", default_path));
	}
	if (path[talloc_array_length(path) - 1] == ':') {
		MEM(path = talloc_bstr_realloc(ctx, path, talloc_array_length(path) - 2));
	}

	return path;
}

/*
 *	Python 3 interpreter initialisation and destruction
 */
static PyObject *python_module_init(void)
{
	rlm_python_t	*inst = current_inst;
	PyObject	*module;

	static struct PyModuleDef py_module_def = {
		PyModuleDef_HEAD_INIT,
		.m_name = "freeradius",
		.m_doc = "freeRADIUS python module",
		.m_size = -1,
		.m_methods = module_methods
	};

	fr_assert(inst);

	module = PyModule_Create(&py_module_def);
	if (!module) {
		python_error_log(inst, NULL);
		Py_RETURN_NONE;
	}

	return module;
}

static int python_interpreter_init(rlm_python_t *inst, CONF_SECTION *conf)
{
	char		*path;
	PyObject	*module;
	wchar_t	        *wide_path;

	/*
	 *	python_module_init takes no args, so we need
	 *	to set these globals so that when it's
	 *	called during interpreter initialisation
	 *	it can get at the current instance config.
	 */
	current_inst = inst;
	current_conf = conf;

	PyEval_RestoreThread(global_interpreter);
	LSAN_DISABLE(inst->interpreter = Py_NewInterpreter());
	if (!inst->interpreter) {
		ERROR("Failed creating new interpreter");
		return -1;
	}
	DEBUG3("Created new interpreter %p", inst->interpreter);
	PyEval_SaveThread();		/* Unlock GIL */

	PyEval_RestoreThread(inst->interpreter);

	path = python_path_build(inst, inst, conf);
	DEBUG3("Setting python path to \"%s\"", path);
	wide_path = Py_DecodeLocale(path, NULL);
	talloc_free(path);
	PySys_SetPath(wide_path);
	PyMem_RawFree(wide_path);

	/*
	 *	Import the radiusd module into this python
	 *	environment.  Each interpreter gets its
	 *	own copy which it can mutate as much as
	 *      it wants.
	 */
 	module = PyImport_ImportModule("freeradius");
 	if (!module) {
 		ERROR("Failed importing \"freeradius\" module into interpreter %p", inst->interpreter);
 		return -1;
 	}
	if ((python_module_import_config(inst, conf, module) < 0) ||
	    (python_module_import_constants(inst, module) < 0)) {
		Py_DECREF(module);
		return -1;
	}
	inst->module = module;
	PyEval_SaveThread();

	return 0;
}

static void python_interpreter_free(UNUSED rlm_python_t *inst, PyThreadState *interp)
{
	/*
	 *	We incremented the reference count earlier
	 *	during module initialisation.
	 */
	Py_XDECREF(inst->module);

	PyEval_RestoreThread(interp);	/* Switches thread state and locks GIL */
	Py_EndInterpreter(interp);	/* Destroys interpreter (GIL still locked) - sets thread state to NULL */
	PyThreadState_Swap(global_interpreter);	/* Get a none-null thread state */
	PyEval_SaveThread();		/* Unlock GIL */
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
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_python_t	*inst = instance;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	if (python_interpreter_init(inst, conf) < 0) return -1;

	/*
	 *	Switch to our module specific interpreter
	 */
	PyEval_RestoreThread(inst->interpreter);

	/*
	 *	Process the various sections
	 */
#define PYTHON_FUNC_LOAD(_x) if (python_function_load(inst, &inst->_x) < 0) goto error
	PYTHON_FUNC_LOAD(instantiate);
	PYTHON_FUNC_LOAD(authenticate);
	PYTHON_FUNC_LOAD(authorize);
	PYTHON_FUNC_LOAD(preacct);
	PYTHON_FUNC_LOAD(accounting);
	PYTHON_FUNC_LOAD(post_auth);
	PYTHON_FUNC_LOAD(detach);

	/*
	 *	Call the instantiate function.
	 */
	if (inst->instantiate.function) {
		rlm_rcode_t rcode;

		do_python_single(&rcode, inst, NULL, inst->instantiate.function, "instantiate");
		switch (rcode) {
		case RLM_MODULE_FAIL:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_YIELD:	/* Yield not valid in instantiate */
		error:
			fr_cond_assert(PyEval_SaveThread() == inst->interpreter);
			return -1;

		default:
			break;
		}
	}

	/*
	 *	Switch back to the global interpreter
	 */
	if (!fr_cond_assert(PyEval_SaveThread() == inst->interpreter)) goto error;

	return 0;
}

static int mod_detach(void *instance)
{
	rlm_python_t	*inst = instance;

	/*
	 *	If we don't have a interpreter
	 *	we didn't get far enough into
	 *	instantiation to generate things
	 *	we need to clean up...
	 */
	if (!inst->interpreter) return 0;

	/*
	 *	Call module destructor
	 */
	PyEval_RestoreThread(inst->interpreter);

	/*
	 *	We don't care if this fails.
	 */
	if (inst->detach.function) {
		rlm_rcode_t rcode;

		(void)do_python_single(&rcode, inst, NULL, inst->detach.function, "detach");
	}

#define PYTHON_FUNC_DESTROY(_x) python_function_destroy(&inst->_x)
	PYTHON_FUNC_DESTROY(instantiate);
	PYTHON_FUNC_DESTROY(authorize);
	PYTHON_FUNC_DESTROY(authenticate);
	PYTHON_FUNC_DESTROY(preacct);
	PYTHON_FUNC_DESTROY(accounting);
	PYTHON_FUNC_DESTROY(post_auth);
	PYTHON_FUNC_DESTROY(detach);

	Py_XDECREF(inst->pythonconf_dict);
	PyEval_SaveThread();

	/*
	 *	Free the module specific interpreter
	 */
	python_interpreter_free(inst, inst->interpreter);

	return 0;
}

static int mod_thread_instantiate(UNUSED CONF_SECTION const *conf, void *instance,
				  UNUSED fr_event_list_t *el, void *thread)
{
	PyThreadState		*state;
	rlm_python_t		*inst = instance;
	rlm_python_thread_t	*this_thread = thread;

	state = PyThreadState_New(inst->interpreter->interp);
	if (!state) {
		ERROR("Failed initialising local PyThreadState");
		return -1;
	}

	DEBUG3("Initialised new thread state %p", state);
	this_thread->state = state;

	return 0;
}

static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	rlm_python_thread_t	*this_thread = thread;

	PyEval_RestoreThread(this_thread->state);	/* Swap in our local thread state */
	PyThreadState_Clear(this_thread->state);
	PyEval_SaveThread();

	PyThreadState_Delete(this_thread->state);	/* Don't need to hold lock for this */

	return 0;
}

static int mod_load(void)
{
#define LOAD_INFO(_fmt, ...) fr_log(LOG_DST, L_INFO, __FILE__, __LINE__, "rlm_python - " _fmt,  ## __VA_ARGS__)
#define LOAD_WARN(_fmt, ...) fr_log_perror(LOG_DST, L_WARN, __FILE__, __LINE__, \
					   &(fr_log_perror_format_t){ \
					   	.first_prefix = "rlm_python - ", \
					   	.subsq_prefix = "rlm_python - ", \
					   }, \
					   _fmt,  ## __VA_ARGS__)

	fr_assert(!Py_IsInitialized());

	LOAD_INFO("Python version: %s", Py_GetVersion());
	dependency_version_number_add(NULL, "python", Py_GetVersion());

	/*
	 *	Load python using RTLD_GLOBAL and dlopen.
	 *	This fixes issues where python C extensions
	 *	can't find the symbols they need.
	 */
	python_dlhandle = dl_open_by_sym("Py_IsInitialized", RTLD_NOW | RTLD_GLOBAL);
	if (!python_dlhandle) LOAD_WARN("Failed loading libpython symbols into global symbol table");

	/*
	 *	Python 3 introduces the concept of a
	 *	"inittab", i.e. a list of modules which
	 *	are automatically created when the first
	 *	interpreter is spawned.
	 */
	PyImport_AppendInittab("freeradius", python_module_init);
	LSAN_DISABLE(Py_InitializeEx(0));	/* Don't override signal handlers - noop on subs calls */

	/*
	 *	Get the default search path so we can append to it.
	 */
	default_path = Py_EncodeLocale(Py_GetPath(), NULL);

	/*
	 *	As of 3.7 this is called by Py_Initialize
	 */
#if PY_VERSION_HEX < 0x03070000
	PyEval_InitThreads(); 			/* This also grabs a lock (which we then need to release) */
#endif

	/*
	 *	Set program name (i.e. the software calling the interpreter)
	 */
	{
		wchar_t *wide_name;
		wide_name = Py_DecodeLocale(main_config->name, NULL);
		Py_SetProgramName(wide_name);		/* The value of argv[0] as a wide char string */
		PyMem_RawFree(wide_name);
	}
	global_interpreter = PyEval_SaveThread();	/* Store reference to the main interpreter and release the GIL */

	return 0;
}

static void mod_unload(void)
{
	PyThreadState_Swap(global_interpreter); /* Swap to the main thread */
	if (default_path) PyMem_Free(default_path);

	/*
	 *	PyImport_Cleanup - Leaks memory in python 3.6
	 *	should check once we require 3.8 that this is
	 *	still needed.
	 */
	LSAN_DISABLE(Py_Finalize());			/* Ignore leaks on exit, we don't reload modules so we don't care */
	if (python_dlhandle) dlclose(python_dlhandle);	/* dlclose will SEGV on null handle */
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
	.magic			= RLM_MODULE_INIT,
	.name			= "python",
	.type			= RLM_TYPE_THREAD_SAFE,

	.inst_size		= sizeof(rlm_python_t),
	.thread_inst_size	= sizeof(rlm_python_thread_t),

	.config			= module_config,
	.onload			= mod_load,
	.unload			= mod_unload,

	.instantiate		= mod_instantiate,
	.detach			= mod_detach,

	.thread_instantiate	= mod_thread_instantiate,
	.thread_detach		= mod_thread_detach,

	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_POST_AUTH]		= mod_post_auth,
	}
};
