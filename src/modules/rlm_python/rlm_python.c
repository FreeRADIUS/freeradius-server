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

#define LOG_PREFIX "rlm_python - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/lsan.h>

#include <Python.h>
#include <dlfcn.h>

static uint32_t		python_instances = 0;
static void		*python_dlhandle;

static PyThreadState	*main_interpreter;	//!< Main interpreter (cext safe)
static PyObject		*main_module;		//!< Pthon configuration dictionary.

#if PY_VERSION_HEX >= 0x03050000
static wchar_t		*wide_name;		//!< Special wide char encoding of radiusd name.
#endif


#if PY_VERSION_HEX < 0x03000000
/*
 *	Python 2.7 has its own versions of these which
 *	operate on UCS2 encoding *sigh*
 */
#undef PyUnicode_AsUTF8
#undef PyUnicode_FromString
#undef PyUnicode_CheckExact
#undef PyUnicode_FromFormat

#define PyUnicode_AsUTF8 PyString_AsString
#define PyUnicode_FromString PyString_FromString
#define PyUnicode_CheckExact PyString_CheckExact
#define PyUnicode_FromFormat PyString_FromFormat
#endif

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
	PyThreadState	*sub_interpreter;	//!< The main interpreter/thread used for this instance.
	char const	*python_path;		//!< Path to search for python files in.

#if PY_VERSION_HEX >= 0x03050000
	wchar_t		*wide_path;		//!< Special wide char encoding of radiusd path.
						//!< FreeRADIUS functions.
#endif

	PyObject	*module;		//!< Local, interpreter specific module, containing
	bool		cext_compat;		//!< Whether or not to create sub-interpreters per module
						//!< instance.

	python_func_def_t
	instantiate,
	authorize,
	authenticate,
	preacct,
	accounting,
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
} rlm_python_t;

/** Tracks a python module inst/thread state pair
 *
 * Multiple instances of python create multiple interpreters and each
 * thread must have a PyThreadState per interpreter, to track execution.
 */
typedef struct {
	PyThreadState	*state;			//!< Module instance/thread specific state.
} rlm_python_thread_t;

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
	A(pre_proxy)
	A(post_proxy)
	A(post_auth)
#ifdef WITH_COA
	A(recv_coa)
	A(send_coa)
#endif
	A(detach)

#undef A

	{ FR_CONF_OFFSET("python_path", FR_TYPE_STRING, rlm_python_t, python_path) },
	{ FR_CONF_OFFSET("cext_compat", FR_TYPE_BOOL, rlm_python_t, cext_compat), .dflt = false },

	CONF_PARSER_TERMINATOR
};

static struct {
	char const *name;
	int  value;
} radiusd_constants[] = {

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
	A(RLM_MODULE_USERLOCK)
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
		return NULL;
	}

	fr_log(&default_log, status, __FILE__, __LINE__, "%s", msg);
	Py_INCREF(Py_None);

	return Py_None;
}

static PyMethodDef module_methods[] = {
	{ "log", &mod_log, METH_VARARGS,
	  "radiusd.log(level, msg)\n\n" \
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
	PyObject *pType = NULL, *pValue = NULL, *pTraceback = NULL, *pStr1 = NULL, *pStr2 = NULL;

	PyErr_Fetch(&pType, &pValue, &pTraceback);
	if (!pType || !pValue)
		goto failed;
	if (((pStr1 = PyObject_Str(pType)) == NULL) ||
	    ((pStr2 = PyObject_Str(pValue)) == NULL))
		goto failed;

	ERROR("%s (%s)", PyUnicode_AsUTF8(pStr1), PyUnicode_AsUTF8(pStr2));

failed:
	Py_XDECREF(pStr1);
	Py_XDECREF(pStr2);
	Py_XDECREF(pType);
	Py_XDECREF(pValue);
	Py_XDECREF(pTraceback);
}

static void mod_vptuple(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR **vps, PyObject *pValue,
			char const *funcname, char const *list_name)
{
	int	     	i;
	int	     	tuplesize;
	vp_tmpl_t       *dst;
	VALUE_PAIR      *vp;
	REQUEST	*current = request;

	/*
	 *	If the Python function gave us None for the tuple,
	 *	then just return.
	 */
	if (pValue == Py_None) return;

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

		if ((!PyUnicode_CheckExact(pStr1)) || (!PyUnicode_CheckExact(pStr2))) {
			ERROR("%s - Tuple element %d of %s must be as (str, str)",
			      funcname, i, list_name);
			continue;
		}
		s1 = PyUnicode_AsUTF8(pStr1);
		s2 = PyUnicode_AsUTF8(pStr2);

		if (pairsize == 3) {
			pOp = PyTuple_GET_ITEM(pTupleElement, 1);
			if (PyUnicode_CheckExact(pOp)) {
				if (!(op = fr_table_value_by_str(fr_tokens_table, PyUnicode_AsUTF8(pOp), 0))) {
					ERROR("%s - Invalid operator %s:%s %s %s, falling back to '='",
					      funcname, list_name, s1, PyUnicode_AsUTF8(pOp), s2);
					op = T_OP_EQ;
				}
			} else if (PyNumber_Check(pOp)) {
				op = PyLong_AsLong(pOp);
				if (!fr_table_str_by_value(fr_tokens_table, op, NULL)) {
					ERROR("%s - Invalid operator %s:%s %i %s, falling back to '='",
					      funcname, list_name, s1, op, s2);
					op = T_OP_EQ;
				}
			} else {
				ERROR("%s - Invalid operator type for %s:%s ? %s, using default '='",
				      funcname, list_name, s1, s2);
			}
		}

		if (tmpl_afrom_attr_str(ctx, NULL, &dst, s1,
					&(vp_tmpl_rules_t){
						.dict_def = request->dict,
						.list_def = PAIR_LIST_REPLY
					}) <= 0) {
			ERROR("%s - Failed to find attribute %s:%s", funcname, list_name, s1);
			continue;
		}

		if (radius_request(&current, dst->tmpl_request) < 0) {
			ERROR("%s - Attribute name %s:%s refers to outer request but not in a tunnel, skipping...",
			      funcname, list_name, s1);
			talloc_free(dst);
			continue;
		}

		vp = fr_pair_afrom_da(ctx, dst->tmpl_da);
		talloc_free(dst);
		if (!vp) {
			ERROR("%s - Failed to create attribute %s:%s", funcname, list_name, s1);
			continue;
		}


		vp->op = op;
		if (fr_pair_value_from_str(vp, s2, -1, '\0', false) < 0) {
			DEBUG("%s - Failed: '%s:%s' %s '%s'", funcname, list_name, s1,
			      fr_table_str_by_value(fr_tokens_table, op, "="), s2);
		} else {
			DEBUG("%s - '%s:%s' %s '%s'", funcname, list_name, s1,
			      fr_table_str_by_value(fr_tokens_table, op, "="), s2);
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
static int mod_populate_vptuple(PyObject *pp, VALUE_PAIR *vp)
{
	PyObject *attribute = NULL;
	PyObject *value = NULL;

	/* Look at the fr_pair_fprint_name? */

	if (vp->da->flags.has_tag) {
		attribute = PyUnicode_FromFormat("%s:%d", vp->da->name, vp->tag);
	} else {
		attribute = PyUnicode_FromString(vp->da->name);
	}

	if (!attribute) return -1;

	PyTuple_SET_ITEM(pp, 0, attribute);

	switch (vp->vp_type) {
	case FR_TYPE_STRING:
		value = PyUnicode_FromStringAndSize(vp->vp_strvalue, vp->vp_length);
		break;

	case FR_TYPE_OCTETS:
		value = PyUnicode_FromStringAndSize((char const *)vp->vp_octets, vp->vp_length);
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
		value = PyLong_FromUnsignedLongLong((unsigned long long)vp->vp_size);
		break;

	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_DATE:
	case FR_TYPE_ABINARY:
	case FR_TYPE_IFID:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_IPV4_PREFIX:
	{
		size_t len;
		char buffer[256];

		len = fr_pair_value_snprint(buffer, sizeof(buffer), vp, '\0');
		value = PyUnicode_FromStringAndSize(buffer, len);
	}
		break;

	case FR_TYPE_NON_VALUES:
		rad_assert(0);
		return -1;
	}

	if (value == NULL) return -1;

	PyTuple_SET_ITEM(pp, 1, value);

	return 0;
}

static rlm_rcode_t do_python_single(REQUEST *request, PyObject *pFunc, char const *funcname)
{
	fr_cursor_t	cursor;
	VALUE_PAIR      *vp;
	PyObject	*pRet = NULL;
	PyObject	*pArgs = NULL;
	int		tuplelen;
	int		ret;

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
		     vp = fr_cursor_next(&cursor)) tuplelen++;
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
			PyObject *pp;

			/* The inside tuple has two only: */
			if ((pp = PyTuple_New(2)) == NULL) {
				ret = RLM_MODULE_FAIL;
				goto finish;
			}

			if (mod_populate_vptuple(pp, vp) == 0) {
				/* Put the tuple inside the container */
				PyTuple_SET_ITEM(pArgs, i, pp);
			} else {
				Py_INCREF(Py_None);
				PyTuple_SET_ITEM(pArgs, i, Py_None);
				Py_DECREF(pp);
			}
		}
	}

	/* Call Python function. */
	pRet = PyObject_CallFunctionObjArgs(pFunc, pArgs, NULL);
	if (!pRet) {
		ret = RLM_MODULE_FAIL;
		goto finish;
	}

	if (!request) {
		// check return code at module instantiation time
		if (PyNumber_Check(pRet)) ret = PyLong_AsLong(pRet);
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

		if (PyTuple_GET_SIZE(pRet) != 3) {
			ERROR("%s - Tuple must be (return, replyTuple, configTuple)", funcname);
			ret = RLM_MODULE_FAIL;
			goto finish;
		}

		pTupleInt = PyTuple_GET_ITEM(pRet, 0);
		if (!PyNumber_Check(pTupleInt)) {
			ERROR("%s - First tuple element not an integer", funcname);
			ret = RLM_MODULE_FAIL;
			goto finish;
		}
		/* Now have the return value */
		ret = PyLong_AsLong(pTupleInt);
		/* Reply item tuple */
		mod_vptuple(request->reply, request, &request->reply->vps,
			    PyTuple_GET_ITEM(pRet, 1), funcname, "reply");
		/* Config item tuple */
		mod_vptuple(request, request, &request->control,
			    PyTuple_GET_ITEM(pRet, 2), funcname, "config");

	} else if (PyNumber_Check(pRet)) {
		/* Just an integer */
		ret = PyLong_AsLong(pRet);

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

	return ret;
}

static void python_interpreter_free(PyThreadState *interp)
{
#if PY_VERSION_HEX >= 0x03000000
	PyEval_AcquireThread(interp);
	Py_EndInterpreter(interp);
#else
	PyEval_AcquireLock();
	PyThreadState_Swap(interp);
	Py_EndInterpreter(interp);
	PyEval_ReleaseLock();
#endif
}

/** Thread safe call to a python function
 *
 * Will swap in thread state specific to module/thread.
 */
static rlm_rcode_t do_python(rlm_python_t const *inst, rlm_python_thread_t *this_thread,
			     REQUEST *request, PyObject *pFunc, char const *funcname)
{
	int			ret;

	/*
	 *	It's a NOOP if the function wasn't defined
	 */
	if (!pFunc) return RLM_MODULE_NOOP;

	RDEBUG3("Using thread state %p/%p", inst, this_thread->state);

	PyEval_RestoreThread(this_thread->state);	/* Swap in our local thread state */
	ret = do_python_single(request, pFunc, funcname);
	PyEval_SaveThread();

	return ret;
}

#define MOD_FUNC(x) \
static rlm_rcode_t CC_HINT(nonnull) mod_##x(void *instance, void *thread, REQUEST *request) { \
	return do_python((rlm_python_t const *) instance, (rlm_python_thread_t *)thread, \
			 request, ((rlm_python_t const *)instance)->x.function, #x);\
}

MOD_FUNC(authenticate)
MOD_FUNC(authorize)
MOD_FUNC(preacct)
MOD_FUNC(accounting)
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
static int python_function_load(python_func_def_t *def)
{
	char const *funcname = "python_function_load";

	if (def->module_name == NULL || def->function_name == NULL) return 0;

	LSAN_DISABLE(def->module = PyImport_ImportModuleNoBlock(def->module_name));
	if (!def->module) {
		ERROR("%s - Module '%s' not found", funcname, def->module_name);

	error:
		python_error_log();
		ERROR("%s - Failed importing python function '%s.%s'", funcname, def->module_name, def->function_name);
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
static void python_parse_config(CONF_SECTION *cs, int lvl, PyObject *dict)
{
	int		indent_section = (lvl + 1) * 4;
	int		indent_item = (lvl + 2) * 4;
	CONF_ITEM	*ci = NULL;

	if (!cs || !dict) return;

	DEBUG("%*s%s {", indent_section, " ", cf_section_name1(cs));

	while ((ci = cf_item_next(cs, ci))) {
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

			pKey = PyUnicode_FromString(key);
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

			pKey = PyUnicode_FromString(key);
			pValue = PyUnicode_FromString(value);
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

/** Initialises a separate python interpreter for this module instance
 *
 */
static int python_interpreter_init(rlm_python_t *inst, CONF_SECTION *conf)
{
	int i;

	/*
	 *	Increment the reference counter
	 */
	python_instances++;

	/*
	 *	This sets up a separate environment for each python module instance
	 *	These will be destroyed on Py_Finalize().
	 */
	if (!inst->cext_compat) {
		LSAN_DISABLE(inst->sub_interpreter = Py_NewInterpreter());
	} else {
		inst->sub_interpreter = main_interpreter;
	}

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
#if PY_VERSION_HEX >= 0x03050000
			{
				inst->wide_path = Py_DecodeLocale(inst->python_path, NULL);
				PySys_SetPath(inst->wide_path);
			}
#else
			{
				char *path;

				memcpy(&path, &inst->python_path, sizeof(path));
				PySys_SetPath(path);
			}
#endif
		}

		/*
		 *	Initialise a new module, with our default methods
		 */
#if PY_VERSION_HEX >= 0x03000000
	        {
			static struct PyModuleDef py_module_def = {
				PyModuleDef_HEAD_INIT,
				"radiusd",			/* m_name */
				"FreeRADIUS python module",	/* m_doc */
				-1,				/* m_size */
				module_methods,			/* m_methods */
				NULL,				/* m_reload */
				NULL,				/* m_traverse */
				NULL,				/* m_clear */
				NULL,				/* m_free */
			};

			inst->module = PyModule_Create(&py_module_def);
		}
#else
		inst->module = Py_InitModule3("radiusd", module_methods, "FreeRADIUS python module");
#endif
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

		cs = cf_section_find(conf, "config", NULL);
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
static int mod_instantiate(void *instance, CONF_SECTION *conf)
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
#define PYTHON_FUNC_LOAD(_x) if (python_function_load(&inst->_x) < 0) goto error
	PYTHON_FUNC_LOAD(instantiate);
	PYTHON_FUNC_LOAD(authenticate);
	PYTHON_FUNC_LOAD(authorize);
	PYTHON_FUNC_LOAD(preacct);
	PYTHON_FUNC_LOAD(accounting);
	PYTHON_FUNC_LOAD(pre_proxy);
	PYTHON_FUNC_LOAD(post_proxy);
	PYTHON_FUNC_LOAD(post_auth);
#ifdef WITH_COA
	PYTHON_FUNC_LOAD(recv_coa);
	PYTHON_FUNC_LOAD(send_coa);
#endif
	PYTHON_FUNC_LOAD(detach);

	/*
	 *	Call the instantiate function.
	 */
	code = do_python_single(NULL, inst->instantiate.function, "instantiate");
	if (code < 0) {
	error:
		python_error_log();	/* Needs valid thread with GIL */
		PyEval_SaveThread();
		return -1;
	}
	PyEval_SaveThread();

	return 0;
}

static int mod_detach(void *instance)
{
	rlm_python_t *inst = instance;
	int	     ret = 0;

	/*
	 *      If we don't have a sub_interpreter
	 *      we didn't get far enough into
	 *      instantiation to generate things
	 *      we need to clean up...
	 */
	if (!inst->sub_interpreter) return 0;

	/*
	 *	Call module destructor
	 */
	PyEval_RestoreThread(inst->sub_interpreter);

	if (inst->detach.function) ret = do_python_single(NULL, inst->detach.function, "detach");

#define PYTHON_FUNC_DESTROY(_x) python_function_destroy(&inst->_x)
	PYTHON_FUNC_DESTROY(instantiate);
	PYTHON_FUNC_DESTROY(authorize);
	PYTHON_FUNC_DESTROY(authenticate);
	PYTHON_FUNC_DESTROY(preacct);
	PYTHON_FUNC_DESTROY(accounting);
	PYTHON_FUNC_DESTROY(pre_proxy);
	PYTHON_FUNC_DESTROY(post_proxy);
	PYTHON_FUNC_DESTROY(post_auth);
#ifdef WITH_COA
	PYTHON_FUNC_DESTROY(recv_coa);
	PYTHON_FUNC_DESTROY(send_coa);
#endif
	PYTHON_FUNC_DESTROY(detach);

	Py_DecRef(inst->pythonconf_dict);
	Py_DecRef(inst->module);

	PyEval_SaveThread();

	/*
	 *	Only destroy if it's a subinterpreter
	 */
	if (!inst->cext_compat) python_interpreter_free(inst->sub_interpreter);

	if ((--python_instances) == 0) {
#if PY_VERSION_HEX >= 0x03050000
		if (inst->wide_path) PyMem_RawFree(inst->wide_path);
#endif
	}

	return ret;
}

static int mod_thread_instantiate(UNUSED CONF_SECTION const *conf, void *instance,
				  UNUSED fr_event_list_t *el, void *thread)
{
	PyThreadState		*state;
	rlm_python_t		*inst = instance;
	rlm_python_thread_t	*this_thread = thread;

	state = PyThreadState_New(inst->sub_interpreter->interp);
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
	rad_assert(!Py_IsInitialized());

	INFO("Python version: %s", Py_GetVersion());

	/*
	 *	Explicitly load libpython, so symbols will be available to lib-dynload modules
	 */
	python_dlhandle = dlopen("libpython" STRINGIFY(PY_MAJOR_VERSION) "." STRINGIFY(PY_MINOR_VERSION) ".so",
				 RTLD_NOW | RTLD_GLOBAL);
	if (!python_dlhandle) WARN("Failed loading libpython symbols into global symbol table: %s", dlerror());

	LSAN_DISABLE(Py_InitializeEx(0));	/* Don't override signal handlers - noop on subs calls */
	PyEval_InitThreads(); 			/* This also grabs a lock (which we then need to release) */
	rad_assert(PyEval_ThreadsInitialized());
	main_interpreter = PyThreadState_Get();	/* Store reference to the main interpreter */

	/*
	 *	Set program name (i.e. the software calling the interpreter)
	 */
#if PY_VERSION_HEX >= 0x03050000
	{
		wide_name = Py_DecodeLocale(main_config->name, NULL);
		Py_SetProgramName(wide_name);		/* The value of argv[0] as a wide char string */
	}
#else
	{
		char const *const_name;
		char *name;

		const_name = main_config->name;

		memcpy(&name, &const_name, sizeof(name));
		Py_SetProgramName(name);		/* The value of argv[0] as a wide char string */
	}
#endif

	return 0;
}

static void mod_unload(void)
{
	PyThreadState_Swap(main_interpreter); /* Swap to the main thread */
	Py_Finalize();
	dlclose(python_dlhandle);

#if PY_VERSION_HEX >= 0x03050000
	if (wide_name) PyMem_RawFree(wide_name);
#endif
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
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
		[MOD_POST_AUTH]		= mod_post_auth,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_recv_coa,
		[MOD_SEND_COA]		= mod_send_coa
#endif
	}
};
