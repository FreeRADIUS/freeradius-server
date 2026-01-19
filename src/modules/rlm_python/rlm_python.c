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
 * @note Rewritten by Nick Porter for FreeRADIUS v4
 *
 * @copyright 2000,2006,2015-2016 The FreeRADIUS server project
 * @copyright 2025 Network RADIUS SAS
 */
RCSID("$Id$")

#define LOG_PREFIX inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/lsan.h>
#include <freeradius-devel/unlang/action.h>

#include <Python.h>
#include <structmember.h>
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
	char		*name1;			//!< Section name1 where this is called.
	char		*name2;			//!< Section name2 where this is called.
	fr_rb_node_t	node;			//!< Entry in tree of Python functions.
} python_func_def_t;

/** An instance of the rlm_python module
 *
 */
typedef struct {
	char const	*name;			//!< Name of the module instance
	PyThreadState	*interpreter;		//!< The interpreter used for this instance of rlm_python.
	PyObject	*module;		//!< Local, interpreter specific module.
	char const	*def_module_name;	//!< Default module for Python functions
	fr_rb_tree_t	funcs;			//!< Tree of function calls found by call_env parser
	bool		funcs_init;		//!< Has the tree been initialised.

	python_func_def_t
	instantiate,
	detach;

	PyObject	*pythonconf_dict;	//!< Configuration parameters defined in the module
						//!< made available to the python script.
} rlm_python_t;

/** Global config for python library
 *
 */
typedef struct {
	char const	*path;			//!< Path to search for python files in.
	bool		path_include_default;	//!< Include the default python path in `path`
	bool		verbose;		//!< Enable libpython verbose logging
} libpython_global_config_t;

typedef struct {
	python_func_def_t	*func;
} python_call_env_t;

/** Tracks a python module inst/thread state pair
 *
 * Multiple instances of python create multiple interpreters and each
 * thread must have a PyThreadState per interpreter, to track execution.
 */
typedef struct {
	rlm_python_t const	*inst;		//!< Current module instance data.
	PyThreadState		*state;		//!< Module instance/thread specific state.
} rlm_python_thread_t;

/** Additional fields for pairs
 *
 */
typedef struct {
	PyObject_HEAD				//!< Common fields needed for every python object.
	fr_dict_attr_t const	*da;		//!< dictionary attribute for this pair.
	fr_pair_t		*vp;		//!< Real FreeRADIUS pair for this Python pair.
	unsigned int		idx;		//!< Instance index.
	PyObject		*parent;	//!< Parent object of this pair.
} py_freeradius_pair_t;

typedef struct {
	PyObject_HEAD				//!< Common fields needed for every python object.
	PyObject		*request;	//!< Request list.
	PyObject		*reply;		//!< Reply list.
	PyObject		*control;	//!< Control list.
	PyObject		*state;		//!< Session state list.
} py_freeradius_request_t;

/** Wrapper around a python instance
 *
 * This is added to the FreeRADIUS module to allow us to
 * get at the global and thread local instance data.
 */
typedef struct {
	PyObject_HEAD				//!< Common fields needed for every python object.
	rlm_python_t const	*inst;		//!< Module instance.
	rlm_python_thread_t	*t;		//!< Thread-specific python instance.
	request_t		*request;	//!< Current request.
} py_freeradius_state_t;

static void			*python_dlhandle;
static PyThreadState		*global_interpreter;	//!< Our first interpreter.

static rlm_python_t const	*current_inst = NULL;	//!< Used for communication with inittab functions.
static CONF_SECTION		*current_conf;		//!< Used for communication with inittab functions.
static rlm_python_thread_t	*current_t;		//!< Used for communicating with object init function.

static PyObject *py_freeradius_log(UNUSED PyObject *self, PyObject *args, PyObject *kwds);

static int	py_freeradius_state_init(PyObject *self, UNUSED PyObject *args, UNUSED PyObject *kwds);

static PyObject	*py_freeradius_pair_map_subscript(PyObject *self, PyObject *attr);
static PyObject *py_freeradius_attribute_instance(PyObject *self, PyObject *attr);
static int	py_freeradius_pair_map_set(PyObject* self, PyObject* attr, PyObject* value);
static PyObject *py_freeradius_pair_getvalue(PyObject *self, void *closure);
static int	py_freeradius_pair_setvalue(PyObject *self, PyObject *value, void *closure);
static PyObject	*py_freeradius_pair_str(PyObject *self);

static libpython_global_config_t libpython_global_config = {
	.path = NULL,
	.path_include_default = true
};

static conf_parser_t const python_global_config[] = {
	{ FR_CONF_OFFSET("path", libpython_global_config_t, path) },
	{ FR_CONF_OFFSET("path_include_default", libpython_global_config_t, path_include_default) },
	{ FR_CONF_OFFSET("verbose", libpython_global_config_t, verbose) },
	CONF_PARSER_TERMINATOR
};

static int libpython_init(void);
static void libpython_free(void);

static global_lib_autoinst_t rlm_python_autoinst = {
	.name = "python",
	.config = python_global_config,
	.init = libpython_init,
	.free = libpython_free,
	.inst = &libpython_global_config
};

extern global_lib_autoinst_t const * const rlm_python_lib[];
global_lib_autoinst_t const * const rlm_python_lib[] = {
	&rlm_python_autoinst,
	GLOBAL_LIB_TERMINATOR
};

/*
 *	As of Python 3.8 the GIL will be per-interpreter
 *	If there are still issues with CEXTs,
 *	multiple interpreters and the GIL at that point
 *	users can build rlm_python against Python 3.8
 *	and the horrible hack of using a single interpreter
 *	for all instances of rlm_python will no longer be
 *	required.
 */

/*
 *	A mapping of configuration file names to internal variables.
 */
static conf_parser_t module_config[] = {

#define A(x) { FR_CONF_OFFSET("mod_" #x, rlm_python_t, x.module_name), .dflt = "${.module}" }, \
	{ FR_CONF_OFFSET("func_" #x, rlm_python_t, x.function_name) },

	A(instantiate)
	A(detach)

#undef A

	{ FR_CONF_OFFSET("module", rlm_python_t, def_module_name) },

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
	A(L_DBG_LVL_OFF)
	A(L_DBG_LVL_1)
	A(L_DBG_LVL_2)
	A(L_DBG_LVL_3)
	A(L_DBG_LVL_4)
	A(L_DBG_LVL_MAX)
	A(RLM_MODULE_REJECT)
	A(RLM_MODULE_FAIL)
	A(RLM_MODULE_OK)
	A(RLM_MODULE_HANDLED)
	A(RLM_MODULE_INVALID)
	A(RLM_MODULE_DISALLOW)
	A(RLM_MODULE_NOTFOUND)
	A(RLM_MODULE_NOOP)
	A(RLM_MODULE_UPDATED)
	A(RLM_MODULE_TIMEOUT)
#undef A

	{ NULL, 0 },
};

/** The class which all pair types inherit from
 *
 */
static PyTypeObject py_freeradius_pair_def = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "freeradius.Pair",
	.tp_doc = "An attribute value pair",
	.tp_basicsize = sizeof(py_freeradius_pair_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = PyType_GenericNew,
};

/** How to access "value" attribute of a pair
 *
 */
static PyGetSetDef py_freeradius_pair_getset[] = {
	{
		.name = "value",
		.get = py_freeradius_pair_getvalue,
		.set = py_freeradius_pair_setvalue,
		.doc = "Pair value",
		.closure = NULL
	},
	{ .name = NULL }	/* Terminator */
};

/** Contains a value pair of a specific type
 *
 */
static PyTypeObject py_freeradius_value_pair_def = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "freeradius.ValuePair",
	.tp_doc = "A value pair, i.e. one of the type string, integer, ipaddr etc...)",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_base = &py_freeradius_pair_def,
	.tp_getset = py_freeradius_pair_getset,
	.tp_str = py_freeradius_pair_str,
	.tp_as_mapping = &(PyMappingMethods) {
		.mp_subscript = py_freeradius_attribute_instance,
		.mp_ass_subscript = py_freeradius_pair_map_set,
	}
};

/** Contains group attribute of a specific type
 *
 * Children of this attribute may be accessed using the map protocol
 * i.e. foo['child-of-foo'].
 *
 */
static PyTypeObject py_freeradius_grouping_pair_def = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "freeradius.GroupingPair",
	.tp_doc = "A grouping pair, i.e. one of the type group, tlv, vsa or vendor.  "
	          "Children are accessible via the mapping protocol i.e. foo['child-of-foo]",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_base = &py_freeradius_pair_def,
	.tp_as_mapping = &(PyMappingMethods){
		.mp_subscript = py_freeradius_pair_map_subscript,
		.mp_ass_subscript = py_freeradius_pair_map_set,
	}
};

/** Each instance contains a top level list (i.e. request, reply, control, session-state)
 */
static PyTypeObject py_freeradius_pair_list_def = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "freeradius.PairList",
	.tp_doc = "A list of objects of freeradius.GroupingPairList and freeradius.ValuePair",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_base = &py_freeradius_pair_def,
	.tp_as_mapping = &(PyMappingMethods){
		.mp_subscript = py_freeradius_pair_map_subscript,
		.mp_ass_subscript = py_freeradius_pair_map_set,
	}
};

static PyMemberDef py_freeradius_request_attrs[] = {
	{
		.name = "request",
		.type = T_OBJECT,
		.offset = offsetof(py_freeradius_request_t, request),
		.flags = READONLY,
		.doc = "Pairs in the request list - received from the network"
	},
	{
		.name = "reply",
		.type = T_OBJECT,
		.offset = offsetof(py_freeradius_request_t, reply),
		.flags = READONLY,
		.doc = "Pairs in the reply list - sent to the network"
	},
	{
		.name = "control",
		.type = T_OBJECT,
		.offset = offsetof(py_freeradius_request_t, control),
		.flags = READONLY,
		.doc = "Pairs in the control list - control the behaviour of subsequently called modules"
	},
	{
		.name = "session-state",
		.type = T_OBJECT,
		.offset = offsetof(py_freeradius_request_t, state),
		.flags = READONLY,
		.doc = "Pairs in the session-state list - persists for the length of the session"
	},
	{ .name = NULL }	/* Terminator */
};

static PyTypeObject py_freeradius_request_def = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "freeradius.Request",
	.tp_doc = "freeradius request handle",
	.tp_basicsize = sizeof(py_freeradius_request_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_freeradius_request_attrs
};

static PyTypeObject py_freeradius_state_def = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "freeradius.State",
	.tp_doc = "Private state data",
	.tp_basicsize = sizeof(py_freeradius_state_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_init = py_freeradius_state_init
};

#ifndef _PyCFunction_CAST
#define _PyCFunction_CAST(func) (PyCFunction)((void(*)(void))(func))
#endif

/*
 *	freeradius Python functions
 */
static PyMethodDef py_freeradius_methods[] = {
	{ "log", _PyCFunction_CAST(py_freeradius_log), METH_VARARGS | METH_KEYWORDS,
	  "freeradius.log(msg[, type, lvl])\n\n"
	  "Print a message using the freeradius daemon's logging system.\n"
	  "type should be one of the following constants:\n"
	  "        freeradius.L_DBG\n"
	  "        freeradius.L_INFO\n"
	  "        freeradius.L_WARN\n"
	  "        freeradius.L_ERR\n"
	  "lvl should be one of the following constants:\n"
	  "        freeradius.L_DBG_LVL_OFF\n"
	  "        freeradius.L_DBG_LVL_1\n"
	  "        freeradius.L_DBG_LVL_2\n"
	  "        freeradius.L_DBG_LVL_3\n"
	  "        freeradius.L_DBG_LVL_4\n"
	  "        freeradius.L_DBG_LVL_MAX\n"
	},
	{ NULL, NULL, 0, NULL },
};

static PyModuleDef py_freeradius_def = {
	PyModuleDef_HEAD_INIT,
	.m_name = "freeradius",
	.m_doc = "FreeRADIUS python module",
	.m_size = 0,
	.m_methods = py_freeradius_methods
};

/** How to compare two Python calls
 *
 */
static int8_t python_func_def_cmp(void const *one, void const *two)
{
	python_func_def_t const *a = one, *b = two;
	int ret;

	ret = strcmp(a->name1, b->name1);
	if (ret != 0) return CMP(ret, 0);
	if (!a->name2 && !b->name2) return 0;
	if (!a->name2 || !b->name2) return a->name2 ? 1 : -1;
	ret = strcmp(a->name2, b->name2);
	return CMP(ret, 0);
}

/** Return the module instance object associated with the thread state or interpreter state
 *
 */
static inline CC_HINT(always_inline) py_freeradius_state_t *rlm_python_state_obj(void)
{
	PyObject *dict;

	dict = PyThreadState_GetDict();	/* If this is NULL, we're dealing with the main interpreter */
	if (!dict) {
		PyObject *module;

		module = PyState_FindModule(&py_freeradius_def);
		if (unlikely(!module)) return NULL;

		dict = PyModule_GetDict(module);
		if (unlikely(!dict)) return NULL;
	}

	return (py_freeradius_state_t *)PyDict_GetItemString(dict, "__State");
}

/** Return the rlm_python instance associated with the current interpreter
 *
 */
static rlm_python_t const *rlm_python_get_inst(void)
{
	py_freeradius_state_t const *p_state;

	p_state = rlm_python_state_obj();
	if (unlikely(!p_state)) return NULL;
	return p_state->inst;
}

/** Return the request associated with the current thread state
 *
 */
static request_t *rlm_python_get_request(void)
{
	py_freeradius_state_t const *p_state;

	p_state = rlm_python_state_obj();
	if (unlikely(!p_state)) return NULL;

	return p_state->request;
}

/** Set the request associated with the current thread state
 *
 */
static void rlm_python_set_request(request_t *request)
{
	py_freeradius_state_t *p_state;

	p_state = rlm_python_state_obj();
	if (unlikely(!p_state)) return;

	p_state->request = request;
}

/** Allow fr_log to be called from python
 *
 */
static PyObject *py_freeradius_log(UNUSED PyObject *self, PyObject *args, PyObject *kwds)
{
	static char const	*kwlist[] = { "msg", "type", "lvl", NULL };
	char			*msg;
	int			type = L_DBG;
	int			lvl = L_DBG_LVL_2;
	rlm_python_t const	*inst = rlm_python_get_inst();

	if (fr_debug_lvl < lvl) Py_RETURN_NONE;	/* Don't bother parsing args */

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|ii", (char **)((uintptr_t)kwlist),
					 &msg, &type, &lvl)) Py_RETURN_NONE;

	fr_log(&default_log, type, __FILE__, __LINE__, "rlm_python (%s) - %s", inst->name, msg);

	Py_RETURN_NONE;
}

static int py_freeradius_state_init(PyObject *self, UNUSED PyObject *args, UNUSED PyObject *kwds)
{
	py_freeradius_state_t	*our_self = (py_freeradius_state_t *)self;
	rlm_python_t const	*inst;

	fr_assert(current_inst);
	our_self->t = current_t ? talloc_get_type_abort(current_t, rlm_python_thread_t) : NULL;	/*  May be NULL if this is the first interpreter */
	our_self->inst = inst = current_t ? current_t->inst : current_inst;
	DEBUG3("Populating __State data with %p/%p", our_self->inst, our_self->t);

	return 0;
}

/** Returns a specific instance of freeradius.Pair
 *
 * Called when a numeric index is used on a PairGroup or PairValue as part of an object getter
 */
static PyObject *py_freeradius_attribute_instance(PyObject *self, PyObject *attr)
{
	long			index;
	py_freeradius_pair_t	*pair, *init_pair = (py_freeradius_pair_t *)self;

	if (!PyLong_CheckExact(attr)) Py_RETURN_NONE;
	index = PyLong_AsLong(attr);

	if (index < 0) {
		PyErr_SetString(PyExc_AttributeError, "Cannot use negative attribute instance values");
		return NULL;
	}
	if (index == 0) return self;

	if (fr_type_is_leaf(init_pair->da->type)) {
		pair = PyObject_New(py_freeradius_pair_t, (PyTypeObject *)&py_freeradius_value_pair_def);

	} else if (fr_type_is_struct(init_pair->da->type)) {
		pair = PyObject_New(py_freeradius_pair_t, (PyTypeObject *)&py_freeradius_grouping_pair_def);
	} else {
		PyErr_SetString(PyExc_AttributeError, "Unsupported data type");
		return NULL;
	}
	if (!pair) {
		PyErr_SetString(PyExc_MemoryError, "Failed to allocate PyObject");
		return NULL;
	};
	pair->parent = init_pair->parent;
	Py_INCREF(init_pair->parent);
	pair->da = init_pair->da;
	pair->idx = index;
	if (init_pair->vp) pair->vp = fr_pair_find_by_da_idx(fr_pair_parent_list(init_pair->vp), pair->da, (unsigned int)index);
	return (PyObject *)pair;
}

/** Returns a freeradius.Pair
 *
 * Called when pair["attr"] or pair["attr"][n] is accessed.
 * When pair["attr"] is accessed, `self` is `pair` - which is the list or a pair group object
 * When pair["attr"][n] is accessed, `self` is pair["attr"]
 *
 * Either a group object or pair object will be returned.
 */
static PyObject *py_freeradius_pair_map_subscript(PyObject *self, PyObject *attr)
{
	py_freeradius_pair_t	*our_self = (py_freeradius_pair_t *)self;
	char const		*attr_name;
	ssize_t			len;
	request_t		*request = rlm_python_get_request();
	py_freeradius_pair_t	*pair;
	fr_dict_attr_t const	*da;
	fr_pair_list_t		*list = NULL;

	/*
	 *	If we have a numeric subscript, find the nth instance of the pair.
	 */
	if (PyLong_CheckExact(attr)) return py_freeradius_attribute_instance(self, attr);

	if (!PyUnicode_CheckExact(attr)) {
		PyErr_Format(PyExc_AttributeError, "Invalid type '%s' for map attribute",
			  ((PyTypeObject *)PyObject_Type(attr))->tp_name);
		return NULL;
	}
	attr_name = PyUnicode_AsUTF8AndSize(attr, &len);

	if (PyObject_IsInstance(self, (PyObject *)&py_freeradius_pair_list_def)) {
		fr_dict_attr_search_by_name_substr(NULL, &da, request->proto_dict, &FR_SBUFF_IN(attr_name, len),
						   NULL, true, false);
	} else {
		fr_dict_attr_by_name_substr(NULL, &da, our_self->da, &FR_SBUFF_IN(attr_name, len), NULL);
	}
	if (our_self->vp) list = &our_self->vp->vp_group;

	if (!da) {
		PyErr_Format(PyExc_AttributeError, "Invalid attribute name '%.*s'", (int)len, attr_name);
		return NULL;
	}

	if (fr_type_is_leaf(da->type)) {
		pair = PyObject_New(py_freeradius_pair_t, (PyTypeObject *)&py_freeradius_value_pair_def);
	} else if (fr_type_is_structural(da->type)) {
		pair = PyObject_New(py_freeradius_pair_t, (PyTypeObject *)&py_freeradius_grouping_pair_def);
	} else {
		PyErr_SetString(PyExc_AttributeError, "Unsupported data type");
		return NULL;
	}
	if (!pair) {
		PyErr_SetString(PyExc_MemoryError, "Failed to allocate PyObject");
		return NULL;
	};

	pair->parent = self;
	Py_INCREF(self);
	pair->da = da;
	pair->vp = list ? fr_pair_find_by_da(list, NULL, da) : NULL;
	pair->idx = 0;

	return (PyObject *)pair;
}

/** Build out missing parent pairs when a leaf node is assigned a value.
 *
 */
static fr_pair_t *py_freeradius_build_parents(PyObject *obj)
{
	py_freeradius_pair_t	*obj_pair = (py_freeradius_pair_t *)obj;
	fr_pair_t		*parent = ((py_freeradius_pair_t *)obj_pair->parent)->vp;

	if (!parent) {
		parent = py_freeradius_build_parents(obj_pair->parent);
		if (!parent) return NULL;
	}

	/*
	 *	Asked to populate foo[n] - check that we have n instances already
	 */
	if (obj_pair->idx > 0) {
		unsigned int count = fr_pair_count_by_da(&parent->vp_group, obj_pair->da);
		if (count < obj_pair->idx) {
			PyErr_Format(PyExc_AttributeError, "Attempt to set instance %d when only %d exist", index, count);
			return NULL;
		}
	}
	fr_pair_append_by_da(parent, &obj_pair->vp, &parent->vp_group, obj_pair->da);

	return obj_pair->vp;
}

/**  Set the value of a pair
 *
 * Called with two Python syntaxes
 *
 *  - request['foo'] = 'baa'
 *    `self` will be the parent object - either the list or parent structural object.
 *    `attr` is the value in [].
 *    `value` is what we want to set the pair to.
 *
 *   - request['foo'][n] = 'baa'
 *     `self` will be the first instance of the attribute `foo`
 *     `attr` will be the instance number
 *     `value` is what we want to set the pair to.
 *
 * We expect `value` to be a UTF8 string object.
 *
 * Due to Python "magic" this is also called when `del request['foo']` happens - only with
 * value as NULL.
 */
static int py_freeradius_pair_map_set(PyObject* self, PyObject* attr, PyObject* value)
{
	fr_pair_list_t		*list = NULL;
	request_t		*request = rlm_python_get_request();
	py_freeradius_pair_t	*our_self = (py_freeradius_pair_t *)self;
	fr_pair_t		*vp = NULL;
	char const		*vstr;
	ssize_t			vlen;
	bool			del = (value ? false : true);

	if (value && !PyUnicode_CheckExact(value)) {
		PyErr_Format(PyExc_AttributeError, "Invalid value type '%s'", ((PyTypeObject *)PyObject_Type(value))->tp_name);
		return -1;
	}

	/*
	 *	list['attr'] = 'value'
	 *	Look up DA represented by 'attr' and find pair or create pair to update
	 */
	if (PyUnicode_CheckExact(attr)) {
		char const		*attr_name;
		ssize_t			len;
		fr_dict_attr_t const	*da = NULL;

		attr_name = PyUnicode_AsUTF8AndSize(attr, &len);

		if (PyObject_IsInstance(self, (PyObject *)&py_freeradius_pair_list_def)) {
			fr_dict_attr_search_by_name_substr(NULL, &da, request->proto_dict, &FR_SBUFF_IN(attr_name, len),
							   NULL, true, false);
		} else {
			fr_dict_attr_by_name_substr(NULL, &da, our_self->da, &FR_SBUFF_IN(attr_name, len), NULL);
		}

		if (!da) {
			PyErr_Format(PyExc_AttributeError, "Invalid attribute name %.*s", (int)len, attr_name);
			return -1;
		}

		// `self` is the parent of the pair we're building - so we build parents to that point.
		if (!our_self->vp) {
			if (del) return 0;	// If we're deleting then no need to build parents.
			our_self->vp = py_freeradius_build_parents(self);
		}
		if (!our_self->vp) return -1;

		list = &our_self->vp->vp_group;

		vp = fr_pair_find_by_da(list, NULL, da);
		if (del) goto del;

		if (!vp) {
			if (fr_pair_append_by_da(fr_pair_list_parent(list), &vp, list, da) < 0) {
				PyErr_Format(PyExc_MemoryError, "Failed to add attribute %s", da->name);
				return -1;
			}
		} else {
			fr_value_box_clear_value(&vp->data);
		}

	/*
	 *	list['attr'][n] = 'value'
	 *	Look for instance n, creating if necessary
	 */
	} else if (PyLong_CheckExact(attr)) {
		long			index = PyLong_AsLong(attr);
		py_freeradius_pair_t	*parent = (py_freeradius_pair_t *)our_self->parent;

		if (index < 0) {
			PyErr_SetString(PyExc_AttributeError, "Cannot use negative attribute instance values");
			return -1;
		}

		if (!parent->vp) {
			if (del) return 0;
			parent->vp = py_freeradius_build_parents(our_self->parent);
		}
		if (!parent->vp) return -1;

		list = &parent->vp->vp_group;

		if (index == 0) {
			if (!our_self->vp) {
				if (fr_pair_append_by_da(fr_pair_list_parent(list), &our_self->vp, list, our_self->da) < 0) {
					PyErr_Format(PyExc_MemoryError, "Failed to add attribute %s", our_self->da->name);
					return -1;
				}
			} else {
				fr_value_box_clear_value(&our_self->vp->data);
			}
			vp = our_self->vp;
			if (del) goto del;
		} else {
			vp = fr_pair_find_by_da_idx(list, our_self->da, index);
			if (del) goto del;
			if (!vp) {
				unsigned int	count = fr_pair_count_by_da(list, our_self->da);
				if (count < index) {
					PyErr_Format(PyExc_AttributeError, "Attempt to set instance %ld when only %d exist", index, count);
					return -1;
				}
				if (fr_pair_append_by_da(fr_pair_list_parent(list), &vp, list, our_self->da) < 0) {
					PyErr_Format(PyExc_MemoryError, "Failed to add attribute %s", our_self->da->name);
					return -1;
				}
			}
		}
	} else {
		PyErr_Format(PyExc_AttributeError, "Invalid object type '%s'", ((PyTypeObject *)PyObject_Type(attr))->tp_name);
		return -1;
	}

	fr_assert(fr_type_is_leaf(vp->da->type));

	vstr = PyUnicode_AsUTF8AndSize(value, &vlen);

	if (fr_pair_value_from_str(vp, vstr, vlen, NULL, false) < 0) {
		PyErr_Format(PyExc_AttributeError, "Failed setting '%s' = '%.*s", vp->da->name, (int)vlen, vstr);
		fr_pair_delete(list, vp);
		return -1;
	}

	RDEBUG2("set %pP", vp);
	return 0;

del:
	if (vp) {
		RDEBUG2("delete %pP", vp);
		fr_pair_delete(list, vp);
	}
	return 0;
}

/** Return a native Python object of the appropriate type for leaf pair objects
 *
 * Accessed as `request['attr'].value`
 *
 * `self` is the Python leaf pair object
 */
static PyObject *py_freeradius_pair_getvalue(PyObject *self, UNUSED void *closure)
{
	py_freeradius_pair_t	*own_self = (py_freeradius_pair_t *)self;
	PyObject		*value = NULL;
	fr_pair_t		*vp = own_self->vp;

	if (!vp) Py_RETURN_NONE;

	switch(vp->vp_type) {
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
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_ATTR:
	{
		ssize_t slen;
		char buffer[1024];

		slen = fr_value_box_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), &vp->data, NULL);
		if (slen < 0) {
		error:
			PyErr_Format(PyExc_MemoryError, "Failed marshalling %s to Python value", vp->da->name);
			return NULL;
		}
		value = PyUnicode_FromStringAndSize(buffer, (size_t)slen);
	}
		break;

	case FR_TYPE_NON_LEAF:
		fr_assert(0);
		break;
	}

	if (value == NULL) goto error;

	Py_INCREF(value);
	return value;
}

/** Use a native Python object of the appropriate type to set a leaf pair
 *
 * Using Python syntax `request['attr'].value = object` or `request['attr'][n].value`
 *
 * `self` is the Python object representing the leaf node pair
 */
static int py_freeradius_pair_setvalue(PyObject *self, PyObject *value, UNUSED void *closure)
{
	py_freeradius_pair_t	*own_self = (py_freeradius_pair_t *)self;
	fr_pair_t		*vp = own_self->vp;

	/*
	 *	The pair doesn't exist yet - so create it
	 */
	if (!vp) {
		py_freeradius_pair_t	*parent = (py_freeradius_pair_t *)own_self->parent;
		fr_pair_list_t		*list;
		unsigned int		count;

		if (!parent->vp) parent->vp = py_freeradius_build_parents(own_self->parent);
		if (!parent->vp) return -1;

		list = &parent->vp->vp_group;
		count = fr_pair_count_by_da(list, own_self->da);
		if (count < own_self->idx) {
			PyErr_Format(PyExc_AttributeError, "Attempt to set instance %d when only %d exist", own_self->idx, count);
			return -1;
		}
		fr_pair_append_by_da(fr_pair_list_parent(list), &vp, list, own_self->da);
		own_self->vp = vp;
	}

	switch (vp->da->type) {
	case FR_TYPE_STRING:
	{
		char const	*val;
		ssize_t		len;
		if (!PyUnicode_CheckExact(value)){
		wrong_type:
			PyErr_Format(PyExc_AttributeError, "Incorrect Python type '%s' for attribute type '%s'",
				     ((PyTypeObject *)PyObject_Type(value))->tp_name, fr_type_to_str(vp->da->type));
			return -1;
		}
		val = PyUnicode_AsUTF8AndSize(value, &len);
		fr_value_box_clear_value(&vp->data);
		fr_value_box_bstrndup(vp, &vp->data, NULL, val, len, false);
	}
		break;

	case FR_TYPE_OCTETS:
	{
		uint8_t	*val;
		ssize_t	len;
		if (!PyObject_IsInstance(value, (PyObject *)&PyBytes_Type)) goto wrong_type;
		PyBytes_AsStringAndSize(value, (char **)&val, &len);
		fr_value_box_clear(&vp->data);
		fr_value_box_memdup(vp, &vp->data, NULL, val, len, false);
	}
		break;

	case FR_TYPE_BOOL:
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
	case FR_TYPE_SIZE:
	{
		long long val;
		if (!PyLong_CheckExact(value)) goto wrong_type;
		val = PyLong_AsLongLong(value);

		switch (vp->da->type) {
		case FR_TYPE_BOOL:
			vp->vp_bool = (bool)val;
			break;
		case FR_TYPE_UINT8:
			vp->vp_uint8 = (uint8_t)val;
			break;
		case FR_TYPE_UINT16:
			vp->vp_uint16 = (uint16_t)val;
			break;
		case FR_TYPE_UINT32:
			vp->vp_uint32 = (uint32_t)val;
			break;
		case FR_TYPE_UINT64:
			vp->vp_uint64 = (uint64_t)val;
			break;
		case FR_TYPE_INT8:
			vp->vp_int8 = (int8_t)val;
			break;
		case FR_TYPE_INT16:
			vp->vp_int16 = (int16_t)val;
			break;
		case FR_TYPE_INT32:
			vp->vp_int32 = (int32_t)val;
			break;
		case FR_TYPE_INT64:
			vp->vp_int64 = (int64_t)val;
			break;
		case FR_TYPE_SIZE:
			vp->vp_size = (size_t)val;
			break;
		default:
			fr_assert(0);
		}
	}
		break;

	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
	{
		double val;
		if (!PyFloat_CheckExact(value)) goto wrong_type;
		val = PyFloat_AsDouble(value);

		if (vp->da->type == FR_TYPE_FLOAT32) {
			vp->vp_float32 = (float)val;
		} else {
			vp->vp_float64 = val;
		}
	}
		break;

	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_DATE:
	case FR_TYPE_IFID:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_ATTR:
	{
		char const	*val;
		ssize_t		len;

		if (!PyUnicode_CheckExact(value)) goto wrong_type;

		val = PyUnicode_AsUTF8AndSize(value, &len);
		if (fr_pair_value_from_str(vp, val, len, NULL, false) < 0) {
			PyErr_Format(PyExc_AttributeError, "Failed parsing %.*s as %s", (int)len, val, fr_type_to_str(vp->da->type));
			return -1;
		}
	}
		break;

	case FR_TYPE_NON_LEAF:
		fr_assert(0);
		break;
	}

	return 0;
}

/** Return the string representation of a leaf pair node
 *
 * Called when the attribute is accessed in print() or str() or selective other
 * magical Python contexts.
 */
static PyObject *py_freeradius_pair_str(PyObject *self) {
	py_freeradius_pair_t	*own_self = (py_freeradius_pair_t *)self;
	PyObject		*value = NULL;
	fr_pair_t		*vp = own_self->vp;

	if (!vp) return PyObject_Str(Py_None);

	switch(vp->vp_type) {
	case FR_TYPE_STRING:
		value = PyUnicode_FromStringAndSize(vp->vp_strvalue, vp->vp_length);
		break;

	case FR_TYPE_NON_LEAF:
		fr_assert(0);
		break;

	default:
	{
		ssize_t		slen;
		char		buffer[1024];

		slen = fr_value_box_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), &vp->data, NULL);
		if (slen < 0) {
		error:
			PyErr_Format(PyExc_MemoryError, "Failed casting %s to Python string", vp->da->name);
			return NULL;
		}
		value = PyUnicode_FromStringAndSize(buffer, (size_t)slen);
	}
		break;
	}

	if (value == NULL) goto error;

	return value;
}

/** Print out the current error
 *
 * Must be called with a valid thread state set
 */
static void python_error_log(rlm_python_t const *inst, request_t *request)
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
#if PY_VERSION_HEX >= 0x030A0000
			PyCodeObject *code = PyFrame_GetCode(cur_frame);

			ROPTIONAL(RERROR, ERROR, "[%ld] %s:%d at %s()",
				fnum,
				PyUnicode_AsUTF8(code->co_filename),
				PyFrame_GetLineNumber(cur_frame),
				PyUnicode_AsUTF8(code->co_name)
			);
			Py_XDECREF(code);
#else
			ROPTIONAL(RERROR, ERROR, "[%ld] %s:%d at %s()",
				  fnum,
				  PyUnicode_AsUTF8(cur_frame->f_code->co_filename),
				  PyFrame_GetLineNumber(cur_frame),
				  PyUnicode_AsUTF8(cur_frame->f_code->co_name)
			);
#endif

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

/** Create the Python object representing a pair list
 *
 */
static inline CC_HINT(always_inline) PyObject *pair_list_alloc(request_t *request, fr_dict_attr_t const *list)
{
	PyObject		*py_list;
	py_freeradius_pair_t	*our_list;

	/*
	 *	When handing instantiate and detach, there is no request
	 */
	if (!request) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	py_list = PyObject_CallObject((PyObject *)&py_freeradius_pair_list_def, NULL);
	if (unlikely(!py_list)) return NULL;

	our_list = (py_freeradius_pair_t *)py_list;
	our_list->da = list;
	our_list->vp = fr_pair_list_parent(tmpl_list_head(request, list));
	our_list->parent = NULL;
	our_list->idx = 0;
	return py_list;
}

static unlang_action_t do_python_single(unlang_result_t *p_result, module_ctx_t const *mctx,
					request_t *request, PyObject *p_func, char const *funcname)
{
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	rlm_python_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_python_t);

	PyObject		*p_ret = NULL;
	PyObject		*py_request;
	py_freeradius_request_t	*our_request;

	/*
	 *	Instantiate the request
	 */
	py_request = PyObject_CallObject((PyObject *)&py_freeradius_request_def, NULL);
	if (unlikely(!py_request)) {
		python_error_log(inst, request);
		RETURN_UNLANG_FAIL;
	}

	our_request = (py_freeradius_request_t *)py_request;
	rlm_python_set_request(request);

	/*
	 *	Create the list roots
	 */
	our_request->request = pair_list_alloc(request, request_attr_request);
	if (unlikely(!our_request->request)) {
	req_error:
		Py_DECREF(py_request);
		python_error_log(inst, request);
		RETURN_UNLANG_FAIL;
	}

	our_request->reply = pair_list_alloc(request, request_attr_reply);
	if (unlikely(!our_request->reply)) goto req_error;

	our_request->control = pair_list_alloc(request, request_attr_control);
	if (unlikely(!our_request->control)) goto req_error;

	our_request->state = pair_list_alloc(request, request_attr_state);
	if (unlikely(!our_request->state)) goto req_error;

	/* Call Python function. */
	p_ret = PyObject_CallFunctionObjArgs(p_func, py_request, NULL);
	if (!p_ret) {
		RERROR("Python function returned no value");
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	if (!request) {
		// check return code at module instantiation time
		if (PyNumber_Check(p_ret)) rcode = PyLong_AsLong(p_ret);
		goto finish;
	}

	/*
	 *  The function is expected to either return a return value
	 *  or None, which results in the default return value.
	 */
	if (PyNumber_Check(p_ret)) {
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
	rlm_python_set_request(NULL);

	if (rcode == RLM_MODULE_FAIL) python_error_log(inst, request);
	Py_XDECREF(p_ret);
	Py_XDECREF(py_request);

	RETURN_UNLANG_RCODE(rcode);
}

/** Thread safe call to a python function
 *
 * Will swap in thread state specific to module/thread.
 */
static unlang_action_t mod_python(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_python_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_python_thread_t);
	python_call_env_t	*func = talloc_get_type_abort(mctx->env_data, python_call_env_t);

	/*
	 *	It's a NOOP if the function wasn't defined
	 */
	if (!func->func->function) RETURN_UNLANG_NOOP;

	RDEBUG3("Using thread state %p/%p", mctx->mi->data, t->state);

	PyEval_RestoreThread(t->state);	/* Swap in our local thread state */
	do_python_single(p_result, mctx, request, func->func->function, func->func->function_name);
	(void)fr_cond_assert(PyEval_SaveThread() == t->state);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

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
static int python_function_load(module_inst_ctx_t const *mctx, python_func_def_t *def)
{
	rlm_python_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_python_t);
	char const *funcname = "python_function_load";

	if (def->module_name == NULL || (def->function_name == NULL && def->name1 == NULL)) return 0;

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

	/*
	 *	Calls found by call_env parsing will have name1 set
	 *	If name2 is set first look for <name1>_<name2> and fall back to <name1>
	 */
	if (!def->function_name) def->function_name = def->name2 ? talloc_asprintf(def, "%s_%s", def->name1, def->name2) : def->name1;

	def->function = PyObject_GetAttrString(def->module, def->function_name);
	if (!def->function && def->name2) {
		PyErr_Clear();	// Since we're checking for another function, clear any errors.
		talloc_const_free(def->function_name);
		def->function_name = def->name1;
		def->function = PyObject_GetAttrString(def->module, def->function_name);
	}
	if (!def->function) {
		ERROR("%s - Function '%s.%s' is not found", funcname, def->module_name, def->function_name);
		goto error;
	}

	if (!PyCallable_Check(def->function)) {
		ERROR("%s - Function '%s.%s' is not callable", funcname, def->module_name, def->function_name);
		goto error;
	}

	DEBUG2("Loaded function '%s.%s'", def->module_name, def->function_name);
	return 0;
}

/*
 *	Parse a configuration section, and populate a dict.
 *	This function is recursively called (allows to have nested dicts.)
 */
static int python_parse_config(rlm_python_t const *inst, CONF_SECTION *cs, int lvl, PyObject *dict)
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
static int python_module_import_constants(rlm_python_t const *inst, PyObject *module)
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

/*
 *	Python 3 interpreter initialisation and destruction
 */
static PyObject *python_module_init(void)
{
	PyObject		*module;
	PyObject		*p_state;
	static pthread_mutex_t	init_lock = PTHREAD_MUTEX_INITIALIZER;
	static bool		type_ready = false;

	fr_assert(current_inst);

	/*
	 *	Only allow one thread at a time to do the module init.  This is
	 *	out of an abundance of caution as it's unclear whether the
	 *	reference counts on the various objects are thread safe.
	 */
	pthread_mutex_lock(&init_lock);

	/*
	 *	The type definitions are global, so we only need to call the
	 *	init functions the first pass through.
	*/

	if (!type_ready) {
		/*
		 *	We need to initialise the definitions first
		 *	this fills in any fields we didn't explicitly
		 *	specify, and gets the structures ready for
		 *	use by the python interpreter.
		 */
		if (PyType_Ready(&py_freeradius_pair_def) < 0) {
		error:
			pthread_mutex_unlock(&init_lock);
			python_error_log(current_inst, NULL);
			Py_RETURN_NONE;
		}

		if (PyType_Ready(&py_freeradius_value_pair_def) < 0) goto error;

		if (PyType_Ready(&py_freeradius_grouping_pair_def) < 0) goto error;

		if (PyType_Ready(&py_freeradius_pair_list_def) < 0) goto error;

		if (PyType_Ready(&py_freeradius_request_def) < 0) goto error;

		if (PyType_Ready(&py_freeradius_state_def) < 0) goto error;

		type_ready = true;
	}

	/*
	 *	The module is per-interpreter
	 */
	module = PyModule_Create(&py_freeradius_def);
	if (!module) {
		python_error_log(current_inst, NULL);
		goto error;
	}

	/*
	 *	PyModule_AddObject steals ref on success, we we
	 *	INCREF here to give it something to steal, else
	 *	on free the refcount would go negative.
	 *
	 *	Note here we're creating a new instance of an
	 *	object, not adding the object definition itself
	 *	as there's no reason that a python script would
	 *	ever need to create an instance object.
	 *
	 *	The instantiation function associated with the
	 *	the __State object takes care of populating the
	 *	instance data from globals and thread-specific
	 *	variables.
	 */
	p_state = PyObject_CallObject((PyObject *)&py_freeradius_state_def, NULL);
	Py_INCREF(&py_freeradius_state_def);

	if (PyModule_AddObject(module, "__State", p_state) < 0) {
		Py_DECREF(&py_freeradius_state_def);
		Py_DECREF(module);
		goto error;
	}

	/*
	 *	For "Pair" we're inserting an object definition
	 *	as opposed to the object instance we inserted
	 *	for inst.
	 */
	Py_INCREF(&py_freeradius_pair_def);
	if (PyModule_AddObject(module, "Pair", (PyObject *)&py_freeradius_pair_def) < 0) {
		Py_DECREF(&py_freeradius_pair_def);
		Py_DECREF(module);
		goto error;
	}
	pthread_mutex_unlock(&init_lock);

	return module;
}

static int python_interpreter_init(module_inst_ctx_t const *mctx)
{
	rlm_python_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_python_t);
	CONF_SECTION	*conf = mctx->mi->conf;
	PyObject	*module;

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

static void python_interpreter_free(rlm_python_t *inst, PyThreadState *interp)
{
	PyEval_RestoreThread(interp);	/* Switches thread state and locks GIL */

	/*
	 *	We incremented the reference count earlier
	 *	during module initialisation.
	 */
	Py_XDECREF(inst->module);

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
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_python_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_python_t);
	python_func_def_t	*func = NULL;
	fr_rb_iter_inorder_t	iter;
	CONF_PAIR		*cp;
	char			*pair_name;

	if (inst->interpreter) return 0;
	if (python_interpreter_init(mctx) < 0) return -1;
	inst->name = mctx->mi->name;
	if (!inst->funcs_init) fr_rb_inline_init(&inst->funcs, python_func_def_t, node, python_func_def_cmp, NULL);
	/*
	 *	Switch to our module specific interpreter
	 */
	PyEval_RestoreThread(inst->interpreter);

	/*
	 *	Process the various sections
	 */
#define PYTHON_FUNC_LOAD(_x) if (python_function_load(mctx, &inst->_x) < 0) goto error
	PYTHON_FUNC_LOAD(instantiate);
	PYTHON_FUNC_LOAD(detach);

	/*
	 *	Load all the Python functions found by the call_env parser.
	 */
	for (func = fr_rb_iter_init_inorder(&inst->funcs, &iter);
	     func != NULL;
	     func = fr_rb_iter_next_inorder(&inst->funcs, &iter)) {
		/*
		 *	Check for mod_<name1>_<name2> or mod_<name1> config pairs.
		 *	If neither exist, fall back to default Python module.
		 */
		if (func->name2) {
			pair_name = talloc_asprintf(func, "mod_%s_%s", func->name1, func->name2);
			cp = cf_pair_find(mctx->mi->conf, pair_name);
			talloc_free(pair_name);
			if (cp) goto found_mod;
		}
		pair_name = talloc_asprintf(func, "mod_%s", func->name1);
		cp = cf_pair_find(mctx->mi->conf, pair_name);
		talloc_free(pair_name);
	found_mod:
		func->module_name = cp ? cf_pair_value(cp) : inst->def_module_name;

		/*
		 *	Check for func_<name1>_<name2> or func_<name1> function overrides.
		 *	Checks for Python functions <name1>_<name2> and <name1> are done
		 *	in python_function_load.
		 */
		if (func->name2) {
			pair_name = talloc_asprintf(func, "func_%s_%s", func->name1, func->name2);
			cp = cf_pair_find(mctx->mi->conf, pair_name);
			talloc_free(pair_name);
			if (cp) goto found_func;
		}
		pair_name = talloc_asprintf(func, "func_%s", func->name1);
		cp = cf_pair_find(mctx->mi->conf, pair_name);
		talloc_free(pair_name);
	found_func:
		if (cp) func->function_name = cf_pair_value(cp);

		if (python_function_load(mctx, func) < 0) goto error;
	}

	/*
	 *	Call the instantiate function.
	 */
	if (inst->instantiate.function) {
		unlang_result_t result;

		do_python_single(&result, MODULE_CTX_FROM_INST(mctx), NULL, inst->instantiate.function, "instantiate");
		switch (result.rcode) {
		case RLM_MODULE_FAIL:
		case RLM_MODULE_REJECT:
		error:
			fr_cond_assert(PyEval_SaveThread() == inst->interpreter);
			python_interpreter_free(inst, inst->interpreter);
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

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_python_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_python_t);
	python_func_def_t	*func = NULL;
	fr_rb_iter_inorder_t	iter;

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
		unlang_result_t result;

		(void)do_python_single(&result, MODULE_CTX_FROM_INST(mctx), NULL, inst->detach.function, "detach");
	}

#define PYTHON_FUNC_DESTROY(_x) python_function_destroy(&inst->_x)
	PYTHON_FUNC_DESTROY(instantiate);
	PYTHON_FUNC_DESTROY(detach);

	for (func = fr_rb_iter_init_inorder(&inst->funcs, &iter);
	     func != NULL;
	     func = fr_rb_iter_next_inorder(&inst->funcs, &iter)) {
		python_function_destroy(func);
	}

	PyEval_SaveThread();

	/*
	 *	Free the module specific interpreter
	 */
	python_interpreter_free(inst, inst->interpreter);

	return 0;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_python_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_python_t);
	rlm_python_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_python_thread_t);

	PyThreadState		*t_state;
	PyObject		*t_dict;
	PyObject		*p_state;

	current_t = t;

	t->inst = inst;
	t_state = PyThreadState_New(inst->interpreter->interp);
	if (!t_state) {
		ERROR("Failed initialising local PyThreadState");
		return -1;
	}

	PyEval_RestoreThread(t_state);	/* Switches thread state and locks GIL */
	t_dict = PyThreadState_GetDict();
	if (unlikely(!t_dict)) {
		ERROR("Failed getting PyThreadState dictionary");
	error:
		PyEval_SaveThread();			/* Unlock GIL */
		PyThreadState_Delete(t_state);

		return -1;
	}

	/*
	 *	Instantiate a new instance object which captures
	 *	the global and thread instances, and associates
	 *	them with the thread.
	 */
	p_state = PyObject_CallObject((PyObject *)&py_freeradius_state_def, NULL);
	if (unlikely(!p_state)) {
		ERROR("Failed instantiating module instance information object");
		goto error;
	}

	if (unlikely(PyDict_SetItemString(t_dict, "__State", p_state) < 0)) {
		ERROR("Failed setting module instance information in thread dict");
		goto error;
	}

	DEBUG3("Initialised PyThreadState %p", t_state);
	t->state = t_state;
	PyEval_SaveThread();				/* Unlock GIL */

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_python_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_python_thread_t);

	PyEval_RestoreThread(t->state);	/* Swap in our local thread state */
	PyThreadState_Clear(t->state);
	PyEval_SaveThread();

	PyThreadState_Delete(t->state);	/* Don't need to hold lock for this */

	return 0;
}

static int libpython_init(void)
{
#define LOAD_INFO(_fmt, ...) fr_log(LOG_DST, L_INFO, __FILE__, __LINE__, "rlm_python - " _fmt,  ## __VA_ARGS__)
#define LOAD_WARN(_fmt, ...) fr_log_perror(LOG_DST, L_WARN, __FILE__, __LINE__, \
					   &(fr_log_perror_format_t){ \
					   	.first_prefix = "rlm_python - ", \
					   	.subsq_prefix = "rlm_python - ", \
					   }, \
					   _fmt,  ## __VA_ARGS__)
	PyConfig	config;
	PyStatus	status;
	wchar_t		*wide_name;

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

	PyConfig_InitPythonConfig(&config);

	/*
	 *	Set program name (i.e. the software calling the interpreter)
	 *	The value of argv[0] as a wide char string
	 */
	wide_name = Py_DecodeLocale(main_config->name, NULL);
	status = PyConfig_SetString(&config, &config.program_name, wide_name);
	PyMem_RawFree(wide_name);

	if (PyStatus_Exception(status)) {
	fail:
		LOAD_WARN("%s", status.err_msg);
		PyConfig_Clear(&config);
		return -1;
	}

	/*
	 *	Python 3 introduces the concept of a
	 *	"inittab", i.e. a list of modules which
	 *	are automatically created when the first
	 *	interpreter is spawned.
	 */
	PyImport_AppendInittab("freeradius", python_module_init);

	if (libpython_global_config.path) {
		wchar_t *wide_path = Py_DecodeLocale(libpython_global_config.path, NULL);

		if (libpython_global_config.path_include_default) {
			/*
			 *	The path from config is to be used in addition to the default.
			 *	Set it in the pythonpath_env.
			 */
			status = PyConfig_SetString(&config, &config.pythonpath_env, wide_path);
		} else {
			/*
			 *	Only the path from config is to be used.
			 *	Setting module_search_paths_set to 1 disables any automatic paths.
			 */
			config.module_search_paths_set = 1;
			status = PyWideStringList_Append(&config.module_search_paths, wide_path);
		}
		PyMem_RawFree(wide_path);
		if (PyStatus_Exception(status)) goto fail;
	}

	config.install_signal_handlers = 0;	/* Don't override signal handlers - noop on subs calls */

	if (libpython_global_config.verbose) config.verbose = 1;	/* Enable libpython logging*/

	LSAN_DISABLE(status = Py_InitializeFromConfig(&config));
	if (PyStatus_Exception(status)) goto fail;

	PyConfig_Clear(&config);

	global_interpreter = PyEval_SaveThread();	/* Store reference to the main interpreter and release the GIL */

	return 0;
}

static void libpython_free(void)
{
	PyThreadState_Swap(global_interpreter); /* Swap to the main thread */

	/*
	 *	PyImport_Cleanup - Leaks memory in python 3.6
	 *	should check once we require 3.8 that this is
	 *	still needed.
	 */
	LSAN_DISABLE(Py_Finalize());			/* Ignore leaks on exit, we don't reload modules so we don't care */
	if (python_dlhandle) dlclose(python_dlhandle);	/* dlclose will SEGV on null handle */
}

/*
 *	Restrict automatic Python function names to lowercase characters, numbers and underscore
 *	meaning that a module call in `recv Access-Request` will look for `recv_access_request`
 */
static void python_func_name_safe(char *name) {
	char	*p;
	size_t	i;

	p = name;
	for (i = 0; i < talloc_array_length(name); i++) {
		*p = tolower(*p);
		if (!strchr("abcdefghijklmnopqrstuvwxyz1234567890", *p)) *p = '_';
		p++;
	}
}

static int python_func_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, UNUSED tmpl_rules_t const *t_rules,
			     UNUSED CONF_ITEM *ci, call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_python_t		*inst = talloc_get_type_abort(cec->mi->data, rlm_python_t);
	call_env_parsed_t	*parsed;
	python_func_def_t	*func;
	void			*found;

	if (!inst->funcs_init) {
		fr_rb_inline_init(&inst->funcs, python_func_def_t, node, python_func_def_cmp, NULL);
		inst->funcs_init = true;
	}

	MEM(parsed = call_env_parsed_add(ctx, out,
					 &(call_env_parser_t){
						.name = "func",
						.flags = CALL_ENV_FLAG_PARSE_ONLY,
						.pair = {
							.parsed = {
								.offset = rule->pair.offset,
								.type = CALL_ENV_PARSE_TYPE_VOID
							}
						}
					 }));

	MEM(func = talloc_zero(inst, python_func_def_t));
	func->name1 = talloc_strdup(func, cec->asked->name1);
	python_func_name_safe(func->name1);
	if (cec->asked->name2) {
		func->name2 = talloc_strdup(func, cec->asked->name2);
		python_func_name_safe(func->name2);
	}

	if (fr_rb_find_or_insert(&found, &inst->funcs, func) < 0) {
		talloc_free(func);
		return -1;
	}

	/*
	 *	If the function call is already in the tree, use that entry.
	 */
	if (found) {
		talloc_free(func);
		call_env_parsed_set_data(parsed, found);
	} else {
		call_env_parsed_set_data(parsed, func);
	}
	return 0;
}

static const call_env_method_t python_method_env = {
	FR_CALL_ENV_METHOD_OUT(python_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_SUBSECTION_FUNC(CF_IDENT_ANY, CF_IDENT_ANY, CALL_ENV_FLAG_PARSE_MISSING, python_func_parse) },
		CALL_ENV_TERMINATOR
	}
};

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_python;
module_rlm_t rlm_python = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "python",

		.inst_size		= sizeof(rlm_python_t),
		.thread_inst_size	= sizeof(rlm_python_thread_t),

		.config			= module_config,

		.instantiate		= mod_instantiate,
		.detach			= mod_detach,

		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_python, .method_env = &python_method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
