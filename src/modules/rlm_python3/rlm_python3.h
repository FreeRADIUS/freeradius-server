#ifndef __RLM_PYTHON3_H__
#define __RLM_PYTHON3_H__

#include <Python.h>

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
	rlm_python_t const      *inst;          //!< Module instance that created this thread state.
} python_thread_state_t;


#endif //__RLM_PYTHON_H__

