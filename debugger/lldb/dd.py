#!/usr/bin/env python

import lldb
import optparse
import shlex

_howTo = {
    'fr_value_box_t *'           : ('fr_value_box_debug',		True),
    'fr_value_box_list_t *'      : ('fr_value_box_list_debug',		True),
    'tmpl_t *'                   : ('tmpl_debug',			True),
    'CONF_ITEM *'                : ('_cf_debug',			True),
    'dl_loader_t *'              : ('dl_loader_debug',			False),
    'fr_dict_gctx_t * '          : ('fr_dict_global_ctx_debug',		True),
    'fr_pair_t *'                : ('fr_pair_debug',			True),
    'fr_pair_list_t *'           : ('fr_pair_list_debug',		True),
    'fr_sbuff_term_t *'          : ('fr_sbuff_terminal_debug',		True),
    'fr_sbuff_parse_rules_t *'   : ('fr_sbuff_parse_rules_debug',	True),
    'fr_sbuff_unescape_rules_t *': ('fr_sbuff_unescape_debug',		True),
    'tmpl_attr_list_head_t *'    : ('tmpl_attr_ref_list_debug',		True),
    'tmpl_attr_rules_t *'        : ('tmpl_attr_rules_debug',		True),
    'fr_dlist_head_t *'          : ('tmpl_extents_debug',		False),
    'tmpl_request_list_head_t *' : ('tmpl_request_ref_list_debug',	True),
    'tmpl_rules_t *'             : ('tmpl_rules_debug',			True),
    'lua_State *'                : ('_util_log_debug',			False),
    'xlat_exp_t *'               : ('xlat_debug',			True)
}

# A Python function to be called from lldb must have the following parameters:
#
# debugger		the debugger currently running
# command		the curiously named string containing the parameters
# exe_ctx		the execution context 
# result		an SBCommandReturnObject. We use its SetError() method
# 			for error messages, but in this particular case the
# 			real goal is to call the right foo_debug() function
# 			which writes a readable version of the data to stderr.
# 			In other cases, you may use result.PutOutput() or
# 			result.PutCString().
# 			gather that output and result.PutCString() it.
# internal_dict		a Python dictionary containing all variables and
#                       functions for the current embedded script session

def dd(debugger, command, exe_ctx, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    sb_var = frame.FindVariable(command)
    if not sb_var.IsValid():
        sb_var = target.FindFirstGlobalVariable(command)
        if not sb_var.IsValid():
            result.SetError('{} is not a variable'.format(command))
            return
    arg = sb_var if sb_var.type.is_pointer else sb_var.address_of
    type = arg.GetDisplayTypeName()
    if not (type in _howTo):
        result.SetError('unsupported type "{}"'.format(type))
        return
    function, const = _howTo[type]
    cast = '({} const *)'.format(type[0:-2]) if const else ''
    argName = arg.GetName()
    cmd = 'expr {0}({1}({2}))'.format(function, cast, argName)
    interpreter = debugger.GetCommandInterpreter()
    if not interpreter.IsValid():
       result.SetError("can't set up SBCommandInterpreter")
       return
    # The use of fr_value_box_t to represent two different structures
    # makes the command fail for it, but only once(!). Until we find
    # the right way to disambiguate, we'll give it up to two tries.
    for i in range(2):
        if (cmdStatus := interpreter.HandleCommand(cmd, result)) == lldb.eReturnStatusSuccessFinishResult:
            return
    result.SetError("command {} failed, status {}".format(cmd, cmdStatus))

# And then some boilerplate to set up the command and announce its availability.
# I'm guessing that the -f option is <file name without extension>.<name of function>,
# and it's followed by the name one uses on the lldb command line.
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f dd.dd dd')
    print('The "dd" python command has been installed and is ready for use.')

# To make this available to you in lldb, you need to do this:
#
# (lldb) command script import <path to this file>
#
# or have it done in your .lldbinit file, which needn't be in your home directory;
# giving lldb the --local-lldbinit option makes it look in the current directory.
