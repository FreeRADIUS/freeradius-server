import gdb

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

class DD (gdb.Command):
  """Display selected data structures using FreeRADIUS C calls."""

  def __init__ (self):
    super (DD, self).__init__ ("dd", gdb.COMMAND_USER)

  def invoke (self, arg, from_tty):
    # Python code goes here
    var = gdb.parse_and_eval(arg) # really just sets up for eventual evaluation
    isAddress = var.type.code == gdb.TYPE_CODE_PTR
    if isAddress:
       argMod = ''
    else:
       argMod = '&'
       var = var.address
    varType = str(var.type)
    if not (varType in _howTo):
       print('unsupported type "{}"'.format(varType))
       return
    function, const = _howTo[varType]
    cast = '({} const *)'.format(varType[0:-2]) if const else ''
    command = 'call {0}({1}{2}({3}))'.format(function, cast, argMod, arg)
    try:
       gdb.execute(command)
    except:
       print("command failed")

DD () # Create an instance so you can run it
