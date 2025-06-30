#include <stdio.h>

#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/cf_priv.h>
#include <freeradius-devel/unlang/unlang_priv.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/tlist.h>

int main(UNUSED int argc, UNUSED char **argv)
{
#define SIZEOF(_struct)	printf("%-24s\t%zu\tbytes\n", STRINGIFY(_struct), sizeof(_struct))

	SIZEOF(fr_dict_attr_t);
	SIZEOF(fr_dict_attr_flags_t);
	SIZEOF(fr_dict_enum_value_t);

	SIZEOF(fr_dlist_t);
	SIZEOF(fr_dlist_head_t);

	SIZEOF(CONF_ITEM);
	SIZEOF(CONF_PAIR);
	SIZEOF(CONF_SECTION);

	SIZEOF(fr_pair_t);
	SIZEOF(fr_pair_list_t);

	SIZEOF(fr_rb_tree_t);
	SIZEOF(fr_rb_node_t);

	SIZEOF(fr_tlist_t);
	SIZEOF(fr_tlist_head_t);

	SIZEOF(fr_type_t);
	SIZEOF(fr_value_box_t);
	SIZEOF(fr_value_box_datum_t);
	SIZEOF(fr_ipaddr_t);

	SIZEOF(tmpl_t);
	SIZEOF(tmpl_attr_rules_t);
	SIZEOF(tmpl_rules_t);
	SIZEOF(tmpl_xlat_rules_t);

	SIZEOF(unlang_t);
	SIZEOF(unlang_group_t);
	SIZEOF(unlang_thread_t);
	SIZEOF(unlang_stack_frame_t);

	SIZEOF(xlat_call_t);
	SIZEOF(xlat_exp_t);
	SIZEOF(xlat_exp_head_t);

	return 0;
}
