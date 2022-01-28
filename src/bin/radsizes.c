#include <stdio.h>

#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/util/value.h>

int main(UNUSED int argc, UNUSED char **argv)
{
#define SIZEOF(_struct)	printf("%s %zu bytes\n", STRINGIFY(_struct), sizeof(_struct))

	SIZEOF(xlat_exp_t);
	SIZEOF(xlat_call_t);
	SIZEOF(tmpl_t);
	SIZEOF(tmpl_rules_t);
	SIZEOF(tmpl_attr_rules_t);
	SIZEOF(tmpl_xlat_rules_t);
	SIZEOF(fr_value_box_t);
	SIZEOF(fr_pair_t);

	return 0;
}
