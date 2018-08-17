#
#  Create the soft link for the protocol-specific include files
#  before building the protocols.
#
define PROTO_INCLUDE
#
#  This is a hack to get the include files linked correctly.  We would
#  LOVE to be able to do:
#
#	$${libfreeradius-${1}.la_OBJS}: | src/include/${1}
#
#  but GNU Make is too stupid to wait until that variable is defined
#  to evaluate the condition.  Instead, it evaluates the rule
#  immediately, and decides that nothing is there.
#
#  So, we instead depend on a library which has already been defined.
#
$${libfreeradius-io.la_OBJS}: | src/include/${1}

src/include/${1}:
	$${Q}[ -e $$@ ] || ln -sf $${top_srcdir}/src/protocols/${1} $$@
	@echo LN-SF src/protocols/${1} $$@

install.src.include: $(addprefix ${SRC_INCLUDE_DIR}/,${1}/${1}.h)
endef


#
#  All protocols go into subdirectories of the "protocols" directory.
#
SUBMAKEFILES := $(wildcard ${top_srcdir}/src/protocols/*/all.mk)

#
#  Add protocol-specific rules to link include files, etc.
#
$(foreach x,$(SUBMAKEFILES), \
	$(eval $(call PROTO_INCLUDE,$(subst /all.mk,,$(subst ${top_srcdir}/src/protocols/,,$x)))) \
)
