#  Create the soft link for the protocol-specific include files
#  before building the lib.
#
define LIB_INCLUDE
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
#  So, we instead depend on a targe which has already been defined.t
#  - This is a terrible hack
#
src/freeradius-devel: | src/include/${1}

src/include/${1}:
	@echo LN-SF src/lib/${1} $$@
	$${Q}[ -e $$@ ] || ln -sf $${top_srcdir}/src/lib/${1} $$@

install.src.include: $(addprefix ${SRC_INCLUDE_DIR}/,${1}/base.h)
endef

define PROTO_INCLUDE
src/freeradius-devel: | src/include/${1}

src/include/${1}:
	@echo LN-SF src/protocols/${1} $$@
	$${Q}[ -e $$@ ] || ln -sf $${top_srcdir}/src/protocols/${1} $$@

install.src.include: $(addprefix ${SRC_INCLUDE_DIR}/${1}/,$(notdir $(wildcard src/protocols/${1}/*.h)))
endef

#
#  All lib go into subdirectories of the "lib" directory.
#
SUBMAKEFILES := $(wildcard ${top_srcdir}/src/lib/*/all.mk)

#
#  Add library-specific rules to link include files, etc.
#
$(foreach x,$(SUBMAKEFILES), \
	$(eval $(call LIB_INCLUDE,$(subst /all.mk,,$(subst ${top_srcdir}/src/lib/,,$x)))) \
)


#
#  Add protocol-specific rules to link include files, etc.
#
$(foreach x,$(wildcard ${top_srcdir}/src/protocols/*/all.mk), \
	$(eval $(call PROTO_INCLUDE,$(subst /all.mk,,$(subst ${top_srcdir}/src/protocols/,,$x)))) \
)
