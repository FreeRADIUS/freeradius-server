#  Create the soft link for the protocol-specific include files
#  before building the lib.
#
define LIB_INCLUDE
#
#  This is a hack to get the include files linked correctly.  We would
#  LOVE to be able to do:
#
#	$${libfreeradius-${2}.la_OBJS}: | src/include/${2}
#
#  but GNU Make is too stupid to wait until that variable is defined
#  to evaluate the condition.  Instead, it evaluates the rule
#  immediately, and decides that nothing is there.
#
#  So, we instead depend on a targe which has already been defined.t
#  - This is a terrible hack
#
src/freeradius-devel: | src/include/${2}

src/include/${2}:
	$${Q}[ -e $$@ ] || ln -sf $${top_srcdir}/src/${1}/${2} $$@
	@echo LN-SF src/lib/${2} $$@

ifeq "${1}" "lib"
install.src.include: $(addprefix ${SRC_INCLUDE_DIR}/,src/${1}/base.h)
else
install.src.include: $(addprefix ${SRC_INCLUDE_DIR}/,src/${1}/${1}.h)
endif
endef


#
#  All lib go into subdirectories of the "lib" directory.
#
SUBMAKEFILES := $(wildcard ${top_srcdir}/src/lib/*/all.mk)

#
#  Add library-specific rules to link include files, etc.
#
$(foreach x,$(SUBMAKEFILES), \
	$(eval $(call LIB_INCLUDE,lib,$(subst /all.mk,,$(subst ${top_srcdir}/src/lib/,,$x)))) \
)


#
#  Add protocol-specific rules to link include files, etc.
#
$(foreach x,$(wildcard ${top_srcdir}/src/protocols/*/all.mk), \
	$(eval $(call LIB_INCLUDE,protocols,$(subst /all.mk,,$(subst ${top_srcdir}/src/protocols/,,$x)))) \
)
