#
#  Changes the behaviour of autoconf.h to undef definitions that would conflict
#  with module config.h files.
#
CFLAGS += -DIS_MODULE=1


SUBMAKEFILES := $(wildcard ${top_srcdir}/src/modules/rlm_*/all.mk)
SUBMAKEFILES += $(wildcard ${top_srcdir}/src/modules/proto_*/all.mk)

EXT_MODULES := $(subst ${top_srcdir}/,,$(wildcard ${top_srcdir}/src/modules/*_ext))

#
#  If we haven't run configure, ignore the modules which require it.
#  Otherwise, load in all of the module makefiles, including ones
#  which have not yet been configured.  We do the "sort" to remove
#  duplicates.
#
ifeq "$(CONFIGURE_ARGS)" ""
NEEDS_CONFIG := $(patsubst %.in,%,$(foreach file,$(SUBMAKEFILES),$(wildcard $(file).in)))
SUBMAKEFILES := $(sort $(SUBMAKEFILES) $(NEEDS_CONFIG))
endif

ifeq "$(MAKECMDGOALS)" "check.configure"
src/modules/%/configure: src/modules/%/configure.ac
	@echo WARNING - may need "'make reconfig'" for AUTOCONF $(dir $@)
endif

ifeq "$(MAKECMDGOALS)" "reconfig"
src/modules/%/configure: src/modules/%/configure.ac $(wildcard ${top_srcdir}/m4/*.m4)
	@echo AUTOCONF $(dir $@)
	@cd $(dir $@) && \
		$(ACLOCAL) -I $(top_builddir)/m4 && \
		$(AUTOCONF)
endif

#
#  This dictionary file loads all of the module-specific ones.
#
share/dictionary/freeradius/dictionary: $(patsubst src/modules/rlm_%/dictionary,share/dictionary/freeradius/modules/%.txt,$(wildcard src/modules/rlm_*/dictionary))
	@touch $@

#
#  In the modules they're called "dictionary".  In the installed directory, they're just text files.
#
#  No one should be editing them.
#
share/dictionary/freeradius/modules/%.txt: src/modules/rlm_%/dictionary
	@cp $< $@
