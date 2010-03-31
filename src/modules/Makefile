#
# Makefile
#
# Version:	$Id$
#

include ../../Make.inc

WHAT_TO_MAKE	= all

all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

install:
	$(INSTALL) -d -m 755 $(R)$(libdir)
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f *~ lib/rlm_* lib/*.o lib/smbencrypt lib/radeapclient

distclean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

# Requires GNU Make, but even older ones will do.
SUBDIRS := $(patsubst %/,%,$(dir $(wildcard $(addsuffix /Makefile,$(MODULES)))))

.PHONY: common $(SUBDIRS)

common: $(SUBDIRS)
	@[ -d lib/ ] || mkdir lib
	@[ -d lib/.libs ] || mkdir lib/.libs

$(SUBDIRS): 
	@echo "Making $(WHAT_TO_MAKE) in $@..."
	$(MAKE) $(MFLAGS) -C $@ $(WHAT_TO_MAKE)

# The rlm_*/*/* stuff is to catch the configure
CONFIG_FILES := $(wildcard rlm_*/configure.in rlm_*/*/*/configure.in)

.PHONY: reconfig $(CONFIG_FILES)

#
#  Do NOT use "common", because some modules may not be built,
#  and therefore their makefiles may be empty or non-existent.
#
ifeq "$(AUTOCONF)" ""
reconfig:
	@echo autoconf is needed for this target
else
ifeq "$(AUTOHEADER)" ""
reconfig:
	@echo autoheader is needed for this target
else
reconfig: $(CONFIG_FILES)
endif
endif

# Don't use: $(MAKE) -C $(dir $@) reconfig
# The modules may not have a Makefile
$(CONFIG_FILES):
	@echo "Making reconfig in $(dir $@)..."
	@cd $(dir $@) && $(AUTOCONF) -I $(top_builddir)
	@if grep AC_CONFIG_HEADERS $@ >/dev/null; then\
		cd $(dir $@) && $(AUTOHEADER); \
	 fi
