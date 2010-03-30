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

#
#  Do NOT use "common", because some modules may not be built,
#  and therefore their makefiles may be empty or non-existent.
#
reconfig:
	@[ "x$(AUTOCONF)" != "x" ] || exit 0
	@[ "x$(AUTOHEADER)" != "x" ] || exit 0
	@for x in `find . -name "configure.in" -print`; do \
		( \
		 cd `dirname $$x` || exit $$?; \
		 if [ -f configure.in ]; then \
			$(AUTOCONF) -I $(top_builddir); \
		 fi; \
		 if grep AC_CONFIG_HEADERS configure.in >/dev/null; then\
			$(AUTOHEADER); \
		 fi; \
		)  || exit $$?; \
	done

# Requires GNU Make, but even older ones will do.
SUBDIRS := $(patsubst %/,%,$(dir $(wildcard $(addsuffix /Makefile,$(MODULES)))))

.PHONY: common $(SUBDIRS)

common: $(SUBDIRS)
	@[ -d lib/ ] || mkdir lib
	@[ -d lib/.libs ] || mkdir lib/.libs

$(SUBDIRS): 
	echo "Making $(WHAT_TO_MAKE) in $@..."
	$(MAKE) $(MFLAGS) -C $@ $(WHAT_TO_MAKE)
