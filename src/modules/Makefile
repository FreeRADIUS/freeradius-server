#
# Makefile	
#
# Version:	$Id$
#

include ../../Make.inc

WHAT_TO_MAKE	= all

#
#  Build static AND dynamic libraries by default.
#  Later, we'll figure out how to get libtool to automagically do this.
#
TARGET_LIBS = static dynamic

all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

static:
	@[$$USE_STATIC_LIBS = "yes" ] && $(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

dynamic:
	@[$$USE_SHARED_LIBS = "yes" ] && $(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

install:
	$(INSTALL) -d -m 755 $(R)$(libdir)
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f *~ lib/rlm_* lib/*.o lib/smbencrypt

distclean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

common:
	@[ -d lib/ ] || mkdir lib
	@for mod in $(MODULES); do \
		what=$(WHAT_TO_MAKE); \
		if [ -d $$mod ] && [ -f $$mod/Makefile ]; then \
			echo "Making $$what in $$mod..."; \
			(cd $$mod && $(MAKE) $(MFLAGS) $$what) || exit 1;\
		fi; \
	done
