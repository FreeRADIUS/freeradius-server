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
	@rm -f *~ lib/[0-9a-z]*

distclean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

common:
	@[ -d lib/ ] || mkdir lib
	@for mod in rlm_*; do \
		what=$(WHAT_TO_MAKE); \
		[ "$$what" = "all" ] && what="$(TARGET_LIBS)"; \
		echo "Making $$what in $$mod..."; \
		(cd $$mod && $(MAKE) $(MFLAGS) $$what) || exit 1;\
	done
