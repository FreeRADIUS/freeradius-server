#
# Makefile	Makefile for the cistron-radius package.
#
# Version:	$Id$
#

include ../../Make.inc

WHAT_TO_MAKE	= all

#
#  Build static libraries by default.  If 'DYNAMIC_MODULES' is defined
#  to be something, then build dynamic libraries, too.
#
TARGET_LIBS = static
ifneq ($(DYNAMIC_MODULES),)
TARGET_LIBS += dynamic
endif

all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

static:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

dynamic:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f *~ lib/[0-9a-z]* lib/STATIC_MODULE_LDFLAGS

install:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	install -d -m 755 $(libdir)
	[ "lib/*.so" != "" ] && install -m 755 lib/*.so $(libdir)

common:
	@rm -f lib/STATIC_MODULE_LDFLAGS
	@for mod in rlm_*; do \
		what=$(WHAT_TO_MAKE); \
		[ "$$what" = "all" ] && what="$(TARGET_LIBS)"; \
		echo "Making $$what in $$mod..."; \
		(cd $$mod ; $(MAKE) $(MFLAGS) $$what) || exit 1;\
	done
