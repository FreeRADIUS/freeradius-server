#
# Makefile	Makefile for the cistron-radius package.
#
# Version:	$Id$
#

include ../../Make.inc

WHAT_TO_MAKE	= all

#
#  Build static libraries by default.  If 'LIBDL' is defined
#  to be something, then build dynamic libraries, too.
#
TARGET_LIBS = static
ifneq ($(LIBDL),)
TARGET_LIBS += dynamic
endif

all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f *~ lib/[0-9a-z]*

install:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

common:
	@for mod in rlm_*; do \
		what=$(WHAT_TO_MAKE); \
		[ "$$what" = "all" ] && what="$(TARGET_LIBS)"; \
		echo "Making $$what in $$mod..."; \
		(cd $$mod ; $(MAKE) $(MFLAGS) $$what) || exit 1;\
	done
