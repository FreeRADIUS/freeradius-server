#
# Makefile
#
# Version:	$Id$
#

include ../Make.inc

SUBDIRS		= include lib modules main
WHAT_TO_MAKE	= all

all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f include/*~ *~

install:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

common:
	@for dir in $(SUBDIRS); do \
		echo "Making $(WHAT_TO_MAKE) in $$dir..."; \
		(cd $$dir && $(MAKE) $(MFLAGS) $(WHAT_TO_MAKE)) || exit 1;\
	done

