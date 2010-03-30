#
# Makefile
#
# Version:	$Id$
#

include ../Make.inc

SUBDIRS		= include lib modules main
WHAT_TO_MAKE	= all

all: freeradius-devel
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f include/*~ *~

install:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

.PHONY: common $(SUBDIRS)

common: $(SUBDIRS)

$(SUBDIRS): 
	echo "Making $(WHAT_TO_MAKE) in $@..."
	$(MAKE) $(MFLAGS) -C $@ $(WHAT_TO_MAKE)

freeradius-devel:
	ln -s include freeradius-devel
