#
# Makefile	Makefile for the cistron-radius package.
#
#		NOTE: This top-level Makefile must not
#		use GNU-make extensions. The lower ones can.
#
# Version:	$Id$
#

include Make.inc

SUBDIRS		= src raddb doc scripts
WHAT_TO_MAKE	= all

all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f *~ stamp*

install:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

common:
	@for dir in $(SUBDIRS); do \
		echo "Making $(WHAT_TO_MAKE) in $$dir..."; \
		(cd $$dir ; $(MAKE) $(MFLAGS) $(WHAT_TO_MAKE)) || exit 1;\
	done

distclean: clean
	rm -f config.cache config.log config.status
	-find . ! -name configure.in -name \*.in -print | \
		sed 's/\.in$$//' | \
		while read file; do rm -f $$file; done

######################################################################
#
#  Automatic remaking rules suggested by info:autoconf#Automatic_Remaking
#
######################################################################
configure: configure.in
	autoconf

# autoheader might not change config.h.in, so touch a stamp file
config.h.in: stamp-h.in
stamp-h.in: configure.in acconfig.h config.h.top config.h.bot
	autoheader
	echo timestamp > stamp-h.in

config.h: stamp-h
stamp-h: config.h.in config.status
	./config.status

config.status: configure
	./config.status --recheck
