#
# Makefile	Makefile for the cistron-radius package.
#
#		NOTE: This top-level Makefile must not
#		use GNU-make extensions. The lower ones can.
#
# Version:	$Id$
#

include Make.inc

SUBDIRS		= libltdl src raddb doc scripts
WHAT_TO_MAKE	= all

all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f *~

install:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	$(INSTALL) -d -m 755	$(R)$(mandir);
	for i in 1 5 8; do \
		$(INSTALL) -d -m 755	$(R)$(mandir)/man$$i; \
		$(INSTALL) -m 644 man/man$$i/*.$$i $(R)$(mandir)/man$$i; \
	done
	@echo "Creating/updating files in $(R)$(raddbdir)"; \
	$(INSTALL) -d -m 755	$(R)$(raddbdir); \
	cd raddb; \
	for i in [a-c]* [e-z]*; do \
		[ $$i != radiusd.conf.in -a ! -f $(R)$(raddbdir)/$$i ] && \
                $(INSTALL) -m 644 $$i $(R)$(raddbdir); \
	done; \
	for i in dictionary*; do \
		[ ! -f $(R)$(raddbdir)/$$i ] && $(INSTALL) -m 644 $$i $(R)$(raddbdir); \
		if [ "`find $$i -newer $(R)$(raddbdir)/$$i`" ]; then \
			echo "** $(R)$(raddbdir)/$$i"; \
			nt=1; \
		fi; \
	done; \
	if [ "$$nt" ]; then \
		echo "** The samples in ../raddb are newer than these files";\
		echo "** Please investigate and copy manually if appropriate";\
	fi

common:
	@for dir in $(SUBDIRS); do \
		echo "Making $(WHAT_TO_MAKE) in $$dir..."; \
		(cd $$dir && $(MAKE) $(MFLAGS) $(WHAT_TO_MAKE)) || exit 1;\
	done

distclean: clean
	rm -f config.cache config.log config.status libtool \
		src/include/radpaths.h src/include/stamp-h \
		libltdl/config.log libltdl/config.status \
		libltdl/libtool
	-find . ! -name configure.in -name \*.in -print | \
		sed 's/\.in$$//' | \
		while read file; do rm -f $$file; done
	-find src/modules -name config.mak | \
		while read file; do rm -f $$file; done
	-find src/modules -name config.h | \
		while read file; do rm -f $$file; done

######################################################################
#
#  Automatic remaking rules suggested by info:autoconf#Automatic_Remaking
#
######################################################################
reconfig: configure src/include/autoconf.h.in

configure: configure.in aclocal.m4
	$(AUTOCONF)

# autoheader might not change autoconf.h.in, so touch a stamp file
src/include/autoconf.h.in: src/include/stamp-h.in acconfig.h
src/include/stamp-h.in: configure.in acconfig.h
	$(AUTOHEADER)
	echo timestamp > src/include/stamp-h.in

src/include/autoconf.h: src/include/stamp-h
src/include/stamp-h: src/include/autoconf.h.in config.status
	./config.status

config.status: configure
	./config.status --recheck

configure.in:
