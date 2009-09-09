#
# Makefile
#
#		NOTE: This top-level Makefile must not
#		use GNU-make extensions. The lower ones can.
#
# Version:	$Id$
#

include Make.inc

.PHONY: all clean install

SUBDIRS		= $(LTDL_SUBDIRS) src raddb scripts doc
WHAT_TO_MAKE	= all

all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f *~

#
# The $(R) is a magic variable not defined anywhere in this source.
# It's purpose is to allow an admin to create an installation 'tar'
# file *without* actually installing it.  e.g.:
#
#  $ R=/home/root/tmp make install
#  $ cd /home/root/tmp
#  $ tar -cf ~/freeradius-package.tar *
#
# The 'tar' file can then be un-tar'd on any similar machine.  It's a
# cheap way of creating packages, without using a package manager.
# Many of the platform-specific packaging tools use the $(R) variable
# when creating their packages.
#
# For compatibility with typical GNU packages (e.g. as seen in libltdl),
# we make sure DESTDIR is defined.
#
export DESTDIR := $(R)
install:
	$(INSTALL) -d -m 755	$(R)$(sbindir)
	$(INSTALL) -d -m 755	$(R)$(bindir)
	$(INSTALL) -d -m 755	$(R)$(raddbdir)
	$(INSTALL) -d -m 755	$(R)$(mandir)
	$(INSTALL) -d -m 755	$(R)$(RUNDIR)
	$(INSTALL) -d -m 700	$(R)$(logdir)
	$(INSTALL) -d -m 700	$(R)$(radacctdir)
	$(INSTALL) -d -m 755	$(R)$(datadir)
	$(INSTALL) -d -m 755	$(R)$(dictdir)
	for i in 1 5 8; do \
		$(INSTALL) -d -m 755	$(R)$(mandir)/man$$i; \
		for p in man/man$$i/*.$$i; do \
			$(INSTALL) -m 644 $$p $(R)$(mandir)/man$$i; \
		done \
	done
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@echo "Installing dictionary files in $(R)$(dictdir)"; \
	cd share; \
	for i in dictionary*; do \
		$(INSTALL) -m 644 $$i $(R)$(dictdir); \
	done
	$(LIBTOOL) --finish $(R)$(libdir)

common:
	@for dir in $(SUBDIRS); do \
		echo "Making $(WHAT_TO_MAKE) in $$dir..."; \
		$(MAKE) $(MFLAGS) -C $$dir $(WHAT_TO_MAKE) || exit $$?; \
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

TAGS:
	etags `find src -type f -name '*.[ch]' -print`


######################################################################
#
#  Make a release.
#
#  Note that "Make.inc" has to be updated with the release number
#  BEFORE running this command!
#
######################################################################
freeradius-$(RADIUSD_VERSION).tar.gz: .git
	git archive --format=tar --prefix=freeradius-$(RADIUSD_VERSION)/ branch_1_1_7 | gzip > $@

freeradius-$(RADIUSD_VERSION).tar.gz.sig: freeradius-$(RADIUSD_VERSION).tar.gz
	gpg --default-key aland@freeradius.org -b $<

freeradius-$(RADIUSD_VERSION).tar.bz2: .git
	git archive --format=tar --prefix=freeradius-$(RADIUSD_VERSION)/ branch_1_1_7 | bzip2 > $@

freeradius-$(RADIUSD_VERSION).tar.bz2.sig: freeradius-$(RADIUSD_VERSION).tar.bz2
	gpg --default-key aland@freeradius.org -b $<

# high-level targets
.PHONY: dist-check
dist-check: redhat/freeradius.spec suse/freeradius.spec debian/changelog
	@if [ `grep ^Version: redhat/freeradius.spec | sed 's/.*://;s/ //'` != "$(RADIUSD_VERSION)" ]; then \
		cat redhat/freeradius.spec | sed 's/^Version: .*/Version: $(RADIUSD_VERSION)/' > redhat/.foo; \
		mv redhat/.foo redhat/freeradius.spec; \
		echo redhat/freeradius.spec 'Version' needs to be updated; \
		exit 1; \
	fi
	@if [ `grep ^Version: suse/freeradius.spec | sed 's/.*://;s/ //'` != "$(RADIUSD_VERSION)" ]; then \
		cat suse/freeradius.spec | sed 's/^Version: .*/Version: $(RADIUSD_VERSION)/' > suse/.foo; \
		mv suse/.foo suse/freeradius.spec; \
		echo suse/freeradius.spec 'Version' needs to be updated; \
		exit 1; \
	fi
	@if [ `head -n 1 debian/changelog | sed 's/.*(//;s/-0).*//;s/-1).*//;'`  != "$(RADIUSD_VERSION)" ]; then \
		echo debian/changelog needs to be updated; \
		exit 1; \
	fi

dist: dist-check freeradius-$(RADIUSD_VERSION).tar.gz freeradius-$(RADIUSD_VERSION).tar.bz2

dist-sign: freeradius-$(RADIUSD_VERSION).tar.gz.sig freeradius-$(RADIUSD_VERSION).tar.bz2.sig

dist-publish: freeradius-$(RADIUSD_VERSION).tar.gz.sig freeradius-$(RADIUSD_VERSION).tar.gz freeradius-$(RADIUSD_VERSION).tar.gz.sig freeradius-$(RADIUSD_VERSION).tar.bz2 freeradius-$(RADIUSD_VERSION).tar.gz.sig freeradius-$(RADIUSD_VERSION).tar.bz2.sig
	scp $^ freeradius.org@ns5.freeradius.org:public_ftp
	scp $^ freeradius.org@www.tr.freeradius.org:public_ftp

#
#  Note that we do NOT do the tagging here!  We just print out what
#  to do!
#
dist-tag: freeradius-$(RADIUSD_VERSION).tar.gz freeradius-$(RADIUSD_VERSION).tar.bz2
	@echo "git tag release_`echo $(RADIUSD_VERSION) | tr .- __`"

#
#	Build a debian package
#
.PHONY: deb
deb:
	fakeroot dpkg-buildpackage -b -uc

.PHONY: diff-check
diff-check:
	diff -x .git -x '.lo' -r ../freeradius-1.1.7 freeradius-1.1.8 | egrep -v '\$|^diff|^---|^[0-9]+[a-z][0-9]+' | more 
