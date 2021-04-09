#
# Makefile
#
#		NOTE: This top-level Makefile must not
#		use GNU-make extensions. The lower ones can.
#
# Version:	$Id$
#

#
#  The default rule is "all".
#
all:

#
#  Catch people who try to use BSD make
#
ifeq "0" "1"
$(error GNU Make is required to build FreeRADIUS)
endif

#
#  The version of GNU Make is too old,
#  don't use it (.FEATURES variable was added in 3.81)
#
ifndef .FEATURES
$(error This build system requires GNU Make 4.0 or higher)
endif

#
#  Check for our required list of features
#
is_feature = $(if $(filter $1,$(.FEATURES)),T)
ifeq "$(call is_feature,load)" ""
$(error GNU Make $(MAKE_VERSION) does not support the "load" keyword (dynamically loaded extensions), upgrade to GNU Make 4.0 or higher)
endif

#
#  We require Make.inc, UNLESS the target is "make deb"
#
#  Since "make deb" re-runs configure... there's no point in
#  requiring the developer to run configure *before* making
#  the debian packages.
#
ifneq "$(MAKECMDGOALS)" "deb"
ifneq "$(MAKECMDGOALS)" "rpm"
ifeq "$(findstring crossbuild,$(MAKECMDGOALS))" ""
$(if $(wildcard Make.inc),,$(error Missing 'Make.inc' Run './configure [options]' and retry))

include Make.inc
endif
endif
endif

#
#  'configure' was not run?  Get the version number from the file.
#
ifeq "$(RADIUS_VERSION_STRING)" ""
RADIUSD_VERSION_STRING := $(shell cat VERSION)
endif

MFLAGS += --no-print-directory

export DESTDIR := $(R)
export PROJECT_NAME := freeradius

#
#  src/include/all.mk needs these, so define them before we include that file.
#
PROTOCOLS    := \
	arp \
	dhcpv4 \
	dhcpv6 \
	eap/aka-sim \
	ethernet \
	freeradius \
	radius \
	snmp \
	tacacs \
	vmps \
	tftp

#
#  If we're building packages or crossbuilding, just do that.
#  Don't try to do a local build.
#
ifneq "$(MAKECMDGOALS)" "deb"
ifeq "$(findstring crossbuild,$(MAKECMDGOALS))" ""
#
#  Include all of the autoconf definitions into the Make variable space
#
#  We include this file BEFORE starting the full make process.  That
#  way every "all.mk" file can take advantage of the definitions seen
#  here.
#
build/autoconf.mk: src/include/autoconf.h
	@mkdir -p build
	${Q}grep '^#define' $^ | sed 's/#define /AC_/;s/ / := /' > $@
-include build/autoconf.mk

#
#  Autoload the various libraries needed for building.
#
#  If the build is targeting these explicitly, then we are OK if their
#  features don't exist.  If we're building everything else, then
#  build these first, and then load the libraries.
#
#  Ensure that these libraries are built ONLY when doing a full build,
#  AND that they are built and loaded before using the rest of the
#  boilermake framework, UNLESS we're doing "make clean", in which case
#  don't include the magic libraries.
#
ifeq "$(findstring clean,$(MAKECMDGOALS))" ""
ifeq "$(findstring libfreeradius-make,$(MAKECMDGOALS))" ""
_:=$(shell $(MAKE) libfreeradius-make-dlopen.a libfreeradius-make-version.a)

ifeq "${LIBRARY_EXT}" ""
ifneq "$(findstring Darwin,$(shell hostinfo))" ""
LIBRARY_EXT := dylib
else
LIBRARY_EXT := so
endif
endif

load build/lib/.libs/libfreeradius-make-dlopen.${LIBRARY_EXT}(dlopen_gmk_setup)
load build/lib/.libs/libfreeradius-make-version.${LIBRARY_EXT}(version_gmk_setup)

else
#
#  We're building ONLY the libfreeradius-make-* files.
#  Leave the outputs at the default location, but take the
#  inputs from the scripts/build directory.
#
BUILD_DIR:=${top_srcdir}/build
top_builddir:=${top_srcdir}/scripts/build
endif
endif

#
#  Load the huge boilermake framework.
#
include scripts/boiler.mk
endif
endif

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
#  If R is defined, ensure that it ends in a '/'.
#
ifneq "$(R)" ""
R:=$(subst //,/,$(R)/)
export DESTDIR := $(R)
endif

DICTIONARIES := $(wildcard $(addsuffix /dictionary*,$(addprefix share/dictionary/,$(PROTOCOLS))))

install.share: $(addprefix $(R)$(dictdir)/,$(patsubst share/dictionary/%,%,$(DICTIONARIES)))

$(R)$(dictdir)/%: share/dictionary/%
	@echo INSTALL $(patsubst share/dictionary/%,%,$<)
	@$(INSTALL) -m 644 $< $@

.PHONY: dictionary.format
dictionary.format: $(DICTIONARIES)
	@./scripts/dict/format.pl $(DICTIONARIES)

MANFILES := $(wildcard man/man*/*.?) $(AUTO_MAN_FILES)
install.man: $(subst man/,$(R)$(mandir)/,$(MANFILES))

$(R)$(mandir)/%: man/%
	@echo INSTALL $(notdir $<)
	@sed -e "s,/etc/raddb,$(raddbdir),g" \
		-e "s,/usr/local/share,$(datarootdir),g" \
		$< > $<.subst
	@$(INSTALL) -m 644 $<.subst $@
	@rm $<.subst

#
#  Don't install rlm_test
#
ALL_INSTALL := $(patsubst %rlm_test.la,,$(ALL_INSTALL))

install: install.share install.man
	@$(INSTALL) -d -m 700	$(R)$(logdir)
	@$(INSTALL) -d -m 700	$(R)$(radacctdir)

ifneq ($(RADMIN),)
ifneq ($(RGROUP),)
.PHONY: install-chown
install-chown:
	chown -R $(RADMIN)   $(R)$(raddbdir)
	chgrp -R $(RGROUP)   $(R)$(raddbdir)
	chmod u=rwx,g=rx,o=  `find $(R)$(raddbdir) -type d -print`
	chmod u=rw,g=r,o=    `find $(R)$(raddbdir) -type f -print`
	chown -R $(RADMIN)   $(R)$(logdir)
	chgrp -R $(RGROUP)   $(R)$(logdir)
	find $(R)$(logdir) -type d -exec chmod u=rwx,g=rwx,o= {} \;
	find $(R)$(logdir) -type d -exec chmod g+s {} \;
	find $(R)$(logdir) -type f -exec chmod u=rw,g=rw,o= {} \;
	chown -R $(RADMIN)   $(R)$(RUNDIR)
	chgrp -R $(RGROUP)   $(R)$(RUNDIR)
	find $(R)$(RUNDIR) -type d -exec chmod u=rwx,g=rwx,o= {} \;
	find $(R)$(RUNDIR) -type d -exec chmod g+s {} \;
	find $(R)$(RUNDIR) -type f -exec chmod u=rw,g=rw,o= {} \;
endif
endif

distclean: clean
	@-find src/modules -regex .\*/config[.][^.]*\$$ -delete
	@-find src/modules -name autom4te.cache -exec rm -rf '{}' \;
	@rm -rf config.cache config.log config.status libtool \
		src/include/radpaths.h src/include/stamp-h \
		libltdl/config.log libltdl/config.status \
		libltdl/libtool autom4te.cache build
	@-find . ! -name configure.ac -name \*.in -print | \
		sed 's/\.in$$//' | \
		while read file; do rm -f $$file; done

######################################################################
#
#  Automatic remaking rules suggested by info:autoconf#Automatic_Remaking
#
######################################################################
#
#  Do these checks ONLY if we're re-building the "configure"
#  scripts, and ONLY the "configure" scripts.  If we leave
#  these rules enabled by default, then they're run too often.
#
ifeq "$(MAKECMDGOALS)" "reconfig"
CONFIGURE_FILES=1
endif

ifneq "$(filter %configure,$(MAKECMDGOALS))" ""
CONFIGURE_FILES=1
endif

ifeq "$(CONFIGURE_FILES)" "1"

CONFIGURE_AC_FILES := $(shell find . -name configure.ac -print)
CONFIGURE_FILES	   := $(patsubst %.ac,%,$(CONFIGURE_AC_FILES))

#
#  The GNU tools make autoconf=="missing autoconf", which then returns
#  0, even when autoconf doesn't exist.  This check is to ensure that
#  we run AUTOCONF only when it exists.
#
AUTOCONF_EXISTS := $(shell autoconf --version 2>/dev/null)

ifeq "$(AUTOCONF_EXISTS)" ""
$(error You need to install autoconf to re-build the "configure" scripts)
endif

# Configure files depend on "in" files, and on the top-level macro files
# If there are headers, run auto-header, too.
src/%configure: src/%configure.ac acinclude.m4 aclocal.m4 $(wildcard $(dir $@)m4/*m4) | src/freeradius-devel
	@echo AUTOCONF $(dir $@)
	cd $(dir $@) && $(AUTOCONF) -I $(top_builddir) -I $(top_builddir)/m4 -I $(top_builddir)/$(dir $@)m4
	@if grep AC_CONFIG_HEADERS $@ >/dev/null; then\
		echo AUTOHEADER $@ \
		cd $(dir $@) && $(AUTOHEADER); \
	 fi
	@touch $@

# "%configure" doesn't match "configure"
configure: configure.ac $(wildcard ac*.m4) $(wildcard m4/*.m4)
	@echo AUTOCONF $@
	@$(AUTOCONF)

src/include/autoconf.h.in: configure.ac
	@echo AUTOHEADER $@
	@$(AUTOHEADER)

reconfig: $(CONFIGURE_FILES) src/include/autoconf.h.in

config.status: configure
	./config.status --recheck

# target is "configure"
endif

#  If we've already run configure, then add rules which cause the
#  module-specific "all.mk" files to depend on the mk.in files, and on
#  the configure script.
#
ifneq "$(wildcard config.log)" ""
CONFIGURE_ARGS	   := $(shell head -10 config.log | grep '^  \$$' | sed 's/^....//;s:.*configure ::')

src/%all.mk: src/%all.mk.in src/%configure
	@echo CONFIGURE $(dir $@)
	@rm -f ./config.cache $(dir $<)/config.cache
	@cd $(dir $<) && ./configure $(CONFIGURE_ARGS)
endif

.PHONY: check-includes
check-includes:
	scripts/min-includes.pl `find . -name "*.c" -print`

.PHONY: TAGS
TAGS:
	etags `find src -type f -name '*.[ch]' -print` > $@

#
#  Make test certificates.
#
.PHONY: certs
certs:
	@$(MAKE) -C raddb/certs

######################################################################
#
#  Make a release.
#
#  Note that "Make.inc" has to be updated with the release number
#  BEFORE running this command!
#
######################################################################
BRANCH = $(shell git rev-parse --abbrev-ref HEAD)

.PHONY: freeradius-server-$(RADIUSD_VERSION_STRING).tar
freeradius-server-$(RADIUSD_VERSION_STRING).tar: .git
	git archive --format=tar --prefix=freeradius-server-$(RADIUSD_VERSION_STRING)/ $(BRANCH) > $@
ifneq "$(EXT_MODULES)" ""
	rm -rf build/freeradius-server-$(RADIUSD_VERSION_STRING)
	cd $(BUILD_DIR) && tar -xf ../$@
	for x in $(subst _ext,,$(EXT_MODULES)); do \
		cd ${top_srcdir}/$${x}_ext; \
		git archive --format=tar --prefix=freeradius-server-$(RADIUSD_VERSION_STRING)/$$x/ $(BRANCH) | (cd ${top_srcdir}/$(BUILD_DIR) && tar -xf -); \
	done
	cd $(BUILD_DIR) && tar -cf ../$@ freeradius-server-$(RADIUSD_VERSION_STRING)
endif

freeradius-server-$(RADIUSD_VERSION_STRING).tar.gz: freeradius-server-$(RADIUSD_VERSION_STRING).tar
	gzip < $^ > $@

freeradius-server-$(RADIUSD_VERSION_STRING).tar.bz2: freeradius-server-$(RADIUSD_VERSION_STRING).tar
	bzip2 < $^ > $@

%.sig: %
	gpg --default-key packages@freeradius.org -b $<

# high-level targets
.PHONY: dist-check
dist-check: redhat/freeradius.spec suse/freeradius.spec debian/changelog
	@if [ `grep ^Version: redhat/freeradius.spec | sed 's/.*://;s/ //'` != "$(RADIUSD_VERSION_STRING)" ]; then \
		cat redhat/freeradius.spec | sed 's/^Version: .*/Version: $(RADIUSD_VERSION_STRING)/' > redhat/.foo; \
		mv redhat/.foo redhat/freeradius.spec; \
		echo redhat/freeradius.spec 'Version' needs to be updated; \
		exit 1; \
	fi
	@if [ `grep ^Version: suse/freeradius.spec | sed 's/.*://;s/ //'` != "$(RADIUSD_VERSION_STRING)" ]; then \
		cat suse/freeradius.spec | sed 's/^Version: .*/Version: $(RADIUSD_VERSION_STRING)/' > suse/.foo; \
		mv suse/.foo suse/freeradius.spec; \
		echo suse/freeradius.spec 'Version' needs to be updated; \
		exit 1; \
	fi
	@if [ `head -n 1 debian/changelog | sed 's/.*(//;s/-0).*//;s/-1).*//;s/\+.*//'`  != "$(RADIUSD_VERSION_STRING)" ]; then \
		echo debian/changelog needs to be updated; \
		exit 1; \
	fi

dist: dist-check freeradius-server-$(RADIUSD_VERSION_STRING).tar.gz freeradius-server-$(RADIUSD_VERSION_STRING).tar.bz2

dist-sign: freeradius-server-$(RADIUSD_VERSION_STRING).tar.gz.sig freeradius-server-$(RADIUSD_VERSION_STRING).tar.bz2.sig

dist-publish: freeradius-server-$(RADIUSD_VERSION_STRING).tar.gz.sig freeradius-server-$(RADIUSD_VERSION_STRING).tar.gz freeradius-server-$(RADIUSD_VERSION_STRING).tar.gz.sig freeradius-server-$(RADIUSD_VERSION_STRING).tar.bz2 freeradius-server-$(RADIUSD_VERSION_STRING).tar.gz.sig freeradius-server-$(RADIUSD_VERSION_STRING).tar.bz2.sig
	scp $^ freeradius.org@ns5.freeradius.org:public_ftp
	scp $^ freeradius.org@www.tr.freeradius.org:public_ftp

#
#  Note that we do NOT do the tagging here!  We just print out what
#  to do!
#
dist-tag: freeradius-server-$(RADIUSD_VERSION_STRING).tar.gz freeradius-server-$(RADIUSD_VERSION_STRING).tar.bz2
	@echo "git tag release_`echo $(RADIUSD_VERSION_STRING) | tr .- __`"

#
#	Build a debian package
#
.PHONY: deb
deb:
	@if ! which fakeroot; then \
		if ! which apt-get; then \
		  echo "'make deb' only works on debian systems" ; \
		  exit 1; \
		fi ; \
		echo "Please run 'apt-get install build-essentials' "; \
		exit 1; \
	fi
	fakeroot debian/rules debian/control #clean
	fakeroot dpkg-buildpackage -b -uc

.PHONY: rpm

rpmbuild/SOURCES/freeradius-server-$(RADIUSD_VERSION_STRING).tar.bz2: freeradius-server-$(RADIUSD_VERSION_STRING).tar.bz2
	@mkdir -p $(addprefix rpmbuild/,SOURCES SPECS BUILD RPMS SRPMS BUILDROOT)
	@for file in `awk '/^Source...:/ {print $$2}' redhat/freeradius.spec` ; do cp redhat/$$file rpmbuild/SOURCES/$$file ; done
	@cp $< $@

rpm: rpmbuild/SOURCES/freeradius-server-$(RADIUSD_VERSION_STRING).tar.bz2
	@if ! yum-builddep -q -C --assumeno redhat/freeradius.spec 1> /dev/null 2>&1; then \
		echo "ERROR: Required depdendencies not found, install them with: yum-builddep redhat/freeradius.spec"; \
		exit 1; \
	fi
	@QA_RPATHS=0x0003 rpmbuild --define "_topdir `pwd`/rpmbuild" -bb redhat/freeradius.spec

# Developer checks
.PHONY: warnings
warnings:
	@(make clean all 2>&1) | egrep -v '^/|deprecated|^In file included|: In function|   from |^HEADER|^CC|^LINK|^LN' > warnings.txt
	@wc -l warnings.txt

#
#  Ensure we're using tabs in the configuration files,
#  and remove trailing whitespace in source files.
#
.PHONY: whitespace
whitespace:
	@for x in $$(git ls-files raddb/ src/); do unexpand $$x > $$x.bak; cp $$x.bak $$x; rm -f $$x.bak;done
	@perl -p -i -e 'trim' $$(git ls-files src/)

#
#  Include the crossbuild make file only if we're cross building
#
ifneq "$(findstring crossbuild,$(MAKECMDGOALS))" ""
include scripts/docker/crossbuild/crossbuild.mk
endif

#
#  The "coverage" target
#
ifneq "$(findstring coverage,$(MAKECMDGOALS))" ""
include scripts/build/coverage.mk
endif

#
#  Clean gcov files, too.
#
clean: clean.coverage
.PHONY: clean.coverage
clean.coverage:
	@rm -f ${BUILD_DIR}/radiusd.info $(find ${BUILD_DIR} -name "*.gcda" -print)
