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
.error GNU Make is required to build FreeRADIUS
endif

#
#  We require Make.inc, UNLESS the target is "make deb"
#
#  Since "make deb" re-runs configure... there's no point in
#  requiring the developer to run configure *before* making
#  the debian packages.
#
ifneq "$(MAKECMDGOALS)" "deb"
$(if $(wildcard Make.inc),,$(error Missing 'Make.inc' Run './configure [options]' and retry))

include Make.inc
endif

MFLAGS += --no-print-directory

# The version of GNU Make is too old, don't use it (.FEATURES variable was
# wad added in 3.81)
ifndef .FEATURES
$(error The build system requires GNU Make 3.81 or later.)
endif

export DESTDIR := $(R)

# And over-ride all of the other magic.
ifneq "$(MAKECMDGOALS)" "deb"
include scripts/boiler.mk
endif

#
#  To work around OpenSSL issues with travis.
#
.PHONY:
raddb/test.conf:
	@echo 'security {' >> $@
	@echo '        allow_vulnerable_openssl = yes' >> $@
	@echo '}' >> $@
	@echo '$$INCLUDE radiusd.conf' >> $@

#
#  Run "radiusd -C", looking for errors.
#
# Only redirect STDOUT, which should contain details of why the test failed.
# Don't molest STDERR as this may be used to receive output from a debugger.
$(BUILD_DIR)/tests/radiusd-c: raddb/test.conf ${BUILD_DIR}/bin/radiusd | build.raddb
	@$(MAKE) -C raddb/certs
	@printf "radiusd -C... "
	@if ! FR_LIBRARY_PATH=./build/lib/local/.libs/ ./build/make/jlibtool --mode=execute ./build/bin/radiusd -XCMd ./raddb -D ./share -n test > $(BUILD_DIR)/tests/radiusd.config.log; then \
		rm -f raddb/test.conf; \
		cat $(BUILD_DIR)/tests/radiusd.config.log; \
		echo "fail"; \
		exit 1; \
	fi
	@rm -f raddb/test.conf
	@echo "ok"
	@touch $@

test: ${BUILD_DIR}/bin/radiusd ${BUILD_DIR}/bin/radclient tests.unit tests.xlat tests.keywords tests.auth tests.modules $(BUILD_DIR)/tests/radiusd-c | build.raddb
	@$(MAKE) -C src/tests tests

#  Tests specifically for Travis.  We do a LOT more than just
#  the above tests
ifneq "$(findstring travis,${prefix})" ""
travis-test: raddb/test.conf test
	@FR_LIBRARY_PATH=./build/lib/local/.libs/ ./build/make/jlibtool --mode=execute ./build/bin/radiusd -xxxv -n test
	@rm -f raddb/test.conf
	@$(MAKE) install
	@perl -p -i -e 's/allow_vulnerable_openssl = no/allow_vulnerable_openssl = yes/' ${raddbdir}/radiusd.conf
	@${sbindir}/radiusd -XC
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
export DESTDIR := $(R)

DICTIONARIES := $(wildcard share/dictionary*)
install.share: $(addprefix $(R)$(dictdir)/,$(notdir $(DICTIONARIES)))

$(R)$(dictdir)/%: share/%
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -m 644 $< $@

MANFILES := $(wildcard man/man*/*.?)
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

freeradius-server-$(RADIUSD_VERSION_STRING).tar.gz: .git
	git archive --format=tar --prefix=freeradius-server-$(RADIUSD_VERSION_STRING)/ $(BRANCH) | gzip > $@

freeradius-server-$(RADIUSD_VERSION_STRING).tar.bz2: .git
	git archive --format=tar --prefix=freeradius-server-$(RADIUSD_VERSION_STRING)/ $(BRANCH) | bzip2 > $@

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
	scp $^ freeradius.org@ftp.freeradius.org:public_ftp

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
	fakeroot dpkg-buildpackage -b -uc

# Developer checks
.PHONY: warnings
warnings:
	@(make clean all 2>&1) | egrep -v '^/|deprecated|^In file included|: In function|   from |^HEADER|^CC|^LINK' > warnings.txt
	@wc -l warnings.txt

#
#  Ensure we're using tabs in the configuration files,
#  and remove trailing whitespace in source files.
#
.PHONY: whitespace
whitespace:
	@for x in $$(git ls-files raddb/ src/); do unexpand $$x > $$x.bak; cp $$x.bak $$x; rm -f $$x.bak;done
	@perl -p -i -e 'trim' $$(git ls-files src/)
