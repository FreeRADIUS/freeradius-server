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
#  We require Make.inc, UNLESS we're building packages running
#  VMs or producing tar files tar files.
#
#  Since "make deb" and "make rpm" re-run configure...
#  there's no point in requiring the developer to run configure
#  *before* making packages.
#
ifeq "$(filter deb rpm pkg_version dist-check% crossbuild.% docker.% freeradius-server-%,$(MAKECMDGOALS))" ""
  $(if $(wildcard Make.inc),,$(error Missing 'Make.inc' Run './configure [options]' and retry))
  include Make.inc
else
  top_srcdir:=$(realpath $(dir $(lastword $(MAKEFILE_LIST))))
  BUILD_DIR:=build
endif

#
#  'configure' was not run?  Get the version number from the file.
#
ifeq "$(RADIUSD_VERSION)" ""
  RADIUSD_VERSION_MAJOR := $(shell ./version.sh major)
  RADIUSD_VERSION_MINOR := $(shell ./version.sh minor)

  # Default to an incremental version of 0 if we're not building from git
  RADIUSD_VERSION_INCRM := $(shell ./version.sh commit_depth)
endif

ifeq "$(RADIUSD_VERSION_INCRM)" ""
  RADIUSD_VERSION_INCRM := $(shell ./version.sh incrm)
  PKG_VERSION_SUFFIX :=
  ifeq "$(RADIUSD_VERSION_INCRM)" ""
    RADIUSD_VERSION_SEP :=
  else
    RADIUSD_VERSION_SEP := .
  endif
else
  PKG_VERSION_SUFFIX := +git
  RADIUSD_VERSION_SEP := ~
endif

ifeq "$(shell ./version.sh is_release)" "1"
  PKG_VERSION := $(shell cat VERSION)
else
  PKG_VERSION := $(RADIUSD_VERSION_MAJOR).$(RADIUSD_VERSION_MINOR)$(RADIUSD_VERSION_SEP)$(RADIUSD_VERSION_INCRM)$(PKG_VERSION_SUFFIX)
endif

.PHONY: pkg_version
pkg_version:
	@echo $(PKG_VERSION)

MFLAGS += --no-print-directory

export DESTDIR := $(R)
export PROJECT_NAME := freeradius

#
#  src/include/all.mk needs these, so define them before we include that file.
#
PROTOCOLS    := \
	arp \
	bfd \
	der \
	dhcpv4 \
	dhcpv6 \
	dns \
	eap/aka-sim \
	ethernet \
	freeradius \
	ldap \
	radius \
	snmp \
	tacacs \
	vmps \
	tftp \
	tls

#
#  If we're building packages or crossbuilding, just do that.
#  Don't try to do a local build.
#
ifeq "$(filter deb rpm pkg_version dist-check% crossbuild.% docker.% freeradius-server-%,$(MAKECMDGOALS))" ""

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

      #
      #  Manually check the dependencies.  This is because we want to
      #  use special rules for building these libraries.  So we can't
      #  rely on the normal GNU make dependencies.
      #
      define MAKE_LIB_CHECK
        ifeq "$(wildcard build/lib/.libs/libfreeradius-make-${1}.${BUILD_LIB_EXT})" ""
          BUILD_MAKE_LIBS += libfreeradius-make-${1}.${BUILD_LIB_EXT}
        endif
      endef

      $(foreach x, dlopen fork util version,$(eval $(call MAKE_LIB_CHECK,${x})))

      ifdef BUILD_MAKE_LIBS
        #
        #  Define a variable which contains one new line.  Note that
        #  it needs to contain multiple lines, not just one.
        #
        define newline


        endef

        #
        #  Run the shell command to build the targets.  The result is
        #  mashed all on one line, so we do some horrible
        #  substitutions to get it on multiple lines.  Then, we print
        #  out the result.
        #
        $(info $(subst gmake[,$(newline)gmake[,$(subst LINK,$(newline)LINK,$(subst CC,$(newline)CC,$(shell $(MAKE) VERBOSE=$(VERBOSE) ${BUILD_MAKE_LIBS})))))
      endif

      load build/lib/.libs/libfreeradius-make-dlopen.${BUILD_LIB_EXT}(dlopen_gmk_setup)
      load build/lib/.libs/libfreeradius-make-version.${BUILD_LIB_EXT}(version_gmk_setup)
      load build/lib/.libs/libfreeradius-make-util.${BUILD_LIB_EXT}(util_gmk_setup)
      load build/lib/.libs/libfreeradius-make-fork.${BUILD_LIB_EXT}(fork_gmk_setup)
    else
      BUILD_DIR:=${top_srcdir}/build
      top_builddir:=${top_srcdir}/scripts/build
    endif
  endif

  #
  #  Load the huge boilermake framework.
  #
  include scripts/boiler.mk
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
MIBS = $(wildcard share/snmp/mibs/*.mib)

install.share: \
	$(addprefix $(R)$(dictdir)/,$(patsubst share/dictionary/%,%,$(DICTIONARIES))) \
	$(addprefix $(R)$(mibdir)/,$(patsubst share/snmp/mibs/%,%,$(MIBS)))

$(R)$(dictdir)/%: share/dictionary/%
	@echo INSTALL $(patsubst share/dictionary/%,%,$<)
	@$(INSTALL) -m 644 $< $@

$(R)$(mibdir)/%: share/snmp/mibs/%
	@echo INSTALL $(patsubst share/snmp/mibs/%,%,$<)
	@$(INSTALL) -m 644 $< $@

.PHONY: dictionary.format
dictionary.format: $(DICTIONARIES)
	@./scripts/dict/format.pl $(DICTIONARIES)

MANFILES := $(wildcard man/man*/*.?) $(AUTO_MAN_FILES)
install.man: $(subst man/,$(R)$(mandir)/,$(MANFILES))

$(R)$(mandir)/%: man/%
	@echo INSTALL $(notdir $<)
	@sed -e "s,/etc/raddb,$(confdir),g" \
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
	chown -R $(RADMIN)   $(R)$(confdir)
	chgrp -R $(RGROUP)   $(R)$(confdir)
	chmod u=rwx,g=rx,o=  `find $(R)$(confdir) -type d -print`
	chmod u=rw,g=r,o=    `find $(R)$(confdir) -type f -print`
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
	@-find src/modules -name aclocal.m4 -exec rm -rf '{}' \;
	@rm -rf config.cache config.log config.status libtool \
		src/include/radpaths.h src/include/stamp-h \
		libltdl/config.log libltdl/config.status \
		libltdl/libtool autom4te.cache build aclocal.m4
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
  DO_RECONFIGURE=1
endif

ifneq "$(filter %configure,$(MAKECMDGOALS))" ""
  DO_RECONFIGURE=1
endif

ifeq "$(DO_RECONFIGURE)" "1"

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
src/%configure: src/%configure.ac $(wildcard $(dir $@)m4/*m4) | src/freeradius-devel
	@echo AUTOCONF $(dir $@)
	@cd $(dir $@) && \
		$(ACLOCAL) --force -I $(top_builddir)/m4 && \
		$(AUTOCONF) --force
	@if grep AC_CONFIG_HEADERS $@ >/dev/null; then\
		echo AUTOHEADER $@ \
		cd $(dir $@) && $(AUTOHEADER) --force; \
	 fi
	@touch $@

# "%configure" doesn't match "configure"
configure: configure.ac $(wildcard m4/*.m4)
	@echo AUTOCONF $@
	@$(ACLOCAL) --force -I $(top_builddir)/m4
	@$(AUTOCONF) --force

src/include/autoconf.h.in: configure.ac
	@echo AUTOHEADER $@
	@$(AUTOHEADER) --force

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
  CONFIGURE_ARGS := $(shell head -10 config.log | grep '^  \$$' | sed 's/^....//;s:.*configure ::')

#
#  ONLY re-run "configure" if we're told to do that.  Otherwise every
#  change to a configure file will have it try to re-run the local
#  configure script, which doesn't always work.
#
ifeq "$(DO_RECONFIGURE)" "1"
src/%all.mk: src/%all.mk.in src/%configure
	@echo CONFIGURE $(dir $@)
	@rm -f ./config.cache $(dir $<)/config.cache
	@cd $(dir $<) && ./configure $(CONFIGURE_ARGS) && touch $(notdir $@)
else
src/%all.mk: src/%all.mk.in src/%configure
	@echo WARNING: $@ is out of date.  Please re-run 'configure'
endif

endif

.PHONY: force-reconfig
force-reconfig:
	@find . -name configure.ac | xargs touch
	@$(MAKE) reconfig

.PHONY: check-includes
check-includes:
	scripts/min-includes.pl `find . -name "*.c" -print`

.PHONY: TAGS
TAGS:
	etags `find src -type f -name '*.[ch]' -print` > $@

.PHONY: compile_commands.json
compile_commands.json:
	@echo '[' > $@ ; \
	find ./build/objs/src -type f -name '*.cc.json' -exec cat {} \; >> $@;\
	echo ']' >> $@

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
#  Note that VERSION has to be updated with the release number and configure should
#  be re-run if it's been run previously, BEFORE running this command!
#
#  These targets determine if release tarballs/rpms/debs should be produced by checking
#  the following conditions:
#
#  - RELEASE=1 is set in make's environment.
#  - A RELEASE file is present in the root of the working directory.
#  - The current commit matches a release_ tag.
#
#  If none of these conditions are true, or RELEASE=0 is set, then development
#  tarballs/rpms/debs will be produced.  These will build with developer-mode
#  enabled, which enables additional debugging, adds full debugging symbols and disables
#  optimisation.
#
######################################################################
.PHONY: freeradius-server-$(PKG_VERSION).tar
#
# This can't depend on .git/ (dirs don't work) or .git/HEAD (not present in submodules)
# so it's just left as a phony target.
#
# Do NOT move calculation of BRANCH outside of the recipe.  Every shell expansion
# carries with it a performance penalty, that is felt every time make is executed.
#
# Original recipe used --add-virtual-file which was added in 237a1d1, on May 30th
# 2022, which was too late for current versions of our target distros.
# Code should be revisited in a few years to switch --add-file to --add-virtual-file.
#
BRANCH_CMD := git rev-parse --abbrev-ref HEAD
freeradius-server-$(PKG_VERSION).tar:
	rm -rf $(top_srcdir)/$(BUILD_DIR)/freeradius-server-$(PKG_VERSION)
	mkdir -p $(top_srcdir)/$(BUILD_DIR)
	BRANCH=$$(${BRANCH_CMD}); \
	tmp=$$(mktemp -d); \
	if [ $$(./version.sh is_release) -eq 1 ]; then\
		touch "$${tmp}/RELEASE"; \
		release_arg="--add-file=$${tmp}/RELEASE"; \
	fi; \
	echo "$$(./version.sh commit)" > "$${tmp}/VERSION_COMMIT"; \
	echo "$$(./version.sh commit_depth)" > "$${tmp}/VERSION_COMMIT_DEPTH"; \
	git archive \
		--format=tar \
		--prefix="freeradius-server-$(PKG_VERSION)/" \
		--add-file="$${tmp}/VERSION_COMMIT" \
		--add-file="$${tmp}/VERSION_COMMIT_DEPTH" \
		$${release_arg} \
		$${BRANCH} | tar -C "${top_srcdir}/${BUILD_DIR}" -xf -; \
	rm -rf "$${tmp}"; \
	git submodule foreach --recursive 'git archive --format=tar --prefix=freeradius-server-$(PKG_VERSION)/$$sm_path/ $$sha1 | tar -C "${top_srcdir}/${BUILD_DIR}" -xf -'
ifneq "$(EXT_MODULES)" ""
	BRANCH=$$(${BRANCH_CMD}); \
	for x in $(subst _ext,,$(EXT_MODULES)); do \
		cd $(top_srcdir)/$${x}_ext && \
		git archive --format=tar --prefix=freeradius-server-$(PKG_VERSION)/$$x/ $${BRANCH} | tar -C "${top_srcdir}/${BUILD_DIR}" -xf -; \
	done
endif
	tar -cf $@ -C $(top_srcdir)/$(BUILD_DIR) freeradius-server-$(PKG_VERSION)

freeradius-server-$(PKG_VERSION).tar.gz: freeradius-server-$(PKG_VERSION).tar
	gzip < $^ > $@

freeradius-server-$(PKG_VERSION).tar.bz2: freeradius-server-$(PKG_VERSION).tar
	bzip2 < $^ > $@

%.sig: %
	gpg --default-key packages@freeradius.org -b $<

# high-level targets
.PHONY: dist-check-rpm
dist-check-rpm: redhat/freeradius.spec
	@if [ `grep '^%global _version' redhat/freeradius.spec | cut -d' ' -f3` != "$(PKG_VERSION)" ]; then \
		sed 's/^%global _version .*/%global _version $(PKG_VERSION)/' redhat/freeradius.spec > redhat/.foo; \
		mv redhat/.foo redhat/freeradius.spec; \
		echo Updated redhat/freeradius.spec '_version' to $(PKG_VERSION); \
	fi
.PHONY: dist-check
dist-check: dist-check-rpm debian/changelog
	@if [ `head -n 1 doc/ChangeLog | awk '/^FreeRADIUS/{print $$2}'` != "$(PKG_VERSION)" ]; then \
		echo doc/ChangeLog needs to be updated; \
		exit 1; \
	fi
	@if [ `head -n 1 debian/changelog | sed 's/.*(//;s/).*//'` != "$(PKG_VERSION)" ]; then \
		echo debian/changelog needs to be updated; \
		exit 1; \
	fi
	@if [ `grep version doc/antora/antora.yml | sed 's/^.*version: //'` != "'$(PKG_VERSION)'" ]; then \
		echo doc/antora/antora.yml needs to be updated with: version '$(PKG_VERSION)'; \
		exit 1; \
	fi

dist: dist-check freeradius-server-$(PKG_VERSION).tar.gz freeradius-server-$(PKG_VERSION).tar.bz2

dist-sign: freeradius-server-$(PKG_VERSION).tar.gz.sig freeradius-server-$(PKG_VERSION).tar.bz2.sig

dist-publish: freeradius-server-$(PKG_VERSION).tar.gz.sig freeradius-server-$(PKG_VERSION).tar.gz freeradius-server-$(PKG_VERSION).tar.gz.sig freeradius-server-$(PKG_VERSION).tar.bz2 freeradius-server-$(PKG_VERSION).tar.gz.sig freeradius-server-$(PKG_VERSION).tar.bz2.sig
	scp $^ freeradius.org@ns5.freeradius.org:public_ftp
	scp $^ freeradius.org@www.tr.freeradius.org:public_ftp

#
#  Note that we do NOT do the tagging here!  We just print out what
#  to do!
#
dist-tag: freeradius-server-$(PKG_VERSION).tar.gz freeradius-server-$(PKG_VERSION).tar.bz2
	@echo "git tag release_`echo $(PKG_VERSION) | tr .- __`"

.PHONY: tar
tar: freeradius-server-$(PKG_VERSION).tar.gz

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
		echo "Please run 'apt-get install build-essential' "; \
		exit 1; \
	fi
	EMAIL="packages@freeradius.org" fakeroot dch -b -v$(PKG_VERSION) ""
	fakeroot debian/rules debian/control # Clean
	fakeroot dpkg-buildpackage -b -uc

.PHONY: rpm
rpmbuild/SOURCES/freeradius-server-$(PKG_VERSION).tar.bz2: freeradius-server-$(PKG_VERSION).tar.bz2
	@mkdir -p $(addprefix rpmbuild/,SOURCES SPECS BUILD RPMS SRPMS BUILDROOT)
	@for file in `awk '/^Source...:/ {print $$2}' redhat/freeradius.spec` ; do cp redhat/$$file rpmbuild/SOURCES/$$file ; done
	@cp $< $@

rpm: rpmbuild/SOURCES/freeradius-server-$(PKG_VERSION).tar.bz2
	@if ! $(SUDO) dnf builddep ${YUM_BUILDDEP_FLAGS} -q -C --assumeno redhat/freeradius.spec 1> rpmbuild/builddep.log 2>&1; then \
		echo "ERROR: Required dependencies not found, install them with: dnf builddep redhat/freeradius.spec"; \
		cat rpmbuild/builddep.log; \
		exit 1; \
	fi
	@cwd=`pwd` && cd redhat && QA_RPATHS=0x0003 rpmbuild --define "_topdir $$cwd/rpmbuild" --define "version $(PKG_VERSION)" -bb $(RPMBUILD_FLAGS) freeradius.spec

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
  include scripts/docker/crossbuild.mk
endif

#
#  Conditionally include the docker make file
#
ifneq "$(findstring docker,$(MAKECMDGOALS))" ""
  include scripts/docker/docker.mk
endif
