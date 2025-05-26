#
# Version:	$Id$
#

#
#  Build dynamic headers by substituting various values from autoconf.h, these
#  get installed with the library files, so external programs can tell what
#  the server library was built with.
#
#  The RFC headers are dynamic, too.
#
#  The rest of the headers are static.
#

HEADERS_DY = attributes.h features.h missing.h radpaths.h tls.h

HEADERS	= \
	autoconf.h \
	build.h \
	conf.h \
	conffile.h \
	detail.h \
	event.h \
	hash.h \
	heap.h \
	libradius.h \
	md4.h \
	md5.h \
	modcall.h \
	modules.h \
	packet.h \
	rad_assert.h \
	radius.h \
	radiusd.h \
	radutmp.h \
	realms.h \
	regex.h \
	sha1.h \
	stats.h \
	sysutmp.h \
	tcp.h \
	threads.h \
	token.h \
	udpfromto.h \
	base64.h \
	map.h \
	$(HEADERS_DY)

#
#  Solaris awk doesn't recognise [[:blank:]] hence [\t ]
#
src/include/autoconf.sed: src/include/autoconf.h
	@grep ^#define $< | sed 's,/\*\*/,1,;' | awk '{print "'\
	's,#[\\t ]*ifdef[\\t ]*" $$2 "$$,#if "$$3 ",g;'\
	's,#[\\t ]*ifndef[\\t ]*" $$2 "$$,#if !"$$3 ",g;'\
	's,defined(" $$2 ")," $$3 ",g;"}' > $@
	@grep -o '#undef [^ ]*' $< | sed 's,/#undef /,,;' | awk '{print "'\
	's,#[\\t ]*ifdef[\\t ]*" $$2 "$$,#if 0,g;'\
	's,#[\\t ]*ifndef[\\t ]*" $$2 "$$,#if 1,g;'\
	's,defined(" $$2 "),0,g;"}' >> $@


######################################################################
#
#  Create the header files from the dictionaries.
#

RFC_DICTS := $(filter-out %~,$(wildcard share/dictionary.rfc*)) share/dictionary.vqp share/dictionary.freeradius
HEADERS_RFC := $(patsubst share/dictionary.%,src/include/%.h,$(RFC_DICTS))
HEADERS	+= $(notdir ${HEADERS_RFC})

.PRECIOUS: $(HEADERS_RFC)

src/include/attributes.h: share/dictionary.freeradius.internal
	@$(ECHO) HEADER $@
	@echo "/* AUTO-GENERATED HEADER FILE.  DO NOT EDIT. */" > $@
	@grep ^ATTRIBUTE $<  | awk '{print "PW_"$$2 " " $$3 }' | tr '[:lower:]' '[:upper:]' | tr -- - _ | sed 's/^/#define /' >> $@
	@echo " " >> $@
	@grep -- 'Auth-Type' $< | grep ^VALUE | awk '{print "PW_"$$2 "_" $$3 " " $$4 }' | tr '[:lower:]' '[:upper:]' | tr -- - _ | sed 's/^/#define /' >> $@

src/include/%.h: share/dictionary.% share/dictionary.vqp
	@$(ECHO) HEADER $@
	@echo "/* AUTO-GENERATED HEADER FILE.  DO NOT EDIT. */" > $@
	@grep ^ATTRIBUTE $<  | awk '{print "PW_"$$2 " " $$3 } ' | tr '[:lower:]' '[:upper:]' | tr -- - _ | sed 's/^/#define /' >> $@

#
#  Build features.h by copying over WITH_* and RADIUSD_VERSION_*
#  preprocessor macros from autoconf.h
#  This means we don't need to include autoconf.h in installed headers.
#
#  We use simple patterns here to work with the lowest common
#  denominator's grep (Solaris).
#
src/include/features.h: src/include/features-h src/include/autoconf.h
	@$(ECHO) HEADER $@
	@cp $< $@
	@grep "^#define[ ]*WITH_" src/include/autoconf.h >> $@
	@grep "^#define[ ]*RADIUSD_VERSION" src/include/autoconf.h >> $@
	@echo '#define DOC_ROOT_URL "https://www.freeradius.org/documentation/freeradius-server/" RADIUSD_VERSION_STRING' >> $@
	@echo '#define DOC_KEYWORD_URL(_x) DOC_ROOT_URL "/unlang/" STRINGIFY(_x) ".html"' >> $@
	@echo '#define DOC_KEYWORD_REF(_x) "For more information, please see " DOC_KEYWORD_URL(_x)' >> $@


#
#  Use the SED script we built earlier to make permanent substitutions
#  of definitions in missing-h to build missing.h
#
src/include/missing.h: src/include/missing-h src/include/autoconf.sed
	@$(ECHO) HEADER $@
	@sed -f src/include/autoconf.sed < $< > $@

src/include/tls.h: src/include/tls-h src/include/autoconf.sed
	@$(ECHO) HEADER $@
	@sed -f src/include/autoconf.sed < $< > $@

src/include/radpaths.h: src/include/build-radpaths-h
	@$(ECHO) HEADER $@
	@cd src/include && /bin/sh build-radpaths-h

#
#  Create the soft link for the fake include file path.
#
src/freeradius-devel:
	@[ -e $@ ] || ln -s include $@

#
#  Ensure we set up the build environment
#
BOOTSTRAP_BUILD += src/freeradius-devel $(addprefix src/include/,$(HEADERS_DY)) $(HEADERS_RFC)
scan: $(BOOTSTRAP_BUILD)

######################################################################
#
#  Installation
#
# define the installation directory
SRC_INCLUDE_DIR := ${R}${includedir}/freeradius

$(SRC_INCLUDE_DIR):
	@$(INSTALL) -d -m 755 ${SRC_INCLUDE_DIR}

#
#  install the headers by re-writing the local files
#
#  install-sh function for creating directories gets confused
#  if there's a trailing slash, tries to create a directory
#  it already created, and fails...
#
${SRC_INCLUDE_DIR}/%.h: src/include/%.h | $(SRC_INCLUDE_DIR)
	@echo INSTALL $(notdir $<)
	@$(INSTALL) -d -m 755 `echo $(dir $@) | sed 's/\/$$//'`
# Expression must deal with indentation after the hash and copy it to the substitution string.
# Hash not anchored to allow substitution in function documentation.
	@sed -e 's/#\([\\t ]*\)include <freeradius-devel\/\([^>]*\)>/#\1include <freeradius\/\2>/g' < $< > $@
	@chmod 644 $@

install.src.include: $(addprefix ${SRC_INCLUDE_DIR}/,${HEADERS})
install: install.src.include

#
#  Cleaning
#
.PHONY: clean.src.include distclean.src.include
clean.src.include:
	@rm -f $(addprefix src/include/,$(HEADERS_DY)) $(HEADERS_RFC)

clean: clean.src.include

distclean.src.include: clean.src.include
	@rm -f autoconf.sed

distclean: distclean.src.include
