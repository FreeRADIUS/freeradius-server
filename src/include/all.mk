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

HEADERS_DY	:= attributes.h features.h missing.h radpaths.h tls.h
SUBDIRS		:= util

HEADERS	= \
	build.h \
	conf.h \
	event.h \
	hash.h \
	heap.h \
	libradius.h \
	md4.h \
	md5.h \
	modules.h \
	packet.h \
	rad_assert.h \
	radius.h \
	radiusd.h \
	radutmp.h \
	realms.h \
	sha1.h \
	stats.h \
	sysutmp.h \
	token.h \
	udpfromto.h \
	base64.h \
	map.h \
	udp.h \
	tcp.h \
	threads.h \
	regex.h \
	inet.h \
	dict.h \
	pair.h \
	proto.h \
	$(HEADERS_DY)

#
#  Solaris awk doesn't recognise [[:blank:]] hence [\t ]
#
src/include/autoconf.sed: src/include/autoconf.h
	${Q}grep ^#define $< | sed 's,/\*\*/,1,;' | awk '{print "'\
	's,#[\\t ]*ifdef[\\t ]*" $$2 "$$,#if "$$3 ",g;'\
	's,#[\\t ]*ifndef[\\t ]*" $$2 "$$,#if !"$$3 ",g;'\
	's,defined(" $$2 ")," $$3 ",g;"}' > $@
	${Q}grep -o '#undef [^ ]*' $< | sed 's,/#undef /,,;' | awk '{print "'\
	's,#[\\t ]*ifdef[\\t ]*" $$2 "$$,#if 0,g;'\
	's,#[\\t ]*ifndef[\\t ]*" $$2 "$$,#if 1,g;'\
	's,defined(" $$2 "),0,g;"}' >> $@


######################################################################
#
#  Create the header files from the dictionaries.
#

RFC_DICTS := $(filter-out %~,$(wildcard share/dictionary.rfc*)) \
    share/dictionary.vqp share/dictionary.freeradius \
    share/dictionary.freeradius.snmp \
    share/dictionary.dhcpv6 \
    share/dictionary.eap.aka \
    share/dictionary.eap.sim \
    share/dictionary.tacacs

HEADERS_RFC := $(patsubst share/dictionary.%,src/include/%.h,$(RFC_DICTS))
HEADERS	+= $(notdir ${HEADERS_RFC})

.PRECIOUS: $(HEADERS_RFC)

NORMALIZE	:= tr -- '[:lower:]/.-' '[:upper:]___' | sed 's/^/\#define /;s/241_//;'
HEADER		:= "/* AUTO_GENERATED FILE.  DO NOT EDIT */"

src/include/attributes.h: share/dictionary.freeradius.internal
	${Q}$(ECHO) HEADER $@
	${Q}echo ${HEADER} > $@
	${Q}grep ^ATTRIBUTE $<  | awk '{print "FR_"$$2 " " $$3 }' | ${NORMALIZE}  >> $@
	${Q}echo " " >> $@
	${Q}grep -- 'Auth-Type' $< | grep ^VALUE | awk '{print "FR_"$$2 "_" $$3 " " $$4 }' | ${NORMALIZE}  >> $@

src/include/%.h: share/dictionary.% share/dictionary.vqp share/dictionary.freeradius.snmp
	${Q}$(ECHO) HEADER $@
	${Q}echo ${HEADER} > $@
	${Q}grep ^ATTRIBUTE $<  | awk '{print "FR_"$$2 " " $$3 }' | ${NORMALIZE} >> $@
	${Q}grep ^VALUE $<  | awk '{print "FR_"$$2"_VALUE_"$$3 " " $$4 }' | ${NORMALIZE} >> $@

#
#  Build features.h by copying over WITH_* and RADIUSD_VERSION_*
#  preprocessor macros from autoconf.h
#  This means we don't need to include autoconf.h in installed headers.
#
#  We use simple patterns here to work with the lowest common
#  denominator's grep (Solaris).
#
src/include/features.h: src/include/features-h src/include/autoconf.h
	${Q}$(ECHO) HEADER $@
	${Q}echo "#ifndef _FR_FEATURES_H" > $@
	${Q}echo "#define _FR_FEATURES_H" >> $@
	${Q}cat $< >> $@
	${Q}grep "^#define[ ]*WITH_" src/include/autoconf.h >> $@
	${Q}grep "^#define[ ]*RADIUSD_VERSION" src/include/autoconf.h >> $@
	${Q}echo "#endif /* _FR_FEATURES_H */" >> $@
#
#  Use the SED script we built earlier to make permanent substitutions
#  of definitions in missing-h to build missing.h
#
src/include/missing.h: src/include/missing-h src/include/autoconf.sed
	${Q}$(ECHO) HEADER $@
	${Q}sed -f src/include/autoconf.sed < $< > $@

src/include/tls.h: src/include/tls-h src/include/autoconf.sed
	${Q}$(ECHO) HEADER $@
	${Q}sed -f src/include/autoconf.sed < $< > $@

src/include/radpaths.h: src/include/build-radpaths-h
	${Q}$(ECHO) HEADER $@
	${Q}cd src/include && /bin/sh build-radpaths-h

#
#  Create the soft link for the fake include file paths.
#
src/freeradius-devel:
	${Q}[ -e $@ ] || ln -s include $@
	@echo LN-SF src/util src/include

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
	${Q}$(INSTALL) -d -m 755 ${SRC_INCLUDE_DIR}

#
#  install the headers by re-writing the local files
#
#  install-sh function for creating directories gets confused
#  if there's a trailing slash, tries to create a directory
#  it already created, and fails...
#
${SRC_INCLUDE_DIR}/%.h: src/include/%.h | $(SRC_INCLUDE_DIR)
	${Q}echo INSTALL $(notdir $<)
	${Q}$(INSTALL) -d -m 755 `echo $(dir $@) | sed 's/\/$$//'`
# Expression must deal with indentation after the hash and copy it to the substitution string.
# Hash not anchored to allow substitution in function documentation.
	${Q}sed -e 's/#\([\\t ]*\)include <freeradius-devel\/\([^>]*\)>/#\1include <freeradius\/\2>/g' < $< > $@
	${Q}chmod 644 $@

#
#  Regenerate the headers if we re-run autoconf.
#  This is to that changes to the build rules (e.g. PW_FOO -> FR_FOO)
#  result in the headers being rebuilt.
#
$(BOOTSTRAP_BUILD): src/include/autoconf.h

install.src.include: $(addprefix ${SRC_INCLUDE_DIR}/,${HEADERS})
install: install.src.include

#
#  Cleaning
#
.PHONY: clean.src.include distclean.src.include
clean.src.include:
	${Q}rm -f $(addprefix src/include/,$(HEADERS_DY)) $(HEADERS_RFC)

clean: clean.src.include

distclean.src.include: clean.src.include
	${Q}rm -f autoconf.sed

distclean: distclean.src.include
