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

HEADERS_DY	:= attributes.h features.h missing.h radpaths.h

HEADERS	= \
	build.h \
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
    share/dictionary.dhcpv4 \
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
	${Q}echo "#pragma once" >> $@
	${Q}grep ^ATTRIBUTE $<  | awk '{print "FR_"$$2 " " $$3 }' | ${NORMALIZE}  >> $@
	${Q}echo " " >> $@
	${Q}grep -- 'Auth-Type' $< | grep ^VALUE | awk '{print "FR_"$$2 "_" $$3 " " $$4 }' | ${NORMALIZE}  >> $@

src/include/%.h: share/dictionary.% share/dictionary.vqp share/dictionary.freeradius.snmp
	${Q}$(ECHO) HEADER $@
	${Q}echo ${HEADER} > $@
	${Q}echo "#pragma once" >> $@
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
	${Q}echo "#pragma once" > $@
	${Q}cat $< >> $@
	${Q}grep "^#define[ ]*WITH_" src/include/autoconf.h >> $@
	${Q}grep "^#define[ ]*RADIUSD_VERSION" src/include/autoconf.h >> $@
#
#  Use the SED script we built earlier to make permanent substitutions
#  of definitions in missing-h to build missing.h
#
src/include/missing.h: src/include/missing-h src/include/autoconf.sed
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
	@echo LN-SF src/include src/freeradius-devel

#
#  Ensure we set up the build environment
#
BOOTSTRAP_BUILD += src/freeradius-devel $(addprefix src/include/,$(HEADERS_DY)) $(HEADERS_RFC)
scan: $(BOOTSTRAP_BUILD)

#
#  Regenerate the headers if we re-run autoconf.
#  This is to that changes to the build rules (e.g. PW_FOO -> FR_FOO)
#  result in the headers being rebuilt.
#
$(BOOTSTRAP_BUILD): src/include/autoconf.h

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
