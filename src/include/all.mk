#
# Makefile
#
# Version:	$Id$
#

HEADERS	= conf.h conffile.h detail.h dhcp.h event.h features.h hash.h heap.h \
	ident.h libradius.h md4.h md5.h missing.h modcall.h modules.h \
	packet.h rad_assert.h radius.h radiusd.h radpaths.h \
	radutmp.h realms.h sha1.h stats.h sysutmp.h token.h \
	udpfromto.h vmps.h vqp.h base64.h

TARGET := src/include/radpaths.h

src/include/radpaths.h: src/include/build-radpaths-h
	cd src/include && /bin/sh build-radpaths-h

#
#  Build dynamic headers by substituting various values from autoconf.h, these
#  get installed with the library files, so external programs can tell what
#  the server library was built with.
#

HEADERS_AC = src/include/missing.h src/include/tls.h
HEADERS_DY = src/include/autoconf.sed src/include/features.h $(HEADERS_AC)

define clean_others
@rm -f $(HEADERS_DY)
endef

TGT_POSTCLEAN := ${clean_others}

all: $(HEADERS_DY)

src/include/features.h:
	@cp src/include/features-h src/include/features.h
	@grep -o "^\#define\s*WITH_.*" src/include/autoconf.h >> src/include/features.h
	
src/include/autoconf.sed:
	@grep ^#define src/include/autoconf.h | sed 's,/\*\*/,1,;' | awk '{print "\
	s,#[[:blank:]]*ifdef[[:blank:]]*" $$2 ",#if "$$3 ",g;\
	s,#[[:blank:]]*ifndef[[:blank:]]*" $$2 ",#if !"$$3 ",g;\
	s,defined(" $$2 ")," $$3 ",g;\
	s," $$2 ","$$3 ",g;"}' > src/include/autoconf.sed

$(HEADERS_AC): src/include/autoconf.sed
	@sed -f src/include/autoconf.sed < `echo $@ | sed 's/\\./-/'` > $@

#
#  Installation
#

# global install depends on the local rule
install: install.src.include

# define the installation directory
SRC_INCLUDE_DIR := ${R}${includedir}/freeradius

# the local rule depends on the installed headers
install.src.include: $(addprefix ${SRC_INCLUDE_DIR}/,${HEADERS})

# the installed headers require a directory
$(addprefix ${SRC_INCLUDE_DIR}/,${HEADERS}): ${SRC_INCLUDE_DIR}/

# make the directory
.PHONY: 
${SRC_INCLUDE_DIR}/:
	$(INSTALL) -d -m 755 $@

# install the headers by re-writing the local files
${SRC_INCLUDE_DIR}/%.h: ${top_srcdir}/src/include/%.h
	@echo INSTALL $(notdir $<)
	@sed 's/^#include <freeradius-devel/#include <freeradius/' < $< > $@
	@chmod 644 $@
