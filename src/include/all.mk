#
# Makefile
#
# Version:	$Id$
#

HEADERS	= autoconf.h conf.h conffile.h detail.h dhcp.h event.h hash.h heap.h \
	ident.h libradius.h md4.h md5.h missing.h modcall.h modules.h \
	packet.h rad_assert.h radius.h radiusd.h radpaths.h \
	radutmp.h realms.h sha1.h stats.h sysutmp.h token.h \
	udpfromto.h vmps.h vqp.h

# Our target
TARGET	:= src/include/radpaths.h

src/include/radpaths.h: src/include/build-radpaths-h
	cd src/include && /bin/sh build-radpaths-h

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
	@sed 's/^#include <freeradius-devel/#include <freeradius/' < $^ > $@
	@chmod 644 $@
