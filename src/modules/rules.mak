#######################################################################
#
# $Id$
#
#  Each module should have a few common defines at the TOP of the
# Makefile, and the 'include ../rules.mak'
#
# e.g.
#
############################
# TARGET = rlm_foo
# SRCS   = rlm_foo.c other.c
#
# include ../rules.mak
#
# RLM_CFLAGS = my_cflags
# RLM_LDLAGS = my_ldflags
############################
#
# and everything will be automagically built
#
#######################################################################

include $(RLM_DIR)../../../Make.inc

.PHONY: all build-module clean distclean install reconfig

all: build-module

#######################################################################
#
#  definitions for new dependencies on suffixes
#
#######################################################################
.SUFFIXES: .lo .o .la .a

#######################################################################
#
# define libtool objects for the libraries,
# along with a number of other useful definitions.
#
#######################################################################
LT_OBJS		+= $(SRCS:.c=.lo)
LT_OBJS		+= $(SRCS:.cpp=.lo)
CFLAGS		+= -I$(top_builddir)/src -I$(top_builddir)/libltdl

#######################################################################
#
# Ensure that the modules get re-built if the server header files
# change.
#
#######################################################################
SERVER_HEADERS	= $(top_builddir)/src/include/radius.h  \
		  $(top_builddir)/src/include/radiusd.h \
		  $(top_builddir)/src/include/modules.h \
		  $(top_builddir)/src/include/libradius.h

$(LT_OBJS): $(SERVER_HEADERS)

#######################################################################
#
# define new rules
#
#######################################################################
%.lo: %.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) $(RLM_CFLAGS) -c $<

%.lo: %.cpp
	$(LIBTOOL) --mode=compile $(CXX) $(CFLAGS) $(RLM_CFLAGS) -c $<

ifneq ($(TARGET),)
#######################################################################
#
# Define a number of new targets
#
#######################################################################

#
#  If the module is in the list of static modules, then the "dynamic"
#  library is built statically, so that the '.la' file contains the
#  libraries that the module depends on.
#
#  Yes, this is a horrible hack.
#
ifeq ($(findstring $(TARGET),$(STATIC_MODULES)),)
LINK_MODE = -export-dynamic
else
LINK_MODE = -static
endif

#
#  Also, if we're NOT using shared libraries, then force the
#  link mode to static.
#
ifneq ($(USE_SHARED_LIBS),yes)
LINK_MODE = -static
endif

#######################################################################
#
#  Generic targets so we can sweep through all modules
# without knowing what their names are.
#
#  These rules also allow us to copy the '.a' or '.la' up
# a level, to the 'src/modules' directory, for general consumption.
#
#######################################################################

build-module: $(TARGET).la $(RLM_UTILS)
	@[ "x$(RLM_SUBDIRS)" = "x" ] || $(MAKE) $(MFLAGS) WHAT_TO_MAKE=all common
	@[ -d $(top_builddir)/src/modules/lib/.libs ] || mkdir $(top_builddir)/src/modules/lib/.libs
	for x in .libs/* $^; do \
		rm -rf $(top_builddir)/src/modules/lib/$$x; \
		ln -s $(PWD)/$(TARGET)/$$x $(top_builddir)/src/modules/lib/$$x; \
	done

$(TARGET).la: $(LT_OBJS)
	$(LIBTOOL) --mode=link $(CC) -release $(RADIUSD_VERSION) \
	-module $(LINK_MODE) $(LDFLAGS) $(RLM_LDFLAGS) -o $@     \
	-rpath $(libdir) $^ $(LIBRADIUS) $(RLM_LIBS) $(LIBS)

#######################################################################
#
#  It's a dummy target: don't build it
#
#######################################################################
else
build-module:

# if $(TARGET) == ""
endif

#######################################################################
#
#  clean and install rules
#
#######################################################################
clean:
	@rm -f *.a *.o *.lo *.la *~
	@rm -rf .libs _libs
	@rm -f config.cache config.log config.status $(RLM_UTILS)
	@[ "x$(RLM_SUBDIRS)" = "x" ] || $(MAKE) $(MFLAGS) WHAT_TO_MAKE=clean common

distclean: clean
	@rm -f config.h config.mak
	@test -f Makefile.in && rm -f Makefile

reconfig:
	@if [ -f configure.in ]; then \
		[ "x$(AUTOCONF)" != "x" ] && $(AUTOCONF) -I $(top_builddir); \
	fi
	@[ "x$(AUTOHEADER)" != "x" ] && [ -f ./configure.in ] && \
	if grep AC_CONFIG_HEADERS configure.in >/dev/null; then\
		$(AUTOHEADER);\
	fi

#
#  Do any module-specific installation.
#
#  If there isn't a TARGET defined, then don't do anything.
#  Otherwise, install the libraries into $(libdir)
#
install:
	@[ "x$(RLM_INSTALL)" = "x" ] || $(MAKE) $(MFLAGS) $(RLM_INSTALL)
	if [ "x$(TARGET)" != "x" ]; then \
	    $(LIBTOOL) --mode=install $(INSTALL) -c \
		$(TARGET).la $(R)$(libdir)/$(TARGET).la || exit $$?; \
	    rm -f $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la; \
	    ln -s $(TARGET).la $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la || exit $$?; \
	fi
