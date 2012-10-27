#######################################################################
#
# $Id$
#
#  Each module should have a few common defines at the TOP of the
# Makefile, and the 'include ../rules.mak'
#
# e.g.
#
##########################
# TARGET = rlm_foo
# SRCS   = rlm_foo.c other.c
#
# include ../rules.mak
#
# CFLAGS += my_c_flags
##########################
#
# and everything will be automagically built
#
#######################################################################

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
LT_OBJS		= $(SRCS:.c=.lo)
CFLAGS		+= -I../.. -I$(top_builddir)/src/

#######################################################################
#
# Ensure that the modules get re-built if the server header files
# change.
#
#######################################################################
SERVER_HEADERS	= ../../rlm_sql.h
$(LT_OBJS):  $(SERVER_HEADERS)

#######################################################################
#
# define new rules
#
#######################################################################
%.lo: %.c
	@echo CC $<@
	@$(LIBTOOL) --quiet --mode=compile $(CC) $(CFLAGS) $(RLM_SQL_CFLAGS) -c $<

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
LINK_MODE=-export-dynamic -rpath ${libdir} -rdynamic
else
LINK_MODE=-static
endif

#
#  Also, if we're NOT using shared libraries, then force the
#  link mode to static.
#
ifneq ($(USE_SHARED_LIBS),yes)
LINK_MODE=-static
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
build-module: $(TARGET).la
	@for x in .libs/* $^; do \
		rm -f $(top_builddir)/src/modules/lib/$$x; \
		ln -s $(top_builddir)/src/modules/rlm_sql/drivers/$(TARGET)/$$x $(top_builddir)/src/modules/lib/$$x; \
	done

$(TARGET).la: $(LT_OBJS)
	@echo LINK $@ $^
	@$(LIBTOOL) --mode=link $(CC) -release $(RADIUSD_VERSION) \
	    $(LINK_MODE) $(LDFLAGS) $(RLM_SQL_LDFLAGS) $(RLM_MOD) -o $@ \
	    -rpath $(libdir) $^ $(RLM_SQL_LIBS)

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
	@rm -f config.log config.status config.cache

distclean: clean
	@rm -f config.h config.mak

reconfig:
	@if [ -f configure.in ]; then \
		[ "x$(AUTOCONF)" != "x" ] && $(AUTOCONF) -I $(top_builddir); \
	fi
	@if [ -f config.h.in ]; then \
		[ "x$(AUTOHEADER)" != "x" ] && $(AUTOHEADER); \
	fi

#
#  Do any module-specific installation.
#
#  If there isn't a TARGET defined, then don't do anything.
#  Otherwise, install the libraries into $(libdir)
#
install:
	if [ "x$(TARGET)" != "x" ]; then \
	    $(LIBTOOL) --mode=install $(INSTALL) -c \
		-rpath $(libdir) $(TARGET).la $(R)$(libdir)/$(TARGET).la || exit $$?; \
	    rm -f $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la; \
	    ln -s $(TARGET).la $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la || exit $$?; \
	fi
