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

include ../../../Make.inc

all: static dynamic

#######################################################################
#
#  definitions for new dependencies on suffixes
#
#######################################################################
.SUFFIXES: .lo .o .la .a

#######################################################################
#
# define static and dynamic objects for the libraries,
# along with a number of other useful definitions.
#
#######################################################################
STATIC_OBJS	= $(SRCS:.c=.o)
DYNAMIC_OBJS	= $(SRCS:.c=.lo)
CFLAGS		+= -I../../include

#######################################################################
#
# Ensure that the modules get re-built if the server header files
# change.
#
#######################################################################
SERVER_HEADERS	= ../../include/radiusd.h ../../include/radius.h ../../include/modules.h
$(STATIC_OBJS):  $(SERVER_HEADERS)
$(DYNAMIC_OBJS): $(SERVER_HEADERS)

#######################################################################
#
# define new rules
#
#######################################################################
%.o : %.c
	$(CC) $(CFLAGS) $(RLM_CFLAGS) -c $< -o $@

%.lo : %.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) $(RLM_CFLAGS) -c $<

ifneq ($(TARGET),)
#######################################################################
#
# Define a number of new targets
#
#######################################################################
$(TARGET).a: $(STATIC_OBJS)
	$(LIBTOOL) --mode=link $(LD) -module -static $(CFLAGS) $(RLM_CFLAGS) $^ -o $@ 

#
#  If the module is in the list of static modules, then the "dynamic"
#  library is built statically, so that the '.la' file contains the
#  libraries that the module depends on.
#
#  Yes, this is a horrible hack.
#
ifeq ($(findstring $(TARGET),$(STATIC_MODULES)),)
LINK_MODE=-export-dynamic
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

$(TARGET).la: $(DYNAMIC_OBJS)
	$(LIBTOOL) --mode=link $(CC) -module $(LINK_MODE) $(CFLAGS) \
	$(RLM_CFLAGS) -o $@ -rpath $(libdir) $^ $(RLM_LIBS) $(LIBS)

#######################################################################
#
#  Generic targets so we can sweep through all modules
# without knowing what their names are.
#
#  These rules also allow us to copy the '.a' or '.la' up
# a level, to the 'src/modules' directory, for general consumption.
#
#######################################################################
static: $(TARGET).a
	@[ "x$(RLM_SUBDIRS)" = "x" ] || $(MAKE) $(MFLAGS) WHAT_TO_MAKE=static common
	@cp $< ../lib

dynamic: $(TARGET).la
	@[ "x$(RLM_SUBDIRS)" = "x" ] || $(MAKE) $(MFLAGS) WHAT_TO_MAKE=dynamic common
	@cp $< ../lib

#######################################################################
#
#  It's a dummy target: don't build it
#
#######################################################################
else
static:

dynamic:

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
	@rm -f config.cache config.log config.status
	@[ "x$(RLM_SUBDIRS)" = "x" ] || $(MAKE) $(MFLAGS) WHAT_TO_MAKE=clean common

distclean: clean
	@rm -f config.h config.mak
	@test -f Makefile.in && rm -f Makefile

reconfig:
	@[ "x$(AUTOCONF)" != "x" ] && [ -f ./configure.in ] && $(AUTOCONF) -l ../../..

#
#  Do any module-specific installation.
#
#  If there isn't a TARGET defined, then don't do anything.
#  Otherwise, install the libraries into $(libdir)
#
install:
	[ "x$(TARGET)" = "x" ] || $(LIBTOOL) --mode=install $(INSTALL) -c $(TARGET).la $(R)$(libdir)/$(TARGET).la
	@[ "x$(RLM_INSTALL)" = "x" ] || $(MAKE) $(MFLAGS) $(RLM_INSTALL)
