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
	$(LIBTOOL) --mode=link $(LD) -static $(CFLAGS) $(RLM_CFLAGS) $(RLM_LIBS) $^ -o $@ 

$(TARGET).la: $(DYNAMIC_OBJS)
	$(LIBTOOL) --mode=link $(CC) -export-dynamic $(CFLAGS) \
	$(RLM_CFLAGS) -o $@ -module -rpath $(libdir) $^ $(RLM_LIBS) && \
	rm -f $(TARGET).so && ln -s .libs/$(TARGET).so $(TARGET).so 

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
	@cp $< ../lib
	@[ "$RLM_LIBS" != "" ] && \
		echo -n $(RLM_LIBS) " " >> ../lib/STATIC_MODULE_LDFLAGS
	@[ "$LDFLAGS" != "" ] && \
		echo -n $(LDFLAGS) " " >> ../lib/STATIC_MODULE_LDFLAGS

dynamic: $(TARGET).la
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
	@rm -f *.a *.o *.lo *.so *.la *~
	rm -rf .libs _libs

reallyclean: clean
	@rm -f config.h config.mak
