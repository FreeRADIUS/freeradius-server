#######################################################################
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
.SUFFIXES: .lo .o .so .a

#######################################################################
#
# define static and dynamic objects for the libraries
#
#######################################################################
STATIC_OBJS	= $(SRCS:.c=.o)
DYNAMIC_OBJS	= $(SRCS:.c=.lo)

#######################################################################
#
# define new rules
#
#######################################################################
%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.lo : %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

CFLAGS		+= -I../../include

ifneq ($(TARGET),)
#######################################################################
#
# Define a number of new targets
#
#######################################################################
$(TARGET).a: $(STATIC_OBJS)
	$(AR) crv $@ $^

$(TARGET).so: $(DYNAMIC_OBJS)
	$(CC) $(CFLAGS) $(LIBS) -shared $^ -o $@

#######################################################################
#
#  Generic targets so we can sweep through all modules
# without knowing what their names are.
#
#  These rules also allow us to copy the '.a' or '.so' up
# a level, to the 'src/modules' directory, for general consumption.
#
#######################################################################
static: $(TARGET).a
	@cp $< ../lib

dynamic: $(TARGET).so
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
	@rm -f *.a *.o *.lo *.so *~

reallyclean: clean
	@rm -f config.h config.mak
