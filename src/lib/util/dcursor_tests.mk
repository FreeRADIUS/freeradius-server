TARGET		:= dcursor_tests

SOURCES		:= dcursor_tests.c

# The cursor tests use manually created pairs rather than talloced ones
# hence this option to prevent them aborting.
SRC_CFLAGS	:= -DTALLOC_GET_TYPE_ABORT_NOOP
TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)

TGT_PREREQS	+= libfreeradius-util.a
