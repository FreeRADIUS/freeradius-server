TARGET		:= sbuff_tests

SOURCES		:= sbuff_tests.c

TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)

TGT_PREREQS	+= libfreeradius-util.a
