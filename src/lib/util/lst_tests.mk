TARGET		:= lst_tests

SOURCES		:= lst_tests.c

TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)

TGT_PREREQS	+= libfreeradius-util.a
