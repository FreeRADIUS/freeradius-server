TARGET      := pair_tests
SOURCES     := pair_tests.c

TGT_PREREQS += libfreeradius-util.la libfreeradius-radius.a

TGT_LDLIBS  := $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS := $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
