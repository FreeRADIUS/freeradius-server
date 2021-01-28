TARGET      := pair_tests
SOURCES     := pair_tests.c

TGT_PREREQS += libfreeradius-radius.a libfreeradius-util.a

TGT_LDLIBS  := $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS := $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
