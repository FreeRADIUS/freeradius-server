TARGET      := pair_legacy_tests$(E)
SOURCES     := pair_legacy_tests.c

TGT_LDLIBS  := $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS := $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS := libfreeradius-util$(L) libfreeradius-radius$(L)
