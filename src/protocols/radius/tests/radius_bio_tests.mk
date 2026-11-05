TARGET		:= radius_bio_tests$(E)
SOURCES		:= radius_bio_tests.c

TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS	:= libfreeradius-radius-bio$(L) libfreeradius-radius$(L) libfreeradius-bio$(L) $(LIBFREERADIUS_UTIL)

TGT_INSTALLDIR	:=
