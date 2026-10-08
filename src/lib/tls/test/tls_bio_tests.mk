TARGET		:= tls_bio_tests$(E)
SOURCES		:= tls_bio_tests.c

#
#  libfreeradius-tls reaches into the server library for cf_log() and the
#  configuration parser, so the test links what the library needs rather than
#  only what the test calls.
#
TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(OPENSSL_FLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS	:= libfreeradius-tls$(L) $(LIBFREERADIUS_SERVER) $(LIBFREERADIUS_UTIL)

TGT_INSTALLDIR	:=
