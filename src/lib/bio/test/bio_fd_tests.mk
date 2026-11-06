TARGET		:= bio_fd_tests$(E)
SOURCES		:= bio_fd_tests.c

TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS	:= libfreeradius-bio$(L) libfreeradius-bio-config$(L) $(LIBFREERADIUS_UTIL) $(LIBFREERADIUS_SERVER)

TGT_INSTALLDIR	:=
