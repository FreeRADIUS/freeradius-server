TARGET      	:= pair_server_tests$(E)
SOURCES     	:= pair_server_tests.c

TGT_LDLIBS  	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS 	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS 	:= $(LIBFREERADIUS_UTIL) libfreeradius-radius$(L) $(LIBFREERADIUS_SERVER)

TGT_INSTALLDIR	:=
