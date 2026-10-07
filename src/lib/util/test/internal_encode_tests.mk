TARGET      	:= internal_encode_tests$(E)
SOURCES    	:= internal_encode_tests.c

TGT_LDLIBS  	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS 	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS 	:= $(LIBFREERADIUS_UTIL) libfreeradius-internal$(L)

TGT_INSTALLDIR	:=
