TARGET      	:= pair_tests$(E)
SOURCES    	:= pair_tests.c

TGT_LDLIBS  	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS 	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS 	:= $(LIBFREERADIUS_UTIL) libfreeradius-radius$(L)

TGT_INSTALLDIR	:=
