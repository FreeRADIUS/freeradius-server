TARGET      	:= pair_nested_tests$(E)
SOURCES    	:= pair_nested_tests.c

SRC_CFLAGS	:= -DTEST_NESTED_PAIRS
TGT_LDLIBS  	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS 	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS 	:= libfreeradius-util$(L) libfreeradius-radius$(L)

TGT_INSTALLDIR	:=
