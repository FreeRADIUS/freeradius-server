TARGET := pair_list_perf_test
SOURCES := pair_list_perf_test.c

TGT_INSTALLDIR	:=
TGT_LDLIBS	:= $(LIBS)
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a
