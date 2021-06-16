TARGET := pair_list_perf_test
SOURCES := pair_list_perf_test.c

TGT_INSTALLDIR	:=
TGT_LDLIBS	:= $(LIBS)
TGT_PREREQS	:= libfreeradius-util.la libfreeradius-internal.la $(LIBFREERADIUS_SERVER)
