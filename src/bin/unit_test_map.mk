TARGET		:= unit_test_map
SOURCES		:= unit_test_map.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)
