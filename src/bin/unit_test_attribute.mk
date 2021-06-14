TARGET		:= unit_test_attribute
SOURCES		:= unit_test_attribute.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)
