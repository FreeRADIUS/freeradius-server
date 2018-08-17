TARGET		:= unit_test_attribute
SOURCES		:= unit_test_attribute.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-tacacs.a libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)
