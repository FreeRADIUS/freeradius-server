TARGET		:= unit_test_attribute
SOURCES		:= unit_test_attribute.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-dhcp.a libfreeradius-tacacs.a libfreeradius-server.a
TGT_LDLIBS	:= $(LIBS)
