TARGET		:= dhcpclient
SOURCES		:= dhcpclient.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-dhcpv4.a
TGT_LDLIBS	:= $(LIBS)
