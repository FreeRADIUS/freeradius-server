TARGET		:= dhcpclient
SOURCES		:= dhcpclient.c

TGT_PREREQS	:= libfreeradius-dhcpv4.a
TGT_LDLIBS	:= $(LIBS)
