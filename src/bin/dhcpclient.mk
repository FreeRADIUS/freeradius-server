TARGET		:= dhcpclient$(E)
SOURCES		:= dhcpclient.c

TGT_PREREQS	:= libfreeradius-dhcpv4$(L)
TGT_LDLIBS	:= $(LIBS)
