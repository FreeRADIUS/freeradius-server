TARGET		:= dhcpclient$(E)
SOURCES		:= dhcpclient.c \
		   ${top_srcdir}/src/lib/server/packet.c

TGT_PREREQS	:= libfreeradius-dhcpv4$(L)
TGT_LDLIBS	:= $(LIBS)
