TARGET		:= radattr
SOURCES		:= radattr.c

ifneq "$(WITH_DHCP)" "no"
TGT_PREREQS	:= libfreeradius-dhcp.a
endif

TGT_PREREQS	+= libfreeradius-server.a libfreeradius-radius.a

TGT_LDLIBS	:= $(LIBS)
