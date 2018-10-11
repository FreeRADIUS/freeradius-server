TARGET		:= radsnmp
SOURCES		:= radsnmp.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-io.a

TGT_LDLIBS	:= $(LIBS)
