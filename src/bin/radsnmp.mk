TARGET		:= radsnmp
SOURCES		:= radsnmp.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a

TGT_LDLIBS	:= $(LIBS)
