TARGET		:= radsnmp
SOURCES		:= radsnmp.c

TGT_PREREQS	:= libfreeradius-util.a

TGT_LDLIBS	:= $(LIBS)
