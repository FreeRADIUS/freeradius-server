TARGET		:= radsnmp
SOURCES		:= radsnmp.c

TGT_PREREQS	:= libfreeradius-radius.a

TGT_LDLIBS	:= $(LIBS)
