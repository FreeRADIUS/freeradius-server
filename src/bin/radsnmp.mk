TARGET		:= radsnmp$(E)
SOURCES		:= radsnmp.c

TGT_PREREQS	:= libfreeradius-radius$(L)
TGT_LDLIBS	:= $(LIBS)
