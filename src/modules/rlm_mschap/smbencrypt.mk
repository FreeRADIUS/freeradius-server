TARGET		:= smbencrypt$(E)
SOURCES		:= smbencrypt.c smbdes.c

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL)

SRC_CFLAGS	:=
TGT_LDLIBS	:= $(LIBS)


