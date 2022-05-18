TARGET		:= smbencrypt$(E)
SOURCES		:= smbencrypt.c smbdes.c

TGT_PREREQS	:= libfreeradius-util$(L)

SRC_CFLAGS	:=
TGT_LDLIBS	:= $(LIBS)


