TARGET		:= smbencrypt
SOURCES		:= smbencrypt.c smbdes.c

TGT_PREREQS	:= libfreeradius-util.a

SRC_CFLAGS	:=
TGT_LDLIBS	:= $(LIBS)


