TARGET		:= smbencrypt
SOURCES		:= smbencrypt.c smbdes.c

TGT_PREREQS	:= libfreeradius-radius.a

SRC_CFLAGS	:=
TGT_LDLIBS	:= $(LIBS)

