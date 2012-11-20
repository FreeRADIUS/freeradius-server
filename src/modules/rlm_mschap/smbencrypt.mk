TARGET		:= smbencrypt
SOURCES		:= smbencrypt.c smbdes.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_PRLIBS	:= ${LIBS}

TGT_LDLIBS	:= $(LIBS)


