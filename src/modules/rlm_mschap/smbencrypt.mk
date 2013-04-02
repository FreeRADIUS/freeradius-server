TARGET		:= smbencrypt
SOURCES		:= smbencrypt.c smbdes.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_PRLIBS	:= ${LIBS}

SRC_CFLAGS	:= $(OPENSSL_INCLUDE)
TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS)


