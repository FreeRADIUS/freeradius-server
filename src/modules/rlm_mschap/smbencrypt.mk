TGT_PREREQS := libfreeradius-radius.a
SOURCES := smbencrypt.c smbdes.c

TGT_LDLIBS := $(LIBS)

TARGET := smbencrypt
