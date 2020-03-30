TARGETNAME	:= libfreeradius-curl

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= base.c io.c

SRC_CFLAGS	:= -isystem /usr/local/Cellar/curl/7.69.1/include
TGT_LDLIBS	:= -L/usr/local/Cellar/curl/7.69.1/lib -lcurl -lldap -lz

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a
