TARGETNAME	:= process_tls

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= base.c
TGT_PREREQS	:= libfreeradius-tls.a
