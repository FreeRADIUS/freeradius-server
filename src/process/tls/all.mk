TARGETNAME	:= process_tls

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c
TGT_PREREQS	:= libfreeradius-tls$(L)
