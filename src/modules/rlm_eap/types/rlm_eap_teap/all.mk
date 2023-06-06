TARGETNAME	:= rlm_eap_teap

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c eap_teap.c eap_teap_crypto.c

SRC_INCDIRS	:= ../../ ../../libeap/
TGT_PREREQS	:= libfreeradius-eap.a
