TARGETNAME	:= process_eap_psk

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c crypto.c

TGT_PREREQS	:= libfreeradius-eap$(L)

SUBMAKEFILES	:= eap_psk_tests.mk
