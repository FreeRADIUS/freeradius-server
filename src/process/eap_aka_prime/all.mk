TARGETNAME	:= process_eap_aka_prime

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-eap-aka-sim.a

