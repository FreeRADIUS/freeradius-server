TARGETNAME	:= process_eap_sim

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-eap-aka-sim.a

