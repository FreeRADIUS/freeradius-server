TARGETNAME	:= rlm_eap_sim

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-eap.a libfreeradius-sim.a libfreeradius-eap-aka-sim.a
