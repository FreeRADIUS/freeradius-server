TARGETNAME	:= rlm_eap_aka

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-radius.a libfreeradius-util.a libfreeradius-eap.a libfreeradius-sim.a libfreeradius-eap-aka-sim.a
