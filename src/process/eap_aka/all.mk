TARGETNAME	:= process_eap_aka

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-eap-aka-sim$(L)

