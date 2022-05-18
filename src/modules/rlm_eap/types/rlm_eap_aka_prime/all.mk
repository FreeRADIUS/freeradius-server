TARGETNAME	:= rlm_eap_aka_prime

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-eap$(L) libfreeradius-sim$(L) libfreeradius-eap-aka-sim$(L)
