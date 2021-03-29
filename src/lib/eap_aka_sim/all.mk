ifneq "$(OPENSSL_LIBS)" ""
TARGET := libfreeradius-eap-aka-sim.a
endif

SOURCES	:= \
	base.c \
	crypto.c \
	decode.c \
	encode.c \
	fips186prf.c \
	id.c \
	module.c \
	state_machine.c \
	vector.c \
	xlat.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-eap.a libfreeradius-util.a libfreeradius-sim.a
