TARGET := libfreeradius-eap-aka-sim.a


SOURCES	:= \
	base.c \
	state_machine.c \
	crypto.c \
	decode.c \
	encode.c \
	fips186prf.c \
	id.c \
	vector.c \
	xlat.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-eap.a libfreeradius-util.a libfreeradius-sim.a
