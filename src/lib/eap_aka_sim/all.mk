ifneq "$(OPENSSL_LIBS)" ""
TARGET := libfreeradius-eap-aka-sim$(L)
endif
TGT_CATEGORY	:= lib-util

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

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL) $(LIBFREERADIUS_SERVER) libfreeradius-eap$(L) libfreeradius-sim$(L)
