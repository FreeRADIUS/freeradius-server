ifneq "$(OPENSSL_LIBS)" ""
TARGET := libfreeradius-eap-sim.a
endif

SOURCES	:= \
	base.c \
	comp128.c \
	crypto.c \
	decode.c \
	encode.c \
	fips186prf.c \
	id.c \
	vector.c \
	xlat.c

SRC_INCDIRS	:= . ${top_srcdir}/src/modules/rlm_eap/lib/base ${top_srcdir}/src/modules/rlm_eap/
