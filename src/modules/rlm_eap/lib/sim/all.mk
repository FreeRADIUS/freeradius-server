ifneq "$(OPENSSL_LIBS)" ""
TARGET := libfreeradius-eap-sim.a
endif

SOURCES	:= \
	comp128.c \
	crypto.c \
	fips186prf.c \
	id.c \
	sim_proto.c \
	vector.c \
	xlat.c

SRC_INCDIRS	:= . ${top_srcdir}/src/modules/rlm_eap/lib/base ${top_srcdir}/src/modules/rlm_eap/
