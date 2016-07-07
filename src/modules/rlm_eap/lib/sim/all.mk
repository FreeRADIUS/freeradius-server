ifneq "$(OPENSSL_LIBS)" ""
TARGET := libfreeradius-eap-sim.a
endif

SOURCES	:= \
	comp128.c \
	crypto.c \
	fips186prf.c \
	sim_proto.c \
	vector.c

SRC_INCDIRS	:= . ${top_srcdir}/src/modules/rlm_eap/lib/base ${top_srcdir}/src/modules/rlm_eap/
