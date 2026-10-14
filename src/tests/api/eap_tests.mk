TARGET		:= eap_tests
SOURCES		:= eap_tests.c ${top_srcdir}/src/modules/rlm_eap/libeap/eapcommon.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
TGT_INSTALLDIR	:=

SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/libeap
