ifneq "$(OPENSSL_LIBS)" ""
TARGET      := rlm_eap_pwd.a
else
TARGET      :=
endif

SOURCES     := rlm_eap_pwd.c eap_pwd.c
HEADERS     = eap_pwd.h rlm_eap_pwd.h

SRC_INCDIRS := ../.. ../../libeap
