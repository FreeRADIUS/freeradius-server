TARGETNAME	:= rlm_otp

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c otp_radstate.c otp_pwe.c otp_pw_valid.c
SOURCES		+= otp_util.c otp_mppe.c

TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS)
