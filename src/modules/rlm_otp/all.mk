# TARGET should be set by autoconf only.  Don't touch it.
# The SOURCES definition should list ALL source files.
TARGET         =
SOURCES           = otp_rlm.c otp_radstate.c otp_pwe.c otp_pw_valid.c
SOURCES          += otp_util.c otp_mppe.c
TGT_LDLIBS       =  $(OPENSSL_LIBS)

