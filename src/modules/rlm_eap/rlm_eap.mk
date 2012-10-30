TARGET := rlm_eap.a

SOURCES := rlm_eap.c eap.c mem.c

SRC_INCDIRS := . libeap

# FIXME: This target is "phony", which means that every "make"
# re-builds rlm_eap.  We need to re-write this to be the name
# of the ${BUILD_DIR}/.../filename!
#TGT_PREREQS := libfreeradius-eap.a
