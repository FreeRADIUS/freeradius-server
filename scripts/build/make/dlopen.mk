TARGET				:= libfreeradius-make-dlopen.$(BUILD_LIB_EXT)
SOURCES				:= dlopen.c log.c

#
#  This target is NOT built with static analyzer flags.
#
$(TARGET): CFLAGS		:= $(filter-out -W%,$(filter-out -fsanitize%,$(CFLAGS)))
$(TARGET): CPPFLAGS		:= $(filter-out -W%,$(CPPFLAGS))
$(TARGET): LDFLAGS		:= $(filter-out -fsanitize%,$(LDFLAGS))

#
#  This gets built with the BUILD_CC i.e. the one we use to bootstrap
#  this build system.
#
SRC_CC := ${HOST_COMPILE.c}
TGT_LINKER := ${HOST_LINK.c}

#
#  If we're building this target, then don't try to use it until we know
#  that building the target succeeds.
#
#ifneq "$(MAKECMDGOALS)" "$(TARGET)"
#load ${BUILD_DIR}/lib/.libs/libfreeradius-make-dlopen.$(BUILD_LIB_EXT)(dlopen_gmk_setup)

#$(info $(dlopen /home/foo/libcrypto,ASN1_verify,/home/user,/foo,/usr/local/Cellar/openssl@1.1/1.1.1d/lib))
#$(info $(dlsym libcrypto,ASN1_verify))
#$(info $(dlclose libcrypto))

#$(info $(dlopen libfoobar))
#$(info $(dlerror ))
#endif
