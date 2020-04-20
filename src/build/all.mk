TARGET = libfreeradius-make-dlopen.a
SOURCES = dlopen.c

#
#  If we're building this target, then don't try to use it until we know
#  that building the target succeeds.
#
ifneq "$(MAKECMDGOALS)" "$(TARGET)"
load ${BUILD_DIR}/lib/.libs/libfreeradius-make-dlopen.dylib(dlopen_gmk_setup)

$(info $(dlopen /home/foo/libcrypto,ASN1_verify,/home/user,/foo,/usr/local/Cellar/openssl@1.1/1.1.1d/lib))
$(info $(dlsym libcrypto,ASN1_verify))
$(info $(dlclose libcrypto))

$(info $(dlopen libfoobar))
$(info $(dlerror ))
endif
