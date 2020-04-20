#
# Makefile
#
# load $(BUILD_DIR)/lib/.libs/libfreeradius-make-dlopen.so(dlopen_gmk_setup)

TARGET := libfreeradius-make-dlopen.a

SOURCES := \
	   dlopen.c

# The called function adds the OS-appropriate extension, so we omit it here.
# $(info $(dlpath $(BUILD_DIR)/lib/.libs/libfreeradius-make-dlopen))
# $(info $(dlerror ))
