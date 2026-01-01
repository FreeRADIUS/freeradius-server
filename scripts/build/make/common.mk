#
#  All of the files in this directory produce GNU make log messages,
#  and not FreeRADIUS log messages,
#
TARGET				:= libfreeradius-make-${TARGET_NAME}.$(BUILD_LIB_EXT)
SOURCES				:= ${TARGET_NAME}.c log.c

#
#  This target is NOT built with static analyzer flags.
#
$(TARGET): CFLAGS		:= $(filter-out -W% -fsanitize%,$(CFLAGS))
$(TARGET): CPPFLAGS		:= $(filter-out -W%,$(CPPFLAGS))
$(TARGET): LDFLAGS		:= $(filter-out -fsanitize% --rtlib=% --unwindlib=%,$(LDFLAGS))

#
#  This gets built with the BUILD_CC i.e. the one we use to bootstrap
#  this build system.
#
SRC_CC := ${HOST_COMPILE.c}
TGT_LINKER := ${HOST_LINK.c}
