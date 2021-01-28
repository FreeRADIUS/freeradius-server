TARGET	:= unit_test_module
SOURCES := unit_test_module.c

TGT_INSTALLDIR  :=
TGT_LDLIBS	:= $(LIBS) $(LCRYPT)
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a libfreeradius-util.a

# Flags needed when linking main executables that link against LuaJIT
ifneq (,$(findstring darwin,$(TARGET_SYSTEM)))
TGT_LDLIBS	+= -pagezero_size 10000 -image_base 100000000
endif

# Libraries can't depend on libraries (oops), so make the binary
# depend on the EAP code...
ifneq "$(filter rlm_eap_%,${ALL_TGTS})" ""
TGT_PREREQS	+= libfreeradius-eap.a
endif

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
