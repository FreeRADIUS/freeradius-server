ifneq (${TARGET_IS_WASM},yes)
TARGET		:= radlock$(E)
else
TARGET		:=
endif

SOURCES		:= radlock.c

TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(LIBS)
TGT_LDFLAGS	:= $(LDFLAGS)
TGT_PREREQS	:= libfreeradius-util$(L)
