TGT_PREREQS := libfreeradius-radius.a
SRC_CFLAGS	+= -DRADIUSD_VERSION=\"${RADIUSD_VERSION}\"

TGT_LDLIBS := $(LIBS) $(LIBREADLINE)

SOURCES	:= radmin.c

ifneq ($(LIBREADLINE),)
TARGET	:= radmin
else
TARGET  :=
endif
