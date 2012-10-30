TGT_PREREQS := libfreeradius-radius.a
SRC_CFLAGS := -I${top_srcdir}/src/modules/rlm_mschap
SRC_CFLAGS	+= -DRADIUSD_VERSION=\"${RADIUSD_VERSION}\"
SRC_CFLAGS	+= -DRADIUSD_VERSION_STRING=\"${RADIUSD_VERSION_STRING}\"
ifdef RADIUSD_VERSION_COMMIT
CFLAGS		+= -DRADIUSD_VERSION_COMMIT=\"${RADIUSD_VERSION_COMMIT}\"
endif
TGT_LDLIBS := $(LIBS)

SOURCES	:= radclient.c ${top_srcdir}/src/modules/rlm_mschap/smbdes.c \
	   ${top_srcdir}/src/modules/rlm_mschap/mschap.c

TARGET	:= radclient
