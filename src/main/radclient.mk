TGT_PREREQS := libfreeradius-radius.a
SRC_CFLAGS := -I${top_srcdir}/src/modules/rlm_mschap
SRC_CFLAGS	+= -DRADIUSD_VERSION=\"${RADIUSD_VERSION}\"

SOURCES	:= radclient.c ${top_srcdir}/src/modules/rlm_mschap/smbdes.c \
	   ${top_srcdir}/src/modules/rlm_mschap/mschap.c

TARGET	:= radclient
