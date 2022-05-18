TARGET		:= radclient$(E)
SOURCES		:= radclient.c ${top_srcdir}/src/modules/rlm_mschap/smbdes.c \
		   ${top_srcdir}/src/modules/rlm_mschap/mschap.c

TGT_PREREQS	:= libfreeradius-radius$(L)

SRC_CFLAGS	:= -I${top_srcdir}/src/modules/rlm_mschap
TGT_LDLIBS	:= $(LIBS)
