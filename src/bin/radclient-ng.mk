TARGET		:= radclient-ng$(E)
SOURCES		:= radclient-ng.c ${top_srcdir}/src/modules/rlm_mschap/smbdes.c \
		   ${top_srcdir}/src/modules/rlm_mschap/mschap.c \
		   ${top_srcdir}/src/lib/server/packet.c \

TGT_PREREQS	:= libfreeradius-radius$(L) libfreeradius-radius-bio$(L) libfreeradius-bio$(L)

SRC_CFLAGS	:= -I${top_srcdir}/src/modules/rlm_mschap
TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS)
TGT_LDFLAGS	:= $(OPENSSL_FLAGS)

TGT_INSTALLDIR	:= $(BUILD_DIR)/bin/ignore
