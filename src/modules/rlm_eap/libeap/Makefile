#
# $Id$
#

TARGET		= $(LIBPREFIX)eap
SRCS		= fips186prf.c eapcrypto.c eapcommon.c eapsimlib.c \
		  eap_tls.c tls.c cb.c mppe_keys.c
INCLUDES	= eap_types.h eap_tls.h
RLM_CFLAGS	= -DEAPLIB -I${top_builddir}/src -I${top_builddir}/src/modules/rlm_eap -I${top_builddir}/src/modules/rlm_eap/libeap
LINK_MODE	= $(RLM_EAP_LINK_MODE)

RLM_DIR		= ../
include ../../rules.mak

# Redefine sane link command
$(TARGET).la: $(DYNAMIC_OBJS)
	$(LIBTOOL) --mode=link $(CC) -release $(RADIUSD_VERSION) \
	$(LINK_MODE) $(RLM_LDFLAGS) $(LDFLAGS) -o $@ -rpath $(libdir) \
	$^ $(RLM_DIR)../../lib/libradius.la $(RLM_LIBS) $(LIBS)
