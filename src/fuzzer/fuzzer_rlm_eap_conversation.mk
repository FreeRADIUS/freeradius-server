TARGET			:= fuzzer_rlm_eap_conversation$(E)
SOURCES			:= fuzzer_rlm_eap_conversation.c common.c

TGT_PREREQS		:= libfreeradius-eap$(L) $(LIBFREERADIUS_SERVER) libfreeradius-io$(L) libfreeradius-tls$(L) $(FUZZER_PROTO_LIBS) \
			   rlm_eap$(L) rlm_eap_md5$(L) rlm_eap_gtc$(L) rlm_eap_mschapv2$(L) rlm_mschap$(L)

SRC_CFLAGS		:= -fsanitize=fuzzer
TGT_LDFLAGS		:= -fsanitize=fuzzer
TGT_LDLIBS		:= $(LIBS)
