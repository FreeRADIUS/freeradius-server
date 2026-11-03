TARGET			:= fuzzer_eap_chbind$(E)
SOURCES			:= fuzzer_eap_chbind.c common.c

TGT_PREREQS		:= libfreeradius-eap$(L) $(LIBFREERADIUS_SERVER) $(FUZZER_PROTO_LIBS)

SRC_CFLAGS		:= -fsanitize=fuzzer
TGT_LDFLAGS		:= -fsanitize=fuzzer
TGT_LDLIBS		:= $(LIBS)
