TARGET		:= rlm_okta.a
SOURCES		:= rlm_okta.c okta.c util/buffer.c util/curl.c

SRC_CFLAGS	:=
TGT_LDLIBS	:= -lc -ljson -lcurl
