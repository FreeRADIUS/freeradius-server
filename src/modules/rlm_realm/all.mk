TARGET		:= rlm_realm.a
SOURCES		:= rlm_realm.c

#TRUSTROUTER	= yes

ifneq "$(TRUSTROUTER)" ""
SRC_CFLAGS	+= -I /path/to/moonshot/include/ -D HAVE_TRUST_ROUTER_TR_DH_H
TGT_LDLIBS	+= -ltr_tid
SOURCES		+= trustrouter.c
endif
