ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= libfreeradius-sim$(L)
endif
TGT_CATEGORY	:= lib-util

SOURCES	:= \
	comp128.c \
	milenage.c \
	ts_34_108.c

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL)
