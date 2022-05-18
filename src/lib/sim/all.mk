ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= libfreeradius-sim$(L)
endif

SOURCES	:= \
	comp128.c \
	milenage.c \
	ts_34_108.c

TGT_PREREQS	:= libfreeradius-util$(L)
