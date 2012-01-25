TGT_PREREQS := libfreeradius-radius.a

TGT_LDLIBS := $(LIBS) -lpcap

SOURCES	:= radsniff.c

TARGET	:= radsniff
