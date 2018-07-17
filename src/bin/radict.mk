TARGET		:= radict
SOURCES		:= radict.c

TGT_PREREQS	:= libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)
