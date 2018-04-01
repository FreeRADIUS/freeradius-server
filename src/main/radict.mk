TARGET		:= radict
SOURCES		:= radict.c

TGT_PREREQS	:= libfreeradius-server.a
TGT_LDLIBS	:= $(LIBS)
