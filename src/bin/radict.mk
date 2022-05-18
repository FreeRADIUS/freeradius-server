TARGET		:= radict$(E)
SOURCES		:= radict.c

TGT_PREREQS	:= libfreeradius-util$(L)
TGT_LDLIBS	:= $(LIBS)
