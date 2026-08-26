TARGET 		:= rbmonkey$(E)

SOURCES 	:= rbmonkey.c

TGT_PREREQS	:= libfreeradius-util$(L)
TGT_LDLIBS	:= $(LIBS)
TGT_INSTALLDIR	:=
