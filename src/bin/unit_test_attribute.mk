TARGET		:= unit_test_attribute$(E)
SOURCES		:= unit_test_attribute.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER)
TGT_LDLIBS	:= $(LIBS)
