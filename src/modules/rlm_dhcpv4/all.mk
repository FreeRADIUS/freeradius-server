TARGETNAME	:= rlm_dhcpv4

TARGET		:= $(TARGETNAME)$(L)
SOURCES		:= $(TARGETNAME).c

TGT_PREREQS	:= libfreeradius-dhcpv4$(L)
LOG_ID_LIB	= 12
