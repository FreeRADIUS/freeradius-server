TARGETNAME	:= proto_arp

#
#  ARP depends on pcap.
#
ifneq "$(PCAP_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_arp.c
TGT_PREREQS	:= libfreeradius-arp$(L)
TGT_LDLIBS	:= $(PCAP_LIBS)
