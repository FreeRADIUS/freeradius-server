TARGETNAME := proto_arp_ethernet

#
#  ARP depends on pcap.
#
ifneq "$(PCAP_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_arp_ethernet.c
TGT_PREREQS	:= libfreeradius-util$(L)
TGT_LDLIBS	:= $(PCAP_LIBS)
