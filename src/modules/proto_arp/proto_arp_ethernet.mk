TARGETNAME := proto_arp_ethernet

#
#  ARP depends on pcap.
#
ifneq "$(PCAP_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_arp_ethernet.c
TGT_PREREQS	:= libfreeradius-util.a
TGT_LDLIBS	:= $(PCAP_LIBS)
