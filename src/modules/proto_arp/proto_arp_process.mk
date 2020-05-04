TARGETNAME := proto_arp_process

#
#  ARP depends on pcap.
#
ifneq "$(PCAP_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_arp_process.c
TGT_PREREQS	:= libfreeradius-util.a
TGT_LDLIBS	:= $(PCAP_LIBS)
