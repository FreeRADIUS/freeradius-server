TARGETNAME	:= proto_arp

#
#  ARP depends on pcap.
#
ifneq "$(PCAP_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_arp.c
TGT_PREREQS	:= libfreeradius-util.a
TGT_LDLIBS	:= $(PCAP_LIBS)
