TARGETNAME := process_arp

#
#  ARP depends on pcap.
#
ifneq "$(PCAP_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= base.c
TGT_PREREQS	:= libfreeradius-util.a libfreeradius-arp.a
TGT_LDLIBS	:= $(PCAP_LIBS)
