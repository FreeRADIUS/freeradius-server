TARGETNAME := process_tls

SOURCES		:= base.c
TGT_PREREQS	:= libfreeradius-tls.a
TGT_LDLIBS	:= $(PCAP_LIBS)
