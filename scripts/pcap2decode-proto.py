#!/usr/bin/env python3
#  -*- coding: utf-8 -*-
#  Copyright 2019 NetworkRADIUS SARL (legal@networkradius.com)
#  This work is licensed under CC-BY version 4.0 https://creativecommons.org/licenses/by/4.0
#
#  Author: Jorge Pereira <jpereira@freeradius.org>
#  Version $Id$
#

#
#  EXAMPLE:
#
#  1. wget https://github.com/the-tcpdump-group/tcpdump/raw/master/tests/dhcpv6-sip-server-d.pcap
#  2. ./scripts/pcap2decode-proto.py -p dhcpv6 -f ./dhcpv6-sip-server-d.pcap > src/tests/unit/protocols/dhcpv6/packet_sip-server-d.txt
#  3. build/make/jlibtool --quiet --mode=execute build/bin/local/unit_test_attribute -xx -D share/dictionary src/tests/unit/protocols/dhcpv6/packet_sip-server-d.txt
#
#  TODO:
#
#  - verify if the jlibtool and unit_test_attribute exist
#  - check if we could call dhcpv6_tp_decode_pair direct from libfreeradius-dhcpv6.{so,dylib}
#

from __future__ import print_function
import argparse
import tempfile
import traceback
import sys
import os
import re

unit_attr = "build/make/jlibtool --quiet --mode=execute " \
            "build/bin/local/unit_test_attribute -xx "    \
            "-D share/dictionary "                        \
            "-d src/tests/unit"

# print to stderr
def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)

try:
	from scapy.all import *
except Exception as e:
	eprint("** ERROR: We need the 'scapy' package. e.g: pip3 install scapy")
	sys.exit(-1)

# It does like: unit_test_attribute ... /path/file.txt | sed '/got.*:/!d; s/.\{2\}/& /g; s/ $//g'
def unit_lookup_payload2attrs(proto, payload):
	# Generating lookup file
	fp = tempfile.NamedTemporaryFile(mode = "w+", delete = False)
	fp.write("# Using {}\n".format(fp.name))
	fp.write("proto {}\n".format(proto))
	fp.write("proto-dictionary {}\n".format(proto))
	fp.write("\n")
	fp.write("decode-proto {}\n".format(payload))
	fp.write("match Packet-Type = 1\n")
	fp.flush()
	fp.close()

	# call the unit_test_attribute
	cmd_unit = "{} {}".format(unit_attr, fp.name)
	cmd_out  = os.popen(cmd_unit).read()
	os.remove(fp.name)

	match = re.search(r"(.\sgot\s+:)\s(.*)", cmd_out)
	if not match:
		eprint("# ERROR: We didn't find the 'got' token in: {}".format(cmd_out))
		return None

	return match.group(2)

def load_args():
	parser = argparse.ArgumentParser(
		description = "Convert .pcap file to FreeRADIUS unit_test_attribute(encode/decode) format. {almost, try}",
	)
	parser.add_argument(
		"-f",
		dest = "pcap_file",
		help = "pcap file to extract the dhcpv6 payload",
		required = True
	)
	parser.add_argument(
		"-p",
		dest = "decode_proto",
		help = "Protocol to be used in: 'proto $proto' and 'proto-dictionary $proto'",
		required = True
	)
	parser.add_argument(
		"-b",
		dest = "both",
		help = "Perform the lookup adding the 'encode-proto attrs' and 'decode_proto -'",
		action='store_true'
	)
	return parser.parse_args()

def _main():
	try:
		args      = load_args()
		count_pkt = 0
		count_mat = 0
		pcap      = rdpcap(args.pcap_file)

		print("#  -*- text -*-")
		print("#  ATTENTION: It was generated automatically, be careful! :)")
		print("#  Based on {}".format(os.path.basename(args.pcap_file)))
		print("#")
		print("")
		print("proto {}".format(args.decode_proto))
		print("proto-dictionary {}".format(args.decode_proto))
		print("")
		count_mat += 2

		for pkt in pcap:
			# statements
			count_pkt += 1
			print("#")
			print("#  {}.".format(count_pkt))
			print("#")

			# get the payload description, remove '#' and trim() spaces.
			app = pkt.getlayer(3)
			packet_desc = app.show(dump=True, indent=1).replace("#", "")
			packet_desc = re.sub('^', "# ", packet_desc, flags=re.MULTILINE)
			packet_desc = re.sub(' $', "",  packet_desc, flags=re.MULTILINE)
			print(packet_desc.strip())

			# Convert the payload to hex separated by space.
			payload = ""
			for d in app.build():
				payload += "{:02x} ".format(d)

			# trim the left/right
			payload = payload.strip()

			# lookup the attrs from the payload
			attrs = unit_lookup_payload2attrs(args.decode_proto, payload)
			if not attrs:
				raise Exception("Error", "Problems to convert the payload to attrs")

			if args.both:
				count_mat += 4
				print("encode-proto {}".format(attrs))
				print("match {}".format(payload))
				print("")
				print("decode-proto -")
				print("match {}".format(attrs))
				print("")
			else:
				count_mat += 2
				print("decode-proto {}".format(payload))
				print("match {}".format(attrs))
				print("")

		# append the 'count'
		print("count")
		print("match {}".format(count_mat))
		print("")

	except Exception as e:
		eprint("** ERROR: Something wrong:\n {}\n".format(str(e)))
		traceback.print_exc()
		sys.exit(-1)

if __name__ == "__main__":
	_main()
