#!/usr/bin/env python3
#
# Test script for pyfr
# Copyright 2023 The FreeRADIUS server project
# Author: Jorge Pereira (jpereira@freeradius.org)
#

import argparse
import binascii
import os
import sys
import time
import json
import traceback

from pprint import pprint

try:
	import pyfr
except pyfr.error as e:
 	print("ERROR: import pyfr {}".format(e))

def load_args():
	"""
	Load all parameters from the command line.
	"""
	parser = argparse.ArgumentParser(description = "test script",
									 formatter_class = argparse.RawDescriptionHelpFormatter)
	parser.add_argument("-v",
			dest = "verbose",
			help = "Verbose mode. (e.g: -vvv)",
			action = 'count',
			required = False,
			default = 0
	)

	parser.add_argument("-d",
			dest = "raddb_dir",
			help = "Set configuration directory (defaults {})".format(pyfr.RADDBDIR),
			required = False,
			default = pyfr.RADDBDIR
	)
	parser.add_argument("-D",
			dest = "dict_dir",
			help = "Path for 'dictionary' directory. (default: {})".format(pyfr.DICTDIR),
			required = False,
			default = pyfr.DICTDIR
	)
	parser.add_argument("-l",
			dest = "lib_dir",
			help = "Path for 'libraries' directory. (default: {})".format(pyfr.LIBDIR),
			required = False,
			default = pyfr.LIBDIR
	)
	args = parser.parse_args()

	return args

print("test.py: ###########################################################")
print("test.py: # Consts")
print("test.py: ###########################################################")

fr = pyfr.PyFR()
# fr = pyfr.PyFR(raddb_dir=raddb_dir, dict_dir=dict_dir, lib_dir=lib_dir, debug_lvl=10)

args = load_args()

fr.set_debug_level(args.verbose+2)
fr.set_lib_dir(args.lib_dir)
fr.set_raddb_dir(args.raddb_dir)
fr.set_dict_dir(args.dict_dir)

# pprint(vars(fr))

print("test.py: ###########################################################")
print("test.py: # pyfr.Util")
print("test.py: ###########################################################")

try:
	u = fr.Util()
	r = fr.Radius()

	print()
	print("test.py: ###########################################################")
	print("test.py: Util.dict_attr_by_oid()")
	print("test.py: ###########################################################")
	attr = "Vendor-Specific.Alcatel.Client-Primary-DNS"
	ret = u.dict_attr_by_oid(attr)
	print("test.py: pyfr.Util.dict_attr_by_oid('{}') = {}".format(attr, json.dumps(ret, indent=4, sort_keys=True)))

	print()
	print("test.py: ###########################################################")
	print("test.py: Radius.encode_pair()")
	print("test.py: ###########################################################")
	attrs = {
		"User-Name": [ "hare", "krishina" ],
		"User-Password": [ "jorge" ],
		"Vendor-Specific.WiMAX.DNS-Server": [ "::1" ],
		"Vendor-Specific.Alcatel.Client-Primary-DNS": [ "8.8.8.8", "8.6.6.6" ]
	}
	data = r.encode_pair(attrs=attrs, secret="testing123")
	print("input:  {}".format(attrs))
	print("output: {}".format(binascii.hexlify(data)))

	print()
	print("test.py: ###########################################################")
	print("test.py: Radius.decode_pair()")
	print("test.py: ###########################################################")
	data = b'010668617265010a6b72697368696e611a19000060b5341300000000000000000000000000000000011a0c00000be10506080808081a0c00000be1050608060606'
	attrs = r.decode_pair(data=binascii.unhexlify(data), secret="testing123")
	print("input:  {}".format(data))
	print("output: {}".format(attrs))

	print()
	print("test.py: ###########################################################")
	print("test.py: Radius.encode_packet()")
	print("test.py: ###########################################################")
	attrs = {
		"Packet-Type": [ "Access-Request" ],
		"User-Name": [ "jorge", "pereira" ],
		"User-Password": [ "jorge" ],
		"Vendor-Specific.WiMAX.DNS-Server": [ "::1" ],
		"Vendor-Specific.Alcatel.Client-Primary-DNS": [ "8.8.8.8" ]
	}
	packet_id = 202
	data = r.encode_packet(attrs=attrs, id=packet_id, secret="testing123")
	print("attrs:     {}".format(attrs))
	print("packet-id: {}".format(packet_id))
	print("packet:    {}".format(binascii.hexlify(data)))

	print()
	print("test.py: ###########################################################")
	print("test.py: Radius.decode_packet()")
	print("test.py: ###########################################################")
	data = b'01ca00490000000000000000000000000000000001076a6f7267650109706572656972611a19000060b5341300000000000000000000000000000000011a0c00000be1050608080808'
	packet_id, attrs = r.decode_packet(data=binascii.unhexlify(data), secret="testing123")
	print("attrs:     {}".format(attrs))
	print("packet-id: {}".format(packet_id))
	print("packet:    {}".format(data))

except Exception as e:
	print("test.py: Problems with: {}".format(e))
	traceback.print_exc()


# print("###########################################################")
# print("# pyfr.Radius")
# print("###########################################################")
# try:
# 	arg = "bar"
# 	radius = fr.Radius(auth_host="localhost", auth_port="1812")
# 	ret = radius.foo("tapioca")
# 	print("pyfr.radius.foo('{}') = {}".format(arg, json.dumps(ret, indent=4, sort_keys=True)))
# except Exception as e:
# 	print("Problems with pyfr.radius.foo(): {}".format(e))
# 	traceback.print_exc()