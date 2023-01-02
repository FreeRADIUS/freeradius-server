#!/usr/bin/env python3
#
# Test script for pyfr
# Copyright 2023 The FreeRADIUS server project
# Author: Jorge Pereira (jpereira@freeradius.org)
#

import argparse
import json
import sys
import textwrap

try:
	import pyfr
except Exception as e:
	print("Please install first the 'pyfr'")
	sys.exit(-1)

raddb_dir = "../../../raddb"
dict_dir = "../../../share/dictionary"
lib_dir = "../../../build/lib/local/.libs/"

def load_args():
	parser = argparse.ArgumentParser(formatter_class = argparse.RawDescriptionHelpFormatter,
					epilog = "Very simple interface to extract attribute definitions from FreeRADIUS dictionaries")

	parser.add_argument("attribute", nargs='+', help="List of attributes.. (e.g: NAS-Port-Id ... User-Password)")
	parser.add_argument("-E",
			dest='export',
			help = "Export dictionary definitions.",
			action = "store_true",
			required = False,
			default = False
	)
	parser.add_argument("-V",
			dest = "all_attributes",
			help = "Write out all attribute values.",
			action = "store_true",
			required = False,
			default = False
	)
	parser.add_argument("-D",
			dest = "dict_dir",
			help = "Set main dictionary directory (defaults to {})".format(pyfr.DICTDIR),
			required = False,
			default = pyfr.DICTDIR
	)
	parser.add_argument("-d",
			dest = "raddb_dir",
			help = "Set configuration directory (defaults {})".format(pyfr.RADDBDIR),
			required = False,
			default = pyfr.RADDBDIR
	)
	parser.add_argument("-p",
			dest = "protocol",
			help = "Set protocol by name",
			required = False,
			default = "radius"
	)
	parser.add_argument("-x",
			dest = "debug",
			help = "Debugging mode.",
			action = 'count',
			required = False,
			default = 0
	)
	parser.add_argument("-c",
			dest = "all_attributes",
			help = "Print out in CSV format.",
			action = "store_true",
			required = False,
			default = False
	)
	parser.add_argument("-H",
			dest = "show_headers",
			help = "Show the headers of each field.",
			action = "store_true",
			required = False,
			default = False
	)
	parser.add_argument("-v",
			dest = "verbose",
			help = "Verbose mode. (e.g: -vvv)",
			action = 'count',
			required = False,
			default = 0
	)

	return parser.parse_args()

def radict_export(ret, args):
	print("TODO radict_export()")

if __name__ == "__main__":
	try:
		args = load_args()

		fr = pyfr.PyFR()
		fr.set_debug_level(args.verbose)
		fr.set_raddb_dir(args.raddb_dir)
		fr.set_dict_dir(args.dict_dir)
		# fr.set_lib_dir(args.lib_dir)

		util = fr.Util()

		if args.show_headers:
			print("Dictionary\tOID\tAttribute\tID\tType\tFlags")

		ret = {}
		i = 0
		for attr in args.attribute:
			if args.debug:
				print("Looking for {}".format(attr))
			
			ret[i] = util.dict_attr_by_oid(attr)
			i += 1

		if args.export:
			radict_export(ret, args)
		else:			
			print("{}".format(json.dumps(ret, indent=4, sort_keys=True)))

	except Exception as e:
		print("Problems with radict.py: {}".format(e))
