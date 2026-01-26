#!/usr/bin/env python3
#
# Wrapper around eaopol_test to allow automated UATs tests.
#
# Author Jorge Pereira <jorge@freeradius.org>
# Copyright 2023 The FreeRADIUS Project
#

import argparse
import binascii
import configparser
import os
import json
import logging
import queue
import re
import socket
import select
import signal
import subprocess
import sys
import struct
import time
import tempfile
import threading
import traceback
import textwrap

fr = None
fr_radius = None
fr_util = None

try:
	import pyfr
except Exception as e:
#	raise Exception("Please install pyfr using: python3 -m pip install pyfr")
	raise Exception("Please install pyfr from https://github.com/FreeRADIUS/freeradius-server/compare/master...jpereira:v4/pyfr")
	sys.exit(-1)

try:
	from prettydiff import print_diff
except Exception as e:
	raise Exception("Please install prettydiff using: python3 -m pip install prettydiff[terminal]")
	sys.exit(-1)

#
# Default settings
#
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = "1812"
DEFAULT_SECRET = "testing123"
DEFAULT_PARALLEL = 1
DEFAULT_INTERATIONS = 1

EAPOL_TEST_BIN = "eapol_test"
EAPOL_TEST_CTRL_IFACE = "/tmp/radeapol_uat_ctrl_iface"

#
# Log settings
#
VERBOSE_LEVEL = 0
LOG_FORMAT = "[%(asctime)s] %(levelname)s [%(name)s %(filename)s:%(lineno)d %(funcName)s() %(threadName)s]: %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG, encoding='utf-8')
logger = logging.getLogger()  # root logger

def dlog(_level, _message):
	if (VERBOSE_LEVEL >= _level):
		logger.debug(_message)

def convert_keyval2json(_paylaod, out_as_list=False):
	"""
	Hack converting the 'eapol_test' status collected from Ctrl to list{}
	"""
	from collections import OrderedDict
	class MultiOrderedDict(dict):
		"""
		It converts key=var to jSON like: "key": "var"
		"""
		def __setitem__(self, key, value):
			if isinstance(value, list) and key in self:
				dlog(6, "MultiOrderedDict: append key={} val={}".format(key, value))
				self[key].extend(value)
			else:
				dlog(6, "MultiOrderedDict: create key={} val={}".format(key, value))
				super().__setitem__(key, value)

	class MultiOrderedDicttoList(dict):
	    """
	    It converts key=var to "key": [ var1, varN ]
	    """
	    def __setitem__(self, key, value):
	        if key in self:
	            items = self[key]
	            new = value[0]
	            if value not in items and new not in "0":
	                dlog(6, "MultiOrderedDicttoList: append key={} value={}".format(key, value))
	                items.append(new)
	        else:
	            dlog(6, "MultiOrderedDicttoList: create key={} value={}".format(key, value))
	            super().__setitem__(key, value)
	dlog(6, "convert_keyval2json(): input='{}'".format(_paylaod))

	if out_as_list:
		parser = configparser.RawConfigParser(dict_type=MultiOrderedDicttoList, strict=False)
	else:
		parser = configparser.RawConfigParser(dict_type=MultiOrderedDict, strict=False)

	parser.optionxform = str
	parser.read_string("[DEFAULT]\n" + _paylaod)

	result = {}
	for k,v in parser.items("DEFAULT"):
		result[k] = v
	return result

def fr_convert_attributes2eapol_cmd(_args, _radius):
	"""
	Lookup for each attributes and return as expected by "eapol_test -N" format.
	"""

	try:
		#
		# Get the attributes by oid
		#
		result = []
		for _attr in _radius.keys():
			dlog(4, "Looking for {}".format(_attr))
			
			attr = fr_util.dict_attr_by_oid(_attr)
			dlog(5, "PyFR.dict_attr_by_oid() out: {}".format(attr))

			# print("ATTR_ID = {}".format(attr_id))

			attr_name = attr["oid.string"]
			value     = _radius[attr_name]

			if attr["parent.type"] == "vendor":
				type    = "x"
				attr_id = "26" # It's a VSA
				data  = fr_radius.encode_pair(attrs={ attr_name: [ value ] }, secret=_args.secret)
				value = binascii.hexlify(data[2:]).decode("utf-8") # Skip the length
			else:
				attr_id   = attr["id"]

				if attr["type"] == "string":
					type = "s" # String
				elif "int" in attr["type"]:
					type = "d" # Decimal
				else:
					type = "x" # Octets
			result += [ "-N", "{}:{}:{}".format(attr_id, type, value) ]

		return result
	except Exception as e:
		raise Exception("** ERROR: Problems in:\n {}\n".format(str(e)))

def fr_eapol_test_init(_args, _radius):
	"""
	It will start a eapol_test instance like:

	e.g: eapol_test -a ip -p port -s secret -T /tmp/radeapol_uat_ctrl_iface -i test -N foo:321:var -N tapioca:123:var

	"""
	try:
		log = subprocess.PIPE
		cmd = [ _args.eapol_test_bin, "-a", _args.host, "-p", str(_args.port), "-s", _args.secret, "-T", _args.eapol_ctrl, "-i", "test" ]
		cmd += fr_convert_attributes2eapol_cmd(_args, _radius)

		dlog(0, "eapol_test cmd: {}".format(' '.join(cmd)))

		if _args.verbose >= 2:
			logfile = "eapol_test.log"
			logger.debug("Saving output in eapol_test.log")
			log = open(logfile, "w")

		proc = subprocess.Popen(cmd, universal_newlines=True, stdout=log, stderr=log)
		time.sleep(0.2) # Wait for eapol_test start up

		# ret = et.request("GET version")
		# dlog(3, "request.GET version: result={}".format(ret))

		# ret = et.request("GET tls_library")
		# dlog(3, "request.GET tls_library: result={}".format(ret))
		return proc
	except Exception as e:
		raise Exception("** ERROR: Problems calling 'eapol_test':\n {}\n".format(str(e)))

def fr_load_config(_args, _cfg_file):
	"""
	Load all the config files:

	"my_peap_test"          - contains all the attributes we want to send
	"my_peap_test_conf"     - contains the eapol test config
	"my_peap_test_expected" - contains the attributes we want to see , and whether it'll be an Access-Accept or Access-Reject

	"""
	result = {
		"radius": {},
		"eapol": {},
		"expected": {}
	}

	# file: RADIUS input attributes $name
	radius_cfg = _cfg_file
	logger.debug("Processing RADIUS config file '{}'".format(radius_cfg))
	with open(radius_cfg, "r") as fp:
		for line in fp:
			if line[0] in [ ' ', '#', '\n' ]:
				continue
			dlog(1, "\t{}".format(line.rstrip()))
			confitem = line.split('=')
			if len(confitem) == 2:
				attr = confitem[0].strip()
				var  = confitem[1].strip()
				try:
					# Check if the attribute is known by PyFR
					ret = fr_util.dict_attr_by_oid(attr)
					attr = ret["oid.string"]
				except Exception as e:
					pass
				result["radius"][attr] = var.strip("\"'")

	# file: eapol_test ${name}_conf
	eapol_cfg = _cfg_file + "_conf"
	logger.debug("Processing EAPOL config file '{}'".format(eapol_cfg))
	with open(eapol_cfg, "r") as fp:
		for line in fp:
			if line[0] in [ ' ', '#', '\n' ]:
				continue
			dlog(1, "\t{}".format(line.rstrip()))
			confitem = line.split('=')
			if len(confitem) == 2:
				key = confitem[0].strip()
				var = confitem[1].strip()
				result["eapol"][key] = var

	#
	# file: ${name}_expected
	# i.e: It should be jSON format because we could have several entries of the same attribute.
	#
	expected_file = _cfg_file + "_expected"
	logger.debug("Processing EXPECTED jSON file '{}'".format(expected_file))
	with open(expected_file, "r") as fp:
		data = json.loads(fp.read())
		for obj in data.items():
			attr, value = obj[0], obj[1]
			try:
				# Check if the attribute is known by PyFR
				ret = fr_util.dict_attr_by_oid(attr)
				attr = ret["oid.string"]
			except Exception as e:
				pass
			result["expected"][attr] = value
	dlog(1, "Test Config: {}".format(json.dumps(result, indent=4)))
	return result

def load_args():
	"""
	Load all parameters from the command line.
	"""
	parser = argparse.ArgumentParser(description = "Simple test wrapper around eaopol_test to allow automated UATs",
									 formatter_class = argparse.RawDescriptionHelpFormatter,
									 epilog = textwrap.dedent('''
The directory containing the tests should contains pairs of request files and filter files.
The request file name must contain 'test<num><num><num>'.
The filter name must match the test name but with suffix.

For example:

  ./scripts/util/radeapol_uat/tests/test001_my_first_test            # Contains all the attributes we want to send.
  ./scripts/util/radeapol_uat/tests/test001_my_first_test_conf       # Contains the eapol test config
  ./scripts/util/radeapol_uat/tests/test001_my_first_test_expected   # Contains the attributes we want to see, and whether it'll be an Access-Accept or Access-Reject

The directory containing the tests may have multiple subdirectories to group the tests.
	'''))
	parser.add_argument("-v",
						dest = "verbose",
						help = "Verbose mode. (e.g: -vvv)",
						action = 'count',
						required = False,
						default = 0
	)
	parser.add_argument("test_files", nargs='+', help="Path of a file or a folder of files. (e.g: test_glob0 ... test_globN)")
	parser.add_argument("-a",
						dest = "host",
						help = "Send test packets to specified host and port. (default: {})".format(DEFAULT_HOST),
						required = False,
						default = DEFAULT_HOST
	)
	parser.add_argument("-p",
						dest = "port",
						help = "Send test packets to specified port. (default: {})".format(DEFAULT_PORT),
						type = int,
						required = False,
						default = DEFAULT_PORT
	)
	parser.add_argument("-s",
						dest = "secret",
						help = "Shared secret. (default: {})".format(DEFAULT_SECRET),
						required = False,
						default = DEFAULT_SECRET
	)
	parser.add_argument("-P",
						dest = "parallel",
						help = "Run tests in parallel. (default: {})".format(DEFAULT_PARALLEL),
						type = int,
						required = False,
						default = DEFAULT_PARALLEL
	)
	parser.add_argument("-i",
						dest = "iter",
						help = "Number of iterations. (default: {})".format(DEFAULT_INTERATIONS),
						type = int,
						required = False,
						default = DEFAULT_INTERATIONS
	)
	parser.add_argument("-n",
						dest='no_fast_reauth',
						help = "disable TLS session resumption",
						action = "store_true",
						required = False,
						default = False
	)
	parser.add_argument("-e",
						dest = "eapol_test_bin",
						help = "Path for 'eapol_test' binary. (default: {})".format(EAPOL_TEST_BIN),
						required = False,
						default = EAPOL_TEST_BIN
	)
	parser.add_argument("-c",
						dest = "eapol_ctrl",
						help = "eapol_test path for ctrl_iface. (default: {})".format(EAPOL_TEST_CTRL_IFACE),
						required = False,
						default = EAPOL_TEST_CTRL_IFACE
	)

	parser.add_argument("-d",
						dest = "raddb_dir",
						help = "Set configuration directory (defaults {})".format(pyfr.CONFDIR),
						required = False,
						default = pyfr.CONFDIR
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

	# if args.parallel > 10:
	# 	raise Exception("Option -P max is 10")

	global VERBOSE_LEVEL
	VERBOSE_LEVEL = args.verbose

	print("##############################################")
	print("* Host:            {}".format(args.host))
	print("* Port:            {}".format(args.port))
	print("* Verbose:         {}".format(args.verbose))
	if args.verbose >= 1:
		print("* Parallel:        {}".format(args.parallel))
		print("* Iterations:      {}".format(args.iter))
		print("* dict_dir:        {}".format(args.dict_dir))
		print("* eapol_test_bin:  {}".format(args.eapol_test_bin))
		print("* eapol_test ctrl: {}".format(args.eapol_ctrl))
	print("* Test Files:      {}".format(args.test_files))
	print("##############################################")

	return args

counter = 0
class Ctrl:
    def __init__(self, args, path):
        global counter
        self.args = args
        self.started = False
        self.attached = False
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.dest = path
        self.local = "{}/local.pid{}.{}".format(self.args.eapol_ctrl, os.getpid(), counter)
        counter += 1
        dlog(3, "Setting dest: {}, local: {}".format(self.dest, self.local))
        self.s.bind(self.local)
        self.s.connect(self.dest)
        self.started = True

    def __del__(self):
        self.close()

    def close(self):
        if self.attached:
            self.detach()
        if self.started:
            self.s.close()
            os.unlink(self.local)
            self.started = False

    def request(self, cmd, timeout=10):
        self.s.send(cmd.encode('utf-8'))
        [r, w, e] = select.select([self.s], [], [], timeout)
        if r:
            data = self.s.recv(4096)
            return data.decode('utf-8')
        raise Exception("Timeout on waiting response")

    def attach(self):
        if self.attached:
            return None
        res = self.request("ATTACH")
        if "OK" in res:
            return None
        raise Exception("ATTACH failed")

    def detach(self):
        if not self.attached:
            return None
        res = self.request("DETACH")
        if "OK" in res:
            return None
        raise Exception("DETACH failed")

    def pending(self, timeout=5):
        [r, w, e] = select.select([self.s], [], [], timeout)
        if r:
            return True
        return False

    def recv(self):
        res = self.s.recv(4096)
        res = res.decode('utf-8')
        return res

class eapol_test:
	def __init__(self, args, ifname):
		self.args = args
		self.ifname = ifname
		self.ctrl = Ctrl(args, os.path.join(EAPOL_TEST_CTRL_IFACE, self.ifname))
		if "PONG" not in self.ctrl.request("PING"):
			raise Exception("Failed to connect to eapol_test (%s)" % self.ifname)
		self.mon = Ctrl(args, os.path.join(EAPOL_TEST_CTRL_IFACE, self.ifname))
		self.mon.attach()

	def add_network(self):
		id = self.request("ADD_NETWORK")
		if "FAIL" in id:
			raise Exception("ADD_NETWORK failed")
		return int(id)

	def remove_network(self, id):
		id = self.request("REMOVE_NETWORK {}".format(id))
		if "FAIL" in id:
			raise Exception("REMOVE_NETWORK failed")
		return None

	def set_network(self, id, field, value):
		res = self.request("SET_NETWORK {} {} {}".format(id, field, value))
		if "FAIL" in res:
			raise Exception("SET_NETWORK failed")
		return None

	def set_network_quoted(self, id, field, value):
		res = self.request("SET_NETWORK {} {} \"{}\"".format(id, field, value))
		if "FAIL" in res:
			raise Exception("SET_NETWORK failed")
		return None

	def request(self, cmd):
		return self.ctrl.request(cmd)

	def request_json(self, cmd, out_as_list=False):
		return convert_keyval2json(self.request(cmd), out_as_list)

	def wait_event(self, events, timeout=10):
		start = os.times()[4]
		while True:
			while self.mon.pending(timeout):
				ev = self.mon.recv()

				dlog(3, "Got the event: '{}'".format(ev))

				for event in events:
					if event in ev:
						return ev
			now = os.times()[4]
			remaining = start + timeout - now
			if remaining <= 0:
				break
			if not self.mon.pending(timeout=remaining):
				break
		return None

def eapol_client(_args, _ifname, _count, _res, _i, _config):
	"""
	Thread in charge to interact with the 'eapol_test' instance.
	"""
	et = eapol_test(_args, _ifname)
	et.request("AP_SCAN 0")

	if _args.no_fast_reauth:
		et.request("SET fast_reauth 0")
	else:
		et.request("SET fast_reauth 1")

	id = et.add_network()
	et.set_network(id, "eapol_flags", "0")

	for item in _config['eapol']:
		et.set_network(id, item, _config['eapol'][item])

	et.set_network(id, "disabled", "0")

	fail = False
	for i in range(_count):
		ret = et.request("REASSOCIATE")
		if "OK" not in ret:
			raise Exception("REASSOCIATE failed")

		ev = et.wait_event([
			"CTRL-EVENT-CONNECTED",
			"CTRL-EVENT-DISCONNECTED",
			"CTRL-EVENT-AUTH-REJECT",
			"CTRL-EVENT-SUBNET-STATUS-UPDATE"
			"CTRL-EVENT-EAP-FAILURE",
			"CTRL-EVENT-EAP-STARTED"
		])

		dlog(3, "request.REASSOCIATE: result={}".format(ret))

		if "CTRL-EVENT-CONNECTED" not in ev:
			fail = True
			break

	# double check
	if fail:
		ev = et.wait_event([
			"CTRL-EVENT-CONNECTED",
			"CTRL-EVENT-DISCONNECTED",
			"CTRL-EVENT-AUTH-REJECT",
			"CTRL-EVENT-SUBNET-STATUS-UPDATE"
			"CTRL-EVENT-EAP-FAILURE",
			"CTRL-EVENT-EAP-STARTED"
		])

		dlog(3, "[{}] Result = '{}'".format(_i, ev))
		
		if "CTRL-EVENT-CONNECTED" not in ev:
			fail = True
		else:
			fail = False

	# Debug
	# ret = et.request_json("GET_RADIUS_REPLY")
	# dlog(4, "request.GET_RADIUS_REPLY: {}".format(json.dumps(ret, indent=4, sort_keys=True)))

	replied_raw = et.request_json("GET_RADIUS_REPLY -RAW")
	dlog(3, "request.GET_RADIUS_REPLY -RAW: {}".format(json.dumps(replied_raw, indent=4, sort_keys=True)))

	data    = bytes.fromhex(replied_raw["raw"])
	packet_id, replied = fr_radius.decode_packet(data=data, secret=_args.secret)
	dlog(3, "replied: packet_id={}, attrs={}".format(packet_id, json.dumps(replied, indent=4, sort_keys=True)))

	# Check 'replied' vs 'expected'
	dlog(0, "Comparing 'EXPECTED' vs 'REPLIED' attributes: ")
	print_diff(replied, _config["expected"])

	# Status and leave.
	status = et.request_json("STATUS")
	dlog(4, "request.STATUS: {}".format(json.dumps(status, indent=4)))

	if not fail and status["wpa_state"] == "COMPLETED":
		_res.put("PASS {}".format(i + 1))
	else:
		_res.put("FAIL {}".format(i))

def main():
	try:
		global fr
		global fr_util
		global fr_radius
		t = {}
		res = {}
		args = load_args()
		num = args.parallel
		iter = args.iter

		# PyFR instance
		fr = pyfr.PyFR()

		fr.set_debug_level(args.verbose)
		fr.set_dict_dir(args.dict_dir)
		fr.set_raddb_dir(args.raddb_dir)
		fr.set_lib_dir(args.lib_dir)

		fr_util = fr.Util()
		fr_radius = fr.Radius()

		for cfg in args.test_files:
			config = fr_load_config(args, cfg)
			eapol = fr_eapol_test_init(args, config["radius"])

			for i in range(num):
				ifname = "test"
				res[i] = queue.Queue()
				t[i] = threading.Thread(target=eapol_client, args=(args, ifname, iter, res[i], i, config))

			for i in range(num):
				t[i].start()

			for i in range(num):
				t[i].join()
				try:
					results = res[i].get(False)
				except:
					results = "N/A"
				print("Result: {}: {}".format(i, results))

			eapol.kill()
	except Exception as e:
		print("** ERROR: Something wrong:\n {}\n".format(str(e)))
		traceback.print_exc()
		sys.exit(-1)

if __name__ == "__main__":
    main()
