#!/usr/bin/env python3
# Author: Jorge Pereira <jpereira@freeradius.org>
# Simple TOTP generator.

import argparse
import base64
import hmac
import struct
import sys
import time

def hotp(key, counter, digits=6, digest='sha1'):
    key = key.encode('ascii')
    counter = struct.pack('>Q', counter)
    mac = hmac.new(key, counter, digest).digest()
    offset = mac[-1] & 0x0f
    binary = struct.unpack('>L', mac[offset:offset+4])[0] & 0x7fffffff
    return str(binary)[-digits:].zfill(digits)

def totp(key, time_step=30, digits=6, digest='sha1'):
    return hotp(key, int(time.time() / time_step), digits, digest)

def main():
    parser = argparse.ArgumentParser(description = "Simple TOTP token generator.")
    parser.add_argument("-k", dest = "key", help = "Key in raw format.", required = True)
    parser.add_argument("-t", dest = "time_step", help = "time step between time changes.", default = 30, type = int)
    parser.add_argument("-d", dest = "digits", help = "Length of the one-time password.", default = 6, type = int)
    parser.add_argument("-e", dest = "encode_base32", help = "Encode the output token in base32.", action='store_true')
    parser.add_argument("-D", dest = "digest", help = "HMAC algorithm as described by RFC 2104. default: sha1, options: sha1, sha256, sha512", required = False, default = "sha1")
    args = parser.parse_args()
    token = totp(args.key, args.time_step, args.digits, args.digest)

    if args.encode_base32:
        token = base64.b32encode(bytearray(token, 'ascii')).decode('ascii')

    print(token)

if __name__ == '__main__':
    main()
