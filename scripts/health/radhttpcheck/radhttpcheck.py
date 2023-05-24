#!/usr/bin/env python3

#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#  Copyright (C) 2023 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
#

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading

from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
import pyrad.packet

import argparse
import json
import yaml

# Our configuration object
config = {}
raddict = {}

class RadiusHealthCheckHandler(BaseHTTPRequestHandler):
    def genericResponse(self, code, content):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        try:
            self.wfile.write(bytes(content, 'utf8'))
        except BrokenPipeError:
            pass

    def codeToStr(self, code):
        code_map = {
            pyrad.packet.AccessRequest : 'Access-Request',
            pyrad.packet.AccessAccept : 'Access-Accept',
            pyrad.packet.AccessReject : 'Access-Reject',
            pyrad.packet.AccountingRequest : 'Accounting-Request',
            pyrad.packet.AccountingResponse : 'Accounting-Response',
            pyrad.packet.AccessChallenge : 'Access-Challenge',
            pyrad.packet.StatusServer : 'Status-Server',
            pyrad.packet.StatusClient : 'Status-Client',
            pyrad.packet.DisconnectRequest : 'Disconnect-Request',
            pyrad.packet.DisconnectACK : 'Disconnect-Ack',
            pyrad.packet.DisconnectNAK : 'Disconnect-NAK',
            pyrad.packet.CoARequest : 'CoA-Request',
            pyrad.packet.CoAACK : 'CoA-ACK',
            pyrad.packet.CoANAK : 'CoA-NAK'
        }
        if code in code_map:
            return code_map[code]
        return str(code)

    def do_GET(self):
        global config

        if self.path == '/alwaysOk':
            self.genericResponse(200, json.dumps({"msg": "This healthcheck is always up, and should be used for RADIUS source ports (for CoA and DM) only"}))
            return

        if self.path == '/list':
            self.genericResponse(200, json.dumps(list(config.healthchecks.keys())))
            return

        if not self.path in config.healthchecks:
            self.genericResponse(404, json.dumps({"msg": "Invalid healthcheck " + self.path + ".  Configured healthchecks are \"" + ', '.join(config.healthchecks.keys()) + "\""}))
            return

        # Send a RADIUS request
        healthcheck = config.healthchecks[self.path]

        # Create a new client for every request, this ensures that for the lifetime of the client
        # a unique source port is used, and so we don't have to care about synchronisation around
        # the different client instances when multiple HTTP requests come in for the same
        # healthcheck.
        port = healthcheck['port']
        client = Client(server = healthcheck['server'],
                        secret = bytes(healthcheck['secret'], 'utf8'),
                        retries = healthcheck['retries'],
                        timeout = healthcheck['timeout'],
                        authport = port, acctport = port, coaport = port,
                        dict = config.raddict)

        # Create the RADIUS request
        if healthcheck['type']['req_code'] == pyrad.packet.AccessRequest:
            req = client.CreateAuthPacket(**healthcheck['attributes'])
        elif healthcheck['type']['req_code'] == pyrad.packet.AccountingRequest:
            req = client.CreateAcctPacket(**healthcheck['attributes'])
        elif healthcheck['type']['req_code'] == pyrad.packet.CoARequest:
            req = client.CreateCoAPacket(**healthcheck['attributes'])
        elif healthcheck['type']['req_code'] == pyrad.packet.StatusServer:
            req = client.CreateAuthPacket(code=pyrad.packet.StatusServer,**healthcheck['attributes'])
        else:
            req = client.CreatePacket(code=healthcheck['type']['req_code'],**healthcheck['attributes'])

        # There's no reason not to add this or to make it configurable
        req.add_message_authenticator()

        # We now block until retries and timeout have expired
        try:
            rsp = client.SendPacket(req)
        except pyrad.packet.PacketError as e:
            self.genericResponse(502, json.dumps({"msg": "Healthcheck error: " + str(e) })) # BadGateway
            return
        except pyrad.client.Timeout as e:
            self.genericResponse(504, json.dumps({"msg": "Healthcheck error: No response from upstream"})) # Gateway timeout
            return
        except Exception as e:
            self.genericResponse(500, json.dumps({"msg": "Internal error: " + str(e) })) # Internal error
            return
        finally:
            del client # Ensure the socket is closed in a timely fashion

        # Deal with response code mismatches
        if healthcheck['require_ack'] and healthcheck['type'].has_key('rsp_code') and rsp.code != healthcheck['type']['rsp_code']:
            self.genericResponse(502, json.dumps({"msg": "Healthcheck error: Bad response code, expected " + self.code2str(healthcheck['type']['rsp_code']) + ", got " + self.code2str(rsp.code) })) # BadGateway
            return

        self.genericResponse(200, json.dumps({"msg": "Healthcheck OK" }))

class Configuration:
    def __init__(self, configuration_filename='radhttpcheck.yml'):
        if configuration_filename is None:
            raise ValueError("Configuration filename must be supplied")
        self._configuration_filename = configuration_filename
        self._config = {}
        self.read_configuration()

    def read_configuration(self):
        packet_types = {
            'access-request': {
                'req_code': pyrad.packet.AccessRequest,
                'rsp_code': pyrad.packet.AccessAccept
            },
            'accounting-request': {
                'req_code': pyrad.packet.AccountingRequest,
                'rsp_code': pyrad.packet.AccountingResponse
            },
            'coa-request': {
                'req_code': pyrad.packet.CoARequest,
                'rsp_code': pyrad.packet.CoAACK
            },
            'disconnect-request': {
                'req_code': pyrad.packet.DisconnectRequest,
                'rsp_code': pyrad.packet.DisconnectACK
            },
            'status-server': {
                'req_code': pyrad.packet.StatusServer
            }
        }

        with open(self._configuration_filename, 'r') as file:
            our_conf = yaml.safe_load(file)

        # Ensure basic keys and structures exist
        our_conf = { 'listen' : {}, 'healthchecks' : {}, 'dictionary' : 'dictionary' } | our_conf

        # Load in our modified default RADIUS dictionary.  We do this here to avoid parsing the
        # dictionary file on every request
        self.raddict = Dictionary(our_conf['dictionary'])

        # Configure defaults for the HTTP listener
        our_conf['listen'] = { 'port': 8080, 'ipaddr': '' } | our_conf['listen']

        # SimpleHTTP tries to resolve '*' and fails.  An empty string means bing to any interface
        if our_conf['listen']['ipaddr'] == '*':
            our_conf['listen']['ipaddr'] = ''

        # Setup packet-specific defaults on the healthchecks
        for healthcheck in our_conf['healthchecks'].keys():
            options = our_conf['healthchecks'][healthcheck]
            options['type'] = options['type'].lower()
            # Set different defaults depending on whether this an Access-Request or something else
            if ('port' in options and options['port'] == '1812') or ('type' in options and options['type'] == 'access-request'):
                our_conf['healthchecks'][healthcheck] = {
                    'port': 1812,
                    'type': 'access-request',
                } | options
            else:
                our_conf['healthchecks'][healthcheck] = {
                    'port': 1813,
                    'type': 'accounting-request',
                } | options

            our_conf['healthchecks'][healthcheck] = {
                    'server': '127.0.0.1',
                    'retries': 1,
                    'timeout': 1,
                    'require_ack': False,
                    'secret': 'testing123',
                    'attributes': {},
                } | options

            # Make sure the packet type is sane
            if not options['type'] in packet_types:
                # If type is a number, allow it so we can send custom packets
                if not options['type'].isnumeric():
                    raise ValueError("healthcheck.type must be one of " + ', '.join(list(packet_types.keys())))
                our_conf['healthchecks'][healthcheck]['type'] = { 'req_code': int(options['type']) }
            else:
                our_conf['healthchecks'][healthcheck]['type'] = packet_types[options['type']]

            # Sanity check the attributes so we can fail early
            for attr, value in our_conf['healthchecks'][healthcheck]['attributes'].items():
                if not attr in self.raddict:
                    raise ValueError("Failed resolving RADIUS attribute " + attr + " for healthcheck " + healthcheck)

                radattr = self.raddict[attr]

                # Resolve enums
                if len(radattr.values) > 0:
                    if not radattr.values.HasForward(value):
                        raise ValueError("Failed resolving RADIUS attribute " + attr + " value " + str(value) + " for healthcheck " + healthcheck)

        # Set default healthcheck parameters
        self._config = our_conf

    def __getattr__(self, name):
        return self._config[name]

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def main():
    global config
    global raddict

    parser = argparse.ArgumentParser(description='HTTP to RADIUS healthcheck')
    parser.add_argument('-c', '--conf', default='radhttpcheck.yml', help='path to configuration file')
    args = parser.parse_args()

    # Parse our configuration, setting defaults
    config = Configuration(args.conf)

    # Start the HTTP server
    with ThreadedHTTPServer((config.listen['ipaddr'], config.listen['port']), RadiusHealthCheckHandler) as httpd:
        print("RADIUS HTTP healthcheck server running on port", config.listen['port'])
        try:
            httpd.serve_forever()
        # Catch the KeyboardInterrupt exception we get on sigint
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()

if __name__ == "__main__":
    main()
