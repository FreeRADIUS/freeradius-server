rlm_couchbase
=============

Stores radius accounting data directly into couchbase. You can use any radius attribute as a document key.  The default will try to use Acct-Unique-Session-Id
and fallback to Acct-Session-Id if Acct-Unique-Session-Id is not present (needs acct_unique policy in preacct to generate the unique id).
Different status types (start/stop/update) are merged into a single document for easy view writing.  To generate the calledStationSSID fields you will need to
use the rewrite_called_station_id policy in the preacct section of your config.  The couchbase module will attempt to produce the Stripped-User-Name and
Stripped-Domain-Name attributes if used in the preacct section.

Example from an Aerohive Wireless Access Point:

    {
      "docType": "radacct",
      "startTimestamp": "Jul 15 2013 13:22:07 CDT",
      "stopTimestamp": "null",
      "sessionId": "51D241D3-0000047A",
      "lastStatus": 3,
      "authentic": 1,
      "userName": "mruser@blargs.com",
      "nasIpAddress": "172.28.4.150",
      "nasIdentifier": "air4.corp.blargs.com",
      "nasPort": 0,
      "calledStationId": "40-18-b1-01-3c-54",
      "framedIpAddress": "172.27.2.87",
      "callingStationId": "8C-2D-AA-72-36-BA",
      "nasPortType": 19,
      "connectInfo": "11ng",
      "sessionTime": 5821,
      "inputPackets": 5591,
      "inputOctets": 681742,
      "inputGigawords": 0,
      "outputOctets": 536306,
      "outputGigawords": 0,
      "outputPackets": 1087,
      "lastUpdated": "Jul 15 2013 14:59:08 CDT",
      "uniqueId": "029d975fc48ecb41444da52a65e62a55",
      "calledStationSSID": "BLARGS-WIFI",
      "strippedUserName": "mruser",
      "strippedUserDomain": "blargs.com"
    }

The module is also capable of authorizing users via documents stored in couchbase.  The document keys should be deterministic based on information available in the document.  The format of those keys may be specified in unlang like the example below:

    userkey = "raduser_%{md5:%{tolower:%{User-Name}}}"

The document structure is straight forward and flexible:

    {
      "docType": "raduser",
      "userName": "test",
      "config": {
        "SHA-Password": {
          "value": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
          "op": ":="
        }
      },
      "reply": {
        "Reply-Message": {
          "value": "Hidey Ho!",
          "op": "="
        }
      }
    }

To Use
------

Pull freeradius-server master and clone this module under src/modules.  Then enable and compile as usual.
You will need [libcouchbase](https://github.com/couchbase/libcouchbase) >= 2.0 installed with a valid libio module.  You will also need [json-c](https://github.com/json-c/json-c) >= 0.11 installed and available.

Configuration
-------------

    couchbase {
        #
        # List of Couchbase hosts semi-colon separated.  Ports are optional if servers
        # are listening on the standard port.  Complete pool urls are preferred.
        #
        server = "http://cb01.blargs.com:8091/pools/;http://cb04.blargs.com:8091/pools/"

        # Couchbase bucket name
        bucket = "radius"

        # Couchbase bucket password
        #pass = "password"

        # Couchbase accounting document key (unlang supported)
        acctkey = "radacct_%{%{Acct-Unique-Session-Id}:-%{Acct-Session-Id}}"

        # Value for the 'docType' element in the json body for accounting documents
        doctype = "radacct"

        ## Accounting document expire time in seconds (0 = never)
        expire = 2592000

        #
        # Map attribute names to json element names for accounting.
        #
        # Configuration items are in the format:
        # <radius attribute> = <element name>
        #
        # JSON element names should be single quoted.
        #
        # Note: Atrributes not in this map will not be recorded.
        #
        map {
            Acct-Session-Id = 'sessionId'
            Acct-Unique-Session-Id = 'uniqueId'
            Acct-Status-Type = 'lastStatus'
            Acct-Authentic = 'authentic'
            User-Name = 'userName'
            Stripped-User-Name = 'strippedUserName'
            Stripped-User-Domain = 'strippedUserDomain'
            Realm = 'realm'
            NAS-IP-Address = 'nasIpAddress'
            NAS-Identifier = 'nasIdentifier'
            NAS-Port = 'nasPort'
            Called-Station-Id = 'calledStationId'
            Called-Station-SSID = 'calledStationSSID'
            Calling-Station-Id = 'callingStationId'
            Framed-IP-Address = 'framedIpAddress'
            NAS-Port-Type = 'nasPortType'
            Connect-Info = 'connectInfo'
            Acct-Session-Time = 'sessionTime'
            Acct-Input-Packets = 'inputPackets'
            Acct-Output-Packets = 'outputPackets'
            Acct-Input-Octets = 'inputOctets'
            Acct-Output-Octets = 'outputOctets'
            Acct-Input-Gigawords = 'inputGigawords'
            Acct-Output-Gigawords = 'outputGigawords'
            Event-Timestamp = 'lastUpdated'
        }

        # Couchbase document key for user documents (unlang supported)
        userkey = "raduser_%{md5:%{tolower:%{User-Name}}}"

        #
        #  The connection pool is new for 3.0, and will be used in many
        #  modules, for all kinds of connection-related activity.
        #
        pool {
            # Number of connections to start
            start = 5

            # Minimum number of connections to keep open
            min = 5

            # Maximum number of connections
            #
            # If these connections are all in use and a new one
            # is requested, the request will NOT get a connection.
            #
            # NOTE: This should be greater than or equal to "min" above.
            max = 20

            # Spare connections to be left idle
            #
            # NOTE: Idle connections WILL be closed if "idle_timeout"
            # is set.  This should be less than or equal to "max" above.
            spare = 15

            # Number of uses before the connection is closed
            #
            # NOTE: A setting of 0 means infinite (no limit).
            uses = 0

            # The lifetime (in seconds) of the connection
            #
            # NOTE: A setting of 0 means infinite (no limit).
            lifetime = 0

            # The idle timeout (in seconds).  A connection which is
            # unused for this length of time will be closed.
            #
            # NOTE: A setting of 0 means infinite (no timeout).
            idle_timeout = 1200

            # NOTE: All configuration settings are enforced.  If a
            # connection is closed because of "idle_timeout",
            # "uses", or "lifetime", then the total number of
            # connections MAY fall below "min".  When that
            # happens, it will open a new connection.  It will
            # also log a WARNING message.
            #
            # The solution is to either lower the "min" connections,
            # or increase lifetime/idle_timeout.
        }
    }

Notes
-----

This module was tested to handle thousands of radius requests in a short period of time from several thousand Aerohive Access Points pointing
to a FreeRADIUS installation for accounting and authorization.  You should list the couchbase module in both the accounting, preacct and authorization sections
of your site configuration if you are planning to use it for both purposes.
You should also have PAP enabled for authenticating users based on cleartext or hashed password attributes.
As always YMMV.

This module was built and tested against the latest [FreeRADIUS v3.0.x branch](https://github.com/FreeRADIUS/freeradius-server/tree/v3.0.x) as of the most
current commit to this repository.
