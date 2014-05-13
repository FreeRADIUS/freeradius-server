rlm_couchbase
=============

General
-------

This module allows you to write accounting data directly to Couchbase as JSON documents and authorize users from JSON documents stored within Couchbase.  It was tested to handle thousands of radius requests per second from several thousand Aerohive access points using a FreeRADIUS installation with this module for accounting and authorization.  You should list the ```couchbase``` module in both the ```accounting``` and ```authorization``` sections of your site configuration if you are planning to use it for both purposes.  You should also have ```pap``` enabled for authenticating users based on cleartext or hashed password attributes.  As always YMMV.

Accounting
----------

You can use any radius attribute available in the accounting request to build the key for storing the accounting documents. The default configuration will try to use 'Acct-Unique-Session-Id' and fallback to 'Acct-Session-Id' if 'Acct-Unique-Session-Id' is not present.  You will need to have the ```acct_unique``` policy in the ```preacct``` section of your configuration to generate the unique id attribute.   Different status types (start/stop/update) are merged into a single document to facilitate querying and reporting via views.  When everything is configured correctly you will see accounting requests recorded as JSON documents in your Couchbaase cluster.  You have full control over what attributes are recorded and how those attributes are mapped to JSON element names via the configuration descibed later in this document.

This exmaple is from an Aerohive wireless access point.

```
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
```

To generate the 'calledStationSSID' fields you will need to use the ```rewrite_called_station_id``` policy in the ```preacct``` section of your config.  Similarly to get the 'Stripped-User-Name' and 'Stripped-User-Domain' attributes you can create a file in ```raddb/policy.d/``` with the following content:

```
## simple nt domain regex
simple_nt_regexp = "^([^\\\\\\\\]*)(\\\\\\\\(.*))$"

## simple nai regex
simple_nai_regexp = "^([^@]*)(@(.*))$"

## split user@domain and domain\user formats
strip_user_domain {
	if(User-Name && (User-Name =~ /${policy.simple_nt_regexp}/)){
		update request {
			Stripped-User-Domain = "%{1}"
			Stripped-User-Name = "%{3}"
		}
	}
	elsif(User-Name && (User-Name =~ /${policy.simple_nai_regexp}/)){
		update request {
			Stripped-User-Name = "%{1}"
			Stripped-User-Domain = "%{3}"
		}
	}
	else {
		noop
	}
}
```

You can then reference this policy in both the ```preacct``` and ```authorization``` sections of your configuration before calling this module.

Authorization
-------------

The authorization funcionality relies on the user documents being stored with deterministic keys based on information available in the authorization request.  The format of those keys may be specified in unlang like the example below:

```user_key = "raduser_%{md5:%{tolower:%{%{Stripped-User-Name}:-%{User-Name}}}}"```

This will create an md5 hash of the lowercase 'Stripped-User-Name' attribute or the 'User-Name' attribute if 'Stripped-User-Name' doesn't exist.  The module will then attempt to fetch the resulting key from the configured couchbase bucket.

The document structure is straight forward and flexible:

```json
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
```

You may specify any valid combination of attributes and operations in the JSON document.

To Use
------

Pull freeradius-server master and clone this module under src/modules.  Then enable and compile as usual.
You will also need the following libraries:

* [libcouchbase](https://github.com/couchbase/libcouchbase) >= 2.0.0 with a valid libio module
* [json-c](https://github.com/json-c/json-c) >= 0.9 (0.10+ HIGHLY encouraged)

Configuration
-------------

```
couchbase {
	#
	# List of Couchbase hosts (hosts may be space, tab, comma or semi-colon separated).
	# Ports are optional if servers are listening on the standard port.
	# Complete pool urls are preferred.
	#
	server = "http://cb01.blargs.com:8091/pools/ http://cb04.blargs.com:8091/pools/"

	# Couchbase bucket name
	bucket = "radius"

	# Couchbase bucket password (optional)
	#password = "password"

	# Couchbase accounting document key (unlang supported)
	acct_key = "radacct_%{%{Acct-Unique-Session-Id}:-%{Acct-Session-Id}}"

	# Value for the 'docType' element in the json body for accounting documents
	doctype = "radacct"

	## Accounting document expire time in seconds (0 = never)
	expire = 2592000

	#
	# Map attribute names to json element names for accounting.
	#
	# Configuration items are in the format:
	# <element name> = '<radius attribute>'
	#
	# Attribute names should be single quoted.
	#
	# Note: Atrributes not in this map will not be recorded.
	#
	map {
		sessionId           = 'Acct-Session-Id'
		uniqueId            = 'Acct-Unique-Session-Id'
		lastStatus          = 'Acct-Status-Type'
		authentic           = 'Acct-Authentic'
		userName            = 'User-Name'
		strippedUserName    = 'Stripped-User-Name'
		strippedUserDomain  = 'Stripped-User-Domain'
		realm               = 'Realm'
		nasIpAddress        = 'NAS-IP-Address'
		nasIdentifier       = 'NAS-Identifier'
		nasPort             = 'NAS-Port'
		calledStationId     = 'Called-Station-Id'
		calledStationSSID   = 'Called-Station-SSID'
		callingStationId    = 'Calling-Station-Id'
		framedIpAddress     = 'Framed-IP-Address'
		nasPortType         = 'NAS-Port-Type'
		connectInfo         = 'Connect-Info'
		sessionTime         = 'Acct-Session-Time'
		inputPackets        = 'Acct-Input-Packets'
		outputPackets       = 'Acct-Output-Packets'
		inputOctets         = 'Acct-Input-Octets'
		outputOctets        = 'Acct-Output-Octets'
		inputGigawords      = 'Acct-Input-Gigawords'
		outputGigawords     = 'Acct-Output-Gigawords'
		lastUpdated         = 'Event-Timestamp'
	}

	# Couchbase document key for user documents (unlang supported)
	user_key = "raduser_%{md5:%{tolower:%{%{Stripped-User-Name}:-%{User-Name}}}}"

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
```
