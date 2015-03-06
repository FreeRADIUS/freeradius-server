rlm_couchbase
=============

General
-------

This module supports accounting, authorization, dynamic clients and simultaneous use checking.  Accounting data is written directly to Couchbase as JSON documents and user authorization information is read from JSON documents stored within Couchbase.    You should list the ```couchbase``` module in both the ```accounting``` and ```authorization``` sections of your site configuration if you are planning to use it for both purposes.  You should also have ```pap``` enabled for authenticating users based on cleartext or hashed password attributes.  To enable simultanous use checking you will need to list the ```couchbase``` module in the ```session``` and ```accounting``` sections of your site configuration.

It was tested to handle thousands of RADIUS requests per second from several thousand Aerohive access points using a FreeRADIUS installation with this module for accounting and authorization.

Accounting
----------

You can use any RADIUS attribute available in the accounting request to build the key for storing the accounting documents. The default configuration will try to use 'Acct-Unique-Session-Id' and fallback to 'Acct-Session-Id' if 'Acct-Unique-Session-Id' is not present.  You will need to have the ```acct_unique``` policy in the ```preacct``` section of your configuration to generate the unique id attribute.   Different status types (start/stop/update) are merged into a single document to facilitate querying and reporting via views.  When everything is configured correctly you will see accounting requests recorded as JSON documents in your Couchbase cluster.  You have full control over what attributes are recorded and how those attributes are mapped to JSON element names via the module configuration.

This example is from an Aerohive wireless access point.

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
simple_nt_regexp = "^([^\\]*)\\(.*)$"

## simple nai regex
simple_nai_regexp = "^([^@]*)@(.*)$"

## split user@domain and domain\user formats
strip_user_domain {
    if(User-Name && (User-Name =~ /${policy.simple_nt_regexp}/)){
        update request {
            &Stripped-User-Domain = "%{1}"
            &Stripped-User-Name = "%{2}"
        }
    }
    elsif(User-Name && (User-Name =~ /${policy.simple_nai_regexp}/)){
        update request {
            &Stripped-User-Name = "%{1}"
            &Stripped-User-Domain = "%{2}"
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

The authorization functionality relies on the user documents being stored with deterministic keys based on information available in the authorization request.  The format of those keys may be specified in unlang like the example below:

```
user_key = "raduser_%{md5:%{tolower:%{%{Stripped-User-Name}:-%{User-Name}}}}"
```

This will create an md5 hash of the lowercase 'Stripped-User-Name' attribute or the 'User-Name' attribute if 'Stripped-User-Name' doesn't exist.  The module will then attempt to fetch the resulting key from the configured Couchbase bucket.

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

You may specify any valid combination of attributes and operators in the JSON document ```config``` and ```reply``` sections.  All other elements present in the user document will not be parsed and are ignored by the module.

Clients
-------

The client functionality depends on a combination of client documents and a simple view that returns those document keys.  Client documents are only loaded ONCE on server startup so there should be no performance penalty using a view for this purpose.

To enable the client loading functionality you will need to set the ```read_clients``` config option to 'yes' and specify a fully qualified view path in the ```client_view``` option.

Example client document:

```json
{
	"docType": "radclient",
	"clientIdentifier": "13.0.0.0/8",
	"clientSecret": "testing123"
}
```

The element names and the client attributes to which they map are completely configurable. Elements present in the document that are not enumerated in the module configuration will be ignored.  In addition to this document you will also need a view that returns the keys of all client documents you wish to load.

Example client view:

```js
function (doc, meta) {
  if (doc.docType && doc.docType == "radclient") {
    emit(meta.id, null);
  }
}
```

This is the simplest possible view that would return all documents in the specified bucket having a ```docType``` element with ```radclient``` value. The module only reads the ```key``` (first emited field) and ```id``` elements in the returned view thus no additional output is needed and any additional output would be ignored.  The ```key``` emitted here will be used as the client name inside the module.

To have the module load only a subset of the client documents contained within the bucket you could add additional elements to the client documents and then filter based on those elements within your view.

Simultaneous Use
----------------

The simultaneous use function relies on data stored in the accounting documents.  When a user attempts to authenticate a view request is made to return all accounting type documents for the current user that do not contain a populated ```stopTimestamp``` value.

Example check view:

```js
function (doc, meta) {
  if (doc.docType && doc.docType == "radacct" && doc.userName && !doc.stopTimestamp) {
    if (doc.strippedUserName) {
      emit(doc.strippedUserName.toLowerCase(), null);
    } else {
      emit(doc.userName.toLowerCase(), null);
    }
  }
}
```

The key (first emitted field) will need to match *EXACTLY* what you set for ```simul_vkey``` in the module configuration.  The default xlat value will attempt to return the lower case 'Stripped-User-Name' attribute or 'User-Name' if the stripped version is not available.

When the total number of keys (sessions) returned is greater than or equal to the ```Simultaneous-Use``` config section value of the current user, the user will be denied access.  When verification is also enabled, each returned key will be fetched and the appropriate information will be passed on to the ```checkrad``` utillity to verify the session status.  If ```checkrad``` determines the session is no longer valid (stale) the session will be updated and closed in Couchbase (if configured) and that session will not be counted against the users login limit.  Further information is available in the module configuration.

To Use
------
Until this module is added to the stable list you will need to explicitly add it to ```src/modules/stable``` before building the server.

```
echo rlm_couchbase >> src/modules/stable
```

You will also need the following libraries installed where they may be found by the server configuration script.

* [libcouchbase](https://github.com/couchbase/libcouchbase) >= 2.0.0 with a valid libio module
* [json-c](https://github.com/json-c/json-c) >= 0.9 (0.10+ HIGHLY encouraged)

Once the above steps are complete, simply configure and install as usual.

Module Configuration
--------------------

Please see [/raddb/mods-available/couchbase](/raddb/mods-available/couchbase) for all available configuration options.
