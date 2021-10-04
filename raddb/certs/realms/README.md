# Multiple Certificate Chains

As of version 3.0.24, FreeRADIUS supports loading multiple certificate
chains, keyed by a realm name.  These chains are in _addition_ to the
default certificates loaded by the `tls` section.

Loading multiple certificate chains means that the server can have
different identities.  i.e. When a user `bob@example.com` requests
network access, the server can present an `example.com` certificate.
On the other hand, when a user `doug@example.org` requests network
access, the server cna present an `example.org` certificate.

This functionality means that it is possible to configure only one
`eap` module, and then use multiple certificate chains. Previous
versions of the server required that the administrator configure
multiple EAP modules, one for each certificate being used.

The selection can be performed in one of two ways.  First, the
certificates can be loaded dynamically at run-time.  Second, the
certificates can be pre-loaded for speed.

## Dynamic Loading of Certificate Chains

The server can dynamically load a certificate chain by setting a
special attribute.  This has to be done _after_ the server has
received the EAP identity request, and _before_ the TLS session setup
has started.

The simplest way to do this is via the following `unlang` statements:

```
authenticate {
	...
	Auth-Type eap {
		if ("%{unpack:&EAP-Message 4 byte}" == 1) {
			update control {
				TLS-Session-Cert-File := "${certdir}/realms/%{Realm}"
			}
		}

		eap
	}
	...
}
```

This configuration looks at the `EAP-Message` attribute, and checks if
it is an EAP-Identity packet.  If so, it then adds a special attribute
`TLS-Session-Cert-File`, with a value based on the `Realm`, from the
`User-Name`.  That setting tells the server to look in the file for a
certificate.

If the file is there, and contains a correctly formatted `PEM`
certificate chain, then it is loaded and used.

If the file does not exist, or the file does not contain a correctly
formatted `PEM` certificate chain, then the user is rejected.

### Format

This file should contain the server certificate, followed by
intermediate certificates, in order.  i.e. If we have a server
certificate signed by CA1, which is signed by CA2, which is signed by
a root CA, then the "certificate_file" should contain server.pem,
followed by CA1.pem, followed by CA2.pem.

When using `ca_file` or `ca_dir`, the file should contain only the
server certificate.

### Private Key

The private should be placed in the same file as the other
certificates, but at the start.

```
private key
server cert
...
ca cert
```

The private key can also be placed into a separate file.  The filename
should be placed into the `TLS-Session-Cert-Private-Key-File`
attribute.

For simplicity, the private keys _should not_ have passwords.  There
is essentially no security benefit to "securing" the key with a
password, and then placing the password into the file system, right
next to the private key.

### Realms

There is no need to place the certificates into files named for each
realm.  However, it is by far and away the easiest way to manage these
certificate chains.

For every realm which is handles this way, the `proxy.conf` file
should define a _local_ realm.  That is, it should contain a
definition such as:

```
example.org {
}
```

This defines the realm `example.org`, and tells FreeRADIUS that there
are no home servers associated with the realm.

The `suffix` module should also be configured, as per the default
configuration.  i.e. list `suffix` in the `authorize` section _before_
the `eap` module.

### Caveats

The root CA certificate for the server certificate should be located
in the `ca_dir`, along with other root CAs.  If the root CA is not
there, then it *must* be included at the end of the file.

These certificates will be loaded and parsed _for every matching
authentication request_.  That limitation means that dynamic loading
of the certificates is likely be slow, and to severely impact
performance.  The good news is that we can fix that with a little more
configuration.

## Preloading Certificate Chains

The server can also pre-load certificate chains.  In the EAP module,
you can do:

```
eap {
    ...
    tls {
    	...
	realm_dir = ${certdir}/realms/
	...
    }
    ...
}
```

Each file in that directory should be a `PEM` encoded certificate
chain, as described in the previous section.  For safety, every file
*must* have a `.pem` as the filename extension.
e.g. `example.org.pem`.

If there is a corresponding private key, it should be placed into a
`.key` file.  e.g. `example.org.key`.

These certificates will be loaded when the server starts, and cached
for the lifetime of the server.  There is no way to reload these
certificates dynamically, the server must be restarted.

Once the `realm_dir` configuration has been added, the selection of
certificates is identical to that described in the previous section.
Just set `TLS-Session-Cert-File`, and the server will figure it out.

However, it is possible to dynamically add new certificate, and have
the server pick it up.  In fact, as the process for choosing
certificates are the same, the server will do this automatically!

## RadSec

The above configuration applies to RadSec, too, as the `tls`
configuration in the server is for all TLS functionality, and not just
EAP.

This means that the server can accept RadSec connections, and then
present different server certificates to different clients.

For this functionality to work, the certificates for EAP and RadSec
*should* be in separate directories.

### Clients

RadSec clients can set the SNI to send in the `tls` subsection of the
`home_server` definition.  See `sites-available/tls` for examples.

### Servers

See the `realm_dir` configuration item in the `tls` subsection for the
location of the server certificates.

If the server receives an SNI for a realm it does not recognize, it
will just use the default TLS configuration.

If the realm is recognized (i.e. there is a file in
`${realm_dir}/%{TLS-Server-Name-Indication}.pem`, then that certificate will be chosen, and
present to the RadSec client.  If there is no such file, then the
default TLS configuration is used.

The current behavior is to _require_ that the server certificate is in
a file which taken from
`${realm_dir}/%{TLS-Server-Name-Indication}.pem`.  Only the
`realm_dir` portion of the filename is configurable.  The SNI portion
is taken from the TLS messages, and the `.pem` suffix is hard-coded in
the source code.

Taking the filename from an untrusted source is fine here.  The
standard (RFC 6066 Section 3) says that the Server Name Indication
field is a DNS "A label".  Which means that there are a limited number
of characters allowed:

* `.`, `-`, `a-Z`, `A-Z`, `0-9`

If the SNI contain anything else, the TLS connection is rejected.

Note that if session resumption is enabled for RadSec, the session
cache *must* also cache the `TLS-Server-Name-Indication` attribute.
The SNI is sent on resumption for TLS 1.2 and earlier, but it is not
sent for TLS 1.3.  As such, the only way to select the right policy on
resumption is to check the value of the cached
TLS-Server-Name-Indication attribute.

