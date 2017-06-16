# Notes on implementation

* We probably need a generic proto_radius_transport, which contains
  the generic functions encode / decode, nak, send_reply, etc.

* split up fr_transport_t into multiple things:
  * IO layer (open / close / read / write)
  * protocol (encode / decode)
  * process (radius_server_auth / acct / coa / status )

* the "parse listener" function then manually glues together a
  fr_transport_t when it parses the listener, and allocates that in
  some context....

* just use fr_transport_t, and rely on IO routines to fill in the
  details.

* proto_radius will glue together the relevant pieces
