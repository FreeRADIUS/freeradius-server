# TO DO

* add proto_radius_connection_io as mostly a clone of master_io
  * which lets us get rid of the horrible `get_inst` hack.
  * We can then either split all functions into 2 which is code duplication...
  * or, have each function call underlying one with both inst && connection...

* REQUIRED doesn't work for "network"?
  * src/main/cf_parse.c[884]: Configuration item "network" must have a value
  * that's a TERRIBLE message.  it should be a fake filename?  <internal>...

* add "new connection" method to sites-available/default ?
  * to separate it from new client?

## fr_io_instance_t

* app_io_private
  * connection set - should just move to app_io function callback
  * network_get is run in proto_radius
  * should be called from io bootstrap function

* add mod_bootstrap to io.c
  * and then grabs network information using public API
* add mod_instantiate to io.c
  * io.c calls app_io->instantiate
  * and creates the client trie
* add mod_open to io.c
  * io.c makes the listener
* move non-proto_radius headers to src/lib/io.h
* move io.c to src/lib/io/io.c
* and have it work!

Things which need to be abstracted

* priorities
* process by code
  * probably just process set?
  * or abstract a way for the app method to know which packets it should accept.
* cleanup delay
  * for access-request.  Not everything needs this
* connection set

## proto_radius uses

* code_allowed
* process_by_code
  * can probably be a callback

* app_io for decode / encode
  * app_io_instance

* max_packet_size
* num_messages

## TO DO

* move bootstrap / instantiate of app_io to io.c
  * and add a bootstrap / instantiate method there
  * have io.c initialize all of the stuff it uses
* have fr_io_instance_t public
  * so that proto_radius can initialize some things...
  * have TALLOC_CTX at the start, so that it can clean things up
  * for parsing simplicity, the struct should just be inline in proto_radius_t
