# Application Layer

The application layer is responsible for all protocol-specific
processing.  It is entirely unaware of any IO related issues.
It exposes the following API.

*We may not need the `fr_application_t`, as the unlang is cached in
 the `CONF_SECTION`, and the processing is entirely dependent on the
 state machine, and the `REQUEST`.

The application layer (i.e. worker thread) receives messages from the
transport layer (i.e. network thread) via the (message API)[message].
The process is reversed when sending messages.

### bootstrap

Takes a `CONF_SECTION *` and returns a `fr_application_t *`.  It
defines the various things necessary in phase 1 bootstrap.

Note that the current server core can't deal with this.  The listeners
are created / parsed at awkward moments due to legacy design.

### compile

Takes a `CONF_SECTION *`, `fr_application_t *`, and returns `int`
(0/-1).  Compiles any necessary `unlang` blocks.

### debug

Takes a `REQUEST *`, and prints debugging information about the
request, to the request debug context.

### process

The function to call when processing a `REQUEST`.
i.e. `request->process()`.  Takes `REQUEST *` and and `fr_action_t`.
It returns `rlm_rcode_t`.  It presumes that there is an event list in
`request->el`.  All events for the request are added to the event
list.

*Do we need to take an `fr_application_t` here?  Or instead of
 `process`, do we have a `push` function?*
