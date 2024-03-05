# The retry bio

The retry bio manages timed retries of requests and responses, using the `fr_retry_t` timers.

As with most bio blocks, the bulk of the work is done via callbacks

## Callbacks

### Sent Callback

On `write()`, the `fr_bio_retry_sent_t` callback is run after the bio
has sent the packet.  The packet is tracked in an internal data
structure called `fr_bio_retry_entry_t`.  The `sent` callback passes
that pointer back to the application, which should cache it in a data
structure associated with the request.  (Usually the `packet_ctx`).

This pointer can be used to cancel an outgoing packet, or can be
returned by the `response` callback.

The request is normally tracked in an RB tree or hash table, keyed by
various fields in the packet header.

### Response callback

On `read()`, the `fr_bio_retry_response_t` callback is run after the bio has
read a full packet (the next bio should usually be a `mem` bio, with a
packet verify callback).

The application should use the response packet data to find the
request usually by looking it up in an RB tree based on packet header.
Once the request packet has been found, the application should return
the pointer from the `fr_bio_retry_sent_t` callback.

This process lets the retry bio find not only the request, but the
internal data needed to do the retries.

Note that the callback should _always_ update the `retry_ctx` pointer,
even if the packet is a duplicate (the application still has to track
that itself).  Returning it lets the retry bio track dups.

i.e. if the retry bio sends 4 packets, we likely don't want to clean
up the `retry_ctx` until we've seen all 4 responses, OR until the
`maximum_retry_duration` timer has been hit.

### Rewrite Callback

The rewrite callback is run when a timer fires.  When no rewrite
callback is given, the bio just re-sends the request packet as-is.

If a rewrite callback is given, it is called.  The application can
then change the packet if necessary (e.g. update Acct-Delay-Time),
re-encode the packet, etc.  The application should *not* call the
`fr_bio_write()` routine to send the updated data.  Instead, the
application should call `fr_bio_retry_rewrite()`, and return that
value as its return value.

The difference is that a call to the main `fr_bio_write()` routine
runs through all of the bios, and sets up a _new_ packet to send, with
_new_ timers.  The `fr_bio_retry_rewrite()` function instead gets
passed the `retry_ctx`, which lets the retry bio update the timers,
but without allocating a new retry context for it.

Note that the bio can block during this write.  And also it could
write a partial packet.  Any partial writes are saved, and cannot be cancelled.

### Release callback

The `release` callback is run when the retry bio has decided to
release the `retry_ctx` associated with the request.  The application
should clean up any tracking table associated with the request / response.

## Cancel Function

An outgoing request can be cancelled at any time by calling the cancel
function, with the `retry_ctx` from the `sent` callback.

The `release` callback will be called when a request packet is cancelled.

