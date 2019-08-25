# TO DO

Add `leftover` argument to `mod_write()`.  So the caller knows if the
data has been partially written.  That way all of the pending / retry
code is handled in `network.c`.

This change will substantially simplify the writers.

* EWOULDBLOCK, network side retries whole packet
* `leftover != 0`, network side localizes message, and retries at a later time.
