# String Protocols

Many protocols are string based.  e.g. SMTP, FTP.  There are now
"attributes" and "types" as with RADIUS.  We would like to have the
server process these attributes, too.

The simple solution is to leverage the existing attribute framework,
with one key change.  Attributes can be defined for these protocols,
*but* they cannot have an attribute number defined.  Instead, the
dictionary code will normalize the name, hash it, and use that hash as
the attribute number.

Many of these attributes can be defined in dictionaries.  Others are
created by reference in policies.  The `unlang` compiler then has to
create named attributes in the main dictionary, instead of creating
unknown attributes.  It becomes more difficult to discover typos in
the configuration, though.  So if the `unlang` compiler creates these
attributes, it should also print out a `WARNING` in debug mode, with a
suggestion that the administrator update the dictionaries.

This method also allows attributes to be defined at run-time, either
when parsed from a packet, or read from a DB (e.g. SQL).

Any attributes created at run-time SHOULD be added to a local
dictionary, which is associated with the request.  Much of the code
compares attributes by simply comparing the `da` pointers.  Adding the
attributes to a local dictionary ensures that the run-time definition
will only be done once.

Alternately, the run-time dictionary could be created per worker
thread, which would be a bit more efficient.  That would be safe, and
would be less work.
