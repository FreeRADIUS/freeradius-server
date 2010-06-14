How is the USERS file processed?
================================

See ``man users`` for more detailed documentation.

After the items of a request have been mangled by the ``hints`` and
``huntgroups`` files, the ``users`` file is processed.

A request has initially an empty check list and an empty reply list
attached to it. So each request has 3 "value-pair" lists associated with it

- the request list (as originated from the terminal server)
- the check list   (initially empty)
- the reply list   (initially empty)

For every entry in the users file, the User-Name attribute
(Value-Pair) is checked.  If it matches, or it is a ``DEFAULT`` entry,
then the items on the first line of the entry are compared with the
attributes from the request. If all items match (logical "and") then
the following actions are taken:

- the check items from the current entry are added to the check list
  of the request.
- The reply list of the ``users`` file entry is appended to the reply
  list of the request

Then a check is made to see if the reply pairlist contains a special
line of ``Fall-Through = Yes``. If so, the next entry in the ``users``
file is processed as above. If not, we stop processing the ``users``
file.
