

		How is the USERS file processed?


After the items of a request have been mangled by the "hints" and
"huntgroups" files, the users file is processed.

A request has initially an empty check list and an empty reply list
attached to it. So each request has 3 A/V pairlists associated with it

- the request list (as originated from the terminal server)
- the check list   (initially empty)
- the reply list   (initially empty)

For every entry in the users file, the Username VP (Value-Pair) is checked.
If it matches or it is a DEFAULT entry, a check pairlist is created
(call it tmpcheck) by adding the check pairlist of the current usersfile
entry to the check pairlist of the request. If an attribute is already
present in the check pairlist of the request it will not be changed
(see files.c:movepair).

Then the request pairlist is compared with the tmpcheck pairlist. If
all items match (except for password-related items at this time!)
the following actions are taken:

- The reply pairlist of the usersfile entry is appended to the reply
  pairlist of the request
- The check pairlist of the request is replaced by the tmpcheck pairlist
  (this is the same as: the check pairlist from the usersfile entry is
   appended to the pairlist of the request)

Then a check is made to see if the reply pairlist contains an A-V pair
of "Fall-Through = Yes". If so, the next entry in the usersfile is processed
as above. If not, we stop processing the users file.

Then after all this is done, the Authentication information is filtered
from the check pairlist, the password of the users is checked, and we
send a reply back to the terminal server.

