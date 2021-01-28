# rlm_mruby
## Metadata
<dl>
  <dt>category</dt><dd>languages</dd>
</dl>

## Summary
Allows the server to call a persistent, embedded mRuby script.

## TODO
There are a lot of possible improvements here:

* Restructure the code, the current status is mainly a PoC
* Allow nested module as name (as in: `Module1::Module2::Radiusd`)
* Document the possibilities, like logging and the methods of the request object
* Find out how to allow the user to include gems, or do we really have to include them compile time
* Add option to allow pre-compiled mruby scripts
* Is using a module really the best solution? We merely use it as a namespace, maybe something more OO would be nicer?
* Can we simplify the getter methods? Simulating something like `attr_reader` would be perfect here
* Use more suitable data types for the values passed to the method. We have data types like Integer and DateTime, so use those instead of stringifying everything
* Add methods on the request object to modify the lists. The current return value is a bit ridiculous, a call like `request.config.add_vp('Password.Cleartext', 'hello')` looks a lot cleaner
* In a similar fashion: methods to get the attributes: `request.request.get_attribute('User-Name')`
* Add a xlat callback, similar to `rlm_perl` `radius_xlat`
* Unit tests
