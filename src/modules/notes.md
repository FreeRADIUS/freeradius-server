# Modules to fix for namespace

Some modules need an explicit `dict` pointer.

Other modules use xlat's, etc. which need to have a dict / namespace set.

We MAY need to add a `namespace = ...` config to EVERY module.  <sigh>
It would be much preferable to just get the namespace from where the
module is being referenced.

The daemon parses the config, and then bootstraps the modules *before*
the virtual servers.  So we can't say "hey, this module is used from
virtual server X, let's go figure out it's namespace!"

* attr_filter
* files
* detail
* cache
  * get dict into TYPE_TMPL config file parsing
* exec
* passwd
* radutmp
* linelog
