# rlm_cache_htrie
## Metadata
<dl>
  <dt>category</dt><dd>datastore</dd>
</dl>

## Summary
Stores cache entries in a process local, non-persistent lookup structure.  This structure will either be a hash, an rbtree, or prefix tree.

It is a submodule of rlm_cache and cannot be used on its own.
