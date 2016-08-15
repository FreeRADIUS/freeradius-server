# rlm_redis_ippool
## Metadata
<dl>
  <dt>category</dt><dd>datastore</dd>
</dl>

## Summary
Implements a fast and scalable IP allocation system using Redis. Supports both IPv4 and IPv6 address and prefix
allocation, and implements pre-allocation for use with DHCPv4.

Lease allocation throughput scales with the number of members in the Redis cluster.
