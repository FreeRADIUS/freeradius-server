# rlm_sigtran
## Metadata
<dl>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary
Supports authentication against a Sigtran interface.

## Description

This module implements sigtran communication for EAP-SIM and EAP-AKA.
It should be listed in the "authenticate" section.

Many people will wonder about the license issues involved in
distributing this module.  The short answer is that the source can be
distributed, the binaries cannot be distributed.  The explanation is
given below.

This module falls under the BSD 3 clause license, with advertising
clause.  This clause is incompatible with the GPL, which means that
binaries of this module cannot be used or distributed without explicit
permission of the copyright holder.

This module includes a modified copy of the libosmo-m3ua library,
which is licensed under the GPLv2 / GPLv3.

Anyone having questions about the license can email
license@networkradius.com.