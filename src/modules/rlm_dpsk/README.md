# rlm_dpsk
## Metadata
<dl>
  <dt>category</dt><dd>datastore</dd>
</dl>

## Summary

The DPSK module implements dynamic PSK (or personal PSK) for WPA-PSK.

## FreeRADIUS 3.2 Notes

This tree contains a FreeRADIUS 3.2 implementation of `rlm_dpsk` with
multi-adapter request handling.

The module can detect and process requests from:

- standard FreeRADIUS attributes
- Ruckus DPSK attributes
- Cisco IOS XE EasyPSK attributes carried in `Cisco-AVPair`
- Meraki iPSK attributes

## Configuration Overview

The module is configured in `raddb/mods-available/dpsk`.

At minimum, configure:

- `filename` if PSKs are stored in a CSV file
- one or more `adapter` sections

Typical adapters in this tree are:

- `adapter standard`
- `adapter ruckus`
- `adapter iosxe`
- `adapter meraki`

The selected adapter determines:

- how request attributes are read
- how the success reply is encoded

## CSV Format

The CSV file supports the following forms:

```text
identity,psk
identity,psk,client_mac
identity,psk,client_mac,vlan
```

Notes:

- `client_mac` is optional
- `vlan` is optional
- `client_mac` must be 12 hex characters with no separators
- `vlan` must be a decimal VLAN ID in the range `1..4094`

Examples:

```text
00220022,00220022
00660066,00660066,f44ee3989fe0
vlan2065,00330033,,2065
00660066,00660066,f44ee3989fe0,2065
```

If `client_mac` is present, the entry is only used for that supplicant MAC.

## Reply Behaviour

On success, the module returns adapter-specific PSK attributes:

- `standard`: `Pre-Shared-Key` and `PSK-Identity`
- `ruckus`: `MS-MPPE-Recv-Key`
- `iosxe`: `Cisco-AVPair` with `psk=<hex pmk>` and `psk-mode=hex`
- `meraki`: `Tunnel-Password`

If a CSV entry includes a VLAN, the module also returns:

- `Tunnel-Type = VLAN`
- `Tunnel-Medium-Type = IEEE-802`
- `Tunnel-Private-Group-Id = <vlan>`

## Adapter Notes

### Ruckus

Uses named Ruckus VSAs such as:

- `Ruckus-SSID`
- `Ruckus-BSSID`
- `Ruckus-DPSK-Anonce`
- `Ruckus-DPSK-EAPoL-Key-Frame`

### Cisco IOS XE

Uses key/value pairs inside `Cisco-AVPair`, including:

- `cisco-wlan-ssid`
- `cisco-bssid`
- `cisco-anonce`
- `cisco-8021x-data`

The successful reply returns the PMK as a hex string in `Cisco-AVPair`.

### Meraki

Uses Meraki iPSK attributes. In this tree the dictionary definitions are
expected to provide:

- `Meraki-IPSK-Anonce`
- `Meraki-IPSK-EAPOL`
- `Meraki-IPSK-BSSID`
- `Meraki-IPSK-AP-MAC`
- `Meraki-IPSK-SSID`

The successful reply returns `Tunnel-Password`, and may also include the VLAN
reply attributes listed above.

## Validation

For configuration validation on a test system, use:

```bash
freeradius -XC
```

For live debugging, run the server manually:

```bash
freeradius -X
```
