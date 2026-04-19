# rlm_dpsk
## Metadata
<dl>
  <dt>category</dt><dd>datastore</dd>
</dl>

## Summary

`rlm_dpsk` verifies WPA2/WPA3-style dynamic PSK handshakes and returns the
matching PSK material for the selected backend.

The current source tree supports four request layouts:

- Ruckus DPSK parameters
- Standard FreeRADIUS attributes
- Cisco IOS XE AVPairs
- Meraki named VSAs

## Request Mapping

The module consumes the same logical inputs regardless of adapter:

- Supplicant identity
- SSID
- Authenticator MAC
- ANonce
- EAPOL-Key message

The current source tree maps those inputs as follows.

### Standard attributes

- This is a generic reference example, not the primary shipped deployment
  path.
- `User-Name`
- `Called-Station-SSID`
- `Called-Station-MAC`
- `FreeRADIUS-EV5.802_1X-Anonce`
- `FreeRADIUS-EV5.802_1X-EAPoL-Key-Msg`

### Ruckus

- `Vendor-Specific.Ruckus.SSID`
- `Vendor-Specific.Ruckus.BSSID`
- `Vendor-Specific.Ruckus.DPSK-Params.DPSK-Anonce`
- `Vendor-Specific.Ruckus.DPSK-Params.DPSK-EAPOL-Key-Frame`

### Cisco IOS XE

- `Vendor-Specific.Cisco.AVPair` key `cisco-wlan-ssid`
- `Vendor-Specific.Cisco.AVPair` key `cisco-bssid`
- `Vendor-Specific.Cisco.AVPair` key `cisco-anonce`
- `Vendor-Specific.Cisco.AVPair` key `cisco-8021x-data`

### Meraki

- `Vendor-Specific.Meraki.Meraki-IPSK.Meraki-IPSK-SSID`
- `Vendor-Specific.Meraki.Meraki-IPSK.Meraki-IPSK-BSSID`
- `Vendor-Specific.Meraki.Meraki-IPSK.Meraki-IPSK-Anonce`
- `Vendor-Specific.Meraki.Meraki-IPSK.Meraki-IPSK-EAPOL`

Meraki uses `Meraki-IPSK-BSSID` as the authenticator MAC. The current source
tree does not use `Meraki-IPSK-AP-MAC`.

## CSV-backed PMKs

When a PSK is loaded from CSV, the module derives the PMK from:

`PBKDF2(PSK, SSID, 4096)`

Because the PMK depends on the SSID, file-backed entries are cached per
`(filename, SSID)` pair instead of per filename alone. This avoids reusing a
PMK derived for one SSID when the same CSV file is shared across multiple WLANs.

No extra configuration is required to enable this behavior. It is implemented
in the module code.

## Installed Template Defaults

The installed template lives at:

- `raddb/mods-available/dpsk`

That template ships with active defaults for caching, CSV fallback, and the
documented adapter examples. The active defaults include:

```text
dpsk {
	cache_size = 1024
	cache_lifetime = 24h

	source csv_fallback {
		type = csv
		csv {
			filename = "${modconfdir}/dpsk/psk.csv"
			format = "identity,psk,mac,vlan"
		}
	}

	adapter standard { ... }
	adapter ruckus  { ... }
	adapter iosxe   { ... }
	adapter meraki  { ... }
}
```

This means:

- Caching is enabled by default
- The shipped template enables CSV fallback by default
- The shipped template includes the standard, key/value-VSA, and named-VSA
  adapter examples

## Example Configuration

The following snippets match the current source tree behavior. Start with the
shared `source` definitions, then add the adapters you need inside the same
`dpsk { ... }` block.

### Shared sources

```text
dpsk {
	cache_size = 1024
	cache_lifetime = 24h

	source csv_fallback {
		type = csv

		csv {
			filename = "${modconfdir}/dpsk/psk.csv"
			format = "identity,psk,mac,vlan"
		}
	}
}
```

### Ruckus adapter

```text
adapter ruckus {
	priority = 10
	type = named_vsa_attrs

	request {
		named_vsa {
			username = User-Name
			ssid = Vendor-Specific.Ruckus.SSID
			called_station = Vendor-Specific.Ruckus.BSSID
			anonce = Vendor-Specific.Ruckus.DPSK-Params.DPSK-Anonce
			key_msg = Vendor-Specific.Ruckus.DPSK-Params.DPSK-EAPOL-Key-Frame
		}
	}

	reply {
		mode = ms_mppe_recv_key

		ms_mppe_recv_key {
			psk_attr = reply.Vendor-Specific.Microsoft.MPPE-Recv-Key
		}

		vlan {
			mode = tunnel
			tunnel_type_attr = reply.Tunnel-Type
			tunnel_medium_type_attr = reply.Tunnel-Medium-Type
			tunnel_private_group_id_attr = reply.Tunnel-Private-Group-Id
			tunnel_type_value = 13
			tunnel_medium_type_value = 6
		}
	}
}
```

### Cisco IOS XE adapter

```text
adapter iosxe {
	priority = 20
	type = key_value_vsa

	request {
		key_value {
			container_attr = Vendor-Specific.Cisco.AVPair
			username = User-Name
			ssid_key = cisco-wlan-ssid
			called_station_key = cisco-bssid
			anonce_key = cisco-anonce
			key_msg_key = cisco-8021x-data
			value_encoding = radius_escaped
		}
	}

	reply {
		mode = avpair_hex_pmk

		avpair_hex_pmk {
			avpair_attr = reply.Vendor-Specific.Cisco.AVPair
			pmk_key = psk
			extra_pairs = "psk-mode=hex"
		}

		vlan {
			mode = tunnel
			tunnel_type_attr = reply.Tunnel-Type
			tunnel_medium_type_attr = reply.Tunnel-Medium-Type
			tunnel_private_group_id_attr = reply.Tunnel-Private-Group-Id
			tunnel_type_value = 13
			tunnel_medium_type_value = 6
		}
	}
}
```

### Meraki adapter

```text
adapter meraki {
	priority = 30
	type = named_vsa_attrs

	request {
		named_vsa {
			username = User-Name
			ssid = Vendor-Specific.Meraki.Meraki-IPSK.Meraki-IPSK-SSID
			called_station = Vendor-Specific.Meraki.Meraki-IPSK.Meraki-IPSK-BSSID
			anonce = Vendor-Specific.Meraki.Meraki-IPSK.Meraki-IPSK-Anonce
			key_msg = Vendor-Specific.Meraki.Meraki-IPSK.Meraki-IPSK-EAPOL
		}
	}

	reply {
		mode = tunnel_password

		tunnel_password {
			psk_attr = reply.Tunnel-Password
		}

		vlan {
			mode = tunnel
			tunnel_type_attr = reply.Tunnel-Type
			tunnel_medium_type_attr = reply.Tunnel-Medium-Type
			tunnel_private_group_id_attr = reply.Tunnel-Private-Group-Id
			tunnel_type_value = 13
			tunnel_medium_type_value = 6
		}
	}
}
```

### Standard adapter

This is a generic reference example.  Current shipped deployments primarily
use the vendor-specific adapters above.

```text
adapter standard {
	priority = 100
	type = standard_attrs

	request {
		standard {
			username = User-Name
			ssid = Called-Station-SSID
			called_station = Called-Station-MAC
			anonce = FreeRADIUS-EV5.802_1X-Anonce
			key_msg = FreeRADIUS-EV5.802_1X-EAPoL-Key-Msg
			master_key = control.Pairwise-Master-Key
			psk = control.Pre-Shared-Key
			psk_identity = control.PSK-Identity
		}
	}

	reply {
		mode = standard

		standard {
			psk_attr = reply.Pre-Shared-Key
			psk_identity_attr = reply.PSK-Identity
		}

		vlan {
			mode = tunnel
			tunnel_type_attr = reply.Tunnel-Type
			tunnel_medium_type_attr = reply.Tunnel-Medium-Type
			tunnel_private_group_id_attr = reply.Tunnel-Private-Group-Id
			tunnel_type_value = 13
			tunnel_medium_type_value = 6
		}
	}
}
```

For direct PMK / PSK lookup from another module, use the `standard` request
fields:

- `master_key = control.Pairwise-Master-Key`
- `psk = control.Pre-Shared-Key`
- `psk_identity = control.PSK-Identity`

Those attributes are resolved through the request mapping itself. They are not
configured through a separate `source attributes { ... }` block.
