# Dynamic Home Servers in v3

FreeRADIUS has some support for dynamic home servers, with certain limitations. This includes the ability to **dynamically resolve home servers from DNS** (e.g., via NAPTR) and load them into the server at runtime using a custom script.

---

## Configuration

Enable dynamic home servers in `proxy.conf`:

```freeradius
proxy server {
	...
	dynamic = true
	directory = ${raddb}/home_servers/
}
```

This ensures internal data structures are thread-safe for updates. Be aware that on high-load proxies, lock contention can cause slowdowns.

The directory `${raddb}/home_servers/` must contain only dynamic home server definitions:

```freeradius
home_server example.com {
	...
}
```

Each file must:
- Be named exactly after the home server (e.g., `example.com`)
- Contain **exactly one** `home_server` block with the matching name
- Optionally `$INCLUDE tls.conf` for RadSec configuration

### Control Socket

Ensure the `sites-available/control-socket` virtual server is enabled, and `radmin` has read/write access. This is mandatory for runtime server management.

```bash
ln -s /etc/freeradius/sites-available/control-socket /etc/freeradius/sites-enabled/control-socket
```

---

## Adding a New Home Server Dynamically

To add a server while FreeRADIUS is running:

1. Create the `home_server` definition in `${raddb}/home_servers/example.com`
2. Load it:

```bash
radmin -e "add home_server file ${raddb}/home_servers/example.com"
```

If successful, it will be immediately available.

---

## Deleting a Home Server

```bash
radmin -e "del home_server file example.com auth"
```

This deletes by `name` and `type` (auth, acct, etc), not file path.

---

## Listing All Home Servers

```bash
radmin -e "show home_server list all"
```

---

## Limitations

- Deleted dynamic home servers are **not freed** (memory grows over time)
- They **cannot** be added to pools or realms
- No failover handling
- No TTL tracking — server does not auto-refresh DNS

---

## Proxying to a Home Server

```freeradius
update control {
	Home-Server-Name := "example.com"
}
```

---

## Checking if a Home Server Exists

```freeradius
%{home_server_dynamic:name}
```

Returns:
- `""` → not found
- `"0"` → static
- `"1"` → dynamic

---

## Dynamic DNS Provisioning (DPD) via `dpd_exec`

To automate adding home servers via DNS discovery, configure an `exec` module named `dpd_exec`.

### 1. Define `mods-available/dpd_exec`

```freeradius
exec dpd_exec {
	wait = yes
	input_pairs = &request
	shell_escape = yes
	timeout = 3
}
```

> This has to be done this way because this script requires `wait = yes`, exec by default doesn't, and we need to execute a custom program.

Enable it:

```bash
ln -s ../mods-available/dpd_exec ../mods-enabled/
```

Ensure the script is executable:

```bash
chmod +x /etc/freeradius/mods-config/realm/freeradius-naptr-to-home-server.sh
```

### 2. Use in `authorize` section

```freeradius
authorize {
	if (&User-Name =~ /@(.*)$/) {
		switch "%{home_server_dynamic:%{1}}" {
			case "1" {
				update control {
					Home-Server-Name := "%{1}"
				}
			}
			case "0" {
				update control {
					Proxy-To-Realm := "%{1}"
				}
			}
			case {
				update control {
					&Temp-Home-Server-String := "%{dpd_exec:/etc/freeradius/mods-config/realm/freeradius-naptr-to-home-server.sh -d %{config:confdir} -t %{1}}"
				}
				if ("%{control:Temp-Home-Server-String}" == "") {
					reject
				} else {
					update control {
						Home-Server-Name := "%{1}"
					}
				}
			}
		}
	}
}
```

---

## Maintenance of Dynamic Servers

Because FreeRADIUS does **not** track DNS TTLs or revalidate dynamic server definitions, periodic maintenance is required.

### Recommended Daily Maintenance

```bash
# Remove all dynamic home servers (except tls.conf)
rm -f $(ls -1 raddb/home_servers | grep -v tls.conf)

# Optionally refresh CRLs and restart the server
systemctl restart freeradius
```

This ensures:
- Updated DNS entries are picked up
- Expired servers are purged
- CRL or certificate changes are applied
