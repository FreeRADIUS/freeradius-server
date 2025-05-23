Here’s the updated version of your full documentation, enhanced to include the configuration and role of the dpd_exec module for dynamic discovery and provisioning of home servers via DNS (e.g., NAPTR), without altering the default exec behavior.

⸻

Dynamic Home Servers in v3

FreeRADIUS has some support for dynamic home servers, with certain limitations. This includes the ability to dynamically resolve home servers from DNS (e.g., via NAPTR) and load them into the server at runtime using a custom script.

⸻

Configuration

Enable dynamic home servers in proxy.conf:

```
proxy server {
	...
	dynamic = true
	...
	directory = ${raddb}/home_servers/
}
```

This ensures internal data structures are thread-safe for updates. Be aware that on high-load proxies, lock contention can cause slowdowns.

The directory `${raddb}/home_servers/` must contain only dynamic home server definitions:

```
home_server example.com {
	...
}
```

Each file must:
	•	Be named exactly after the home server (e.g., example.com)
	•	Contain exactly one home_server block with the matching name
	•	Optionally `$INCLUDE tls.conf` for RadSec configuration

Control Socket

Ensure the sites-enabled/control virtual server is enabled, and radmin has read/write access. This is mandatory for runtime server management.

⸻

Adding a New Home Server Dynamically

To add a server while FreeRADIUS is running:
	1.	Create the home_server definition in ${raddb}/home_servers/example.com
	2.	Load it:

`radmin -e "add home_server file ${raddb}/home_servers/example.com"`

If successful, it will be immediately available.

⸻

Deleting a Home Server

`radmin -e "del home_server file example.com auth"`

This deletes by name and type (auth, acct, etc), not file path.

⸻

Listing All Home Servers

`radmin -e "show home_server list all"`


⸻

Limitations
	•	Deleted dynamic home servers are not freed (memory grows over time)
	•	They cannot be added to pools or realms
	•	No failover handling
	•	No TTL tracking — server does not auto-refresh DNS

⸻

Proxying to a Home Server

```
update control {
	Home-Server-Name := "example.com"
}
```

⸻

Checking if a Home Server Exists

`%{home_server_dynamic:name}`

Returns:
	•	"" → not found
	•	"0" → static
	•	"1" → dynamic

⸻

Dynamic DNS Provisioning (DPD) via dpd_exec

To automate adding home servers via DNS discovery, configure an exec module named `dpd_exec`.

1. Define `mods-available/dpd_exec`

```
exec dpd_exec {
	wait = yes
	input_pairs = request
	shell_escape = yes
	timeout = 10
	program = "%{config:confdir}/mods-config/realm/freeradius-naptr-to-home-server.sh -d %{config:confdir} %{regex:User-Name:^.*@(.*)$:\1}"
}
```

> This has to be done this way because this script requires `wait = yes`, exec by default doesn't, and we need to execute a custom program.

This script:
	•	Performs DNS NAPTR queries
	•	Writes home_server config into the correct file
	•	Calls radmin to load it

Enable it:

```
ln -s ../mods-available/dpd_exec ../mods-enabled/
```

Ensure the script is executable:

```
chmod +x /etc/freeradius/mods-config/realm/freeradius-naptr-to-home-server.sh
```

2. Use in authorize section
```
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
					Temp-Home-Server-String := "%{dpd_exec}"
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

⸻

Maintenance of Dynamic Servers

Because FreeRADIUS does not track DNS TTLs or revalidate dynamic server definitions, periodic maintenance is required:

Recommended Daily Maintenance

# Remove all dynamic home servers (except tls.conf)

```
rm -f $(ls -1 raddb/home_servers | grep -v tls.conf)
```

# Optionally refresh CRLs and restart the server

```
systemctl restart freeradius
```

This ensures:
	•	Updated DNS entries are picked up
	•	Expired servers are purged
	•	CRL or certificate changes are applied
