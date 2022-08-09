# Dynamic Home Servers

This directory is where dynamic home servers are stored.

Each file in the directory should be named for the home server domain
name.  In the above example, the filename should be
`${raddb}/home_servers/example.com`.  The name of the home server in
the file should be the same as the filename which contains the home
server definition.

Each file in the directory should have one, and only one,
`home_server` definition.

See doc/configuration/dynamic_home_servers.md for more information on
dynamic home_servers.

See also `mods-config/realm/freeradius-naptr-to-home-server.sh` for a
sample shell script which creates home servers.

This directory also has a `tls.conf` file which contains site-specific
TLS configuration for home servers.
