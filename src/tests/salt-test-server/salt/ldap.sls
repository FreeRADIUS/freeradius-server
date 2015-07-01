{% if grains['os'] == 'Ubuntu' %}

# In Ubuntu 14.10, openldap comes with a broken AppArmor profile (can't connect through socket)
# Disable AppArmor alltogether
/etc/init.d/apparmor teardown:
   cmd.run

update-rc.d -f apparmor remove:
   cmd.run

{% endif %}

slapd:
    pkg.installed

ldap-utils:
    pkg.installed

# Copy ldif file for base structure
/root/base.ldif:
    file.managed:
        - source: salt://ldap/base.ldif

# Copy ldif file for FreeRADIUS schema
/root/freeradius.ldif:
    file.managed:
        - source: salt://ldap/freeradius.ldif

# Copy ldif file for FreeRADIUS clients schema
/root/freeradius-clients.ldif:
    file.managed:
        - source: salt://ldap/freeradius-clients.ldif

# Add FreeRADIUS schema
add_fr_schema:
    cmd.run:
        - name: "ldapadd -Y EXTERNAL -H ldapi:/// -f /root/freeradius.ldif"
        - cwd: /root/
        - unless: "/usr/bin/ldapsearch -Y EXTERNAL -H ldapi:/// -b cn={4}radius,cn=schema,cn=config -s base"

# Add FreeRADIUS clients schema
add_fr_clients_schema:
    cmd.run:
        - name: "ldapadd -Y EXTERNAL -H ldapi:/// -f /root/freeradius-clients.ldif"
        - cwd: /root/
        - unless: "/usr/bin/ldapsearch -Y EXTERNAL -H ldapi:/// -b cn={5}radiusclient,cn=schema,cn=config -s base"

# Create base structure in LDAP
build_base_structure:
    cmd.run:
        - name: "/usr/bin/ldapadd -Y EXTERNAL -H ldapi:/// -f /root/base.ldif"
        - cwd: /root/
        - unless: "/usr/bin/ldapsearch -Y EXTERNAL -H ldapi:/// -b dc=example,dc=com -s base"
