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
/root/schema_freeradius.ldif:
    file.managed:
        - source: salt://ldap/schema_freeradius.ldif

# Add FreeRADIUS schema
add_fr_schema:
    cmd.run:
        - name: "ldapadd -Y EXTERNAL -H ldapi:/// -f /root/schema_freeradius.ldif"
        - cwd: /root/
        - unless: "/usr/bin/ldapsearch -Y EXTERNAL -H ldapi:/// -b cn={4}radius,cn=schema,cn=config -s base"

# Create base structure in LDAP
build_base_structure:
    cmd.run:
        - name: "/usr/bin/ldapadd -Y EXTERNAL -H ldapi:/// -f /root/base.ldif"
        - cwd: /root/
        - unless: "/usr/bin/ldapsearch -Y EXTERNAL -H ldapi:/// -b dc=example,dc=com -s base"
