Change "dc=samba4,dc=internal" to your LDAP base DN,
then install with:

ldbmodify -H /usr/local/samba/private/sam.ldb freeradius-attrs.ldif \
    --option="dsdb:schema update allowed"=true
ldbmodify -H /usr/local/samba/private/sam.ldb freeradius-classes.ldif \
    --option="dsdb:schema update allowed"=true

These files were created by scripts/ldap/schema_to_samba.py, then
split into two because the attributes must be loaded in a separate
operation to the classes which use them.
