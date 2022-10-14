#!/bin/sh

ROOTDN="cn=Directory Manager"

if [ "x$USE_DOCKER" = "xtrue" ]; then
	dsconf -D "${ROOTDN}" -w "secret123" "${PERSISTENT_SEARCH_TEST_SERVER}" backend create --suffix 'dc=example,dc=com' --be-name localhost
	dsidm -D "${ROOTDN}" -w "secret123" "${PERSISTENT_SEARCH_TEST_SERVER}" -b 'dc=example,dc=com' initialise

else

	# Build template config file
	cat <<-EOF > /tmp/instance.inf
	[general]
	config_version = 2

	[slapd]
	root_dn = ${ROOTDN}
	root_password = secret123
	port = 3892
	secure_port = 6362
	self_sign_cert = True

	[backend-userroot]
	suffix = dc=example,dc=com
	sample_entries = yes
	require_index = yes
	EOF

	# Initialise ds instance from config
	sudo dscreate from-file /tmp/instance.inf

fi

# Load base entries
count=0
while [ $count -lt 10 ] ; do
    if ldapadd -x -H "${PERSISTENT_SEARCH_TEST_SERVER}" -D "${ROOTDN}" -w "secret123" -f src/tests/salt-test-server/salt/ldap/base3.ldif ; then
        break 2
    else
        count=$((count+1))
        sleep 1
    fi
done

if [ $? -ne 0 ]; then
	echo "Error configuring server"
	exit 1
fi


#
#  Some random commands that are used setting up 389ds...
#
#  Get config
#    dsconf -D 'cn=Directory Manager' -w secret123 ldap://threeds:3389/ config get
#
#  List databases:
#    dsconf -D 'cn=Directory Manager' -w secret123 ldap://threeds:3389/ backend suffix list
#    dc=example,dc=com (localhost)
# 
#  Create some basic data in the directory:
#    dsidm -D 'cn=Directory Manager' -w secret123 ldap://threeds:3389/ -b 'dc=example,dc=com' initialise
#
#  Add a new user:
#    dsidm -D 'cn=Directory Manager' -w secret123 ldap://threeds:3389/ -b 'dc=example,dc=com' user create --uid manager --cn manager --displayName manager --uidNumber 1999 --gidNumber 1999 --homeDirectory /home/manager
#
#  Set user password:
#    dsidm -D 'cn=Directory Manager' -w secret123 ldap://threeds:3389/ -b 'dc=example,dc=com' account reset_password uid=manager,ou=people,dc=example,dc=com secret123
# 
#
#  Give permissions for user to edit anything:
#    cat <<EOF > permissions.ldif
#    dn: dc=example,dc=com
#    changetype: modify
#    add: aci
#    aci: (targetattr="*")(target="ldap:///dc=example,dc=com")(version 3.0; acl "allow whatever"; allow (all)(userdn="ldap:///uid=manager,ou=people,dc=example,dc=com");)
#    EOF
# 
#    ldapmodify -D 'cn=Directory Manager' -w secret123 -H "ldap://threeds:3389/" -x -f permissions.ldif
# 
#  List ACLs:
#    ldapsearch -D 'cn=Directory Manager' -w secret123 -H "ldap://threeds:3389/" -x -b 'dc=example,dc=com' '(aci=*)' aci
# 
