#!/bin/sh -e

#
# ### This is a script to setup a dovecot imap server for testing rlm_imap
#

#
# Declare the important path variables
#

# Directories For storing dovecot setup files
BASEDIR=$(git rev-parse --show-toplevel)
BUILDDIR="${BASEDIR}/build/ci/dovecot"
CERTDIR="${BASEDIR}/raddb/certs/rsa"
ETCDIR="${BUILDDIR}/etc"

# Directories for running dovecot 
RUNDIR="${BUILDDIR}/run"
TLSRUNDIR="${BUILDDIR}/tls_run"
MAILDIR="${ETCDIR}/dovecot_mail"
LOGDIR="${BUILDDIR}/log"

# Important files for running dovecot 
CONF="${ETCDIR}/dovecot.conf"
TLSCONF="${ETCDIR}/tls_dovecot.conf"
PASSPATH="${ETCDIR}/dovecot.passwd"

# The path to the two log files
LOGPATH="${LOGDIR}/dovecot.log"
LOGINFOPATH="${LOGDIR}/dovecot-info.log"

# Used for creating `imap-stop.sh`
TRAVISDIR="${BASEDIR}/scripts/travis"

#
# Create all the necessary files
#

# Make the build directory
mkdir -p "${BUILDDIR}"

# Create folders for running, logging, and all parents
mkdir -p "${ETCDIR}"
mkdir -p "${LOGDIR}"
mkdir -p "${RUNDIR}"
mkdir -p "${TLSRUNDIR}"
mkdir -p "${MAILDIR}"

# Make sure there is a password file
touch  "${PASSPATH}"

# Make sure there are log files
touch "${LOGPATH}"
touch "${LOGINFOPATH}" 

#
# Add users to the password file
#

# Generate passwords for the users
USER1P=$(doveadm pw -p test1 -s CRYPT)
USER2P=$(doveadm pw -p test2 -s CRYPT)
USER3P=$(doveadm pw -p test3 -s CRYPT)

# Add user password combinations
echo "\
user1:${USER1P}:::::: 
" >"${PASSPATH}"

echo "\
user2:${USER2P}:::::: 
" >>"${PASSPATH}"

echo "\
user3:${USER3P}:::::: 
" >>"${PASSPATH}"

#
# Configure instance specific dovecot information
#

# Load the template config file for both dovecot instances
cp "${TRAVISDIR}/dovecot/fr_dovecot.conf" "${CONF}"
cp "${TRAVISDIR}/dovecot/fr_dovecot.conf" "${TLSCONF}"

# Configure the specifics for the non_tls dovecot server
echo "
instance_name = "fr_dovecot"

ssl = no

base_dir = ${RUNDIR}

service imap-login {
	process_min_avail = 16
	user = ${USER} 
	chroot =
	inet_listener imap {
		port = 1430
	}
} \
" >> "${CONF}"

# Configure the specifics for the tls dovecot server
echo "
instance_name = "fr_tls_dovecot"


base_dir = ${TLSRUNDIR}

service imap-login {
	process_min_avail = 16
	user = ${USER}
	chroot =
	inet_listener imap {
		port = 1431
	}
	inet_listener imaps {
		port = 1432
	}
} 
# TLS specific configurations
ssl = required
ssl_protocols = !SSLv3
ssl_cert = <${CERTDIR}/server.pem
ssl_key = <${CERTDIR}/server.key
ssl_key_password = whatever
ssl_ca = <${CERTDIR}/ca.pem

verbose_ssl = yes

# ssl_client_ca_file = <${CERTDIR}/ca.pem
# ssl_verify_client_cert = yes
# auth_ssl_require_client_cert=yes
" >> "${TLSCONF}"

# Make sure there is a clean imap-stop.sh file
> ${TRAVISDIR}/imap-stop.sh

#
# Add system specific dovecot information
#
for CONFPATH in $CONF $TLSCONF
do
# Add the path to the log files
echo "
log_path = ${LOGPATH}
info_log_path = ${LOGINFOPATH} \
" >> "${CONFPATH}"

# Add the Password File to the config
echo  "
passdb {
	driver = passwd-file
	args = ${PASSPATH}
}" >> "${CONFPATH}"

# Add the mail directory to the config
echo "
mail_location = maildir:${MAILDIR} \
" >> "${CONFPATH}"

# Set user for permissions
echo "
default_internal_user = ${USER}
default_login_user = ${USER} \
" >> "${CONFPATH}"

#Configure the user mailbox privileges
echo "
userdb {
	driver = static
	args = uid=${USER} gid=${USER}
} \
" >> "${CONFPATH}"

# Run the imap server
echo "Starting a dovecot imap server at ${CONFPATH}"

if ! dovecot -c ${CONFPATH}; then
	echo "The server failed to start up. Here is fr_dovecot.log"
	cat ${LOGPATH}
	echo "And here is fr_dovecot-info.log"
	cat ${LOGINFOPATH}
fi

echo "dovecot -c ${CONFPATH} stop" >> "${TRAVISDIR}/imap-stop.sh"

done

exit 0
