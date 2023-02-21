#!/bin/sh -e
#
# ### This is a script to setup an exim smtp server for testing rlm_smtp
#

#
# Declare the important path variables
#

# Base Directories
BASEDIR=$(git rev-parse --show-toplevel)
BUILDDIR="${BASEDIR}/build/ci/exim4"

# Directories for exim processes
RUNDIR="${BUILDDIR}/run"
MAILDIR="${BUILDDIR}/mail"
MAILDELIVERYDIR="${BUILDDIR}/mail_delivery_test"
LOGDIR="${BUILDDIR}/eximlog"
SPOOLDIR="${BUILDDIR}/spool"
CERTDIR="${BUILDDIR}/certs"
CERTSRCDIR="${BASEDIR}/raddb/certs"
PASSWORD="whatever"

# Important files for running dovecot
CONF="${BUILDDIR}/exim.conf"

#
# Prepare the directories and files needed for running exim
#

# Stop any currently running exim instance
echo "Checking for a running exim instance"
if [ -e "${RUNDIR}/exim.pid" ]
then
	echo "Stopping the current exim instance"
	kill "$(cat ${RUNDIR}/exim.pid)" || true
	rm -r "${BUILDDIR}"
fi

# Create the directories
mkdir -p "${BUILDDIR}" "${RUNDIR}" "${MAILDELIVERYDIR}" "${MAILDIR}" "${LOGDIR}" "${SPOOLDIR}" "${CERTDIR}"

# Create the certificate
echo "Generating the certificates"
openssl pkcs8 -in ${CERTSRCDIR}/rsa/server.key -passin pass:${PASSWORD} -out ${CERTDIR}/server.key
cp ${CERTSRCDIR}/rsa/server.pem ${CERTDIR}/server.pem
cp ${CERTSRCDIR}/rsa/ca.pem ${CERTDIR}/ca.pem

# Create exim.conf file
echo "Generating the exim configuration file"
touch "${CONF}"

# Build exim.conf
echo "
#
# Set the user to run as - use -DEXIMUSER=user -DEXIMGROUP=group
# rather than defining them here.
#
#EXIMUSER = username
#EXIMGROUP = groupname
LISTEN=127.0.0.1
#
#
#  Where all the config files, logs, etc are. See also the
#  "keep_environment" setting below.
#
MAIL_DIR = ${MAILDIR}
PASS_DIR = ${BUILDDIR}
pid_file_path = ${RUNDIR}/exim.pid
log_file_path = ${LOGDIR}/%s
spool_directory = ${SPOOLDIR}
exim_user = EXIMUSER
exim_group = EXIMGROUP
daemon_smtp_ports = 2525 : 2465
local_interfaces = LISTEN
deliver_drop_privilege
keep_environment = ${BASEDIR}
tls_advertise_hosts = *
tls_certificate = ${CERTDIR}/server.pem
tls_privatekey = ${CERTDIR}/server.key
tls_verify_certificates = ${CERTDIR}/ca.pem
#tls_dhparam = ${CERTDIR}/dh
tls_on_connect_ports = 2465
tls_verify_hosts = *
tls_require_ciphers = \${if =={\$received_port}{2525}\
                           {NORMAL:%COMPAT}\
                           {SECURE128}}
received_header_text =
acl_smtp_rcpt = accept
begin acl
begin routers
#
#  Only one router - we'll send everything to the \"local_delivery\"
#  transport.
#
local_delivery:
  driver = accept
  transport = local_delivery
  no_more
begin transports
#
# Transport to write a file - this will write mail to an mbox.
#
local_delivery:
  driver = appendfile
  create_directory
  directory_mode = 0750
  mode = 0600
#
#  File to write to.
#  Files need to be pre-configured in the untaint file to get past exim's tainting rules.
#
  file = \${if eq {\$h_x-testname:}{} {MAIL_DIR/\${lookup{\$local_part}lsearch{PASS_DIR/untaint}}}{MAIL_DIR/\$h_x-testname:}}
begin rewrite
begin retry
*                *                F,1s,1m
begin authenticators

plain_server:
  driver = plaintext
  public_name = PLAIN
  server_condition = "\${if eq{\$auth3}{\${extract{1}{:}{\${lookup{\$auth2}lsearch{PASS_DIR/passwd}{\$value}{*:*}}}}}{1}{0}}"
  server_set_id = \$auth2
  server_prompts = :

" >"${CONF}"

echo "Generating password file"
echo "Bob:Saget" > ${BUILDDIR}/passwd

echo "Generating lookup file to untaint data"
echo "conf_recipient_1: conf_recipient_1" > ${BUILDDIR}/untaint
echo "conf_recipient_2: conf_recipient_2" >> ${BUILDDIR}/untaint
echo "smtp_attachment_receiver: smtp_attachment_receiver" >> ${BUILDDIR}/untaint
echo "crln_test_receiver: crln_test_receiver" >> ${BUILDDIR}/untaint
echo "conf-stringparse-recipient: conf-stringparse-recipient" >> ${BUILDDIR}/untaint
echo "stringparse_test_receiver: stringparse_test_receiver" >> ${BUILDDIR}/untaint
echo "smtp_delivery_receiver: smtp_delivery_receiver" >> ${BUILDDIR}/untaint
echo "smtp_recipient_request: smtp_recipient_request" >> ${BUILDDIR}/untaint
echo "smtp_to_request_1: smtp_to_request_1" >> ${BUILDDIR}/untaint
echo "smtp_to_request_2: smtp_to_request_2" >> ${BUILDDIR}/untaint
echo "smtp_to_request_3: smtp_to_request_3" >> ${BUILDDIR}/untaint
echo "smtp_cc_request_1: smtp_cc_request_1" >> ${BUILDDIR}/untaint
echo "smtp_cc_request_2: smtp_cc_request_2" >> ${BUILDDIR}/untaint

echo "Generating the file attachment"
# Generate a file for test email attachments
dd if=/dev/urandom bs=200 count=1 2>/dev/null | base64 | tr -d '\n'> ${BUILDDIR}/testfile

EXIMUSER=$(id -u)
if [ $EXIMUSER -eq 0 ] ; then
       EXIMUSER=$(id -u Debian-exim)
       EXIMGROUP=$(id -g Debian-exim)
else
       EXIMGROUP=$(id -g)
fi;

chown -R :$EXIMGROUP "${BUILDDIR}" "${RUNDIR}" "${MAILDELIVERYDIR}" "${MAILDIR}" "${LOGDIR}" "${SPOOLDIR}" "${CERTDIR}"
chmod g+w -R "${RUNDIR}" "${MAILDELIVERYDIR}" "${MAILDIR}" "${LOGDIR}" "${SPOOLDIR}"
chmod g+r -R "${CERTDIR}"

#
# Run the exim instance
#
echo "Starting exim"
exim -C ${CONF} -bd -DEXIMUSER=$EXIMUSER -DEXIMGROUP=$EXIMGROUP
echo "Running exim on port 2525, accepting all local connections"
