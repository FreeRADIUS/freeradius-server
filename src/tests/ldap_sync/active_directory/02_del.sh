#!/bin/sh
# OUT:Deletebob

if [ -z $ACTIVE_DIRECTORY_TEST_SERVER ]; then
  echo ACTIVE_DIRECTORY_TEST_SERVER not defined
  exit 1;
fi

# If using a "remote" server, ssh key auth must be set up so
# samba-tool can be run as root to perform modifications

CMDSTART="sudo "
if [ "$ACTIVE_DIRECTORY_TEST_SERVER" != "127.0.0.1" ]; then
CMDSTART="ssh root@$ACTIVE_DIRECTORY_TEST_SERVER "
fi

# Add some entries we can then delete
${CMDSTART}samba-tool group add dummy2 > /dev/null
${CMDSTART}samba-tool computer create test_workstation2 > /dev/null
${CMDSTART}samba-tool user create bob asdf_1234 > /dev/null

${CMDSTART}samba-tool group delete dummy2 > /dev/null
${CMDSTART}samba-tool computer delete test_workstation2 > /dev/null
${CMDSTART}samba-tool user disable bob > /dev/null
${CMDSTART}samba-tool user delete bob > /dev/null
