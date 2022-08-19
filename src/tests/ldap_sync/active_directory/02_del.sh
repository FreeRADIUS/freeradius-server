#!/bin/sh

if [ "$ACTIVE_DIRECTORY_TEST_SERVER " = " " ]; then
  echo ACTIVE_DIRECTORY_TEST_SERVER not defined
  exit 1;
fi

# If using a "remote" server, ssh key auth must be set up so
# samba-tool can be run as root to perform modifications

CMDSTART="sudo "
if [ "$ACTIVE_DIRECTORY_TEST_SERVER" != "127.0.0.1" ]; then
CMDSTART="ssh root@$ACTIVE_DIRECTORY_TEST_SERVER "
fi

${CMDSTART}samba-tool group delete dummy > /dev/null
${CMDSTART}samba-tool computer delete test_workstation > /dev/null
${CMDSTART}samba-tool user disable fred > /dev/null
${CMDSTART}samba-tool user delete fred > /dev/null
