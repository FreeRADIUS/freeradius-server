#!/bin/sh
# OUT:Modifyfred

if [ -z $ACTIVE_DIRECTORY_TEST_SERVER ]; then
  echo ACTIVE_DIRECTORY_TEST_SERVER not defined
  exit 1;
fi

#
#  If using a "remote" server, ssh key auth must be set up so
#  samba-tool can be run as root to perform modifications.
#

CMDSTART="sudo "
if [ "$ACTIVE_DIRECTORY_TEST_SERVER" != "127.0.0.1" ]; then
CMDSTART="ssh root@$ACTIVE_DIRECTORY_TEST_SERVER "
fi

#
#  Create a group, computer and user.  Samba will notify about all
#  three, the filter in the sync config means only the user will be processed.
#

${CMDSTART}samba-tool group add dummy > /dev/null
${CMDSTART}samba-tool computer create test_workstation > /dev/null
${CMDSTART}samba-tool user create fred asdf_1234 > /dev/null
