#!/bin/bash
# Script used to test Dockerfile.systemd containers doing
# the basic tests building the package with systemd support
# and validate if it is possible to start/stop/restart the
# service using "systemctl $opt $radius"
#

#set -fx

build_dir="$1"
build_log="/tmp/test-systemd-$$.log"
container_host="$HOSTNAME"

if [ ! -d "$build_dir" ]; then
	echo "ERROR: Invalid directory: $build_dir"
	exit 1
fi

#
#	1. Which OS?
#
if [ -f /etc/debian_version ]; then
	radius_bin="freeradius"
	cmd_pkg_build="make deb"
	cmd_pkg_install="dpkg -i ../*.deb"
	cmd_pkg_uninstall="dpkg -P $(dpkg -l | awk '/freeradius/ {print $2}')"
elif [ -f /etc/redhat-release ]; then
	radius_bin="radiusd"
	cmd_pkg_build="make rpm"
	cmd_pkg_install="yum install -y rpmbuild/RPMS/x86_64/*.rpm"
	cmd_pkg_uninstall="rpm -e $(rpm -aq | grep radius)"
else
	echo "(!!) Unknown Operation System!"
	uname -a
	exit 1
fi

#
#	2. Build the package
#
echo "(##) Changing to ${build_dir}"
pushd ${build_dir} 1> /dev/null

echo "(##) Building the packages calling '${cmd_pkg_build}' in ${container_host}"
if ! ${cmd_pkg_build} 1>> ${build_log} 2>&1; then
	echo "(!!) Problems to execute '${cmd_pkg_build}' in ${container_host}"
	cat $build_log
	exit 2
fi

echo "(##) Removing any previous installation calling '${cmd_pkg_uninstall}'"
${cmd_pkg_uninstall} 1> /dev/null 2>&1

echo "(##) Installing the packages calling '${cmd_pkg_install}' in ${container_host}"
if ! ${cmd_pkg_install} 1>> ${build_log} 2>&1; then
	echo "(!!) Problems to execute '${cmd_pkg_install}' in ${container_host}"
	cat $build_log
	exit 3
fi

#
#	3. Perform the tests
#

# Is it active?
echo "(##) Checking if the process ${radius_bin} is activated"
ret=$(systemctl is-active ${radius_bin})
if [ "$ret" != "active" ]; then
	if ! systemctl start ${radius_bin}; then
		journalctl -xe | tail -50
		exit 4
	fi
fi

# Stop
echo "(##) Stop the service ${radius_bin}"
if ! systemctl stop ${radius_bin}; then
	echo "(!!) ERROR: Problems to stop the service ${radius_bin}"
	journalctl -xe | tail -50
	exit 5
fi

# Start
echo "(##) Start the service ${radius_bin}"
if ! systemctl start ${radius_bin}; then
	echo "(!!) ERROR: Problems to start the service ${radius_bin}"
	journalctl -xe | tail -50
	exit 6
fi

# Save the PID
pid_cur=$(pidof ${radius_bin})

# Restart the service
echo "(##) Restart the service ${radius_bin}"
if ! systemctl restart ${radius_bin}; then
	echo "(!!) ERROR: Problems to test ${docker_cnt}"
	journalctl -xe | tail -50
	exit 7
fi

# Just print the process
echo "(##) Listing all processes"
ps axuf --cols=100

# Check the pid
pid_new=$(pidof ${radius_bin})
if [ "$pid_cur" == "$pid_new" ]; then
	echo "(!!) ERROR: Problems to restart the service using systemd."
	journalctl -xe | tail -50
	exit 8
fi

echo "(##) Success with Systemd/freeradius-server."

exit 0
