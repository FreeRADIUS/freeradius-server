#!/bin/sh -e

libuv_ver="1.29.1"
libuv_pkg="libuv1_${libuv_ver}-1_amd64.deb"

cassandra_ver="2.13.0"
cassandra_pkgs="cassandra-cpp-driver-dbg_${cassandra_ver}-1_amd64.deb
                cassandra-cpp-driver-dev_${cassandra_ver}-1_amd64.deb
                cassandra-cpp-driver_${cassandra_ver}-1_amd64.deb"

ubuntu_ver="$(lsb_release -rs)"
tmp_dir="/tmp/cassandra-$$"
mkdir -p $tmp_dir

do_exit() {
	rm -rf $tmp_dir
	exit $1
}

# Libuv
libuv_url="https://downloads.datastax.com/cpp-driver/ubuntu/${ubuntu_ver}/dependencies/libuv/v${libuv_ver}/${libuv_pkg}"
if ! wget -q -O "${tmp_dir}/${libuv_pkg}" "${libuv_url}"; then
	echo "ERROR: Failed downloading libuv packages ${libuv_url}"
	do_exit 1
fi

# Cassandra sdk
for _deb in ${cassandra_pkgs}; do
	_url="https://downloads.datastax.com/cpp-driver/ubuntu/${ubuntu_ver}/cassandra/v${cassandra_ver}/${_deb}"

	if ! wget -q -O "${tmp_dir}/${_deb}" "${_url}"; then
		echo "ERROR: Failed downloading packages ${_url}"
		do_exit 1
	fi
done

if ! dpkg -i ${tmp_dir}/*.deb; then
	echo "ERROR: Failed installing packages ${tmp_dir}/*.deb"
	do_exit 1
fi

do_exit 0
