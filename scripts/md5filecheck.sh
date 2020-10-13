#!/bin/bash
# Copyright 2020 NetworkRADIUS SARL (legal@networkradius.com)
# Author: Jorge Pereira <jpereira@freeradius.org>
# Simple wrapper for md5 checksum tool.

function _md5_tool() {
	_file1="$1"
	_file2="$2"
	_md5_bin="md5sum"

	[ "$(uname -s)" = "Darwin" ] &&	_md5_bin="md5"

	if [ ! -f "${_file1}" ]; then
		echo "Such file ${_file1} not found"
		exit 1
	fi

	if [ ! -f "${_file2}" ]; then
		echo "Such file ${_file2} not found"
		exit 1
	fi

	_hash1="$(${_md5_bin} ${_file1} | grep -E -o '[0-9a-f]{32}')"
	_hash2="$(${_md5_bin} ${_file2} | grep -E -o '[0-9a-f]{32}')"

	if [ "${_hash1}" != "${_hash2}" ]; then
		echo "Invalid md5 hash between ${_file1} != ${_file2}"
		echo "${_file1} = ${_hash1}"
		echo "${_file2} = ${_hash2}"
		return 1
	fi

	return 0
}

# main()
if [ $# -lt 2 ]; then
	echo "Usage: $0 <file1> <file2>"
	exit 1
fi

if ! _md5_tool "$1" "$2"; then
	exit 1
fi

exit 0
