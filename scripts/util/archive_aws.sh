#!/bin/bash

#  aws_archive.sh      AWS Log upload script.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#  Copyright (C) 2018 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
#  Copyright (C) 2018 The FreeRADIUS Project http://www.freeradius.org

# Set AWS credentials
: ${AWS_ACCESS_KEY_ID:=}
: ${AWS_SECRET_ACCESS_KEY:=}
: ${AWS_BUCKET:=s3://}

# Default options
: ${COMPRESS:=false}
: ${LOG_R_DAYS:=0}
: ${VERBOSE:=0}
: ${LOG_DIR=/var/log/radius}

function ERROR
{
	echo "$@" 1>&2;
}

function INFO
{
	echo "$@"
}

function DEBUG
{
	if [ $VERBOSE -gt 0 ]; then
		echo "$@"
	fi
}

function unix_now
{
	if [ "$PLATFORM" = 'SunOS' ]; then
		perl -le 'print time()'
	else
		date +%s
	fi
}

# Output date $1 days in the future.
function future_date
{
	if [ -z "$1" ]; then
		date +%Y-%m-%dT%H:%M:%S
		exit
	else
		# Date works fine on Linux but not on old versions of Solaris
		if [ "$PLATFORM" = 'SunOS' ]; then
			awk "BEGIN { print strftime(\"%Y-%m-%dT%H:%M:%S\", `expr \`unix_now\` + $1 \* 86400`)}"
		else
			date -d @`expr \`unix_now\` + $1 \* 86400` +%Y-%m-%dT%H:%M:%S;
		fi
	fi
}

function check_binaries
{
	need_bin="aws lsof find rm"

	if $COMPRESS; then
		need_bin+=" bzip2 mktemp"
	fi

	if [ "$LOG_R_DAYS" -gt 0 ]; then
		need_bin+=" date"
	fi

	# Check we have everything we need
	for bin in ${need_bin}; do
		if ! which $bin > /dev/null; then
			ERROR "Can't find '${bin}' binary.  Ensure it's available in the current PATH"
			exit 64
		fi
	done
}

function show_help
{
	INFO $(basename $0)" [options]"
	INFO "  -a                Append to existing log files."
	INFO "  -d <dir>          Log directory - defaults to \"${LOG_DIR}\"."
	INFO "  -h                Display this help message."
	INFO "  -r <days>         Retain log files for N days in AWS."
	INFO "  -z                bzip files before uploading."
	INFO "  -v                Print debugging information."
}

while getopts "h?ad:r:zv" opt; do
	case "$opt" in
	h|\?)
		show_help
		exit 0
		;;

	a)
		APPEND=true
		;;

	d)
		LOG_DIR="$OPTARG"
		;;

	r)
		LOG_R_DAYS="$OPTARG"
		;;

	v)
		VERBOSE=1
		;;

	z)
		COMPRESS=true
		;;
	esac
done

# Check for binaries
check_binaries

# Get expiry time
if [ $LOG_R_DAYS -gt 0 ]; then
	retain_until="$(future_date ${LOG_R_DAYS})"
	expires_arg=" --expires ${retain_until}"
fi

# Get a temporary directory
if $APPEND; then tmpdir=$(mktemp -d); fi

# For any log files sitting in the log directory see if they're still in use
# and if they're not, compress them and upload them to AWS.
copied=0
while read -r in_file; do
	# The file is still in use, don't move it
	if lsof -lnP -- $in_file > /dev/null; then
		DEBUG "Skipping ${in_file} (still in use)"
		continue
	fi

	# Compress the input file
	if $COMPRESS; then
		if [ "${in_file#*.}" != 'bz2' ]; then
			DEBUG "Compressing \"${in_file}\""
			if ! bzip2 "${in_file}"; then
				ERROR "Failed compressing ${in_file}, skipping..."
				continue
			fi
			in_file="${in_file}.bz2"
		fi
	fi

	# Path to our destination in the AWS bucket
	aws_file="${AWS_BUCKET}/${in_file}"

	#
	#  Check if the file already exists in AWS and append to it if it does
	#
	if $APPEND && aws s3 ls "${aws_file}" > /dev/null; then
		DEBUG "Retrieving previous file \"${aws_file}\""

		tmp_file="${tmpdir}/$(basename \"$aws_file\")"
		if ! aws s3 cp "${aws_file}" "${tmp_file}" > /dev/null; then
			ERROR "Failed retrieving ${aws_file}, skipping..."
			continue
		fi

		# Concatenate the two files together.  This works for bzip files too
		DEBUG "Concatenating \"${in_file}\" with \"${tmp_file}\""
		if ! cat "${in_file}" >> "${tmp_file}" || ! mv "${tmp_file}" "${in_file}"; then
			ERROR "Failed merging previous AWS file \"${tmp_file}\" with input file \"${in_file}\""
			continue
		fi
	fi

	if ! aws s3 mv "${in_file}" "${aws_file}" ${expires_arg} > /dev/null; then
		ERROR "aws s3 mv \"${in_file}\" \"${aws_file}\" ${expires_arg} failed, skipping..."
		continue
	fi

	copied=$((copied + 1))
done < <(find "$LOG_DIR" -type f)

# Cleanup our temporary directory
if $APPEND; then rm -rf "$tmpdir"; fi

if [ $copied -eq 0 ]; then
	DEBUG "No files to process"
elif [ ! -z "$retain_until" ]; then
	DEBUG "Logs will expire at ${retain_until}"
fi

exit 0
