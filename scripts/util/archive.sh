#!/bin/bash
#
# archive.sh	  Packet (detail) log rotation and archiving script.
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; either version 2 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#	Copyright (C) 2008-2018 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
#	Copyright (C) 2018 The FreeRADIUS Project http://www.freeradius.org

# Logging and archive paths
: ${LOG_DIR:='/var/log/freeradius/radacct/packets'}
: ${ARCHIVE_DIR:='/var/log/freeradius/archive'}

# How many days do we keep logs for
: ${LOG_R_DAYS:=5}
# How many days are logs exempt from archival or deletion
: ${LOG_E_DAYS:=1}

# The expression we use to match folders and archives
DATE_EXPR='^[1-2][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]$'
DATE_EXPR_ARC='^[1-2][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]\.tar\.xz$'

# Whether we should be verbose
VERBOSE=0

# What are we running on (so many date variations)
PLATFORM=`uname`

# Some very basic logging functions
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
	if [ "$PLATFORM" = 'SunOS' ];then
		perl -le 'print time()'
	else
		date +%s
	fi
}

# Output directory name $1 days ago.
function past_date
{
	if [ -z "$1" ]; then
		date +%G%m%d
		exit
	else
		# Date works fine on Linux but not on old versions of Solaris
		if [ "$PLATFORM" = 'SunOS' ]; then
			awk "BEGIN { print strftime(\"%G%m%d\", `expr \`unix_now\` - $1 \* 86400`)}"
		else
			date -d @`expr \`unix_now\` - $1 \* 86400` +%G%m%d;
		fi
	fi
}

function show_help
{
	INFO $(basename $0)" [options]"
	INFO "  -d <dir>          Log directory - defaults to \"${LOG_DIR}\"."
	INFO "  -a <dir>          Archive dir - defaults to \"${ARCHIVE_DIR}\"."
	INFO "  -r <days>         How long we retain files for - defaults to ${LOG_R_DAYS} day(s)."
	INFO "  -e <days>         How many days we delay compression - defaults to ${LOG_E_DAYS} day(s)."
	INFO "  -v		  Print debugging information."
	INFO ""
	INFO "Directory structure must be in the format: <prefix>/<yyyy>-<mm>-<dd>/*"
}

while getopts "h?H:d:a:r:e:" opt; do
	case "$opt" in
	h|\?)
		show_help
		exit 0
	;;

	v)
		VERBOSE=1
	;;

	d)
		LOG_DIR="$OPTARG"
	;;

	a)
		ARCHIVE_DIR="$OPTARG"
	;;

	r)
		LOG_R_DAYS="$OPTARG"
	;;

	e)
		LOG_E_DAYS="$OPTARG"
	;;
	esac
done

# Check existence of relevant directories
if [ -d "$LOG_DIR" -a -r "$LOG_DIR" ]; then
	cd $LOG_DIR
	if [ ! -d "$ARCHIVE_DIR" ]; then
		DEBUG "Creating archive dir '$ARCHIVE_DIR'"
		if ! mkdir $ARCHIVE_DIR; then
			ERROR "Can't create archive dir '$ARCHIVE_DIR'"
			exit 64
		fi
	fi
else
	ERROR "Can't read log directory '$LOG_DIR'"
	exit 64
fi

E_DATE=$(past_date $LOG_E_DAYS` ; ERROR "Logs after $E_DATE will be ignored")
R_DATE=$(past_date $LOG_R_DAYS` ; ERROR "Logs and archives prior to $R_DATE will be deleted")

# Remove old archives
for ARCDD in $(ls $ARCHIVE_DIR | egrep "$DATE_EXPR_ARC" | cut -d '.' -f 1); do
	ARCFP="$ARCHIVE_DIR/$ARCDD.tar.xz"
	if [ "$R_DATE" -gt "$ARCDD" ]; then
		DEBUG "Removing '$ARCFP'"
		rm -rf "$ARCFP"
	else
		DEBUG "Ignoring archive '$ARCFP'"
	fi
done

# Archive and remove directories
for LOGDD in $(ls $LOG_DIR | egrep "$DATE_EXPR"); do
	LOGFP="$LOG_DIR/$LOGDD"
	if [ "$E_DATE" -lt "$LOGDD" ]; then
		DEBUG "Ignoring '$LOGFP'"
	elif [ "$R_DATE" -gt "$LOGDD" ]; then
		DEBUG "Removing '$LOGFP'"
		rm -rf $LOGDD
	else
		DEBUG "Archiving '$LOGFP'"
		ARCF="$ARCHIVE_DIR/$LOGDD.tar.xz"
		if ! tar -cJf "$ARCF" "$LOGDD"; then
			DEBUG "Error creating archive for '$LOGFP'"
			exit 65
		elif ! rm -rf $LOGDD; then
			DEBUG "Error removing uncompresed directory"
			exit 65
		fi
	fi
done

exit 0

