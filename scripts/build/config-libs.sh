#!/bin/sh
#
#  Parse the configuration files, and print out the list of libraries
#  that the configuration will load.
#
#  See src/tests/all.mk, function TEST_CONFIG_LIBS for more information.
#
#  this script does not read the configuration as such, but instead
#  looks for a few standard patterns:
#
#	$INCLUDE .../mods-enabled/NAME		-> rlm_NAME.la
#	a module declared in modules { }		-> rlm_<type>.la
#	namespace = NAME			-> process_NAME.la
#	transport = PROTO inside that server	-> proto_NAME.la, proto_NAME_PROTO.la
#
#  The output is a list of candidates, and may name something which is
#  not a real target.  The caller must filter the list through
#  ALL_TGTS, which drops both targets which don't exist, and targets
#  which were not built as part of this run.
#
#  Usage: config-libs.sh <config file> [<config file> ...]
#
#  Copyright (C) 2026 Network RADIUS SAS (legal@networkradius.com)
#
#  $Id$
#
######################################################################

for file in "$@"; do
	[ -f "$file" ] || continue

	awk '
	BEGIN	{ depth = 0; modules_at = -1; ns = ""; ns_at = -1 }
	{
		line = $0
		sub(/#.*/, "", line)
		gsub(/^[ \t]+|[ \t]+$/, "", line)
		if (line == "") next

		#
		#  An explicitly enabled module.
		#
		if (line ~ /\$INCLUDE[ \t]+.*mods-enabled\//) {
			name = line
			sub(/.*mods-enabled\//, "", name)
			sub(/[ \t].*/, "", name)
			if (name != "") print "rlm_" name ".la"
		}

		#
		#  A virtual server names the process module which drives it.
		#
		if (line ~ /^namespace[ \t]*=/) {
			ns = line
			sub(/^namespace[ \t]*=[ \t]*/, "", ns)
			sub(/[ \t].*/, "", ns)
			ns_at = depth
			if (ns != "") print "process_" ns ".la"
		}

		#
		#  A listener names its transport, which gives the two proto
		#  libraries: the protocol itself and the transport under it.
		#
		if ((line ~ /^transport[ \t]*=/) && (ns != "")) {
			t = line
			sub(/^transport[ \t]*=[ \t]*/, "", t)
			sub(/[ \t].*/, "", t)
			if (t != "") {
				print "proto_" ns ".la"
				print "proto_" ns "_" t ".la"
			}
		}

		#
		#  A module declaration sits at the top level of modules { }.
		#  Anything deeper is one of the module s own subsections.
		#
		if ((modules_at >= 0) && (depth == modules_at)) {
			if (line ~ /^[a-z_][a-z_0-9]*([ \t]+[A-Za-z0-9_.-]+)?[ \t]*\{/) {
				m = line
				sub(/[ \t{].*/, "", m)
				print "rlm_" m ".la"
			}
		}

		if ((line ~ /^modules[ \t]*\{/) && (modules_at < 0)) modules_at = depth + 1

		opens = gsub(/\{/, "{", line)
		closes = gsub(/\}/, "}", line)
		depth += opens - closes

		if ((modules_at >= 0) && (depth < modules_at)) modules_at = -1
		if ((ns_at >= 0) && (depth < ns_at)) { ns = ""; ns_at = -1 }
	}
	' "$file"
done | sort -u
