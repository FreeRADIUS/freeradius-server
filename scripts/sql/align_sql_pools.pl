#!/usr/bin/perl -Tw

######################################################################
#
#  Copyright (C) 2020 Network RADIUS
#
#  $Id$
#
######################################################################
#
#  Helper script for generating the SQL commands to align the SQL IP pools in a
#  database with a given specification.
#
#  The radippool table is updated is a way that preserves existing leases,
#  provided that the corresponding IP addresses still exist in their pool.
#
#  This script typically receives the output of the generate_pool_addresses.pl
#  script, as follows:
#
#    generate_pool_addresses.pl <options> | align_sqlippools.pl <sql_dialect>
#
#  For example:
#
#    generate_pool_addresses.pl main_pool 10.0.1.0 10.0.1.255 | \
#            align_sqlippools.pl mariadb
#
#    generate_pool_addresses.pl yaml pool_defs.yml existing_ips.txt | \
#            align_sqlippools.pl postgresql
#
#  For the latter example the existing_ips.txt file might be created as
#  follows:
#
#    psql radius -qtAc 'SELECT framedipaddress FROM radippool' > existing_ips.txt
#
#  Note: The generate_pool_addresses.pl script describes the input format
#  expected by this script (as well as the format of the pool_defs.yml and
#  existing_ips.txt files.)
#
#  Output:
#
#  The output of this script is the SQL command sequence for aligning the pools
#  with the definition provided, which you should review before running them
#  against your database.
#

use strict;
use Template;

my %template=load_templates();

if ($#ARGV != 0) {
	print STDERR <<'EOF';
Usage: generate_pool_addresses.pl ... | align_sqlippools.pl <dialect>

EOF
	exit 1;
}

my $dialect=$ARGV[0];

unless (defined $template{$dialect}) {
	print STDERR "Unknown dialect. Pick one of: ";
	print STDERR "$_ " foreach sort keys %template;
	print STDERR "\n";
	exit 1;
}

my @ips=();

my $line = 0;
while (<STDIN>) {
	$line++;

	chomp;

	next if $_ =~ /^#/ || $_ =~ /^\s*$/;

	# The SQL works out what addresses to remove by itself
	next if $_ =~ /^-/;

	(my $action, my $pool_name, my $ip) = $_ =~ /^(.)\s+(.+)\s+([^\s]+)$/;

	unless (defined $ip) {
		warn "Unrecognised line $line: $_";
		next;
	}

	push @ips, { poolname => $pool_name, ip => $ip };

}

my $tt=Template->new();
$tt->process(\$template{$dialect}, {ips => \@ips, batchsize => 100}) || die $tt->error();

exit 0;


#
#  SQL dialect templates
#

sub load_templates {

	my %template;

#
#  MariaDB
#
	$template{'mariadb'} = <<'END_mariadb';
-- Temporary table holds the provided IP pools
DROP TEMPORARY TABLE IF EXISTS radippool_temp;
CREATE TEMPORARY TABLE radippool_temp (
  id                    int(11) unsigned NOT NULL auto_increment,
  pool_name             varchar(30) NOT NULL,
  framedipaddress       varchar(15) NOT NULL,
  PRIMARY KEY (id),
  KEY pool_name_framedipaddress (pool_name,framedipaddress)
);

-- Populate the temporary table
[%- FOREACH m IN ips %]
[%- "\n\nINSERT INTO radippool_temp (pool_name,framedipaddress) VALUES" IF loop.index % batchsize == 0 %]
[%-   IF (loop.index+1) % batchsize == 0 OR loop.last %]
('[% m.poolname %]','[% m.ip %]');
[%-   ELSE %]
('[% m.poolname %]','[% m.ip %]'),
[%-   END %]
[%- END %]

START TRANSACTION;

-- Delete old pools that have been removed
DELETE r FROM radippool r
  LEFT JOIN radippool_temp t USING (pool_name,framedipaddress)
      WHERE t.id IS NULL;

-- Add new pools that have been created
INSERT INTO radippool (pool_name,framedipaddress)
  SELECT pool_name,framedipaddress FROM radippool_temp t WHERE NOT EXISTS (
    SELECT * FROM radippool r
    WHERE r.pool_name=t.pool_name AND r.framedipaddress=t.framedipaddress
  );

COMMIT;
END_mariadb


#
#  PostgreSQL
#
	$template{'postgresql'} = <<'END_postgresql';
-- Temporary table holds the provided IP pools
DROP TABLE IF EXISTS radippool_temp;
CREATE TEMPORARY TABLE radippool_temp (
  pool_name               varchar(64) NOT NULL,
  FramedIPAddress         INET NOT NULL
);
CREATE INDEX radippool_temp_idx ON radippool_temp USING btree (pool_name,FramedIPAddress);

-- Populate the temporary table
[%- FOREACH m IN ips %]
[%- "\n\nINSERT INTO radippool_temp (pool_name,framedipaddress) VALUES" IF loop.index % batchsize == 0 %]
[%-   IF (loop.index+1) % batchsize == 0 OR loop.last %]
('[% m.poolname %]','[% m.ip %]');
[%-   ELSE %]
('[% m.poolname %]','[% m.ip %]'),
[%-   END %]
[%- END %]

START TRANSACTION;

-- Delete old pools that have been removed
DELETE FROM radippool r WHERE NOT EXISTS (
  SELECT FROM radippool_temp t
  WHERE t.pool_name = r.pool_name AND t.framedipaddress = r.framedipaddress
);

-- Add new pools that have been created
INSERT INTO radippool (pool_name,framedipaddress)
  SELECT pool_name,framedipaddress FROM radippool_temp t WHERE NOT EXISTS (
    SELECT * FROM radippool r
    WHERE r.pool_name=t.pool_name AND r.framedipaddress=t.framedipaddress
  );

COMMIT;
END_postgresql

	return %template;

}
