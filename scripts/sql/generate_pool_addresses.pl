#!/usr/bin/perl -Tw

######################################################################
#
#  Copyright (C) 2020 Network RADIUS
#
#  $Id$
#
######################################################################
#
#  Helper script for populating IP pools with address entries.
#
#  This script generates output that is useful for populating an IP pool for
#  use with FreeRADIUS (and possibly other purposes). The pool may be
#  implemented as an SQL IP Pool (rlm_sqlippool) or any other backing store
#  that has one entry per IP address.
#
#  This script output a list of address to add, retain and remove in order to
#  align a pool to a specification. It is likely that you will want to
#  process the output to generate the actual commands (e.g. SQL statements)
#  that make changes to the datastore. For example:
#
#    generate_pool_addresses.pl ... | align_sql_pools.pl postgresql
#
#
#  Use with a single address range
#  -------------------------------
#
#  For basic use, arguments can be provided to this script that denote the ends
#  of a single IP (v4 or v6) address range together with the pool_name.
#
#  Optionally the number of IPs to sparsely populate the range with can be
#  provided. If the range is wider than a /16 then the population of the range
#  is capped at 65536 IPs, unless otherwise specified.
#
#  In the case that a sparse range is defined, a file containing pre-existing
#  IP entries can be provided. The range will be populated with entries from
#  this file that fall within the range, prior to the remainder of the range
#  being populated with random address in the range.
#
#    generate_pool_addresses.pl <pool_name> <range_start> <range_end> \
#            [ <capacity> [ <existing_ips_file> ] ]
#
#  Note: Sparse ranges are populated using a deterministic, pseudo-random
#        function. This allows pools to be trivially extended without having to
#        supply the existing contents using a file. If you require
#        less-predictable randomness or a different random sequence then remove
#        or modify the line calling srand(), below.
#
#
#  Use with multiple pools and address ranges
#  ------------------------------------------
#
#  For more complex us, the script allows a set of pool definitions to be
#  provided in a YAML file which describes a set of one or more pools, each
#  containing a set of one or more ranges. The first argument in this case is
#  always "yaml":
#
#    generate_pool_addresses.pl yaml <pool_defs_yaml_file> [ <existing_ips_file> ]
#
#  The format for the YAML file is demonstrated by the following example:
#
#      pool_with_a_single_contiguous_range:
#        - start:    192.0.2.3
#          end:      192.0.2.250
#
#      pool_with_a_single_sparse_range:
#        - start:    10.10.10.0
#          end:      10.10.20.255
#          capacity: 200
#
#      pool_with_multiple_ranges:
#        - start:    10.10.10.1
#          end:      10.10.10.253
#        - start:    10.10.100.0
#          end:      10.10.199.255
#          capacity: 1000
#
#      v6_pool_with_contiguous_range:
#        - start:    '2001:db8:1:2:3:4:5:10'
#          end:      '2001:db8:1:2:3:4:5:7f'
#
#      v6_pool_with_sparse_range:
#        - start:    '2001:db8:1:2::'
#          end:      '2001:db8:1:2:ffff:ffff:ffff:ffff'
#          capacity: 200
#
#  As with the basic use case, a file containing pre-existing IP entries can be
#  provided with which any sparse ranges will be populated ahead of any random
#  addresses.
#
#
#  Output
#  ------
#
#  The script returns line-based output beginning with "+", "=" or "-", and
#  includes the pool_name and an IP address.
#
#    + pool_name 192.0.2.10
#
#      A new address to be added to the corresponding range in the pool.
#
#    = pool_name 192.0.2.20
#
#      A pre-existing address that is to be retained in the pool. (Only if a
#      pre-existing pool entries file is given.)
#
#    - pool_name 192.0.2.30
#
#      A pre-existing address that is to be removed from the corresponding
#      range in the pool. (Only if a pre-existing pool entries file is given.)
#
#    # main_pool: 192.0.10.3 - 192.0.12.250 (500)
#
#      Lines beginning with "#" are comments
#
#
#  Examples
#  --------
#
#    generate_pool_addresses.pl main_pool 192.0.2.3 192.0.2.249
#
#      Will create a pool from a full populated IPv4 range, i.e. all IPs in the
#      range available for allocation).
#
#    generate_pool_addresses.pl main_pool 10.66.0.0 10.66.255.255 10000
#
#      Will create a pool from a sparsely populated IPv4 range for a /16
#      network (maximum of 65.536 addresses), populating the range with 10,000
#      addreses. The effective size of the pool can be increased in future by
#      increasing the capacity of the range with:
#
#    generate_pool_addresses.pl main_pool 10.66.0.0 10.66.255.255 20000
#
#      This generates the same initial set of 10,000 addresses as the previous
#      example but will create 20,000 addresses overall, unless the random seed
#      has been amended since the initial run.
#
#    generate_pool_addresses.pl main_pool 2001:db8:1:2:: \
#            2001:db8:1:2:ffff:ffff:ffff:ffff
#
#      Will create a pool from the IPv6 range 2001:db8:1:2::/64, initially
#      populating the range with 65536 (by default) addresses.
#
#    generate_pool_addresses.pl main_pool 2001:db8:1:2:: \
#            2001:db8:1:2:ffff:ffff:ffff:ffff \
#            10000 existing_ips.txt
#
#      Will create a pool using the same range as the previous example, but
#      this time the range will be populated with 10,000 addresses.  The range
#      will be populated using lines extracted from the `existing_ips.txt` file
#      that represent IPs which fall within range.
#
#    generate_pool_addresses.pl yaml pool_defs.yml existing_ips.txt
#
#      Will create one of more pools using the definitions found in the
#      pool_defs.yml YAML file. The pools will contain one or more ranges with
#      each of the ranges first being populated with entries from the
#      existing_ips.txt file that fall within the range, before being filled
#      with random addresses to the defined capacity.
#

use strict;
use Net::IP qw/ip_bintoip ip_iptobin ip_bincomp ip_binadd ip_is_ipv4 ip_is_ipv6/;

my $yaml_available = 0;

eval {
    require YAML::XS;
    YAML::XS->import('LoadFile');
    $yaml_available = 1;
};

if ($#ARGV < 2 || $#ARGV > 4) {
	usage();
	exit 1;
}

if ($ARGV[0] eq 'yaml') {

	if ($#ARGV > 3) {
		usage();
		exit 1;
	}

	unless ($yaml_available) {
		die "ERROR: YAML is not available. Install the YAML::XS Perl module.";
	}
	process_yaml_file();

	goto done;

}

process_commandline();

done:

exit 0;


sub usage {
	print STDERR <<'EOF'
Usage:
  generate_pool_addresses.pl <pool_name> <range_start> <range_end> [ <capacity> [ <existing_ips_file> ] ]
or:
  generate_pool_addresses.pl yaml <pool_defs_yaml_file> [ <existing_ips_file> ]

EOF
}


sub process_commandline {

	$SIG{__DIE__} = sub { usage(); die(@_); };

	my $pool_name   = $ARGV[0];
	my $range_start = $ARGV[1];
	my $range_end   = $ARGV[2];
	my $capacity    = $ARGV[3];

	my @entries = ();
	@entries = load_entries($ARGV[4]) if ($#ARGV >= 4);

	handle_range($pool_name, $range_start, $range_end, $capacity, @entries);

}


sub process_yaml_file {

	my $yaml_file = $ARGV[1];

	unless (-r $yaml_file) {
		die "ERROR: Cannot open <pool_defs_yaml_file> for reading: $yaml_file";
	}

	my %pool_defs = %{LoadFile($yaml_file)};

	my @entries = ();
	@entries = load_entries($ARGV[2]) if ($#ARGV >= 2);

	foreach my $pool_name (sort keys %pool_defs) {
		foreach my $range (@{$pool_defs{$pool_name}}) {
			my $range_start = $range->{start};
			my $range_end   = $range->{end};
			my $capacity    = $range->{capacity};
			handle_range($pool_name, $range_start, $range_end, $capacity, @entries);
		}
	}

}


sub load_entries {

	my $entries_file = shift;

	my @entries = ();
	unless (-r $entries_file) {
		die "ERROR: Cannot open <existing_ips_file> for reading: $entries_file"
	}
	open(my $fh, "<", $entries_file) || die "Failed to open $entries_file";
	while(<$fh>) {
		chomp;
		push @entries, $_;
	}

	return @entries;

}


sub handle_range {

	my $pool_name = shift;
	my $range_start = shift;
	my $range_end = shift;
	my $capacity = shift;
	my @entries = @_;

	unless (ip_is_ipv4($range_start) || ip_is_ipv6($range_start)) {
		die "ERROR: Incorrectly formatted IPv4/IPv6 address for range_start: $range_start";
	}

	unless (ip_is_ipv4($range_end) || ip_is_ipv6($range_end)) {
		die "ERROR: Incorrectly formatted IPv4/IPv6 address for range_end: $range_end";
	}

	my $ip_start = new Net::IP($range_start);
	my $ip_end   = new Net::IP($range_end);
	my $ip_range = new Net::IP("$range_start - $range_end");

	unless (defined $ip_range) {
		die "ERROR: The range defined by <range_start> - <range_end> is invalid: $range_start - $range_end";
	}

	my $range_size = $ip_range->size;
	$capacity = $range_size < 65536 ? "$range_size" : 65536 unless defined $capacity;

	if ($range_size < $capacity) {
		$capacity = "$range_size";
		warn "WARNING: Insufficent IPs in the range. Will create $capacity entries.";
	}

	# Prune the entries to only those within the specified range
	for (my $i = 0; $i <= $#entries; $i++) {
		my $version = ip_is_ipv4($entries[$i]) ? 4 : 6;
		my $binip = ip_iptobin($entries[$i],$version);
		if ($ip_start->version != $version ||
			ip_bincomp($binip, 'lt', $ip_start->binip) == 1 ||
			ip_bincomp($binip, 'gt', $ip_end->binip) == 1) {
			$entries[$i]='';
		}
	}

	#
	#  We use the sparse method if the number of entries available occupies < 80% of
	#  the network range, otherwise we use a method that involves walking the
	#  entire range.
	#

	srand(42);  # Set the seed for the PRNG

	if (length($range_size) > 9 || $capacity / "$range_size" < 0.8) {  # From "BigInt" to FP
		@entries = sparse_fill($pool_name, $ip_start, $ip_end, $capacity, @entries);
	} else {
		@entries = dense_fill($pool_name, $ip_start, $ip_end, $ip_range, $capacity, @entries);
	}

	print "# $pool_name: $range_start - $range_end ($capacity)\n";
	print "$_\n" foreach @entries;
	print "\n";

}


#
#  With this sparse fill method we randomly allocate within the scope of the
#  smallest enclosing network prefix, checking that we are within the given
#  range, retrying if we are outside or we hit a duplicate.
#
#  This method can efficiently choose a small number of addresses relative to
#  the size of the range. It becomes slower as the population of a range nears
#  the range's limit since it is harder to choose a free address at random.
#
#  It is useful for selecting a handful of addresses from an enourmous IPv6 /64
#  network for example.
#
sub sparse_fill {

	my $pool_name = shift;
	my $ip_start = shift;
	my $ip_end = shift;
	my $capacity = shift;
	my @entries = @_;

	# Find the smallest network that encloses the given range
	my $version = $ip_start->version;
	( $ip_start->binip ^ $ip_end->binip ) =~ /^\0*/;
	my $net_prefix = $+[0];
	my $net_bits = substr($ip_start->binip, 0, $net_prefix);
	my $host_length = length($ip_start->binip) - $net_prefix;

	my %ips = ();
	my $i = 0;
	while ($i < $capacity) {

		# Use the given entries first
		my $rand_ip;
		my $given_lease = 0;
		shift @entries while $#entries >= 0 && $entries[0] eq '';
		if ($#entries >= 0) {
			$rand_ip = ip_iptobin(shift @entries, $version);
			$given_lease = 1;
		} else {
			$rand_ip = $net_bits;
			$rand_ip .= [0..1]->[rand 2] for 1..$host_length;
			# Check that we are inside the given range
			next if ip_bincomp($rand_ip, 'lt', $ip_start->binip) == 1 ||
				ip_bincomp($rand_ip, 'gt', $ip_end->binip) == 1;
		}

		next if defined $ips{$rand_ip};

		$ips{$rand_ip} = $given_lease ? '=' : '+';
		$i++;

	}

	# Allow the pool to be shrunk
	$ips{ip_iptobin($_, $version)} = '-' foreach @entries;

	return map { $ips{$_}." ".$pool_name." ".ip_bintoip($_, $version) } sort keys %ips;

}


#
#  With this dense fill method, after first selecting the given entries we walk
#  the network range picking IPs with evenly distributed probability.
#
#  This method can efficiently choose a large number of addresses relative to
#  the size of a range, provided that the range isn't massive. It becomes
#  slower as the range size increases.
#
sub dense_fill {

	my $pool_name = shift;
	my $ip_start = shift;
	my $ip_end = shift;
	my $ip_range = shift;
	my $capacity = shift;
	my @entries = @_;

	my $version = $ip_start->version;

	my $one = ("0"x($version == 4 ? 31 : 127)) . '1';

	my %ips = ();
	my $remaining_entries = $capacity;
	my $remaining_ips = $ip_range->size;
	my $ipbin = $ip_start->binip;

	while ($remaining_entries > 0 && (ip_bincomp($ipbin, 'le', $ip_end->binip) == 1)) {

		# Use the given entries first
		shift @entries while $#entries >= 0 && $entries[0] eq '';
		if ($#entries >= 0) {
			$ips{ip_iptobin(shift @entries, $version)} = '=';
			$remaining_entries--;
			$remaining_ips--;
			next;
		}

		goto next_ip if defined $ips{$ipbin};

		# Skip the IP that we have already selected by given entries, otherwise
		# randomly pick it
		if (!defined $ips{$ipbin} &&
		    (rand) <= $remaining_entries / "$remaining_ips") {  # From "BigInt" to FP
			$ips{$ipbin} = '+';
			$remaining_entries--;
		}

		$remaining_ips--;
		$ipbin = ip_binadd($ipbin,$one);

	}

	# Allow the pool to be shrunk
	$ips{ip_iptobin($_, $version)} = '-' foreach @entries;

	return map { $ips{$_}." ".$pool_name." ".ip_bintoip($_, $version) } sort keys %ips;

}
