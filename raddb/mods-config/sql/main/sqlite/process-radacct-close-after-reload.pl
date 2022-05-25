#!/usr/bin/perl -Tw

#
#  main/sqlite/process-radacct-close-after_reload.pl -- Script for
#    processing radacct entries to close sessions interrupted by a NAS reload
#
#  Requires the DBD::SQLite module: perl-DBD-SQLite (RedHat); libdbd-sqlite3-perl (Debian)
#
#  $Id$
#
#  It may be desirable to periodically "close" radacct sessions belonging to a
#  reloaded NAS, replicating the "bulk close" Accounting-On/Off behaviour,
#  just not in real time.
#
#  This script will set radacct.acctstoptime to nasreload.reloadtime, calculate
#  the corresponding radacct.acctsessiontime, and set acctterminatecause to
#  "NAS reboot" for interrupted sessions. It does so in batches, which avoids a
#  single long-lived lock on the table.
#
#  It can be invoked as follows:
#
#      ./process-radacct-close-after-reload.pl <sqlite_db_file>
#
#  Note: This script walks radacct in strides of v_batch_size. It will
#  typically skip closed and ongoing sessions at a rate significantly faster
#  than 10,000 rows per second and process batched updates faster than 5000
#  orphaned sessions per second. If this isn't fast enough then you should
#  really consider using a server-based database for accounting purposes.
#

use strict;
use DBI;

#
#  Fine for most purposes
#
my $batch_size = 2500;

if ($#ARGV != 0) {
    print "Usage: process-radacct-close-after_reload.pl SQLITE_DB_FILE\n\n";
    exit 1;
}
die "The SQLite database must exist: $ARGV[0]" unless -r $ARGV[0];


my $dbh = DBI->connect("DBI:SQLite:dbname=$ARGV[0]", '', '', { RaiseError => 1 }) or die $DBI::errstr;

#
#  There is no UPDATE ... JOIN/FROM in SQLite, so we have to resort to this
#  construction #  which does not provide an accurate rows updated count...
#
my $sth_upd = $dbh->prepare(<<'EOF');
    UPDATE radacct
    SET
        acctstoptime = (
            SELECT COALESCE(acctstoptime, CASE WHEN radacct.acctstarttime < reloadtime THEN reloadtime END)
            FROM nasreload WHERE nasipaddress = radacct.nasipaddress
        ),
        acctsessiontime = (
            SELECT COALESCE(acctsessiontime,
                CASE WHEN radacct.acctstoptime IS NULL AND radacct.acctstarttime < reloadtime THEN
                   CAST((julianday(reloadtime) - julianday(radacct.acctstarttime)) * 86400 AS integer)
                END)
            FROM nasreload WHERE nasipaddress = radacct.nasipaddress
        ),
        acctterminatecause = (
            SELECT
                CASE WHEN radacct.acctstoptime IS NULL AND radacct.acctstarttime < reloadtime THEN
                    'NAS reboot'
                ELSE
                    acctterminatecause
                END
            FROM nasreload WHERE nasipaddress = radacct.nasipaddress
        )
    WHERE
        radacctid BETWEEN ? AND ?
        AND acctstoptime IS NULL
EOF

my $sth = $dbh->prepare('SELECT MIN(radacctid), MAX(radacctid) FROM radacct WHERE acctstoptime IS NULL');
$sth->execute() or die $DBI::errstr;
(my $a, my $m) = $sth->fetchrow_array();
$sth->finish;

my $sth_nxt = $dbh->prepare('SELECT radacctid FROM radacct WHERE radacctid > ? ORDER BY radacctid LIMIT ?,1');


my $last = 0;
my $last_report = 0;

unless ($last) {

    $sth_nxt->execute($a, $batch_size) or die $DBI::errstr;
    (my $z) = $sth_nxt->fetchrow_array();

    unless ($z) {
        $z = $m;
        $last = 1;
    }

    my $rc = $sth_upd->execute($a, $z) or die $DBI::errstr;

    $a = $z + 1;

    #
    #  Periodically report how far we've got
    #
    my $now = time();
    if ($last_report != $now || $last) {
        print "RadAcctID: $z\n";
        $last_report = $now;
    }

}

$sth_upd->finish;
$sth_nxt->finish;

$dbh->disconnect;
