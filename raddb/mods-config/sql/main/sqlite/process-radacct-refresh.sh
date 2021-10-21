#!/bin/sh
#
#  main/sqlite/process-radacct-refresh.sh -- Schema extensions and script for processing radacct entries
#
#  $Id$

#
#  See process-radacct-schema.sql for details.
#

if [ "$#" -ne 1 ]; then
    echo "Usage: process-radacct-refresh.sh SQLITE_DB_FILE" 2>&1
    exit 1
fi

if [ ! -r "$1" ]; then
    echo "The SQLite database must exist: $1" 1>&2
    exit 1
fi

cat <<EOF | sqlite3 "$1"

    --
    -- SQLite doesn't have a concept of session variables so we fake it.
    --
    DROP TABLE IF EXISTS vars;
    CREATE TEMPORARY TABLE vars (
        key text,
        value text,
        PRIMARY KEY (key)
    );

    INSERT INTO vars SELECT 'v_start', COALESCE(DATETIME(MAX(period_end), '+1 seconds'), DATETIME(0, 'unixepoch')) FROM data_usage_by_period;
    INSERT INTO vars SELECT 'v_end', CURRENT_TIMESTAMP;


    --
    -- Make of copy of the sessions that were active during this period to
    -- avoid having to execute a potentially long transaction that might hold a
    -- global database lock.
    --
    DROP TABLE IF EXISTS radacct_sessions;
    CREATE TEMPORARY TABLE radacct_sessions (
        username text,
        acctstarttime datetime,
        acctstoptime datetime,
        acctinputoctets bigint,
        acctoutputoctets bigint
    );
    CREATE INDEX temp.idx_radacct_sessions_username ON radacct_sessions(username);
    CREATE INDEX temp.idx_radacct_sessions_acctstoptime ON radacct_sessions(acctstoptime);

    INSERT INTO radacct_sessions
        SELECT
            username,
            acctstarttime,
            acctstoptime,
            acctinputoctets,
            acctoutputoctets
        FROM
            radacct
        WHERE
            acctstoptime > (SELECT value FROM vars WHERE key='v_start') OR
            acctstoptime IS NULL;


    --
    -- Add the data usage for the sessions that were active in the current
    -- period to the table. Include all sessions that finished since the start
    -- of this period as well as those still ongoing.
    --
    INSERT INTO data_usage_by_period (username, period_start, period_end, acctinputoctets, acctoutputoctets)
    SELECT
        username,
        (SELECT value FROM vars WHERE key='v_start'),
        (SELECT value FROM vars WHERE key='v_end'),
        SUM(acctinputoctets) AS acctinputoctets,
        SUM(acctoutputoctets) AS acctoutputoctets
    FROM
        radacct_sessions
    GROUP BY
        username
    ON CONFLICT(username,period_start) DO UPDATE
        SET
            acctinputoctets = data_usage_by_period.acctinputoctets + EXCLUDED.acctinputoctets,
            acctoutputoctets = data_usage_by_period.acctoutputoctets + EXCLUDED.acctoutputoctets,
            period_end = (SELECT value FROM vars WHERE key='v_end');

    --
    -- Create an open-ended "next period" for all ongoing sessions and carry a
    -- negative value of their data usage to avoid double-accounting when we
    -- process the next period. Their current data usage has already been
    -- allocated to the current and possibly previous periods.
    --
    INSERT INTO data_usage_by_period (username, period_start, period_end, acctinputoctets, acctoutputoctets)
    SELECT
        username,
        (SELECT DATETIME(value, '+1 seconds') FROM vars WHERE key='v_end'),
        NULL,
        0 - SUM(acctinputoctets),
        0 - SUM(acctoutputoctets)
    FROM
        radacct_sessions
    WHERE
        acctstoptime IS NULL
    GROUP BY
        username;

    DROP TABLE vars;
    DROP TABLE radacct_sessions;

EOF
