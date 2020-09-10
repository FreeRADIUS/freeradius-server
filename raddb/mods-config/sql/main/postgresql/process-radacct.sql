#  -*- text -*-
#
#  main/postgresql/process-radacct.sql -- Schema extensions for processing radacct entries
#
#  $Id$

--  ---------------------------------
--  - Per-user data usage over time -
--  ---------------------------------
--
--  An extension to the standard schema to hold per-user data usage statistics
--  for arbitrary periods.
--
--  The data_usage_by_period table is populated by periodically calling the
--  fr_new_data_usage_period stored procedure.
--
--  This table can be queried in various ways to produce reports of aggregate
--  data use over time. For example, if the fr_new_data_usage_period SP is
--  invoked one per day just after midnight, to produce usage data with daily
--  granularity, then a reasonably accurate monthly bandwidth summary for a
--  given user could be obtained by queriing this table with:
--
--      SELECT
--          TO_CHAR(CURRENT_TIMESTAMP, 'YYYY-Month') AS month,
--          TRUNC(SUM(acctinputoctets)/1000/1000/1000,9) AS gb_in,
--          TRUNC(SUM(acctoutputoctets)/1000/1000/1000,9) AS gb_out
--      FROM
--          data_usage_by_period
--      WHERE
--          username='bob' AND
--          period_end IS NOT NULL
--      GROUP BY
--          month;
--
--           month      |    gb_in    |    gb_out
--      ----------------+-------------+--------------
--       2019-July      | 5.782279231 | 50.545664824
--       2019-August    | 4.230543344 | 48.523096424
--       2019-September | 4.847360599 | 48.631835488
--       2019-October   | 6.456763254 | 51.686231937
--       2019-November  | 6.362537735 | 52.385710572
--       2019-December  | 4.301524442 | 50.762240277
--       2020-January   | 5.436280545 | 49.067775286
--      (7 rows)
--
CREATE TABLE data_usage_by_period (
    username text,
    period_start timestamp with time zone,
    period_end timestamp with time zone,
    acctinputoctets bigint,
    acctoutputoctets bigint
);
ALTER TABLE data_usage_by_period ADD CONSTRAINT data_usage_by_period_pkey PRIMARY KEY (username, period_start);
CREATE INDEX data_usage_by_period_pkey_period_end ON data_usage_by_period(period_end);


--
--  Stored procedure that when run with some arbitrary frequency, say
--  once per day by cron, will process the recent radacct entries to extract
--  time-windowed data containing acct{input,output}octets ("data usage") per
--  username, per period.
--
--  Each invocation will create new rows in the data_usage_by_period tables
--  containing the data used by each user since the procedure was last invoked.
--  The intervals do not need to be identical but care should be taken to
--  ensure that the start/end of each period aligns well with any intended
--  reporting intervals.
--
--  It can be invoked by running:
--
--      SELECT fr_new_data_usage_period();
--
--
CREATE OR REPLACE FUNCTION fr_new_data_usage_period ()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE v_start timestamp;
DECLARE v_end timestamp;
BEGIN

    SELECT COALESCE(MAX(period_end) + INTERVAL '1 SECOND', TO_TIMESTAMP(0)) INTO v_start FROM data_usage_by_period;
    SELECT DATE_TRUNC('second',CURRENT_TIMESTAMP) INTO v_end;

    --
    -- Add the data usage for the sessions that were active in the current
    -- period to the table. Include all sessions that finished since the start
    -- of this period as well as those still ongoing.
    --
    INSERT INTO data_usage_by_period (username, period_start, period_end, acctinputoctets, acctoutputoctets)
    SELECT *
    FROM (
        SELECT
            username,
            v_start,
            v_end,
            SUM(acctinputoctets) AS acctinputoctets,
            SUM(acctoutputoctets) AS acctoutputoctets
        FROM
            radacct
        WHERE
            acctstoptime > v_start OR
            acctstoptime IS NULL
        GROUP BY
            username
    ) AS s
    ON CONFLICT ON CONSTRAINT data_usage_by_period_pkey
    DO UPDATE
        SET
            acctinputoctets = data_usage_by_period.acctinputoctets + EXCLUDED.acctinputoctets,
            acctoutputoctets = data_usage_by_period.acctoutputoctets + EXCLUDED.acctoutputoctets,
            period_end = v_end;

    --
    -- Create an open-ended "next period" for all ongoing sessions and carry a
    -- negative value of their data usage to avoid double-accounting when we
    -- process the next period. Their current data usage has already been
    -- allocated to the current and possibly previous periods.
    --
    INSERT INTO data_usage_by_period (username, period_start, period_end, acctinputoctets, acctoutputoctets)
    SELECT *
    FROM (
        SELECT
            username,
            v_end + INTERVAL '1 SECOND',
            NULL::timestamp,
            0 - SUM(acctinputoctets),
            0 - SUM(acctoutputoctets)
        FROM
            radacct
        WHERE
            acctstoptime IS NULL
        GROUP BY
            username
    ) AS s;

END
$$;
