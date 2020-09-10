#  -*- text -*-
#
#  main/mssql/process-radacct.sql -- Schema extensions for processing radacct entries
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
--  given user could be obtained with:
--
--     SELECT
--          FORMAT(period_start, 'yyyy-MMMM') AS month,
--          SUM(acctinputoctets)/1000/1000/1000 AS GB_in,
--          SUM(acctoutputoctets)/1000/1000/1000 AS GB_out
--      FROM
--          data_usage_by_period
--      WHERE
--          username='bob' AND
--          period_end <> 0
--      GROUP BY
--          FORMAT(period_start, 'yyyy-MMMM');
--
--      +----------------+----------+-----------+
--      | month          | GB_in    | GB_out    |
--      +----------------+----------+-----------+
--      | 2019-July      | 5.782279 | 50.545664 |
--      | 2019-August    | 4.230543 | 48.523096 |
--      | 2019-September | 4.847360 | 48.631835 |
--      | 2019-October   | 6.456763 | 51.686231 |
--      | 2019-November  | 6.362537 | 52.385710 |
--      | 2019-December  | 4.301524 | 50.762240 |
--      | 2020-January   | 5.436280 | 49.067775 |
--      +----------------+----------+-----------+
--
CREATE TABLE data_usage_by_period (
    username VARCHAR(64) NOT NULL,
    period_start DATETIME NOT NULL,
    period_end DATETIME NOT NULL,
    acctinputoctets NUMERIC(19),
    acctoutputoctets NUMERIC(19),
    PRIMARY KEY (username, period_start)
);
GO

CREATE INDEX idx_data_usage_by_period_period_end ON data_usage_by_period(period_end);
GO

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
--      EXEC fr_new_data_usage_period;
--
--
CREATE OR ALTER PROCEDURE fr_new_data_usage_period
AS
BEGIN

    DECLARE @v_start DATETIME;
    DECLARE @v_end DATETIME;

    SELECT @v_start = COALESCE(DATEADD(ss, 1, MAX(period_end)), CAST('1970-01-01' AS DATETIME)) FROM data_usage_by_period;
    SELECT @v_end = CAST(CURRENT_TIMESTAMP AS DATETIME2(0));

    BEGIN TRAN;

    --
    -- Add the data usage for the sessions that were active in the current
    -- period to the table. Include all sessions that finished since the start
    -- of this period as well as those still ongoing.
    --
    MERGE INTO data_usage_by_period d
        USING (
            SELECT
                username,
                @v_start AS period_start,
                @v_end AS period_end,
                SUM(acctinputoctets) AS acctinputoctets,
                SUM(acctoutputoctets) AS acctoutputoctets
            FROM
                radacct
            WHERE
                acctstoptime > @v_start OR
                acctstoptime=0
            GROUP BY
                username
        ) s
        ON ( d.username = s.username AND d.period_start = s.period_start )
        WHEN MATCHED THEN
            UPDATE SET
                acctinputoctets = d.acctinputoctets + s.acctinputoctets,
                acctoutputoctets = d.acctoutputoctets + s.acctoutputoctets,
                period_end = @v_end
        WHEN NOT MATCHED THEN
            INSERT
                (username, period_start, period_end, acctinputoctets, acctoutputoctets)
            VALUES
                (s.username, s.period_start, s.period_end, s.acctinputoctets, s.acctoutputoctets);

    --
    -- Create an open-ended "next period" for all ongoing sessions and carry a
    -- negative value of their data usage to avoid double-accounting when we
    -- process the next period. Their current data usage has already been
    -- allocated to the current and possibly previous periods.
    --
    -- MSSQL doesn't allow a DATETIME to be NULL so we use "0" (1900-01-01) to
    -- indicate the open-ended interval.
    --
    INSERT INTO data_usage_by_period (username, period_start, period_end, acctinputoctets, acctoutputoctets)
    SELECT *
    FROM (
        SELECT
            username,
            DATEADD(ss,1,@v_end) AS period_start,
            0 AS period_end,
            0 - SUM(acctinputoctets) AS acctinputoctets,
            0 - SUM(acctoutputoctets) AS acctoutputoctets
        FROM
            radacct
        WHERE
            acctstoptime=0
        GROUP BY
            username
    ) s;

    COMMIT;

END
GO
