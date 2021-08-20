#  -*- text -*-
#
#  main/mysql/process-radacct.sql -- Schema extensions for processing radacct entries
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
--      SELECT
--          DATE_FORMAT(period_start, '%Y-%M') AS month,
--          SUM(acctinputoctets)/1000/1000/1000 AS GB_in,
--          SUM(acctoutputoctets)/1000/1000/1000 AS GB_out
--      FROM
--          data_usage_by_period
--      WHERE
--          username='bob' AND
--          period_end IS NOT NULL
--      GROUP BY
--          YEAR(period_start), MONTH(period_start);
--
--      +----------------+----------------+-----------------+
--      | month          | GB_in          | GB_out          |
--      +----------------+----------------+-----------------+
--      | 2019-July      | 5.782279230000 | 50.545664820000 |
--      | 2019-August    | 4.230543340000 | 48.523096420000 |
--      | 2019-September | 4.847360590000 | 48.631835480000 |
--      | 2019-October   | 6.456763250000 | 51.686231930000 |
--      | 2019-November  | 6.362537730000 | 52.385710570000 |
--      | 2019-December  | 4.301524440000 | 50.762240270000 |
--      | 2020-January   | 5.436280540000 | 49.067775280000 |
--      +----------------+----------------+-----------------+
--      7 rows in set (0.000 sec)
--
CREATE TABLE data_usage_by_period (
    username VARCHAR(64),
    period_start DATETIME,
    period_end DATETIME,
    acctinputoctets BIGINT(20),
    acctoutputoctets BIGINT(20),
    PRIMARY KEY (username,period_start)
);
CREATE INDEX idx_data_usage_by_period_period_start ON data_usage_by_period (period_start);
CREATE INDEX idx_data_usage_by_period_period_end ON data_usage_by_period (period_end);


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
--      CALL fr_new_data_usage_period();
--
--
DELIMITER $$

DROP PROCEDURE IF EXISTS fr_new_data_usage_period;
CREATE PROCEDURE fr_new_data_usage_period ()
SQL SECURITY INVOKER
BEGIN

    DECLARE v_start DATETIME;
    DECLARE v_end DATETIME;

    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    SELECT IFNULL(DATE_ADD(MAX(period_end), INTERVAL 1 SECOND), FROM_UNIXTIME(0)) INTO v_start FROM data_usage_by_period;
    SELECT NOW() INTO v_end;

    START TRANSACTION;

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
    ON DUPLICATE KEY UPDATE
        acctinputoctets = data_usage_by_period.acctinputoctets + s.acctinputoctets,
        acctoutputoctets = data_usage_by_period.acctoutputoctets + s.acctoutputoctets,
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
            DATE_ADD(v_end, INTERVAL 1 SECOND),
            NULL,
            0 - SUM(acctinputoctets),
            0 - SUM(acctoutputoctets)
        FROM
            radacct
        WHERE
            acctstoptime IS NULL
        GROUP BY
            username
    ) AS s;

    COMMIT;

END$$

DELIMITER ;
