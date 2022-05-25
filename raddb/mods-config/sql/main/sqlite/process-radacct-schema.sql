#  -*- text -*-
#
#  main/sqlite/process-radacct.sql -- Schema extensions for processing radacct entries
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
--  process-radacct-new-data-usage-period.sh script.
--
--  This table can be queried in various ways to produce reports of aggregate
--  data use over time. For example, if the refresh script is invoked once per
--  day just after midnight, to produce usage data with daily granularity, then
--  a reasonably accurate monthly bandwidth summary for a given user could be
--  obtained by queriing this table with:
--
--      SELECT
--          STRFTIME('%Y-%m',CURRENT_TIMESTAMP) AS month,
--          SUM(acctinputoctets)*1.0/1000/1000/1000 AS gb_in,
--          SUM(acctoutputoctets)*1.0/1000/1000/1000 AS gb_out
--      FROM
--          data_usage_by_period
--      WHERE
--          username='bob' AND
--          period_end IS NOT NULL
--      GROUP BY
--          month;
--
--       2019-07|5.782279231|50.545664824
--       2019-08|4.230543344|48.523096424
--       2019-09|4.847360599|48.631835488
--       2019-10|6.456763254|51.686231937
--       2019-11|6.362537735|52.385710572
--       2019-12|4.301524442|50.762240277
--       2020-01|5.436280545|49.067775286
--
CREATE TABLE data_usage_by_period (
    username text,
    period_start datetime,
    period_end datetime,
    acctinputoctets bigint,
    acctoutputoctets bigint,
    PRIMARY KEY (username, period_start)
);
CREATE INDEX idx_data_usage_by_period_period_start ON data_usage_by_period(period_start);
CREATE INDEX idx_data_usage_by_period_period_end ON data_usage_by_period(period_end);


--  ------------------------------------------------------
--  - "Lightweight" Accounting-On/Off strategy resources -
--  ------------------------------------------------------
--
--  The following resources are for use only when the "lightweight"
--  Accounting-On/Off strategy is enabled in queries.conf.
--
--  Instead of bulk closing the radacct sessions belonging to a reloaded NAS,
--  this strategy leaves them open and records the NAS reload time in the
--  nasreload table.
--
--  Where applicable, the onus is on the administator to:
--
--    * Consider the nas reload times when deriving a list of
--      active/inactive sessions, and when determining the duration of sessions
--      interrupted by a NAS reload. (Refer to the view below.)
--
--    * Close the affected sessions out of band. (Refer to the
--      process-radacct-close-after_reload.pl script.)
--
--  The radacct_with_reloads view presents the radacct table with two additional
--  columns: acctstoptime_with_reloads and acctsessiontime_with_reloads
--
--  Where the session isn't closed (acctstoptime IS NULL), yet it started before
--  the last reload of the NAS (radacct.acctstarttime < nasreload.reloadtime),
--  the derived columns are set based on the reload time of the NAS (effectively
--  the point in time that the session was interrupted.)
--
CREATE VIEW radacct_with_reloads AS
SELECT
    a.*,
    COALESCE(a.AcctStopTime,
        CASE WHEN a.AcctStartTime < n.ReloadTime THEN n.ReloadTime END
    ) AS AcctStopTime_With_Reloads,
    COALESCE(a.AcctSessionTime,
        CASE WHEN a.AcctStopTime IS NULL AND a.AcctStartTime < n.ReloadTime THEN
            CAST((julianday(n.ReloadTime) - julianday(a.AcctStartTime)) * 86400 AS integer)
        END
    ) AS AcctSessionTime_With_Reloads
FROM radacct a
LEFT OUTER JOIN nasreload n USING (nasipaddress);
