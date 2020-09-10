#  -*- text -*-
#
#  main/sqlite/process-radacct.sql -- Schema extensions and script for processing radacct entries
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
--  process-radacct-refresh.sh script.
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
