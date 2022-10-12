-- -*- text -*-
--
--  main/postgresql/process-radacct.sql -- Schema extensions for processing radacct entries
--
--  $Id$

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
--          TO_CHAR(period_start, 'YYYY-Month') AS month,
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
        FROM ((
            SELECT
                username, acctinputoctets, acctoutputoctets
            FROM
                radacct
            WHERE
                acctstoptime > v_start
        ) UNION ALL (
            SELECT
                username, acctinputoctets, acctoutputoctets
            FROM
                radacct
            WHERE
                acctstoptime IS NULL
        )) AS a
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
--    * Close the affected sessions out of band. (Refer to the SP below.)
--
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
            EXTRACT(EPOCH FROM (n.ReloadTime - a.AcctStartTime))
        END
    ) AS AcctSessionTime_With_Reloads
FROM radacct a
LEFT OUTER JOIN nasreload n USING (nasipaddress);


--
--  It may be desirable to periodically "close" radacct sessions belonging to a
--  reloaded NAS, replicating the "bulk close" Accounting-On/Off behaviour,
--  just not in real time.
--
--  The fr_radacct_close_after_reload SP will set radacct.acctstoptime to
--  nasreload.reloadtime, calculate the corresponding radacct.acctsessiontime,
--  and set acctterminatecause to "NAS reboot" for interrupted sessions. It
--  does so in batches, which avoids long-lived locks on the affected rows.
--
--  It can be invoked as follows:
--
--      CALL fr_radacct_close_after_reload();
--
--  Note: This SP requires PostgreSQL >= 11 which was the first version to
--  introduce PROCEDUREs which permit transaction control. This allows COMMIT
--  to be called to incrementally apply successive batch updates prior to the
--  end of the procedure. Prior to version 11 there exists only FUNCTIONs that
--  execute atomically. You can convert this procedure to a function, but by
--  doing so you are really no better off than performing a single,
--  long-running bulk update.
--
--  Note: This SP walks radacct in strides of v_batch_size. It will typically
--  skip closed and ongoing sessions at a rate significantly faster than
--  500,000 rows per second and process batched updates faster than 25,000
--  orphaned sessions per second. If this isn't fast enough then you should
--  really consider using a custom schema that includes partitioning by
--  nasipaddress or acct{start,stop}time.
--
CREATE OR REPLACE PROCEDURE fr_radacct_close_after_reload ()
LANGUAGE plpgsql
AS $$

DECLARE v_a bigint;
DECLARE v_z bigint;
DECLARE v_updated bigint DEFAULT 0;
DECLARE v_last_report bigint DEFAULT 0;
DECLARE v_now bigint;
DECLARE v_last boolean DEFAULT false;
DECLARE v_rowcount integer;

--
--  This works for many circumstances
--
DECLARE v_batch_size CONSTANT integer := 2500;

BEGIN

    SELECT MIN(RadAcctId) INTO v_a FROM radacct WHERE AcctStopTime IS NULL;

    LOOP

        v_z := NULL;
        SELECT RadAcctId INTO v_z FROM radacct WHERE RadAcctId > v_a ORDER BY RadAcctId OFFSET v_batch_size LIMIT 1;

        IF v_z IS NULL THEN
            SELECT MAX(RadAcctId) INTO v_z FROM radacct;
            v_last := true;
        END IF;

        UPDATE radacct a
        SET
            AcctStopTime = n.reloadtime,
            AcctSessionTime = EXTRACT(EPOCH FROM (n.ReloadTime - a.AcctStartTime)),
            AcctTerminateCause = 'NAS reboot'
        FROM nasreload n
        WHERE
            a.NASIPAddress = n.NASIPAddress
            AND RadAcctId BETWEEN v_a AND v_z
            AND AcctStopTime IS NULL
            AND AcctStartTime < n.ReloadTime;

        GET DIAGNOSTICS v_rowcount := ROW_COUNT;
        v_updated := v_updated + v_rowcount;

        COMMIT;     -- Make the update visible

        v_a := v_z + 1;

        --
        --  Periodically report how far we've got
        --
        SELECT EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) INTO v_now;
        IF v_last_report != v_now OR v_last THEN
            RAISE NOTICE 'RadAcctID: %; Sessions closed: %', v_z, v_updated;
            v_last_report := v_now;
        END IF;

        EXIT WHEN v_last;

    END LOOP;

END
$$;
