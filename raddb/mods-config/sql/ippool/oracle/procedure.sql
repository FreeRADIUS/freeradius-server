--
-- A stored procedure to reallocate a user's previous address, otherwise
-- provide a free address.
--
-- Using this SP reduces the usual set dialogue of queries to a single
-- query:
--
--   BEGIN; SELECT FOR UPDATE; UPDATE; COMMIT;  ->  SELECT sp() FROM dual
--
-- The stored procedure is executed on an database instance within a single
-- round trip which often leads to reduced deadlocking and significant
-- performance improvements especially on multi-master clusters, perhaps even
-- by an order of magnitude or more.
--
-- To use this stored procedure the corresponding queries.conf statements must
-- be configured as follows:
--
-- allocate_begin = ""
-- allocate_find = "\
--         SELECT fr_allocate_previous_or_new_framedipaddress( \
--                 '%{control:${pool_name}}', \
--                 '%{User-Name}', \
--                 '%{%{Calling-Station-Id}:-0}', \
--                 '%{NAS-IP-Address}', \
--                 '${pool_key}', \
--                 ${lease_duration} \
--         ) FROM dual"
-- allocate_update = ""
-- allocate_commit = ""
--

CREATE OR REPLACE FUNCTION fr_allocate_previous_or_new_framedipaddress (
        v_pool_name IN VARCHAR2,
        v_username IN VARCHAR2,
        v_callingstationid IN VARCHAR2,
        v_nasipaddress IN VARCHAR2,
        v_pool_key IN VARCHAR2,
        v_lease_duration IN INTEGER
)
RETURN varchar2 IS
        PRAGMA AUTONOMOUS_TRANSACTION;
        r_address varchar2(15);
BEGIN

        -- Reissue an existing IP address lease when re-authenticating a session
        --
          BEGIN
                SELECT framedipaddress INTO r_address FROM radippool WHERE id IN (
                        SELECT id FROM (
                                SELECT *
                                FROM radippool
                                WHERE pool_name = v_pool_name
                                        AND expiry_time > current_timestamp
                                        AND username = v_username
                                        AND callingstationid = v_callingstationid
                        ) WHERE ROWNUM <= 1
                ) FOR UPDATE SKIP LOCKED;
          EXCEPTION
                    WHEN NO_DATA_FOUND THEN
                        r_address := NULL;
          END;

        -- Reissue an user's previous IP address, provided that the lease is
        -- available (i.e. enable sticky IPs)
        --
        -- When using this SELECT you should delete the one above. You must also
        -- set allocate_clear = "" in queries.conf to persist the associations
        -- for expired leases.
        --
        -- BEGIN
        --         SELECT framedipaddress INTO r_address FROM radippool WHERE id IN (
        --                 SELECT id FROM (
        --                         SELECT *
        --                         FROM radippool
        --                         WHERE pool_name = v_pool_name
        --                                 AND username = v_username
        --                                 AND callingstationid = v_callingstationid
        --                 ) WHERE ROWNUM <= 1
        --         ) FOR UPDATE SKIP LOCKED;
        -- EXCEPTION
        --         WHEN NO_DATA_FOUND THEN
        --              r_address := NULL;
        -- END;

        -- If we didn't reallocate a previous address then pick the least
        -- recently used address from the pool which maximises the likelihood
        -- of re-assigning the other addresses to their recent user
        --
        IF r_address IS NULL THEN
                BEGIN
                        SELECT framedipaddress INTO r_address FROM radippool WHERE id IN (
                                SELECT id FROM (
                                        SELECT *
                                        FROM radippool
                                        WHERE pool_name = v_pool_name
                                        AND expiry_time < CURRENT_TIMESTAMP
                                        ORDER BY expiry_time
                                       ) WHERE ROWNUM <= 1
                        ) FOR UPDATE SKIP LOCKED;
                EXCEPTION
                        WHEN NO_DATA_FOUND THEN
                                r_address := NULL;
                END;
        END IF;

        -- Return nothing if we failed to allocated an address
        --
        IF r_address IS NULL THEN
                COMMIT;
                RETURN r_address;
        END IF;

        -- Update the pool having allocated an IP address
        --
        UPDATE radippool
        SET
                nasipaddress = v_nasipaddress,
                pool_key = v_pool_key,
                callingstationid = v_callingstationid,
                username = v_username,
                expiry_time = CURRENT_TIMESTAMP + v_lease_duration * INTERVAL '1' SECOND(1)
        WHERE framedipaddress = r_address;

        -- Return the address that we allocated
        COMMIT;
        RETURN r_address;

END;
/
