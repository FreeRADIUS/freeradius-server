--
-- A stored procedure to reallocate a user's previous address, otherwise
-- provide a free address.
--
-- NOTE: This version of the SP is intended for MySQL variants that do not
--       support the SKIP LOCKED pragma, i.e. MariaDB and versions of MySQL
--       prior to 8.0. It should be a lot faster than using the default SP
--       without the SKIP LOCKED pragma under highly concurrent workloads
--       and not result in thread starvation.
--
--       It is however a *useful hack* which should not be used if SKIP
--       LOCKED is available.
--
-- WARNING: This query uses server-local, "user locks" (GET_LOCK and
--	  RELEASE_LOCK), without the need for a transaction, to emulate
--	  row locking with locked-row skipping. User locks are not
--	  supported on clusters such as Galera and MaxScale.
--
-- Using this SP reduces the usual set dialogue of queries to a single
-- query:
--
--   START TRANSACTION; SELECT FOR UPDATE; UPDATE; COMMIT;  ->  CALL sp()
--
-- The stored procedure is executed within a single round trip which often
-- leads to reduced deadlocking and significant performance improvements.
--
-- To use this stored procedure the corresponding queries.conf statements must
-- be configured as follows:
--
-- allocate_begin = ""
-- allocate_find = "\
-- 	CALL fr_dhcp_allocate_previous_or_new_framedipaddress( \
-- 		'%{control:${pool_name}}', \
-- 		'%{DHCP-Gateway-IP-Address}', \
-- 		'${pool_key}', \
-- 		${lease_duration}, \
-- 		'%{%{${req_attribute_name}}:-0.0.0.0}' \
-- 	)"
-- allocate_update = ""
-- allocate_commit = ""
--

DELIMITER $$

DROP PROCEDURE IF EXISTS fr_dhcp_allocate_previous_or_new_framedipaddress;
CREATE PROCEDURE fr_allocate_previous_or_new_framedipaddress (
	IN v_pool_name VARCHAR(64),
	IN v_gateway VARCHAR(15),
	IN v_pool_key VARCHAR(64),
	IN v_lease_duration INT,
	IN v_requested_address VARCHAR(15)
)
SQL SECURITY INVOKER
proc:BEGIN
	DECLARE r_address VARCHAR(15);

	-- Reissue an existing IP address lease when re-authenticating a session
	--
	-- Note: In this query we get away without the need for FOR UPDATE
	--       becase:
	--
	--         (a) Each existing lease only belongs to a single device, so
	--             no two devices will be racing over a single address.
	--         (b) The set of existing leases (not yet expired) are
	--             disjoint from the set of free leases, so not subject to
	--             reallocation.
	--
	SELECT framedipaddress INTO r_address
	FROM dhcpippool
	WHERE pool_name = v_pool_name
		AND expiry_time > NOW()
		AND pool_key = v_pool_key
		AND `status` IN ('dynamic', 'static')
	LIMIT 1;

	-- Reissue an user's previous IP address, provided that the lease is
	-- available (i.e. enable sticky IPs)
	--
	-- When using this SELECT you should delete the one above. You must also
	-- set allocate_clear = "" in queries.conf to persist the associations
	-- for expired leases.
	--
	-- SELECT framedipaddress INTO r_address
	-- FROM dhcpippool
	-- WHERE pool_name = v_pool_name
	--	AND pool_key = v_pool_key
	--	AND `status` IN ('dynamic', 'static')
	-- LIMIT 1;

	--
	-- Normally here we would honour an IP address hint if the IP were
	-- available, however we cannot do that without taking a lock which
	-- defeats the purpose of this version of the stored procedure.
	--
	-- It you need to honour an IP address hint then use a database with
	-- support for SKIP LOCKED and use the normal stored procedure.
	--

	IF r_address IS NOT NULL THEN
		UPDATE dhcpippool
		SET
			gateway = v_gateway,
			pool_key = v_pool_key,
			expiry_time = NOW() + INTERVAL v_lease_duration SECOND
		WHERE
			framedipaddress = r_address;
		SELECT r_address;
		LEAVE proc;
	END IF;

	REPEAT

		-- If we didn't reallocate a previous address then pick the least
		-- recently used address from the pool which maximises the likelihood
		-- of re-assigning the other addresses to their recent user
		--
		SELECT framedipaddress INTO r_address
		FROM dhcpippool
		WHERE pool_name = v_pool_name
			AND expiry_time < NOW()
			AND `status` = 'dynamic'
		--
		-- WHERE ... GET_LOCK(...,0) = 1 is a poor man's SKIP LOCKED that simulates
		-- a row-level lock using a "user lock" that allows the locked "rows" to be
		-- skipped. After the user lock is acquired and the SELECT retired it does
		-- not mean that the entirety of the WHERE clause is still true: Another
		-- thread may have updated the expiry time and released the lock after we
		-- checked the expiry_time but before we acquired the lock since SQL is free
		-- to reorder the WHERE condition. Therefore we must recheck the condition
		-- in the UPDATE statement below to detect this race.
		--
			AND GET_LOCK(CONCAT('dhcpippool_', framedipaddress), 0) = 1
		LIMIT 1;

		IF r_address IS NULL THEN
			DO RELEASE_LOCK(CONCAT('dhcpippool_', r_address));
			LEAVE proc;
		END IF;

		UPDATE dhcpippool
		SET
			gateway = v_gateway,
			pool_key = v_pool_key,
			expiry_time = NOW() + INTERVAL v_lease_duration SECOND
		WHERE
			framedipaddress = r_address
		--
		-- Here we re-evaluate the original condition for selecting the address
		-- to detect a race, in which case we try again...
		--
			AND expiry_time<NOW();

	UNTIL ROW_COUNT() <> 0 END REPEAT;

	DO RELEASE_LOCK(CONCAT('dhcpippool_', r_address));
	SELECT r_address;

END$$

DELIMITER ;
