--
-- A stored procedure to reallocate a user's previous address, otherwise
-- provide a free address.
--
-- Using this SP reduces the usual set dialogue of queries to a single
-- query:
--
--   START TRANSACTION; SELECT FOR UPDATE; UPDATE; COMMIT;  ->  CALL sp()
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
CREATE PROCEDURE fr_dhcp_allocate_previous_or_new_framedipaddress (
	IN v_pool_name VARCHAR(30),
	IN v_gateway VARCHAR(15),
	IN v_pool_key VARCHAR(30),
	IN v_lease_duration INT,
	IN v_requested_address VARCHAR(15)
)
SQL SECURITY INVOKER
proc:BEGIN
	DECLARE r_address VARCHAR(15);

	DECLARE EXIT HANDLER FOR SQLEXCEPTION
	BEGIN
		ROLLBACK;
		RESIGNAL;
	END;

	SET TRANSACTION ISOLATION LEVEL READ COMMITTED;

	START TRANSACTION;

	-- Reissue an existing IP address lease when re-authenticating a session
	--
	SELECT framedipaddress INTO r_address
	FROM dhcpippool
	WHERE pool_name = v_pool_name
		AND expiry_time > NOW()
		AND pool_key = v_pool_key
		AND `status` IN ('dynamic', 'static')
	LIMIT 1
	FOR UPDATE;
--      FOR UPDATE SKIP LOCKED;  -- Better performance, but limited support

	-- NOTE: You should enable SKIP LOCKED here (as well as any other
	--       instances) if your database server supports it. If it is not
	--       supported and you are not running a multi-master cluster (e.g.
	--       Galera or MaxScale) then you should instead consider using the
	--       SP in procedure-no-skip-locked.sql which will be faster and
	--       less likely to result in thread starvation under highly
	--       concurrent load.

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
	-- LIMIT 1
	-- FOR UPDATE;
	-- -- FOR UPDATE SKIP LOCKED;  -- Better performance, but limited support

	-- Issue the requested IP address if it is available
	--
	IF r_address IS NULL AND v_requested_address <> '0.0.0.0' THEN
		SELECT framedipaddress INTO r_address
		FROM dhcpippool
		WHERE pool_name = v_pool_name
			AND framedipaddress = v_requested_address
			AND `status` = 'dynamic'
			AND ( pool_key = v_pool_key OR expiry_time < NOW() )
		FOR UPDATE;
--	      FOR UPDATE SKIP LOCKED;  -- Better performance, but limited support
	END IF;

	-- If we didn't reallocate a previous address then pick the least
	-- recently used address from the pool which maximises the likelihood
	-- of re-assigning the other addresses to their recent user
	--
	IF r_address IS NULL THEN
		SELECT framedipaddress INTO r_address
		FROM dhcpippool
		WHERE pool_name = v_pool_name
			AND expiry_time < NOW()
			AND `status` = 'dynamic'
		ORDER BY
			expiry_time
		LIMIT 1
		FOR UPDATE;
--	      FOR UPDATE SKIP LOCKED;  -- Better performance, but limited support
	END IF;

	-- Return nothing if we failed to allocated an address
	--
	IF r_address IS NULL THEN
		COMMIT;
		LEAVE proc;
	END IF;

	-- Update the pool having allocated an IP address
	--
	UPDATE dhcpippool
	SET
		gateway = v_gateway,
		pool_key = v_pool_key,
		expiry_time = NOW() + INTERVAL v_lease_duration SECOND
	WHERE framedipaddress = r_address;

	COMMIT;

	-- Return the address that we allocated
	SELECT r_address;

END$$

DELIMITER ;
