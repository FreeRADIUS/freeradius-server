--
-- A stored procedure to reallocate a user's previous address, otherwise
-- provide a free address.
--
-- Using this SP reduces the usual set dialogue of queries to a single
-- query:
--
--   START TRANSACTION; SELECT FOR UPDATE; UPDATE; COMMIT;  ->  SELECT sp()
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
--	SELECT fr_dhcp_allocate_previous_or_new_framedipaddress( \
--		'%{control:${pool_name}}', \
--		'%{DHCP-Gateway-IP-Address}', \
--		'${pool_key}', \
--		${lease_duration}, \
--		'%{%{${req_attribute_name}}:-0.0.0.0}' \
--	)"
-- allocate_update = ""
-- allocate_commit = ""
--

CREATE OR REPLACE FUNCTION fr_dhcp_allocate_previous_or_new_framedipaddress (
	v_pool_name VARCHAR(64),
	v_gateway VARCHAR(16),
	v_pool_key VARCHAR(64),
	v_lease_duration INT,
	v_requested_address INET
)
RETURNS inet
LANGUAGE plpgsql
AS $$
DECLARE
	r_address INET;
BEGIN

	-- Reissue an existing IP address lease when re-authenticating a session
	--
	WITH ips AS (
		SELECT framedipaddress FROM dhcpippool
		WHERE pool_name = v_pool_name
			AND pool_key = v_pool_key
			AND expiry_time > NOW()
			AND status IN ('dynamic', 'static')
		LIMIT 1 FOR UPDATE SKIP LOCKED )
	UPDATE dhcpippool
	SET expiry_time = NOW() + v_lease_duration * interval '1 sec'
	FROM ips WHERE dhcpippool.framedipaddress = ips.framedipaddress
	RETURNING dhcpippool.framedipaddress INTO r_address;

	-- Reissue an user's previous IP address, provided that the lease is
	-- available (i.e. enable sticky IPs)
	--
	-- When using this SELECT you should delete the one above. You must also
	-- set allocate_clear = "" in queries.conf to persist the associations
	-- for expired leases.
	--
	-- WITH ips AS (
	--	SELECT framedipaddress FROM dhcpippool
	--	WHERE pool_name = v_pool_name
	--		AND pool_key = v_pool_key
	--		AND status IN ('dynamic', 'static')
	--	LIMIT 1 FOR UPDATE SKIP LOCKED )
	-- UPDATE dhcpippool
	-- SET expiry_time = NOW + v_lease_duration * interval '1 sec'
	-- FROM ips WHERE dhcpippool.framedipaddress = ips.framedipaddress
	-- RETURNING dhcpippool.framedipaddress INTO r_address;

	-- Issue the requested IP address if it is available
	--
	IF r_address IS NULL AND v_requested_address != '0.0.0.0' THEN
		WITH ips AS (
			SELECT framedipaddress FROM dhcpippool
			WHERE pool_name = v_pool_name
				AND framedipaddress = v_requested_address
				AND status = 'dynamic'
				AND ( pool_key = v_pool_key OR expiry_time < NOW() )
			LIMIT 1 FOR UPDATE SKIP LOCKED )
		UPDATE dhcpippool
		SET pool_key = v_pool_key,
			expiry_time = NOW() + v_lease_duration * interval '1 sec',
			gateway = v_gateway
		FROM ips WHERE dhcpippool.framedipaddress = ips.framedipaddress
		RETURNING dhcpippool.framedipaddress INTO r_address;
	END IF;

	-- If we didn't reallocate a previous address then pick the least
	-- recently used address from the pool which maximises the likelihood
	-- of re-assigning the other addresses to their recent user
	--
	IF r_address IS NULL THEN
		WITH ips AS (
			SELECT framedipaddress FROM dhcpippool
			WHERE pool_name = v_pool_name
				AND expiry_time < NOW()
				AND status = 'dynamic'
			ORDER BY expiry_time
			LIMIT 1 FOR UPDATE SKIP LOCKED )
		UPDATE dhcpippool
		SET pool_key = v_pool_key,
			expiry_time = NOW() + v_lease_duration * interval '1 sec',
			gateway = v_gateway
		FROM ips WHERE dhcpippool.framedipaddress = ips.framedipaddress
		RETURNING dhcpippool.framedipaddress INTO r_address;
	END IF;

	-- Return the address that we allocated
	RETURN r_address;

END
$$;
