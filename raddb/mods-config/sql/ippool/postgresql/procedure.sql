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
--	SELECT fr_ippool_allocate_previous_or_new_address( \
--		'%{control.${pool_name}}', \
--		'${gateway}', \
--		'${owner}', \
--		${offer_duration}, \
--		'%{${requested_address}:-0.0.0.0}' \
--	)"
-- allocate_update = ""
-- allocate_commit = ""
--

CREATE OR REPLACE FUNCTION fr_ippool_allocate_previous_or_new_address (
	v_pool_name VARCHAR(64),
	v_gateway VARCHAR(128),
	v_owner VARCHAR(128),
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
		SELECT address FROM fr_ippool
		WHERE pool_name = v_pool_name
			AND owner = v_owner
			AND expiry_time > NOW()
			AND status IN ('dynamic', 'static')
		LIMIT 1 FOR UPDATE SKIP LOCKED )
	UPDATE fr_ippool
	SET expiry_time = NOW() + v_lease_duration * interval '1 sec'
	FROM ips WHERE fr_ippool.address = ips.address
	RETURNING fr_ippool.address INTO r_address;

	-- Reissue an user's previous IP address, provided that the lease is
	-- available (i.e. enable sticky IPs)
	--
	-- When using this SELECT you should delete the one above. You must also
	-- set allocate_clear = "" in queries.conf to persist the associations
	-- for expired leases.
	--
	-- WITH ips AS (
	--	SELECT address FROM fr_ippool
	--	WHERE pool_name = v_pool_name
	--		AND owner = v_owner
	--		AND status IN ('dynamic', 'static')
	--	LIMIT 1 FOR UPDATE SKIP LOCKED )
	-- UPDATE fr_ippool
	-- SET expiry_time = NOW + v_lease_duration * interval '1 sec'
	-- FROM ips WHERE fr_ippool.address = ips.address
	-- RETURNING fr_ippool.address INTO r_address;

	-- Issue the requested IP address if it is available
	--
	IF r_address IS NULL AND v_requested_address != '0.0.0.0' THEN
		WITH ips AS (
			SELECT address FROM fr_ippool
			WHERE pool_name = v_pool_name
				AND address = v_requested_address
				AND status = 'dynamic'
				AND expiry_time < NOW()
			LIMIT 1 FOR UPDATE SKIP LOCKED )
		UPDATE fr_ippool
		SET owner = v_owner,
			expiry_time = NOW() + v_lease_duration * interval '1 sec',
			gateway = v_gateway
		FROM ips WHERE fr_ippool.address = ips.address
		RETURNING fr_ippool.address INTO r_address;
	END IF;

	-- If we didn't reallocate a previous address then pick the least
	-- recently used address from the pool which maximises the likelihood
	-- of re-assigning the other addresses to their recent user
	--
	IF r_address IS NULL THEN
		WITH ips AS (
			SELECT address FROM fr_ippool
			WHERE pool_name = v_pool_name
				AND expiry_time < NOW()
				AND status = 'dynamic'
			ORDER BY expiry_time
			LIMIT 1 FOR UPDATE SKIP LOCKED )
		UPDATE fr_ippool
		SET owner = v_owner,
			expiry_time = NOW() + v_lease_duration * interval '1 sec',
			gateway = v_gateway
		FROM ips WHERE fr_ippool.address = ips.address
		RETURNING fr_ippool.address INTO r_address;
	END IF;

	-- Return the address that we allocated
	RETURN r_address;

END
$$;
