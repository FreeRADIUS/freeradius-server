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
--	 SELECT fr_ippool_allocate_previous_or_new_address( \
--		 '%{control.${pool_name}}', \
--		 '${gateway}', \
--		 '${owner}', \
--		 ${offer_duration}, \
--		 '%{${requested_address}:-0.0.0.0}'
--	 ) FROM dual"
-- allocate_update = ""
-- allocate_commit = ""
--

CREATE OR REPLACE FUNCTION fr_ippool_allocate_previous_or_new_address (
	v_pool_name IN VARCHAR2,
	v_gateway IN VARCHAR2,
	v_owner IN VARCHAR2,
	v_lease_duration IN INTEGER,
	v_requsted_address IN VARCHAR2
)
RETURN varchar2 IS
	PRAGMA AUTONOMOUS_TRANSACTION;
	r_address varchar2(15);
BEGIN

	-- Reissue an existing IP address lease when re-authenticating a session
	--
	BEGIN
		SELECT address INTO r_address FROM fr_ippool WHERE id IN (
			SELECT id FROM (
				SELECT *
				FROM fr_ippool
				JOIN fr_ippool_status
				ON fr_ippool_status.status_id = fr_ippool.status_id
				WHERE pool_name = v_pool_name
					AND expiry_time > current_timestamp
					AND owner = v_owner
					AND fr_ippool_status.status IN ('dynamic', 'static')
			) WHERE ROWNUM <= 1
		) FOR UPDATE SKIP LOCKED;
	EXCEPTION
		WHEN NO_DATA_FOUND THEN
			r_address := NULL;
	END;

	-- Oracle >= 12c version of the above query
	--
	-- BEGIN
	--	SELECT address INTO r_address FROM fr_ippool WHERE id IN (
	--		SELECT id FROM fr_ippool
	--		JOIN fr_ippool_status
	--		ON fr_ippool_status.status_id = fr_ippool.status_id
	--		WHERE pool_name = v_pool_name
	--			AND expiry_time > current_timestamp
	--			AND owner = v_owner
	--			AND fr_ippool_status.status IN ('dynamic', 'static')
	--		FETCH FIRST 1 ROWS ONLY
	--	) FOR UPDATE SKIP LOCKED;
	-- EXCEPTION
	--	WHEN NO_DATA_FOUND THEN
	--		r_address := NULL;
	-- END;

	-- Reissue an user's previous IP address, provided that the lease is
	-- available (i.e. enable sticky IPs)
	--
	-- When using this SELECT you should delete the one above. You must also
	-- set allocate_clear = "" in queries.conf to persist the associations
	-- for expired leases.
	--
	-- BEGIN
	--	SELECT address INTO r_address FROM fr_ippool WHERE id IN (
	--		SELECT id FROM (
	--			SELECT *
	--			FROM fr_ippool
	--			JOIN fr_ippool_status
	--			ON fr_ippool_status.status_id = fr_ippool.status_id
	--			WHERE pool_name = v_pool_name
	--				AND owner = v_owner
	--				AND fr_ippool_status.status IN ('dynamic', 'static')
	--		) WHERE ROWNUM <= 1
	--	) FOR UPDATE SKIP LOCKED;
	-- EXCEPTION
	--	WHEN NO_DATA_FOUND THEN
	--		r_address := NULL;
	-- END;

	-- Oracle >= 12c version of the above query
	--
	-- BEGIN
	--	SELECT address INTO r_address FROM fr_ippool WHERE id IN (
	--		SELECT id FROM fr_ippool
	--		JOIN fr_ippool_status
	--		ON fr_ippool_status.status_id = fr_ippool.status_id
	--		WHERE pool_name = v_pool_name
	--			AND owner = v_owner
	--			AND fr_ippool_status.status IN ('dynamic', 'static')
	--		FETCH FIRST 1 ROWS ONLY
	--	) FOR UPDATE SKIP LOCKED;
	-- EXCEPTION
	--	WHEN NO_DATA_FOUND THEN
	--		r_address := NULL;
	-- END;

	-- Issue the requested IP address if it is available
	--
	IF r_address IS NULL AND v_requested_address <> '0.0.0.0' THEN
		BEGIN
		SELECT address INTO r_address FROM fr_ippool WHERE id IN (
			SELECT id FROM (
				SELECT *
				FROM fr_ippool
				JOIN fr_ippool_status
				ON fr_ippool_status.status_id = fr_ippool.status_id
				WHERE pool_name = v_pool_name
					AND address = v_requested_address
					AND fr_ippool_status.status = 'dynamic'
					AND expiry_time < CURRENT_TIMESTAMP
				) WHERE ROWNUM <= 1
		) FOR UPDATE SKIP LOCKED;
		EXCEPTION
		WHEN NO_DATA_FOUND THEN
			r_address := NULL;
		END;
	END IF;

	-- Oracle >= 12c version of the above query
	--
	-- IF r_address IS NULL AND v_requested_address <> '0.0.0.0' THEN
	--	BEGIN
	--	SELECT address INTO r_address FROM fr_ippool WHERE id IN (
	--		SELECT id FROM fr_ippool
	--		JOIN fr_ippool_status
	--		ON fr_ippool_status.status_id = fr_ippool.status_id
	--		WHERE pool_name = v_pool_name
	--			AND address = v_requested_address
	--			AND fr_ippool_status.status = 'dynamic'
	--			AND expiry_time < CURRENT_TIMESTAMP
	--		FETCH FIRST 1 ROWS ONLY
	--	) FOR UPDATE SKIP LOCKED;
	--	EXCEPTION
	--	WHEN NO_DATA_FOUND THEN
	--		r_address := NULL;
	--	END;
	-- END IF;

	-- If we didn't reallocate a previous address then pick the least
	-- recently used address from the pool which maximises the likelihood
	-- of re-assigning the other addresses to their recent user
	--

	IF r_address IS NULL THEN
		DECLARE
			l_cursor sys_refcursor;
		BEGIN
			OPEN l_cursor FOR
				SELECT address
				FROM fr_ippool
				JOIN fr_ippool_status
				ON fr_ippool_status.status_id = fr_ippool.status_id
				WHERE pool_name = v_pool_name
				AND expiry_time < CURRENT_TIMESTAMP
				AND fr_ippool_status.status = 'dynamic'
				ORDER BY expiry_time
				FOR UPDATE SKIP LOCKED;
			FETCH l_cursor INTO r_address;
			CLOSE l_cursor;
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
	UPDATE fr_ippool
	SET
		gateway = v_gateway,
		owner = v_owner,
		expiry_time = CURRENT_TIMESTAMP + v_lease_duration * INTERVAL '1' SECOND(1)
	WHERE address = r_address;

	-- Return the address that we allocated
	COMMIT;
	RETURN r_address;

END;

