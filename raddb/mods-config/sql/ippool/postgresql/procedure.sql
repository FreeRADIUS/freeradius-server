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
--	SELECT fr_allocate_previous_or_new_framedipaddress( \
--		'%{control:${pool_name}}', \
--		'%{User-Name}', \
--		'%{Calling-Station-Id}', \
--		'%{NAS-IP-Address}', \
--		'${pool_key}', \
--		${lease_duration} \
--	)"
-- allocate_update = ""
-- allocate_commit = ""
--

CREATE INDEX radippool_poolname_username_callingstationid ON radippool(pool_name,username,callingstationid);

CREATE OR REPLACE FUNCTION fr_allocate_previous_or_new_framedipaddress (
	v_pool_name VARCHAR(64),
	v_username VARCHAR(64),
	v_callingstationid VARCHAR(64),
	v_nasipaddress VARCHAR(16),
	v_pool_key VARCHAR(64),
	v_lease_duration INT
)
RETURNS inet
LANGUAGE plpgsql
AS $$
DECLARE
	r_address inet;
BEGIN

	-- Reissue an existing IP address lease when re-authenticating a session
	--
	SELECT framedipaddress INTO r_address
	FROM radippool
	WHERE pool_name = v_pool_name
		AND expiry_time > NOW()
		AND username = v_username
		AND callingstationid = v_callingstationid
	LIMIT 1
	FOR UPDATE SKIP LOCKED;

	-- Reissue an user's previous IP address, provided that the lease is
	-- available (i.e. enable sticky IPs)
	--
	-- When using this SELECT you should delete the one above. You must also
	-- set allocate_clear = "" in queries.conf to persist the associations
	-- for expired leases.
	--
	-- SELECT framedipaddress INTO r_address
	-- FROM radippool
	-- WHERE pool_name = v_pool_name
	--	 AND username = v_username
	--	 AND callingstationid = v_callingstationid
	-- LIMIT 1
	-- FOR UPDATE SKIP LOCKED;

	-- If we didn't reallocate a previous address then pick the least
	-- recently used address from the pool which maximises the likelihood
	-- of re-assigning the other addresses to their recent user
	--
	IF r_address IS NULL THEN
		SELECT framedipaddress INTO r_address
		FROM radippool
		WHERE pool_name = v_pool_name
		AND expiry_time < NOW()
		ORDER BY
		    expiry_time
		LIMIT 1
		FOR UPDATE SKIP LOCKED;
	END IF;

	-- Return nothing if we failed to allocated an address
	--
	IF r_address IS NULL THEN
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
		expiry_time = NOW() + v_lease_duration * interval '1 sec'
	WHERE framedipaddress = r_address;

	-- Return the address that we allocated
	RETURN r_address;

END
$$;
