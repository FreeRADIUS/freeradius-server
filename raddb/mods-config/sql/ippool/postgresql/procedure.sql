--
-- Use the following indexes and function if using the stored procedure to
-- find the previously used address.
--
-- You may wish to set the ORDER BY expiry_time to DESC for the first two
-- queries in order to assign the address that the user had most recently,
-- instead of assigning the oldest address the user had used.
--

CREATE INDEX radippool_pool_name ON radippool USING btree (pool_name);
CREATE INDEX radippool_username ON radippool USING btree (username);
CREATE INDEX radippool_callingstationid ON radippool USING btree (callingstationid);

CREATE OR REPLACE FUNCTION find_previous_or_new_framedipaddress (
	v_pool_name VARCHAR(64),
	v_username VARCHAR(64),
	v_callingstationid VARCHAR(64)
)
RETURNS inet
LANGUAGE plpgsql
AS $$
DECLARE
	r_address inet;
BEGIN
	SELECT framedipaddress INTO r_address
	FROM radippool
	WHERE radippool.pool_name = v_pool_name
		AND radippool.expiry_time < 'now'::timestamp(0)
		AND radippool.username = v_username
		AND radippool.callingstationid = v_callingstationid
	ORDER BY expiry_time
	LIMIT 1
	FOR UPDATE SKIP LOCKED;
	IF r_address IS NOT NULL THEN
		RETURN r_address;
	END IF;
 SELECT framedipaddress INTO r_address
	FROM radippool
	WHERE radippool.pool_name = v_pool_name
		AND radippool.expiry_time < 'now'::timestamp(0)
		AND radippool.username = v_username
	ORDER BY expiry_time
	LIMIT 1
	FOR UPDATE SKIP LOCKED;
	IF r_address IS NOT NULL THEN
		RETURN r_address;
	END IF;
 SELECT framedipaddress INTO r_address
	FROM radippool
	WHERE radippool.pool_name = v_pool_name
		AND radippool.expiry_time < 'now'::timestamp(0)
	ORDER BY expiry_time
	LIMIT 1
	FOR UPDATE SKIP LOCKED;
	RETURN r_address;
END
$$;
