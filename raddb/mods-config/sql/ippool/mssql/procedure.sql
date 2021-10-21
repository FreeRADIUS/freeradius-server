--
-- A stored procedure to reallocate a user's previous address, otherwise
-- provide a free address.
--
-- Using this SP reduces the usual set dialogue of queries to a single
-- query:
--
--   BEGIN TRAN; "SELECT FOR UPDATE"; UPDATE; COMMIT TRAN;  ->  EXEC sp
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
--      EXEC fr_ippool_allocate_previous_or_new_address \
--              @v_pool_name = '%{control.${pool_name}}', \
--              @v_gateway = '${gateway}', \
--              @v_owner = '${owner}', \
--              @v_lease_duration = ${offer_duration}, \
--              @v_requested_address = '%{${requested_address}:-0.0.0.0}' \
--      "
-- allocate_update = ""
-- allocate_commit = ""
--

CREATE OR ALTER PROCEDURE fr_ippool_allocate_previous_or_new_address
	@v_pool_name VARCHAR(64),
	@v_gateway VARCHAR(128),
	@v_owner VARCHAR(128),
	@v_lease_duration INT,
	@v_requested_address VARCHAR(15)
AS
	BEGIN

		-- MS SQL lacks a "SELECT FOR UPDATE" statement, and its table
		-- hints do not provide a direct means to implement the row-level
		-- read lock needed to guarentee that concurrent queries do not
		-- select the same Framed-IP-Address for allocation to distinct
		-- users.
		--
		-- The "WITH cte AS ( SELECT ... ) UPDATE cte ... OUTPUT INTO"
		-- patterns in this procedure body compensate by wrapping
		-- the SELECT in a synthetic UPDATE which locks the row.

		DECLARE @r_address_tab TABLE(id VARCHAR(15));
		DECLARE @r_address VARCHAR(15);

		BEGIN TRAN;

		-- Reissue an existing IP address lease when re-authenticating a session
		--
		WITH cte AS (
			SELECT TOP(1) address
			FROM fr_ippool
			JOIN fr_ippool_status
			ON fr_ippool_status.status_id = fr_ippool.status_id
			WHERE pool_name = @v_pool_name
				AND expiry_time > CURRENT_TIMESTAMP
				AND owner = @v_owner
				AND fr_ippool_status.status IN ('dynamic', 'static')
		)
		UPDATE cte WITH (rowlock, readpast)
		SET address = address
		OUTPUT INSERTED.address INTO @r_address_tab;
		SELECT @r_address = id FROM @r_address_tab;

		-- Reissue an user's previous IP address, provided that the lease is
		-- available (i.e. enable sticky IPs)
		--
		-- When using this SELECT you should delete the one above. You must also
		-- set allocate_clear = "" in queries.conf to persist the associations
		-- for expired leases.
		--
		-- WITH cte AS (
		-- 	SELECT TOP(1) address
		-- 	FROM fr_ippool
		--	JOIN fr_ippool_status
		--	ON fr_ippool_status.status_id = fr_ippool.status_id
		-- 	WHERE pool_name = @v_pool_name
		-- 		AND owner = @v_owner
		--		AND fr_ippool_status.status IN ('dynamic', 'static')
		-- )
		-- UPDATE cte WITH (rowlock, readpast)
		-- SET address = address
		-- OUTPUT INSERTED.address INTO @r_address_tab;
		-- SELECT @r_address = id FROM @r_address_tab;

		-- Issue the requested IP address if it is available
		--
		IF @r_address IS NULL AND @v_requested_address <> '0.0.0.0'
		BEGIN
			WITH cte AS (
				SELECT TOP(1) address
				FROM fr_ippool WITH (rowlock, readpast)
				JOIN fr_ippool_status
				ON fr_ippool_status.status_id = fr_ippool.status_id
				WHERE pool_name = @v_pool_name
					AND address = @v_requested_address
					AND fr_ippool_status.status = 'dynamic'
					AND expiry_time < CURRENT_TIMESTAMP
			)
			UPDATE cte
			SET address = address
			OUTPUT INSERTED.address INTO @r_address_tab;
			SELECT @r_address = id FROM @r_address_tab;
		END

		-- If we didn't reallocate a previous address then pick the least
		-- recently used address from the pool which maximises the likelihood
		-- of re-assigning the other addresses to their recent user
		--
		IF @r_address IS NULL
		BEGIN
			WITH cte AS (
				SELECT TOP(1) address
				FROM fr_ippool WITH (xlock rowlock readpast)
				JOIN fr_ippool_status
				ON fr_ippool_status.status_id = fr_ippool.status_id
				WHERE pool_name = @v_pool_name
					AND expiry_time < CURRENT_TIMESTAMP
					AND fr_ippool_status.status = 'dynamic'
				ORDER BY
					expiry_time
			)
			UPDATE cte
			SET address = address
			OUTPUT INSERTED.address INTO @r_address_tab;
			SELECT @r_address = id FROM @r_address_tab;
		END

		-- Return nothing if we failed to allocated an address
		--
		IF @r_address IS NULL
		BEGIN
			COMMIT TRAN;
			RETURN;
		END

		-- Update the pool having allocated an IP address
		--
		UPDATE fr_ippool
		SET
			gateway = @v_gateway,
			owner = @v_owner,
			expiry_time = DATEADD(SECOND,@v_lease_duration,CURRENT_TIMESTAMP)
		WHERE address = @r_address;

		COMMIT TRAN;

		-- Return the address that we allocated
		SELECT @r_address;

	END
GO
