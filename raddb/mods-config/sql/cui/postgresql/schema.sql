-- Table for Chargeable-User-Identity.
-- Note: If you change name of the table, change name of cui_pkey as well.
CREATE TABLE cui (
	clientipaddress inet NOT NULL DEFAULT '0.0.0.0',
	callingstationid text NOT NULL DEFAULT '',
	username text NOT NULL DEFAULT '',
	cui text NOT NULL DEFAULT '',
	creationdate timestamp with time zone NOT NULL DEFAULT now(),
	lastaccounting timestamp with time zone NOT NULL DEFAULT '-infinity'::timestamp,
	CONSTRAINT cui_pkey PRIMARY KEY (username, clientipaddress, callingstationid)
);

/* This is an old workaround for upsert which was needed prior PostgreSQL 9.5.
 * It's incompatible with the currently used method (ON CONFLICT clause), so if
 * you're updating an old database, you have to remove it:
 * DROP RULE postauth_query ON cui;

CREATE RULE postauth_query AS ON INSERT TO cui
	WHERE EXISTS(SELECT 1 FROM cui WHERE (username, clientipaddress, callingstationid)=(NEW.username, NEW.clientipaddress, NEW.callingstationid))
	DO INSTEAD UPDATE cui SET lastaccounting ='-infinity'::timestamp with time zone, cui=NEW.cui WHERE (username, clientipaddress, callingstationid)=(NEW.username, NEW.clientipaddress, NEW.callingstationid);
*/
