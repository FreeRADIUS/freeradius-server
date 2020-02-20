CREATE TABLE cui (
	clientipaddress inet NOT NULL DEFAULT '0.0.0.0',
	callingstationid varchar(50) NOT NULL DEFAULT '',
	username varchar(64) NOT NULL DEFAULT '',
	cui varchar(128) NOT NULL DEFAULT '',
	creationdate timestamp with time zone NOT NULL DEFAULT 'now()',
	lastaccounting timestamp with time zone NOT NULL DEFAULT '-infinity'::timestamp,
	PRIMARY KEY (username, clientipaddress, callingstationid)
);

CREATE RULE postauth_query AS ON INSERT TO cui
	WHERE EXISTS(SELECT 1 FROM cui WHERE (username, clientipaddress, callingstationid)=(NEW.username, NEW.clientipaddress, NEW.callingstationid))
	DO INSTEAD UPDATE cui SET lastaccounting ='-infinity'::timestamp with time zone, cui=NEW.cui WHERE (username, clientipaddress, callingstationid)=(NEW.username, NEW.clientipaddress, NEW.callingstationid);

