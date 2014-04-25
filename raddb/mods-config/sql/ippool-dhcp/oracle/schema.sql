CREATE TABLE radippool (
	id                      INT PRIMARY KEY,
	pool_name               VARCHAR(30) NOT NULL,
	framedipaddress         VARCHAR(30) NOT NULL,
	nasipaddress            VARCHAR(30) NOT NULL,
	pool_key                VARCHAR(64) NOT NULL,
	calledstationid         VARCHAR(64),
	callingstationid        VARCHAR(64) NOT NULL,
	expiry_time             TIMESTAMP(0) NOT NULL,
	username                VARCHAR(100)
);

CREATE INDEX radippool_poolname_ipaddr ON radippool (pool_name, framedipaddress);
CREATE INDEX radippool_poolname_expire ON radippool (pool_name, expiry_time);
CREATE INDEX radippool_nasipaddr_key ON radippool (nasipaddress, pool_key);
CREATE INDEX radippool_nasipaddr_calling ON radippool (nasipaddress, callingstationid);

CREATE SEQUENCE radippool_seq START WITH 1 INCREMENT BY 1;

CREATE OR REPLACE TRIGGER radippool_serialnumber
	BEFORE INSERT OR UPDATE OF id ON radippool
	FOR EACH ROW
	BEGIN
		IF ( :NEW.id = 0 OR :NEW.id IS NULL ) THEN
			SELECT radippool_seq.NEXTVAL INTO :NEW.id FROM dual;
		END IF;
	END;
/
