CREATE TABLE radippool (
	id                      INT PRIMARY KEY,
	pool_name               VARCHAR(30) NOT NULL,
	framedipaddress         VARCHAR(15) NOT NULL,
	nasipaddress            VARCHAR(15) NOT NULL,
	pool_key                VARCHAR(30) NOT NULL,
	CalledStationId         VARCHAR(64) NOT NULL,
	CallingStationId        VARCHAR(64) NOT NULL,
	expiry_time             timestamp(0) NOT NULL,
	username                VARCHAR(64)
);

CREATE INDEX radippool_poolname_expire ON radippool (pool_name, expiry_time);
CREATE INDEX radippool_framedipaddress ON radippool (framedipaddress);
CREATE INDEX radippool_nasip_poolkey_ipaddress ON radippool (nasipaddress, pool_key, framedipaddress);

CREATE SEQUENCE radippool_seq START WITH 1 INCREMENT BY 1;

CREATE OR REPLACE TRIGGER radippool_serialnumber
	BEFORE INSERT OR UPDATE OF id ON radippool
	FOR EACH ROW
	BEGIN
		if ( :new.id = 0 or :new.id is null ) then
			SELECT radippool_seq.nextval into :new.id from dual;
		end if;
	END;
/
