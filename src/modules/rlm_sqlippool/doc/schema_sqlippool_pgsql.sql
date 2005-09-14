
CREATE TABLE radippool (
    id serial NOT NULL,
    pool_name text NOT NULL,
    ip_address inet,
    nas_ip_address text NOT NULL,
    nas_port integer NOT NULL,
    calling_station_id text DEFAULT ''::text NOT NULL,
    expiry_time timestamp(0) without time zone NOT NULL,
    username text DEFAULT ''::text
);

CREATE INDEX radippool_poolname_ipaadr ON radippool USING btree (pool_name, ip_address);
CREATE INDEX radippool_poolname_expire ON radippool USING btree (pool_name, expiry_time);
CREATE INDEX radippool_nasipaddr_port ON radippool USING btree (nas_ip_address, nas_port);
CREATE INDEX radippool_nasipaddr_calling ON radippool USING btree (nas_ip_address, calling_station_id);


-- NOTE: don't forget to vaccum a DB regulary
