CREATE TABLE moonshot_targeted_ids (
  gss_acceptor varchar(254) NOT NULL DEFAULT '',
  namespace varchar(36) NOT NULL DEFAULT '',
  username varchar(64) NOT NULL DEFAULT '',
  targeted_id varchar(128) NOT NULL DEFAULT '',
  creationdate TIMESTAMP with time zone NOT NULL default 'now()',
  PRIMARY KEY  (username, gss_acceptor, namespace)
);
