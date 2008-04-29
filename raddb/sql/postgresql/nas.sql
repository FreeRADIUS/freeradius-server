/*
 * Table structure for table 'nas'
 */
CREATE TABLE nas (
	id		SERIAL PRIMARY KEY,
	nasname		VARCHAR(128) NOT NULL,
	shortname	VARCHAR(32) NOT NULL,
	type		VARCHAR(30) NOT NULL DEFAULT 'other',
	ports		int4,
	secret		VARCHAR(60) NOT NULL,
/*
	server		VARCHAR(64),
 */
	community	VARCHAR(50),
	description	VARCHAR(200)
);
create index nas_nasname on nas (nasname);
