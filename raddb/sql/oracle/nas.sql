/*
 * Table structure for table 'nas'
 */

CREATE TABLE nas (
	id 		INT PRIMARY KEY,
	nasname		VARCHAR(128),
	shortname	VARCHAR(32),
	type		VARCHAR(30),
	ports		INT,
	secret		VARCHAR(60),
/*
	server		VARCHAR(64),
 */
	community	VARCHAR(50),
	description	VARCHAR(200)
);
CREATE SEQUENCE nas_seq START WITH 1 INCREMENT BY 1;

