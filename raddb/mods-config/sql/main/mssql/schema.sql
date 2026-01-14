-- $Id$d$
--
-- schema.sql   rlm_sql - FreeRADIUS SQL Module
--
-- Database schema for MSSQL rlm_sql module
--
-- To load:
--  isql -S db_ip_addr -d db_name -U db_login -P db_passwd -i db_mssql.sql
--
-- Based on: db_mysql.sql (Mike Machado <mike@innercite.com>)
--
--					Dmitri Ageev <d_ageev@ortcc.ru>
--


--
-- Table structure for table 'radacct'
--

CREATE TABLE [radacct] (
	[radacctid] [numeric](21, 0) IDENTITY (1, 1) NOT NULL,
	[acctsessionid] [varchar] (64) NOT NULL,
	[acctuniqueid] [varchar] (32) NOT NULL,
	[username] [varchar] (64) NOT NULL,
	[groupname] [varchar] (64) NOT NULL,
	[realm] [varchar] (64) NOT NULL,
	[nasipaddress] [varchar] (15) NOT NULL,
	[nasportid] [varchar] (15) NULL,
	[nasporttype] [varchar] (32) NULL,
	[acctstarttime] [datetime] NOT NULL,
	[acctupdatetime] [datetime] NOT NULL,
	[acctstoptime] [datetime] NOT NULL,
	[acctinterval] [bigint] NULL,
	[acctsessiontime] [bigint] NULL,
	[acctauthentic] [varchar] (32) NULL,
	[connectinfo_start] [varchar] (32) NULL,
	[connectinfo_stop] [varchar] (32) NULL,
	[acctinputoctets] [bigint] NULL,
	[acctoutputoctets] [bigint] NULL,
	[calledstationid] [varchar] (30) NOT NULL,
	[callingstationid] [varchar] (30) NOT NULL,
	[acctterminatecause] [varchar] (32) NOT NULL,
	[servicetype] [varchar] (32) NULL,
	[framedprotocol] [varchar] (32) NULL,
	[framedipaddress] [varchar] (15) NOT NULL,
	[framedipv6address] [varchar] (45) NOT NULL,
	[framedipv6prefix] [varchar] (45) NOT NULL,
	[framedinterfaceid] [varchar] (44) NOT NULL,
	[delegatedipv6prefix] [varchar] (45) NOT NULL,
	[class] [varchar] (64) NULL
) ON [PRIMARY]
GO

ALTER TABLE [radacct] WITH NOCHECK ADD
	CONSTRAINT [DF_radacct_groupname] DEFAULT ('') FOR [groupname],
	CONSTRAINT [DF_radacct_acctsessionid] DEFAULT ('') FOR [acctsessionid],
	CONSTRAINT [DF_radacct_acctuniqueid] DEFAULT ('') FOR [acctnniqueid],
	CONSTRAINT [DF_radacct_username] DEFAULT ('') FOR [username],
	CONSTRAINT [DF_radacct_realm] DEFAULT ('') FOR [realm],
	CONSTRAINT [DF_radacct_nasipaddress] DEFAULT ('') FOR [nasipaddress],
	CONSTRAINT [DF_radacct_nasportid] DEFAULT (null) FOR [nasportid],
	CONSTRAINT [DF_radacct_nasporttype] DEFAULT (null) FOR [nasporttype],
	CONSTRAINT [DF_radacct_acctstarttime] DEFAULT ('1900-01-01 00:00:00') FOR [acctstarttime],
	CONSTRAINT [DF_radacct_acctupdatetime] DEFAULT ('1900-01-01 00:00:00') FOR [acctupdatetime],
	CONSTRAINT [DF_radacct_acctstoptime] DEFAULT ('1900-01-01 00:00:00') FOR [acctstoptime],
	CONSTRAINT [DF_radacct_acctsessiontime] DEFAULT (null) FOR [acctsessiontime],
	CONSTRAINT [DF_radacct_acctauthentic] DEFAULT (null) FOR [acctauthentic],
	CONSTRAINT [DF_radacct_connectinfo_start] DEFAULT (null) FOR [connectinfo_start],
	CONSTRAINT [DF_radacct_connectinfo_stop] DEFAULT (null) FOR [connectinfo_stop],
	CONSTRAINT [DF_radacct_acctinputoctets] DEFAULT (null) FOR [acctinputoctets],
	CONSTRAINT [DF_radacct_acctoutputoctets] DEFAULT (null) FOR [acctoutputoctets],
	CONSTRAINT [DF_radacct_calledstationid] DEFAULT ('') FOR [calledstationid],
	CONSTRAINT [DF_radacct_callingstationid] DEFAULT ('') FOR [callingstationid],
	CONSTRAINT [DF_radacct_acctterminatecause] DEFAULT ('') FOR [acctterminatecause],
	CONSTRAINT [DF_radacct_servicetype] DEFAULT (null) FOR [servicetype],
	CONSTRAINT [DF_radacct_framedprotocol] DEFAULT (null) FOR [framedprotocol],
	CONSTRAINT [DF_radacct_framedipaddress] DEFAULT ('') FOR [framedipaddress],
	CONSTRAINT [DF_radacct_framedipv6address] DEFAULT ('') FOR [framedipv6address],
	CONSTRAINT [DF_radacct_framedipv6prefix] DEFAULT ('') FOR [framedipv6prefix],
	CONSTRAINT [DF_radacct_framedinterfaceid] DEFAULT ('') FOR [framedinterfaceid],
	CONSTRAINT [DF_radacct_delegatedipv6prefix] DEFAULT ('') FOR [delegatedipv6prefix],
	CONSTRAINT [DF_radacct_class] DEFAULT (null) FOR [class],
	CONSTRAINT [PK_radacct] PRIMARY KEY NONCLUSTERED
	(
		[radacctid]
	) ON [PRIMARY]
GO

CREATE INDEX [username] ON [radacct]([username]) ON [PRIMARY]
GO

CREATE INDEX [framedipaddress] ON [radacct]([framedipaddress]) ON [PRIMARY]
GO

CREATE INDEX [framedipv6address] ON [radacct]([framedipv6address]) ON [PRIMARY]
GO

CREATE INDEX [framedipv6prefix] ON [radacct]([framedipv6prefix]) ON [PRIMARY]
GO

CREATE INDEX [framedinterfaceid] ON [radacct]([framedinterfaceid]) ON [PRIMARY]
GO

CREATE INDEX [delegatedipv6prefix] ON [radacct]([delegatedipv6prefix]) ON [PRIMARY]
GO

CREATE INDEX [acctsessionid] ON [radacct]([acctsessionid]) ON [PRIMARY]
GO

CREATE UNIQUE INDEX [acctuniqueid] ON [radacct]([acctuniqueid]) ON [PRIMARY]
GO

CREATE INDEX [acctstarttime] ON [radacct]([acctstarttime]) ON [PRIMARY]
GO

CREATE INDEX [acctstoptime] ON [radacct]([acctstoptime]) ON [PRIMARY]
GO

CREATE INDEX [nasipaddress] ON [radacct]([nasipaddress]) ON [PRIMARY]
GO

CREATE INDEX [class] ON [radacct]([class]) ON [PRIMARY]
GO

-- For use by onoff
CREATE INDEX [radacctbulkclose] ON [radacct]([nasipaddress],[acctstarttime]) WHERE [acctstoptime] IS NULL ON [PRIMARY]
GO


--
-- Table structure for table 'radcheck'
--
-- Note: [op] is varchar to allow for "=" as a value -
-- depending on which driver is used to access the database, if
-- the field is defined as char, then the trailing space may be
-- returned, which fails to parse correctly.
--

CREATE TABLE [radcheck] (
	[id] [int] IDENTITY (1, 1) NOT NULL ,
	[username] [varchar] (64) NOT NULL ,
	[attribute] [varchar] (32) NOT NULL ,
	[value] [varchar] (253) NOT NULL ,
	[op] [varchar] (2) NULL
) ON [PRIMARY]
GO

ALTER TABLE [radcheck] WITH NOCHECK ADD
	CONSTRAINT [DF_radcheck_username] DEFAULT ('') FOR [username],
	CONSTRAINT [DF_radcheck_attribute] DEFAULT ('') FOR [attribute],
	CONSTRAINT [DF_radcheck_value] DEFAULT ('') FOR [value],
	CONSTRAINT [DF_radcheck_op] DEFAULT (null) FOR [op],
	CONSTRAINT [PK_radcheck] PRIMARY KEY NONCLUSTERED
	(
		[id]
	) ON [PRIMARY]
GO

CREATE INDEX [username] ON [radcheck]([username]) ON [PRIMARY]
GO


--
-- Table structure for table 'radgroupcheck'
--

CREATE TABLE [radgroupcheck] (
	[id] [int] IDENTITY (1, 1) NOT NULL ,
	[groupname] [varchar] (64) NOT NULL ,
	[attribute] [varchar] (32) NOT NULL ,
	[value] [varchar] (253) NOT NULL ,
	[op] [varchar] (2) NULL
) ON [PRIMARY]
GO

ALTER TABLE [radgroupcheck] WITH NOCHECK ADD
	CONSTRAINT [DF_radgroupcheck_groupname] DEFAULT ('') FOR [groupname],
	CONSTRAINT [DF_radgroupcheck_attribute] DEFAULT ('') FOR [attribute],
	CONSTRAINT [DF_radgroupcheck_value] DEFAULT ('') FOR [value],
	CONSTRAINT [DF_radgroupcheck_op] DEFAULT (null) FOR [op],
	CONSTRAINT [PK_radgroupcheck] PRIMARY KEY NONCLUSTERED
	(
		[id]
	) ON [PRIMARY]
GO

CREATE INDEX [groupname] ON [radgroupcheck]([groupname]) ON [PRIMARY]
GO


--
-- Table structure for table 'radgroupreply'
--

CREATE TABLE [radgroupreply] (
	[id] [int] IDENTITY (1, 1) NOT NULL ,
	[groupname] [varchar] (64) NOT NULL ,
	[attribute] [varchar] (32) NOT NULL ,
	[value] [varchar] (253) NOT NULL ,
	[op] [varchar] (2) NULL ,
	[prio] [int] NOT NULL
) ON [PRIMARY]
GO

ALTER TABLE [radgroupreply] WITH NOCHECK ADD
	CONSTRAINT [DF_radgroupreply_groupname] DEFAULT ('') FOR [groupname],
	CONSTRAINT [DF_radgroupreply_attribute] DEFAULT ('') FOR [attribute],
	CONSTRAINT [DF_radgroupreply_value] DEFAULT ('') FOR [value],
	CONSTRAINT [DF_radgroupreply_op] DEFAULT (null) FOR [op],
	CONSTRAINT [DF_radgroupreply_prio] DEFAULT (0) FOR [prio],
	CONSTRAINT [PK_radgroupreply] PRIMARY KEY NONCLUSTERED
	(
		[id]
	) ON [PRIMARY]
GO

CREATE INDEX [groupname] ON [radgroupreply]([groupname]) ON [PRIMARY]
GO


--
-- Table structure for table 'radreply'
--

CREATE TABLE [radreply] (
	[id] [int] IDENTITY (1, 1) NOT NULL ,
	[username] [varchar] (64) NOT NULL ,
	[attribute] [varchar] (32) NOT NULL ,
	[value] [varchar] (253) NOT NULL ,
	[op] [varchar] (2) NULL
) ON [PRIMARY]
GO

ALTER TABLE [radreply] WITH NOCHECK ADD
	CONSTRAINT [DF_radreply_username] DEFAULT ('') FOR [username],
	CONSTRAINT [DF_radreply_attribute] DEFAULT ('') FOR [attribute],
	CONSTRAINT [DF_radreply_value] DEFAULT ('') FOR [value],
	CONSTRAINT [DF_radreply_op] DEFAULT (null) FOR [op],
	CONSTRAINT [PK_radreply] PRIMARY KEY NONCLUSTERED
	(
		[id]
	) ON [PRIMARY]
GO

CREATE INDEX [username] ON [radreply]([username]) ON [PRIMARY]
GO


--
-- Table structure for table 'radusergroup'
--

CREATE TABLE [radusergroup] (
	[id] [int] IDENTITY (1, 1) NOT NULL ,
	[username] [varchar] (64) NOT NULL ,
	[groupName] [varchar] (64) NULL ,
	[priority] [int] NULL
) ON [PRIMARY]
GO

ALTER TABLE [radusergroup] WITH NOCHECK ADD
	CONSTRAINT [DF_radusergroup_username] DEFAULT ('') FOR [username],
	CONSTRAINT [DF_radusergroup_groupname] DEFAULT ('') FOR [groupname],
	CONSTRAINT [PK_radusergroup] PRIMARY KEY NONCLUSTERED
	(
		[id]
	) ON [PRIMARY]
GO

CREATE INDEX [username] ON [radusergroup]([username]) ON [PRIMARY]
GO


--
-- Table structure for table 'radpostauth'
--

CREATE TABLE [radpostauth] (
	[id] [int] IDENTITY (1, 1) NOT NULL ,
	[username] [varchar] (64) NOT NULL ,
	[pass] [varchar] (64) NOT NULL ,
	[reply] [varchar] (32) NOT NULL ,
	[authdate] [datetime] NOT NULL,
	[class] [varchar] (64) NULL
)
GO

ALTER TABLE [radpostauth] WITH NOCHECK ADD
	CONSTRAINT [DF_radpostauth_username] DEFAULT ('') FOR [username],
	CONSTRAINT [DF_radpostauth_pass] DEFAULT ('') FOR [pass],
	CONSTRAINT [DF_radpostauth_reply] DEFAULT ('') FOR [reply],
	CONSTRAINT [DF_radpostauth_authdate] DEFAULT (getdate()) FOR [authdate],
	CONSTRAINT [DF_radpostauth_class] DEFAULT ('') FOR [class],
	CONSTRAINT [PK_radpostauth] PRIMARY KEY NONCLUSTERED
	(
		[id]
	) ON [PRIMARY]
GO

--
-- Table structure for table 'nas'
--
CREATE TABLE [nas] (
	[id] [int] IDENTITY (1, 1) NOT NULL ,
	[nasname] [varchar] (128) NOT NULL,
	[shortname] [varchar] (32) NOT NULL,
	[type] [varchar] (30) NOT NULL,
	[ports] [int] NULL,
	[secret] [varchar] (60) NOT NULL,
	[server] [varchar] (64) NULL,
	[community] [varchar] (50) NULL,
	[description] [varchar] (200) NOT NULL,
	[require_ma] [varchar] (4) NOT NULL,
	[limit_proxy_state] [varchar] (4) NOT NULL
) ON [PRIMARY]
GO

CREATE INDEX [nas_name] ON [nas]([nasname]) ON [PRIMARY]
GO

ALTER TABLE [nas] WITH NOCHECK ADD
	CONSTRAINT [DF_nas_type] DEFAULT ('other') FOR [type],
	CONSTRAINT [DF_nas_secret] DEFAULT ('secret') FOR [secret],
	CONSTRAINT [DF_nas_description] DEFAULT ('RADIUS Client') FOR [description],
	CONSTRAINT [DF_require_ma] DEFAULT ('auto') FOR [require_ma],
	CONSTRAINT [DF_limit_proxy_state] DEFAULT ('auto') FOR [limit_proxy_state]
GO

--
-- Table structure for table 'nasreload'
--
CREATE TABLE [nasreload] (
	[nasipaddress] [varchar] (15) NOT NULL PRIMARY KEY,
	[reloadtime] [datetime] NOT NULL
) ON [PRIMARY]
GO
