-- $Id$
--
-- MSSQL schema for DHCP for FreeRADIUS
--
-- To load:
--  isql -S db_ip_addr -d db_name -U db_login -P db_passwd -i schema.sql

--
-- Table structure for table 'dhcpgroupreply'
--
CREATE TABLE [dhcpgroupreply] (
	[id] [int] IDENTITY (1, 1) NOT NULL,
	[GroupName] [varchar] (64) NOT NULL,
	[Attribute] [varchar] (32) NOT NULL,
	[Value] [varchar] (253) NOT NULL,
	[op] [char] (2) NULL,
	[prio] [int] NOT NULL,
	[Context] [varchar] (16) NOT NULL
) ON [PRIMARY]
GO

ALTER TABLE [dhcpgroupreply] WITH NOCHECK ADD
	CONSTRAINT [DF_dhcpgroupreply_GroupName] DEFAULT ('') FOR [GroupName],
	CONSTRAINT [DF_dhcpgroupreply_Attribute] DEFAULT ('') FOR [Attribute],
	CONSTRAINT [DF_dhcpgroupreply_Value] DEFAULT ('') FOR [Value],
	CONSTRAINT [DF_dhcpgroupreply_op] DEFAULT (null) FOR [op],
	CONSTRAINT [DF_dhcpgroupreply_prio] DEFAULT (0) FOR [prio],
	CONSTRAINT [DF_dhcpgroupreply_context] DEFAULT ('') FOR [Context],
	CONSTRAINT [PK_dhcpgroupreply] PRIMARY KEY NONCLUSTERED
	(
		[id]
	) ON [PRIMARY]
GO

CREATE INDEX [GroupName] ON [dhcpgroupreply]([Context],[GroupName]) ON [PRIMARY]
GO


--
-- Table structure for table 'dhcpreply'
--
CREATE TABLE [dhcpreply] (
	[id] [int] IDENTITY (1, 1) NOT NULL,
	[Identifier] [varchar] (64) NOT NULL,
	[Attribute] [varchar] (32) NOT NULL,
	[Value] [varchar] (253) NOT NULL,
	[op] [char] (2) NULL,
	[Context] [varchar] (16) NOT NULL
) ON [PRIMARY]
GO

ALTER TABLE [dhcpreply] WITH NOCHECK ADD
	CONSTRAINT [DF_dhcpreply_Identifier] DEFAULT ('') FOR [Identifier],
	CONSTRAINT [DF_dhcpreply_Attribute] DEFAULT ('') FOR [Attribute],
	CONSTRAINT [DF_dhcpreply_Value] DEFAULT ('') FOR [Value],
	CONSTRAINT [DF_dhcpreply_op] DEFAULT (null) FOR [op],
	CONSTRAINT [DF_dhcpreply_Context] DEFAULT ('') FOR [Context],
	CONSTRAINT [PK_dhcpreply] PRIMARY KEY NONCLUSTERED
	(
		[id]
	) ON [PRIMARY]
GO

CREATE INDEX [Identifier] ON [dhcpreply]([Context],[Identifier]) ON [PRIMARY]
GO


--
-- Table structure for table 'dhcpgroup'
--
CREATE TABLE [dhcpgroup] (
	[id] [int] IDENTITY (1, 1) NOT NULL,
	[Identifier] [varchar] (64) NOT NULL,
	[GroupName] [varchar] (64) NULL,
	[Priority] [int] NULL,
	[Context] [varchar] (16) NULL
) ON [PRIMARY]
GO

ALTER TABLE [dhcpgroup] WITH NOCHECK ADD
	CONSTRAINT [DF_dhcpgroup_Identifier] DEFAULT ('') FOR [Identifier],
	CONSTRAINT [DF_dhcpgroup_GroupName] DEFAULT ('') FOR [GroupName],
	CONSTRAINT [DF_dhcpgroup_Context] DEFAULT ('') FOR [Context],
	CONSTRAINT [PK_dhcpgroup] PRIMARY KEY NONCLUSTERED
	(
		[id]
	) ON [PRIMARY]
GO

CREATE INDEX [Identifier] ON [dhcpgroup]([Context],[Identifier]) ON [PRIMARY]
GO
