/* Copyright 2006 The FreeRADIUS server project */

#ifndef _SQL_POSTGRESQL_H_
#define _SQL_POSTGRESQL_H_

RCSIDH(sql_postgresql_h, "$Id$")

/** Error Codes and required information
 *
 */
typedef struct pgsql_error{
	char const	*errorcode;	//!< 5 char error code from PG_DIAG_SQLSTATE.
	char const	*meaning;	//!< Verbose description.
	bool 		reconnect;	//!< Should reconnect socket when receiving this error.
} pgerror;

static pgerror errorcodes[] = {
	{ "0100C", "DYNAMIC RESULT SETS RETURNED", false },
	{ "01008", "IMPLICIT ZERO BIT PADDING", false },
	{ "01003", "NULL VALUE ELIMINATED IN SET FUNCTION", false },
	{ "01007", "PRIVILEGE NOT GRANTED", false },
	{ "01006", "PRIVILEGE NOT REVOKED", false },
	{ "01004", "STRING DATA RIGHT TRUNCATION", false },
	{ "01P01", "DEPRECATED FEATURE", false },

	{ "02000", "NO DATA", false },
	{ "02001", "NO ADDITIONAL DYNAMIC RESULT SETS RETURNED", false },

	{ "03000", "SQL STATEMENT NOT YET COMPLETE", false },

	{ "08000", "CONNECTION EXCEPTION", false },
	{ "08003", "CONNECTION DOES NOT EXIST", false },
	{ "08006", "CONNECTION FAILURE", false },
	{ "08001", "SQLCLIENT UNABLE TO ESTABLISH SQLCONNECTION", false },
	{ "08004", "SQLSERVER REJECTED ESTABLISHMENT OF SQLCONNECTION", false },
	{ "08007", "TRANSACTION RESOLUTION UNKNOWN", false },
	{ "08P01", "PROTOCOL VIOLATION", false },

	{ "9000", "TRIGGERED ACTION EXCEPTION", false },

	{ "0A000", "FEATURE NOT SUPPORTED", false },

	{ "0B000", "INVALID TRANSACTION INITIATION", false },

	{ "0F000", "LOCATOR EXCEPTION", false },
	{ "0F001", "INVALID LOCATOR SPECIFICATION", false },

	{ "0L000", "INVALID GRANTOR", false },
	{ "0LP01", "INVALID GRANT OPERATION", false },

	{ "21000", "CARDINALITY VIOLATION", false },

	{ "22000", "DATA EXCEPTION", false },
	{ "2202E", "ARRAY SUBSCRIPT ERROR", false },
	{ "22021", "CHARACTER NOT IN REPERTOIRE", false },
	{ "22008", "DATETIME FIELD OVERFLOW", false },
	{ "22012", "DIVISION BY ZERO", false },
	{ "22005", "ERROR IN ASSIGNMENT", false },
	{ "2200B", "ESCAPE CHARACTER CONFLICT", false },
	{ "22022", "INDICATOR OVERFLOW", false },
	{ "22015", "INTERVAL FIELD OVERFLOW", false },
	{ "2201E", "INVALID ARGUMENT FOR LOGARITHM", false },
	{ "2201F", "INVALID ARGUMENT FOR POWER FUNCTION", false },
	{ "2201G", "INVALID ARGUMENT FOR WIDTH BUCKET FUNCTION", false },
	{ "22018", "INVALID CHARACTER VALUE FOR CAST", false },
	{ "22007", "INVALID DATETIME FORMAT", false },
	{ "22019", "INVALID ESCAPE CHARACTER", false },
	{ "2200D", "INVALID ESCAPE OCTET", false },
	{ "22025", "INVALID ESCAPE SEQUENCE", false },
	{ "22P06", "NONSTANDARD USE OF ESCAPE CHARACTER", false },
	{ "22010", "INVALID INDICATOR PARAMETER VALUE", false },
	{ "22020", "INVALID LIMIT VALUE", false },
	{ "22023", "INVALID PARAMETER VALUE", false },
	{ "2201B", "INVALID REGULAR EXPRESSION", false },
	{ "22009", "INVALID TIME ZONE DISPLACEMENT VALUE", false },
	{ "2200C", "INVALID USE OF ESCAPE CHARACTER", false },
	{ "2200G", "MOST SPECIFIC TYPE MISMATCH", false },
	{ "22004", "NULL VALUE NOT ALLOWED", false },
	{ "22002", "NULL VALUE NO INDICATOR PARAMETER", false },
	{ "22003", "NUMERIC VALUE OUT OF RANGE", false },
	{ "22026", "STRING DATA LENGTH MISMATCH", false },
	{ "22001", "STRING DATA RIGHT TRUNCATION", false },
	{ "22011", "SUBSTRING ERROR", false },
	{ "22027", "TRIM ERROR", false },
	{ "22024", "UNTERMINATED C STRING", false },
	{ "2200F", "ZERO LENGTH CHARACTER STRING", false },
	{ "22P01", "FLOATING POINT EXCEPTION", false },
	{ "22P02", "INVALID TEXT REPRESENTATION", false },
	{ "22P03", "INVALID BINARY REPRESENTATION", false },
	{ "22P04", "BAD COPY FILE FORMAT", false },
	{ "22P05", "UNTRANSLATABLE CHARACTER", false },

	{ "23000", "INTEGRITY CONSTRAINT VIOLATION", false },
	{ "23001", "RESTRICT VIOLATION", false },
	{ "23502", "NOT NULL VIOLATION", false },
	{ "23503", "FOREIGN KEY VIOLATION", false },
	{ "23514", "CHECK VIOLATION", false },

	{ "24000", "INVALID CURSOR STATE", false },

	{ "25000", "INVALID TRANSACTION STATE", false },
	{ "25001", "ACTIVE SQL TRANSACTION", false },
	{ "25002", "BRANCH TRANSACTION ALREADY ACTIVE", false },
	{ "25008", "HELD CURSOR REQUIRES SAME ISOLATION LEVEL", false },
	{ "25003", "INAPPROPRIATE ACCESS MODE FOR BRANCH TRANSACTION", false },
	{ "25004", "INAPPROPRIATE ISOLATION LEVEL FOR BRANCH TRANSACTION", false },
	{ "25005", "NO ACTIVE SQL TRANSACTION FOR BRANCH TRANSACTION", false },
	{ "25006", "READ ONLY SQL TRANSACTION", false },
	{ "25007", "SCHEMA AND DATA STATEMENT MIXING NOT SUPPORTED", false },
	{ "25P01", "NO ACTIVE SQL TRANSACTION", false },
	{ "25P02", "IN FAILED SQL TRANSACTION", false },

	{ "26000", "INVALID SQL STATEMENT NAME", false },

	{ "27000", "TRIGGERED DATA CHANGE VIOLATION", false },

	{ "28000", "INVALID AUTHORIZATION SPECIFICATION", false },

	{ "2B000", "DEPENDENT PRIVILEGE DESCRIPTORS STILL EXIST", false },
	{ "2BP01", "DEPENDENT OBJECTS STILL EXIST", false },

	{ "2D000", "INVALID TRANSACTION TERMINATION", false },

	{ "2F000", "SQL ROUTINE EXCEPTION", false },
	{ "2F005", "FUNCTION EXECUTED NO RETURN STATEMENT", false },
	{ "2F002", "MODIFYING SQL DATA NOT PERMITTED", false },
	{ "2F003", "PROHIBITED SQL STATEMENT ATTEMPTED", false },
	{ "2F004", "READING SQL DATA NOT PERMITTED", false },

	{ "34000", "INVALID CURSOR NAME", false },

	{ "38000", "EXTERNAL ROUTINE EXCEPTION", false },
	{ "38001", "CONTAINING SQL NOT PERMITTED", false },
	{ "38002", "MODIFYING SQL DATA NOT PERMITTED", false },
	{ "38003", "PROHIBITED SQL STATEMENT ATTEMPTED", false },
	{ "38004", "READING SQL DATA NOT PERMITTED", false },

	{ "39000", "EXTERNAL ROUTINE INVOCATION EXCEPTION", false },
	{ "39001", "INVALID SQLSTATE RETURNED", false },
	{ "39004", "NULL VALUE NOT ALLOWED", false },
	{ "39P01", "TRIGGER PROTOCOL VIOLATED", false },
	{ "39P02", "SRF PROTOCOL VIOLATED", false },

	{ "3B000", "SAVEPOINT EXCEPTION", false },
	{ "3B001", "INVALID SAVEPOINT SPECIFICATION", false },

	{ "3D000", "INVALID CATALOG NAME", false },
	{ "3F000", "INVALID SCHEMA NAME", false },

	{ "40000", "TRANSACTION ROLLBACK", false },
	{ "40002", "TRANSACTION INTEGRITY CONSTRAINT VIOLATION", false },
	{ "40001", "SERIALIZATION FAILURE", false },
	{ "40003", "STATEMENT COMPLETION UNKNOWN", false },
	{ "40P01", "DEADLOCK DETECTED", false },

	{ "44000", "WITH CHECK OPTION VIOLATION", false },

	{ "53000", "INSUFFICIENT RESOURCES", false },
	{ "53100", "DISK FULL", false },
	{ "53200", "OUT OF MEMORY", false },
	{ "53300", "TOO MANY CONNECTIONS", false },

	{ "54000", "PROGRAM LIMIT EXCEEDED", false },
	{ "54001", "STATEMENT TOO COMPLEX", false },
	{ "54011", "TOO MANY COLUMNS", false },
	{ "54023", "TOO MANY ARGUMENTS", false },

	{ "55000", "OBJECT NOT IN PREREQUISITE STATE", false },
	{ "55006", "OBJECT IN USE", false },
	{ "55P02", "CANT CHANGE RUNTIME PARAM", false },
	{ "55P03", "LOCK NOT AVAILABLE", false },

	{ "57000", "OPERATOR INTERVENTION", true },

	/*
	 *	This is really 'statement_timeout' or the error which is returned when
	 *	'statement_timeout' is hit.
	 *
	 *	It's unlikely that this has been caused by a connection failure, and
	 *	most likely to have been caused by a long running query.
	 *
	 *	If the query is persistently long running then the database/query should
	 *	be optimised, or 'statement_timeout' should be increased.
	 *
	 *	Forcing a reconnect here only eats more resources on the DB so we will
	 *	no longer do so as of 3.0.4.
	 */
	{ "57014", "QUERY CANCELED", false },
	{ "57P01", "ADMIN SHUTDOWN", true },
	{ "57P02", "CRASH SHUTDOWN", true },
	{ "57P03", "CANNOT CONNECT NOW", true },

	{ "58030", "IO ERROR", true },
	{ "58P01", "UNDEFINED FILE", true },
	{ "58P02", "DUPLICATE FILE", true },

	{ "F0000", "CONFIG FILE ERROR", true },
	{ "F0001", "LOCK FILE EXISTS", true },

	{ "P0000", "PLPGSQL ERROR", false },
	{ "P0001", "RAISE EXCEPTION", false },

	{ "42000", "SYNTAX ERROR OR ACCESS RULE VIOLATION", false },
	{ "42601", "SYNTAX ERROR", false },
	{ "42501", "INSUFFICIENT PRIVILEGE", false },
	{ "42846", "CANNOT COERCE", false },
	{ "42803", "GROUPING ERROR", false },
	{ "42830", "INVALID FOREIGN KEY", false },
	{ "42602", "INVALID NAME", false },
	{ "42622", "NAME TOO LONG", false },
	{ "42939", "RESERVED NAME", false },
	{ "42804", "DATATYPE MISMATCH", false },
	{ "42P18", "INDETERMINATE DATATYPE", false },
	{ "42809", "WRONG OBJECT TYPE", false },
	{ "42703", "UNDEFINED COLUMN", false },
	{ "42883", "UNDEFINED FUNCTION", false },
	{ "42P01", "UNDEFINED TABLE", false },
	{ "42P02", "UNDEFINED PARAMETER", false },
	{ "42704", "UNDEFINED OBJECT", false },
	{ "42701", "DUPLICATE COLUMN", false },
	{ "42P03", "DUPLICATE CURSOR", false },
	{ "42P04", "DUPLICATE DATABASE", false },
	{ "42723", "DUPLICATE FUNCTION", false },
	{ "42P05", "DUPLICATE PREPARED STATEMENT", false },
	{ "42P06", "DUPLICATE SCHEMA", false },
	{ "42P07", "DUPLICATE TABLE", false },
	{ "42712", "DUPLICATE ALIAS", false },
	{ "42710", "DUPLICATE OBJECT", false },
	{ "42702", "AMBIGUOUS COLUMN", false },
	{ "42725", "AMBIGUOUS FUNCTION", false },
	{ "42P08", "AMBIGUOUS PARAMETER", false },
	{ "42P09", "AMBIGUOUS ALIAS", false },
	{ "42P10", "INVALID COLUMN REFERENCE", false },
	{ "42611", "INVALID COLUMN DEFINITION", false },
	{ "42P11", "INVALID CURSOR DEFINITION", false },
	{ "42P12", "INVALID DATABASE DEFINITION", false },
	{ "42P13", "INVALID FUNCTION DEFINITION", false },
	{ "42P14", "INVALID PREPARED STATEMENT DEFINITION", false },
	{ "42P15", "INVALID SCHEMA DEFINITION", false },
	{ "42P16", "INVALID TABLE DEFINITION", false },
	{ "42P17", "INVALID OBJECT DEFINITION", false },

	{ "XX000", "INTERNAL ERROR", false },
	{ "XX001", "DATA CORRUPTED", false },
	{ "XX002", "INDEX CORRUPTED", false },

	{ NULL, NULL, 0 }
};

#endif /*_SQL_POSTGRESQL_H_*/
