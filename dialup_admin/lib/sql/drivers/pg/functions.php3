<?php
function da_sql_connect($config)
{
	if ($config[sql_use_http_credentials] == 'yes'){
		global $HTTP_SERVER_VARS;
		$SQL_user = $HTTP_SERVER_VARS["PHP_AUTH_USER"];
		$SQL_passwd = $HTTP_SERVER_VARS["PHP_AUTH_PW"];
	}
	else{
		$SQL_user = $config[sql_username];
		$SQL_passwd = $config[sql_password];
	}
	return @pg_connect("host=$config[sql_server] port=$config[sql_port]
			dbname=$config[sql_database] user=$SQL_user
			password=$SQL_passwd");
}

function da_sql_pconnect($config)
{
	return @pg_pconnect("host=$config[sql_server] port=$config[sql_port]
			dbname=$config[sql_database] user=$config[sql_username]
			password=$config[sql_password]");
}

function da_sql_close($link,$config)
{
	@pg_close($link);
}

function da_sql_query($link,$config,$query)
{
	return @pg_exec($link,$query);
}

function da_sql_num_rows($result,$config)
{
	return @pg_numrows($result);
}

function da_sql_fetch_array($result,$config)
{
	$row = @pg_fetch_array($result,$config[tmp_pg_array_num][$result]++,PGSQL_ASSOC);
	if (!$row)
		$config[tmp_pg_array_num][$result] = 0;
	return $row;
}

function da_sql_affected_rows($link,$result,$config)
{
	return @pg_cmdtuples($result);
}

function da_sql_list_fields($table,$link,$config)
{
	$res = @pg_exec($link,
		"select count(*) from pg_attribute where attnum > '0' and
		attrelid = (select oid from pg_class where relname='$table');");
	if ($res){
		$row = @pg_fetch_row($res,0);
		if ($row){
			if (!$row[0])
				return NULL;
			$fields[num] = $row[0];
		}
	}
	$res = @pg_exec($link,
		"select attname from pg_attribute where attnum > '0' and
		attrelid = (select oid from pg_class where relname='$table');");
	if ($res)
		$fields[res]=$res;
	else
		return NULL;

	return $fields;
}

function da_sql_num_fields($fields,$config)
{
	if ($fields)
		return $fields[num];
}

function da_sql_field_name($fields,$num,$config)
{
	if ($fields){
		$row = @pg_fetch_row($fields[res],$num);	
		if ($row)
			return $row[0];
	}
}

function da_sql_error($link,$config)
{
	return pg_errormessage($link);
}
?>
