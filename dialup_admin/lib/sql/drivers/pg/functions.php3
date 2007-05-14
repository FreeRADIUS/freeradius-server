<?php
function da_sql_limit($limit,$point,$config)
{
	switch($point){
		case 0:
			return '';
		case 1:
			return '';
		case 2:
			return "LIMIT $limit";
	}
}
function da_sql_host_connect($server,$config)
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
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,PG DRIVER): Connect: User=$SQL_user,Password=$SQL_passwd </b><br>\n";
	return @pg_connect("host=$server port=$config[sql_port]
			dbname=$config[sql_database] user=$SQL_user
			password=$SQL_passwd");
}

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
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,PG DRIVER): Connect: User=$SQL_user,Password=$SQL_passwd </b><br>\n";
	return @pg_connect("host=$config[sql_server] port=$config[sql_port]
			dbname=$config[sql_database] user=$SQL_user
			password=$SQL_passwd");
}

function da_sql_pconnect($config)
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
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,PG DRIVER): Connect: User=$SQL_user,Password=$SQL_passwd </b><br>\n";
	return @pg_pconnect("host=$config[sql_server] port=$config[sql_port]
			dbname=$config[sql_database] user=$SQL_user
			password=$SQL_passwd");
}

function da_sql_close($link,$config)
{
	@pg_close($link);
}

function da_sql_escape_string($string)
{
	return addslashes($string);
}

function da_sql_query($link,$config,$query)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,PG DRIVER): Query: <i>$query</i></b><br>\n";
	return @pg_query($link,$query);
}

function da_sql_num_rows($result,$config)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,PG DRIVER): Query Result: Num rows:: " . @pg_numrows($result) . "</b><br>\n";
	return @pg_numrows($result);
}

function da_sql_fetch_array($result,$config)
{
	$row = @pg_fetch_array($result,$config[tmp_pg_array_num][$result]++,PGSQL_ASSOC);
	if ($row && $config[sql_debug] == 'true'){
		print "<b>DEBUG(SQL,PG DRIVER): Query Result: <pre>";
		print_r($row);
		print  "</b></pre>\n";
	}
	if (!$row)
		$config[tmp_pg_array_num][$result] = 0;
	return $row;
}

function da_sql_affected_rows($link,$result,$config)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,PG DRIVER): Query Result: Affected rows:: " . @pg_cmdtuples($result) . "</b><br>\n";
	return @pg_cmdtuples($result);
}

function da_sql_list_fields($table,$link,$config)
{
	$res = @pg_query($link,
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
	$res = @pg_query($link,
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
