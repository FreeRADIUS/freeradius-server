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

	if ($config[sql_connect_timeout] != 0)
		@ini_set('mysql.connect_timeout',$config[sql_connect_timeout]);
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,MYSQL DRIVER): Connect: User=$SQL_user,Password=$SQL_passwd </b><br>\n";
	return @mysql_connect("$server:$config[sql_port]",$SQL_user,$SQL_passwd);
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

	if ($config[sql_connect_timeout] != 0)
		@ini_set('mysql.connect_timeout',$config[sql_connect_timeout]);
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,MYSQL DRIVER): Connect: User=$SQL_user,Password=$SQL_passwd </b><br>\n";
	return @mysql_connect("$config[sql_server]:$config[sql_port]",$SQL_user,$SQL_passwd);
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

	if ($config[sql_connect_timeout] != 0)
		@ini_set('mysql.connect_timeout',$config[sql_connect_timeout]);
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,MYSQL DRIVER): Connect: User=$SQL_user,Password=$SQL_passwd </b><br>\n";
	return @mysql_pconnect("$config[sql_server]:$config[sql_port]",$SQL_user,$SQL_passwd);
}

function da_sql_close($link,$config)
{
	return @mysql_close($link);
}

function da_sql_escape_string($string)
{
	return @mysql_escape_string($string);
}

function da_sql_query($link,$config,$query)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,MYSQL DRIVER): Query: <i>$query</i></b><br>\n";
	return @mysql_db_query($config[sql_database],$query,$link);
}

function da_sql_num_rows($result,$config)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,MYSQL DRIVER): Query Result: Num rows:: " . @mysql_num_rows($result) . "</b><br>\n";
	return @mysql_num_rows($result);
}

function da_sql_fetch_array($result,$config)
{
	$row = array_change_key_case(@mysql_fetch_array($result,
		MYSQL_ASSOC),CASE_LOWER);
	if ($config[sql_debug] == 'true'){
		print "<b>DEBUG(SQL,MYSQL DRIVER): Query Result: <pre>";
		print_r($row);
		print "</b></pre>\n";
	}
	return $row;
}

function da_sql_affected_rows($link,$result,$config)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,MYSQL DRIVER): Query Result: Affected rows:: " . @mysql_affected_rows($result) . "</b><br>\n";
	return @mysql_affected_rows($link);
}

function da_sql_list_fields($table,$link,$config)
{
	return @mysql_list_fields($config[sql_database],$table);
}

function da_sql_num_fields($fields,$config)
{
	return @mysql_num_fields($fields);
}

function da_sql_field_name($fields,$num,$config)
{
	return @mysql_field_name($fields,$num);
}

function da_sql_error($link,$config)
{
	return @mysql_error($link);
}
?>
