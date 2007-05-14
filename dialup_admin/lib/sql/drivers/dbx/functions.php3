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
	// FIXME: This function is still Postgres specific. Needs to be configurable.
	return @dbx_connect(DBX_PGSQL, "$server", "$config[sql_database]",
			"$SQL_user", "$SQL_passwd", DBX_PERSISTENT);
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
	// FIXME: This function is still Postgres specific. Needs to be configurable.
	return @dbx_connect(DBX_PGSQL, "$server", "$config[sql_database]",
			"$SQL_user", "$SQL_passwd");
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
	// FIXME: This function is still Postgres specific. Needs to be configurable.
	return @dbx_connect(DBX_PGSQL, "$server", "$config[sql_database]",
			"$SQL_user", "$SQL_passwd", DBX_PERSISTENT);
}

function da_sql_close($link,$config)
{
	@dbx_close($link);
}

function da_sql_escape_string($string)
{
	return addslashes($string);
}

function da_sql_query($link,$config,$query)
{
	if ($config[sql_debug] == 'true') {
		print "<b>DEBUG(SQL,PG DRIVER): Query: <i>$query</i></b><br>\n";
	}
	return @dbx_query($link,$query);
}

function da_sql_num_rows($result,$config)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,PG DRIVER): Query Result: Num rows:: " . $result->rows . "</b><br>\n";
	return $result->rows;
}

$dbx_global_record_counter = array() ;
function da_sql_fetch_array($result,$config)
{

	global $dbx_global_record_counter;
	if (!$dbx_global_record_counter[$result->handle]){
		$dbx_global_record_counter[$result->handle] = 0;
	}

	if ($dbx_global_record_counter[$result->handle] <= $result->rows - 1 ){
		return $result->data[$dbx_global_record_counter[$result->handle]++];
	} elseif ($dbx_global_record_counter[$result->handle] > $result->rows - 1 ) {
		$dbx_global_record_counter[$result->handle]++;
		return NULL;
	} else {
		$dbx_global_record_counter[$result->handle]++;
		return FALSE;
	}
}

function da_sql_affected_rows($link,$result,$config)
{
	// FIXME: This function is still Postgres specific.
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,PG DRIVER): Query Result: Affected rows:: " . @pg_cmdtuples($result->handle) . "</b><br>\n";
	return @pg_cmdtuples($result->handle);
}

function da_sql_list_fields($table,$link,$config)
{
	$res = @dbx_query($link,"SELECT * FROM ".$table." LIMIT 1 ;");
	if ($res){
		$fields[num] = $res->cols;
	}
	$res = @dbx_query($link,"SELECT * FROM ".$table." LIMIT 1 ;");
	if ($res)
		$fields[res] = $res->info[name];
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
	if ($fields)
		return $fields[res][$num];
}

function da_sql_error($link,$config)
{
	return dbx_error($link);
}
?>
