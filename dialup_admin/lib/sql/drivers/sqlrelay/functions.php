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
	$retrytime = 0;

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
		$retrytime = $config[sql_connect_timeout];
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,SQLRELAY DRIVER): Connect: User=$SQL_user,Password=$SQL_passwd </b><br>\n";
	$link[con] = @sqlrcon_alloc($server,$port,'',$SQL_user,$SQL_passwd,$retrytime,1);
	if ($link[con]){
		$link[cur] = @sqlrcur_alloc($link[con]);
		if ($link[cur])
			return $link;
		else
			return 0;
	}
	else
		return 0;
}

function da_sql_connect($config)
{
	$retrytime = 0;

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
		$retrytime = $config[sql_connect_timeout];
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,SQLRELAY DRIVER): Connect: User=$SQL_user,Password=$SQL_passwd </b><br>\n";
	$link[con] = @sqlrcon_alloc($config[sql_server],$config[sql_port],'',$SQL_user,$SQL_passwd,$retrytime,1);
	if ($link[con]){
		$link[cur] = @sqlrcur_alloc($link[con]);
		if ($link[cur])
			return $link;
		else
			return 0;
	}
	else
		return 0;
}

function da_sql_pconnect($config)
{
	$retrytime = 0;


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
		$retrytime = $config[sql_connect_timeout];
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,SQLRELAY DRIVER): Connect: Host=$config[sql_server],Port=$config[sql_port],User=$SQL_user,Password=$SQL_passwd </b><br>\n";
	$link[con] = sqlrcon_alloc($config[sql_server],$config[sql_port],'',$SQL_user,$SQL_passwd,$retrytime,1);
	if ($link[con]){
		sqlrcon_debugOn($link[con]);
		$link[cur] = sqlrcur_alloc($link[con]);
		if ($link[cur]){
			sqlrcur_setResultSetBufferSize($link[cur], 4);
			sqlrcur_lowerCaseColumnNames($link[cur]);
			return $link;
		}
		else
			return false;
	}
	else{
		return false;
	}
}

function da_sql_close($link,$config)
{
	if (sqlrcur_free($link[cur]))
		return sqlrcon_free($link[con]);
	else
		return 0;
}

function da_sql_escape_string($string)
{
	return addslashes($string);
}

function da_sql_query($link,$config,$query)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,SQLRELAY DRIVER): Query: <i>$query</i></b><br>\n";
	if (sqlrcur_sendQuery($link[cur],$query)){
		sqlrcon_endSession($link[con]);
		$link[count] = sqlrcur_rowCount($link[cur]);
		return $link;
	}
	else{
		return false;
	}
}

function da_sql_num_rows($result,$config)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,SQLRELAY DRIVER): Query Result: Num rows:: " . @sqlrcur_rowCount($result[cur]) . "</b><br>\n";
	return sqlrcur_rowCount($result[cur]);
	return 0;
}

function da_sql_fetch_array($result,$config)
{
	static $counter = 0;
	if ($counter < $result[count]){
		$row = sqlrcur_getRowAssoc($result[cur],$counter);
		$counter++;
	}
	else{
		$counter = 0;
		return false;
	}
	if ($config[sql_debug] == 'true'){
		print "<b>DEBUG(SQL,SQLRELAY DRIVER): Query Result: <pre>";
	}
	return $row;
}

function da_sql_affected_rows($link,$result,$config)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,SQLRELAY DRIVER): Query Result: Affected rows:: " . @sqlrcur_affectedRows($result[cur]) . "</b><br>\n";
	return sqlrcur_affectedRows($result[cur]);
}

function da_sql_list_fields($table,$link,$config)
{
	if (sqlrcur_sendQuery($link[cur],"SELECT * FROM $table WHERE  1 = 0;")){
		sqlrcon_endSession($link[con]);
		return $link[cur];
	}
	else
		return false;
}

function da_sql_num_fields($fields,$config)
{
	return sqlrcur_colCount($fields);
}

function da_sql_field_name($fields,$num,$config)
{
	return sqlrcur_getColumnName($fields,$num);
}

function da_sql_error($link,$config)
{
	return sqlrcur_errorMessage($link[cur]);
}
?>
