<?php
// $Id$
function da_sql_limit($limit,$point,$config)
{
	switch($point){
		case 0:
			return '';
		case 1:
			return "AND ROWNUM <= $limit";
		case 2:
			return '';
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
	$link = @ocilogon($SQL_user, $SQL_passwd, $config[sql_database]);
        $res = @da_sql_query($link,$config,"ALTER SESSION SET NLS_TIMESTAMP_TZ_FORMAT='YYYY-MM-DD HH24:MI:SS.FF TZH:TZM'");
	return $link;
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
	$link = @ocilogon($SQL_user, $SQL_passwd, $config[sql_database]);
        $res = @da_sql_query($link,$config,"ALTER SESSION SET NLS_TIMESTAMP_TZ_FORMAT='YYYY-MM-DD HH24:MI:SS.FF TZH:TZM'");
	return $link;
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
	$link = @ociplogon($SQL_user, $SQL_passwd, $config[sql_database]);
        $res = @da_sql_query($link,$config,"ALTER SESSION SET NLS_TIMESTAMP_TZ_FORMAT='YYYY-MM-DD HH24:MI:SS.FF TZH:TZM'");
	return $link;
}

function da_sql_close($link,$config)
{
	@ociclose($link);
}

function da_sql_escape_string($string)
{
	return addslashes($string);
}

function da_sql_query($link,$config,$query)
{
	$trimmed_query = rtrim($query, ";");
	if ($config[sql_debug] == 'true') {
		print "<b>DEBUG(SQL,OCI DRIVER): Query: <i>$trimmed_query</i></b><br>\n";
	}
	$statement = OCIParse($link,$trimmed_query);
	OCIExecute($statement);
	return $statement;
}

function da_sql_num_rows($statement,$config)
{
	// Unfortunately we need to fetch the statement as ocirowcount doesn't work on SELECTs
	$rows = OCIFetchStatement($statement,$res);

        if ($config[sql_debug] == 'true'){
                print "<b>DEBUG(SQL,OCI DRIVER): Query Result: Num rows:: " . $rows . "</b><br>\n";
        }
	// Unfortunately we need to re-execute because the statement cursor is reset after OCIFetchStatement :-(
	OCIExecute($statement);
        return $rows;
}


function da_sql_fetch_array($statement,$config)
{
	OCIFetchInto($statement, $temprow, OCI_ASSOC);
	$row = array_change_key_case($temprow, CASE_LOWER);
        if ($config[sql_debug] == 'true') {
                print "<b>DEBUG(SQL,OCI DRIVER): Query Result: <pre>";
                print_r($row);
                print "</b></pre>\n";
        }
        return $row;
}


function da_sql_affected_rows($link,$statement,$config)
{
	if ($config[sql_debug] == 'true')
		print "<b>DEBUG(SQL,OCI DRIVER): Query Result: Affected rows:: " . @ocirowcount($statement) . "</b><br>\n";
	return @ocirowcount($statement);
}

function da_sql_list_fields($table,$link,$config)
{
        $res = @da_sql_query($link,$config,"SELECT * from $table WHERE ROWNUM <=1");
        if ($res){
		$fields[res]=Array();
		for ($i = 1;$i<=ocinumcols($res);$i++) {
			array_push($fields[res],strtolower(OCIColumnName($res,$i)));
		}
                $fields[num]=@ocinumcols($res);
        }else{
                return NULL;
        }
        return $fields;
}

function da_sql_num_fields($fields,$config)
{
        return $fields[num];
}

function da_sql_field_name($fields,$num,$config)
{
	return $fields[res][$num];
}

function da_sql_error($link,$config)
{
	return ocierror($link);
}
?>
