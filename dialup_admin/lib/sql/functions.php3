<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}

function connect2db($config)
{
	$link=@da_sql_pconnect($config);

	return $link;
}

function get_user_info($link,$user,$config)
{
	if ($link && $config[sql_use_user_info_table] == 'true'){
		$res=@da_sql_query($link,$config,
		"SELECT name FROM $config[sql_user_info_table] WHERE username = '$user';");
		if ($res){
			$row = @da_sql_fetch_array($res,$config);
			if ($row)
				return $row[name];
		}	
	}
}

function closedb($link,$config)
{
	return 1;
}
function sql_xlat($filter,$login,$config)
{
	$string = $filter;
	$http_user = $HTTP_SERVER_VARS["PHP_AUTH_USER"];
	if ($filter != ''){
		$string = preg_replace('/%u/',$login,$string);
		$string = preg_replace('/%U/',$http_user,$string);
		$string = preg_replace('/%m/',$mappings[$http_user],$string);
	}

	return $string;
}
?>
