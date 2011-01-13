<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
require_once('../lib/xlat.php');

function connect2db($config)
{
	$link=@da_sql_pconnect($config);

	return $link;
}

function get_user_info($link,$user,$config)
{
	if ($link && $config[sql_use_user_info_table] == 'true'){
		$user = da_sql_escape_string($user);
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
?>
