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
		"SELECT Name FROM $config[sql_user_info_table] WHERE UserName = '$user';");
		if ($res){
			$row = @da_sql_fetch_array($res,$config);
			if ($row)
				return $row[Name];
		}	
	}
}

function closedb($link,$config)
{
	return 1;
}
?>
