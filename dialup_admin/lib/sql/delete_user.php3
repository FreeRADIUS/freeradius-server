<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
$link = @da_sql_pconnect($config);
if ($link){
	$res = @da_sql_query($link,$config,
		"DELETE FROM $config[sql_reply_table] WHERE UserName = '$login';");
	if ($res){
		$res = @da_sql_query($link,$config,
			"DELETE FROM $config[sql_check_table] WHERE UserName = '$login';");
		if ($res){
			if ($config[sql_use_user_info_table] == 'true'){
				$res = @da_sql_query($link,$config,
				"DELETE FROM $config[sql_user_info_table] WHERE UserName = '$login';");
				if ($res)
					echo "<b>User $login deleted successfully</b><br>\n";
				else
					echo "<b>Error deleting user $login from user info table</b><br>\n";
			}
		}
		else
			echo "<b>Error deleting user $login from check table</b><br>\n";
	}
	else
		echo "<b>Error deleting user $login from reply table</b><br>\n";
}
else
	echo "<b>Could not connect to database</b><br>\n";
?>
