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
		"DELETE FROM $config[sql_reply_table] WHERE username = '$login';");
	if ($res){
		$res = @da_sql_query($link,$config,
			"DELETE FROM $config[sql_check_table] WHERE username = '$login';");
		if ($res){
			$res = @da_sql_query($link,$config,
				"DELETE FROM $config[sql_usergroup_table] WHERE username = '$login';");
			if (!$res)
				echo "<b>Error deleting user $login from user group table: " . da_sql_error($link,$config) . "</b><br>\n";
			if ($config[sql_use_user_info_table] == 'true'){
				$res = @da_sql_query($link,$config,
				"DELETE FROM $config[sql_user_info_table] WHERE username = '$login';");
				if ($res)
					echo "<b>User $login deleted successfully</b><br>\n";
				else
					echo "<b>Error deleting user $login from user info table: " . da_sql_error($link,$config) . "</b><br>\n";
			}
		}
		else
			echo "<b>Error deleting user $login from check table: " . da_sql_error($link,$config) . "</b><br>\n";
	}
	else
		echo "<b>Error deleting user $login from reply table: " . da_sql_error($link,$config) . "</b><br>\n";
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
?>
