<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
$link = @da_sql_pconnect($config);
if ($link){
	if (isset($member_groups) && isset($edited_groups)){
		$del_groups = array_diff($member_groups,$edited_groups);
		if (isset($del_groups)){
			foreach ($del_groups as $del){
				$del = da_sql_escape_string($del);
				$res = @da_sql_query($link,$config,
			"DELETE FROM $config[sql_usergroup_table] WHERE username = '$login' AND groupname = '$del';");
				if (!$res)
					echo "<b>Could not delete user $login from group $del: " . da_sql_error($link,$config) . "</b><br>\n";
				else
					echo "<b>User $login deleted from group $del</b><br>\n";
			}
		}
		$new_groups = array_diff($edited_groups,$member_groups);
		if (isset($new_groups)){
			foreach($new_groups as $new){
				$new = da_sql_escape_string($new);
				$res = @da_sql_query($link,$config,
				"INSERT INTO $config[sql_usergroup_table] (groupname,username)
				VALUES ('$new','$login');");
				if (!$res)
					echo "<b>Error while adding user $login to group $login: " . da_sql_error($link,$config) . "</b><br>\n";
				else
					echo "<b>User $login added to group $new</b><br>\n";
			}
		}
	}
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
?>
