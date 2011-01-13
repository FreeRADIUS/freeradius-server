<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
$link = @da_sql_pconnect($config);
if ($link){
	if (isset($del_members)){
		foreach ($del_members as $del){
			$del = da_sql_escape_string($del);
			$res = @da_sql_query($link,$config,
			"DELETE FROM $config[sql_usergroup_table] WHERE username = '$del' AND groupname = '$login';");
			if (!$res)
				echo "<b>Could not delete user $del from group: " . da_sql_error($link,$config) . "</b><br>\n";
		}
	}
	if ($new_members != ''){
		$Members = preg_split("/[\n\s]+/",$new_members,-1,PREG_SPLIT_NO_EMPTY);
		if (!empty($Members)){
			foreach ($Members as $new_member){
				$new_member = da_sql_escape_string($new_member);
				$res = @da_sql_query($link,$config,
				"SELECT username FROM $config[sql_usergroup_table] WHERE
				username = '$new_member' AND groupname = '$login';");
				if ($res){
					if (@da_sql_num_rows($res,$config))
						echo "<b>User $new_member already is a member of the group</b><br>\n";
					else{
						$res = @da_sql_query($link,$config,
						"INSERT INTO $config[sql_usergroup_table] (groupname,username)
						VALUES ('$login','$new_member');");
						if (!$res)
							echo "<b>Error while adding user $new_member to group: " . da_sql_error($link,$config) . "</b><br>\n";
					}
				}
				else
					echo "<b>Could not add new member $new_member: " . da_sql_error($link,$config) . "</b><br>\n";
			}
		}
	}
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
?>
