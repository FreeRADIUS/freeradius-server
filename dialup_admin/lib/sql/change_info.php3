<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
$link = @da_sql_pconnect($config);
$fail = 0;
if ($link){
	if ($config[sql_use_user_info_table] == 'true'){
		$res = @da_sql_query($link,$config,
		"SELECT UserName FROM $config[sql_user_info_table] WHERE
		UserName = '$login';");
		if ($res){
			if (!@da_sql_num_rows($res,$config)){
				$res = @da_sql_query($link,$config,
				"INSERT INTO $config[sql_user_info_table]
				(UserName,Name,Mail,Department,HomePhone,WorkPhone,Mobile) VALUES
				('$login','$Fcn','$Fmail','$Fou','$Ftelephonenumber','$Fhomephone','$Fmobile');");
				if (!$res || !@da_sql_affected_rows($link,$res,$config)){
					echo "<b>Could not add user information in user info table: " . da_sql_error($link,$config) . "</b><br>\n";
					$fail = 1;
				}
			}
			else{
				$res = @da_sql_query($link,$config,
				"UPDATE $config[sql_user_info_table] SET Name = '$Fcn',Mail = '$Fmail',
				Department = '$Fou', HomePhone = '$Fhomephone', WorkPhone = '$Ftelephonenumber',
				Mobile = '$Fmobile' WHERE UserName = '$login';");
				if (!$res || !@da_sql_affected_rows($link,$res,$config)){
					echo "<b>Could not update user information in user info table: " . da_sql_error($link,$config) . "</b><br>\n";
					$fail = 1;
				}
			}
		}
		else{
			echo "<b>Could not find user in user info table: " . da_sql_error($link,$config) . "</b><br>\n";
			$fail = 1;
		}
		if ($fail == 0)
			echo "<b>User information updated successfully</b><br>\n";
	}
	else
		echo "<b>Cannot use the user info table. Check the sql_use_user_info_table directive in admin.conf</b><br>\n";
	
}
else
	echo "<b>Could not connect to database</b><br>\n";
?>
