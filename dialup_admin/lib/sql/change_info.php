<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
$link = @da_sql_pconnect($config);
$fail = 0;
if ($link){
	if ($config[sql_use_user_info_table] == 'true'){
		$res = @da_sql_query($link,$config,
		"SELECT username FROM $config[sql_user_info_table] WHERE
		username = '$login';");
		if ($res){
			$Fcn = da_sql_escape_string($Fcn);
			$Fmail = da_sql_escape_string($Fmail);
			$Fou = da_sql_escape_string($Fou);
			$Ftelephonenumber = da_sql_escape_string($Ftelephonenumber);
			$Fhomephone = da_sql_escape_string($Fhomephone);
			$Fmobile = da_sql_escape_string($Fmobile);

			if (!@da_sql_num_rows($res,$config)){
				$res = @da_sql_query($link,$config,
				"INSERT INTO $config[sql_user_info_table]
				(username,name,mail,department,homephone,workphone,mobile) VALUES
				('$login','$Fcn','$Fmail','$Fou','$Ftelephonenumber','$Fhomephone','$Fmobile');");
				if (!$res || !@da_sql_affected_rows($link,$res,$config)){
					echo "<b>Could not add user information in user info table: " . da_sql_error($link,$config) . "</b><br>\n";
					$fail = 1;
				}
			}
			else{
				$res = @da_sql_query($link,$config,
				"UPDATE $config[sql_user_info_table] SET name = '$Fcn',Mail = '$Fmail',
				department = '$Fou', homephone = '$Fhomephone', workphone = '$Ftelephonenumber',
				mobile = '$Fmobile' WHERE username = '$login';");
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
	echo "<b>Could not connect to SQL database</b><br>\n";
?>
