<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}

$date=date($config[sql_full_date_format]);
$lockmsg_name = $attrmap['Dialup-Lock-Msg'] . '0';
$msg = $$lockmsg_name;
if ($msg == '')
	echo "<b>Lock Message should not be empty</b><br>\n";
else{
	$link = @da_sql_pconnect($config);
	if ($link){
		$r = da_sql_query($link,$config,
		"INSERT INTO $config[sql_badusers_table] (UserName,Date,Reason)
		VALUES ('$login','$date','$msg');");
		if (!$r)
			echo "<b>SQL Error:" . da_sql_error($link) . "</b><br>\n";
	}
	else
		echo "<b>SQL Error: Could not connect to SQL database</b><br>\n";
}
?>
