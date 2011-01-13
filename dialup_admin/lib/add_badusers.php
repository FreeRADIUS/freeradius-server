<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}

$date=date($config[sql_full_date_format]);
$lockmsg_name = $attrmap['Dialup-Lock-Msg'] . '0';
$msg = $$lockmsg_name;
$admin = '-';
if ($_SERVER["PHP_AUTH_USER"] != '')
	$admin = $_SERVER["PHP_AUTH_USER"];
if ($msg == '')
	echo "<b>Lock Message should not be empty</b><br>\n";
else{
	$sql_servers = array();
	if ($config[sql_extra_servers] != '')
		$sql_servers = explode(' ',$config[sql_extra_servers]);
	$sql_servers[] = $config[sql_server];
	foreach ($sql_servers as $server){
		$link = @da_sql_host_connect($server,$config);
		if ($link){
			$r = da_sql_query($link,$config,
			"INSERT INTO $config[sql_badusers_table] (username,incidentdate,admin,reason)
			VALUES ('$login','$date','$admin','$msg');");
			if (!$r)
				echo "<b>SQL Error:" . da_sql_error($link,$config) . "</b><br>\n";
			else
				echo "<b>User added to badusers table</b><br>\n";
			da_sql_close($link,$config);
		}
		else
			echo "<b>SQL Error: Could not connect to SQL database: $server</b><br>\n";
	}
}
?>
