<?php
require('../conf/config.php3');
?>
<html>
<head>
<?php
require('../lib/functions.php3');
require('../lib/defaults.php3');
$date = strftime('%A, %e %B %Y, %T %Z');

if (is_file("../lib/$config[general_lib_type]/user_info.php3")){
	include("../lib/$config[general_lib_type]/user_info.php3");
	if ($user_exists == 'no'){
		echo <<<EOM
<title>user information page</title>
<meta http-equiv="Content-Type" content="text/html; charset=$config[general_charset]">
<link rel="stylesheet" href="style.css">
</head>
<body bgcolor="#80a040" background="images/greenlines1.gif" link="black" alink="black">
<center>
<form action="user_admin.php3" method=get>
<b>User Name&nbsp;&nbsp;</b>
<input type="text" size=10 name="login" value="$login">
<b>&nbsp;&nbsp;does not exist</b><br>
<input type=submit class=button value="Show User">
</body>
</html>
EOM;
		exit();
	}
}

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo <<<EOM
<title>user information page</title>
<meta http-equiv="Content-Type" content="text/html; charset=$config[general_charset]">
<link rel="stylesheet" href="style.css">
</head>
<body bgcolor="#80a040" background="images/greenlines1.gif" link="black" alink="black">
<center>
<b>Could not include SQL library functions. Aborting</b>
</body>
</html>
EOM;
	exit();
}

$monthly_limit = ($item_vals['Max-Monthly-Session'][0] != '') ? $item_vals['Max-Monthly-Session'][0] : $default_vals['Max-Monthly-Session'][0];
$monthly_limit = ($monthly_limit) ? $monthly_limit : $config[counter_default_monthly];
$weekly_limit = ($item_vals['Max-Weekly-Session'][0] != '') ? $item_vals['Max-Weekly-Session'][0] : $default_vals['Max-Weekly-Session'][0];
$weekly_limit = ($weekly_limit) ? $weekly_limit : $config[counter_default_weekly];
$daily_limit = ($item_vals['Max-Daily-Session'][0] != '') ? $item_vals['Max-Daily-Session'][0] : $default_vals['Max-Daily-Session'][0];
$daily_limit = ($daily_limit) ? $daily_limit : $config[counter_default_daily];
$session_limit = ($item_vals['Session-Timeout'][0] != '') ? $item_vals['Session-Timeout'][0] : $default_vals['Session-Timeout'][0];
$session_limit = ($session_limit) ? $session_limit : 'none';
$remaining = 'unlimited time';
$log_color = 'green';

$now = time();
$week = $now - 604800;
$now_str = date("$config[sql_date_format]",$now + 86400);
$week_str = date("$config[sql_date_format]",$week);
$day = date('w');
$week_start = date($config[sql_date_format],$now - ($day)*86400);
$month_start = date($config[sql_date_format],$now - date('j')*86400);
$today = $day;
$now_tmp = $now;
for ($i = $day; $i >-1; $i--){
	$days[$i] = date($config[sql_date_format],$now_tmp);
	$now_tmp -= 86400;
}
$day++;
//$now -= ($day * 86400);
$now -= 604800;
$now += 86400;
for ($i = $day; $i <= 6; $i++){
	$days[$i] = date($config[sql_date_format],$now);
//	$now -= 86400;
	$now += 86400;
}

$daily_used = $weekly_used = $monthly_used = $lastlog_session_time = '-';
$extra_msg = '';
$used = array('-','-','-','-','-','-','-');

$link = @da_sql_pconnect($config);
if ($link){
	$search = @da_sql_query($link,$config,
	"SELECT sum(AcctSessionTime),sum(AcctInputOctets),sum(AcctOutputOctets),
	avg(AcctSessionTime),avg(AcctInputOctets),avg(AcctOutputOctets),COUNT(*) FROM
	$config[sql_accounting_table] WHERE UserName = '$login'
	AND AcctStartTime >= '$week_str' AND AcctStartTime <= '$now_str';");
	if ($search){
		$row = @da_sql_fetch_array($search,$config);
		$tot_time = time2str($row['sum(AcctSessionTime)']);
		$tot_input = bytes2str($row['sum(AcctInputOctets)']);
		$tot_output = bytes2str($row['sum(AcctOutputOctets)']);
		$avg_time = time2str($row['avg(AcctSessionTime)']);
		$avg_input = bytes2str($row['avg(AcctInputOctets)']);
		$avg_output = bytes2str($row['avg(AcctOutputOctets)']);
		$tot_conns = $row['COUNT(*)'];
	}
	else
		echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	$search = @da_sql_query($link,$config,
	"SELECT sum(AcctSessionTime) FROM $config[sql_accounting_table] WHERE UserName = '$login'
	AND AcctStartTime >= '$week_start' AND AcctStartTime <= '$now_str';");
	if ($search){
		$row = @da_sql_fetch_array($search,$config);
		$weekly_used = $row['sum(AcctSessionTime)'];
	}
	else
		echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	if ($monthly_limit != 'none' || $config[counter_monthly_calculate_usage] == 'true'){
		$search = @da_sql_query($link,$config,
		"SELECT sum(AcctSessionTime) FROM $config[sql_accounting_table] WHERE UserName = '$login'
		AND AcctStartTime >= '$month_start' AND AcctStartTime <= '$now_str';");
		if ($search){
			$row = @da_sql_fetch_array($search,$config);
			$monthly_used = $row['sum(AcctSessionTime)'];
		}
		else
			echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	}
	$search = @da_sql_query($link,$config,
	"SELECT COUNT(*) FROM $config[sql_accounting_table] WHERE UserName = '$login'
	AND AcctStopTime >= '$week_str' AND AcctStopTime <= '$now_str'
	AND (AcctTerminateCause LIKE 'Login-Incorrect%' OR
	AcctTerminateCause LIKE 'Invalid-User%' OR
	AcctTerminateCause LIKE 'Multiple-Logins%');");
	if ($search){
		$row = @da_sql_fetch_array($search,$config);
		$tot_badlogins = $row['COUNT(*)'];
	}
	else
		echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	for($i = 0; $i <=6; $i++){
		if ($days[$i] == '')
			continue;
		$search = @da_sql_query($link,$config,
		"SELECT sum(AcctSessionTime) FROM $config[sql_accounting_table] WHERE
		UserName = '$login' AND AcctStopTime >= '$days[$i] 00:00:00'
		AND AcctStopTime <= '$days[$i] 23:59:59';");
		if ($search){
			$row = @da_sql_fetch_array($search,$config);
			$used[$i] = $row['sum(AcctSessionTime)'];
			if ($daily_limit != 'none' && $used[$i] > $daily_limit)
				$used[$i] = "<font color=red>" . time2str($used[$i]) . "</font>";
			else
				$used[$i] = time2str($used[$i]);
			if ($today == $i){
				$daily_used = $row['sum(AcctSessionTime)'];
				if ($daily_limit != 'none'){
					$remaining = $daily_limit - $daily_used;
					if ($remaining <=0)
						$remaining = 0;
					$log_color = ($remaining) ? 'green' : 'red';
					if (!$remaining)
						$extra_msg = '(Out of daily quota)';
				}
				$daily_used = time2str($daily_used);
				if ($daily_limit != 'none' && !$remaining)
					$daily_used = "<font color=red>$daily_used</font>";
			}
		}
		else
			echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	}
	if ($weekly_limit != 'none'){
		$tmp = $weekly_limit - $weekly_used;
		if ($tmp <=0){
			$tmp = 0;
			$extra_msg .= '(Out of weekly quota)';
		}
		if (!is_numeric($remaining))
			$remaining = $tmp;
		if ($remaining > $tmp)
			$remaining = $tmp;
		$log_color = ($remaining) ? 'green' : 'red';
	}
	$weekly_used = time2str($weekly_used);
	if ($weekly_limit != 'none' && !$tmp)
		$weekly_used = "<font color=red>$weekly_used</font>";

	if ($monthly_limit != 'none'){
		$tmp = $monthly_limit - $monthly_used;
		if ($tmp <=0){
			$tmp = 0;
			$extra_msg .= '(Out of monthly quota)';
		}
		if (!is_numeric($remaining))
			$remaining = $tmp;
		if ($remaining > $tmp)
			$remaining = $tmp;
		$log_color = ($remaining) ? 'green' : 'red';
	}
	if ($monthly_limit != 'none' || $config[counter_monthly_calculate_usage] == 'true'){
		$monthly_used = time2str($monthly_used);
		if ($monthly_limit != 'none' && !$tmp)
			$monthly_used = "<font color=red>$monthly_used</font>";
	}

	$search = @da_sql_query($link,$config,
	"SELECT * FROM $config[sql_accounting_table]
	WHERE UserName = '$login' AND AcctStopTime IS NULL
	ORDER BY AcctStartTime DESC LIMIT 1;");
	if ($search){
		if (@da_sql_num_rows($search,$config)){
			$logged_now = 1;
			$row = @da_sql_fetch_array($search,$config);
			$lastlog_time = $row['AcctStartTime'];
			$lastlog_server_ip = $row['NASIPAddress'];
			$lastlog_server_port = $row['NASPortId'];
			$lastlog_session_time = date2timediv($lastlog_time,0);
			if ($daily_limit != 'none'){
				$remaining = $remaining - $lastlog_session_time;
				if ($remaining < 0)
					$remaining = 0;
				$log_color = ($remaining) ? 'green' : 'red'; 
			}
			$lastlog_session_time_jvs = 1000 * $lastlog_session_time;
			$lastlog_session_time = time2strclock($lastlog_session_time);
			$lastlog_client_ip = $row['FramedIPAddress'];	
			$lastlog_server_name = @gethostbyaddr($lastlog_server_ip);
			$lastlog_client_name = @gethostbyaddr($lastlog_client_ip);
			$lastlog_callerid = $row['CallingStationId'];
			if ($lastlog_callerid == '')
				$lastlog_callerid = 'not available';
			$lastlog_input = $row['AcctInputOctets'];
			if ($lastlog_input)
				$lastlog_input = bytes2str($lastlog_input);
			else
				$lastlog_input = 'not available';
			$lastlog_output = $row['AcctOutputOctets'];
			if ($lastlog_output)
				$lastlog_input = bytes2str($lastlog_output);
			else
				$lastlog_output = 'not available';
		}
	}
	else
		echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	if (! $logged_now){
		$search = @da_sql_query($link,$config,
		"SELECT * FROM $config[sql_accounting_table]
		WHERE UserName = '$login' AND AcctSessionTime != '0'
		ORDER BY AcctStopTime DESC LIMIT 1;");
		if ($search){
			if (@da_sql_num_rows($search,$config)){
				$row = @da_sql_fetch_array($search,$config);
				$lastlog_time = $row['AcctStartTime'];
				$lastlog_server_ip = $row['NASIPAddress'];
				$lastlog_server_port = $row['NASPortId'];
				$lastlog_session_time = time2str($row['AcctSessionTime']);
				$lastlog_client_ip = $row['FramedIPAddress'];	
		$lastlog_server_name = ($lastlog_server_ip != '') ? @gethostbyaddr($lastlog_server_ip) : '-';
		$lastlog_client_name = ($lastlog_client_ip != '') ? @gethostbyaddr($lastlog_client_ip) : '-';
				$lastlog_callerid = $row['CallingStationId'];
				if ($lastlog_callerid == '')
					$lastlog_callerid = 'not available';
				$lastlog_input = $row['AcctInputOctets'];
				$lastlog_input = bytes2str($lastlog_input);
				$lastlog_output = $row['AcctOutputOctets'];
				$lastlog_output = bytes2str($lastlog_output);
			}
			else
				$not_known = 1;
		}
		else
			echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	}
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";

$monthly_limit = (is_numeric($monthly_limit)) ? time2str($monthly_limit) : $monthly_limit;
$weekly_limit = (is_numeric($weekly_limit)) ? time2str($weekly_limit) : $weekly_limit;
$daily_limit = (is_numeric($daily_limit)) ? time2str($daily_limit) : $daily_limit;
$session_limit = (is_numeric($session_limit)) ? time2str($session_limit) : $session_limit;
$remaining = (is_numeric($remaining)) ? time2str($remaining) : $remaining;

if ($item_vals['Dialup-Access'][0] == 'FALSE' || (!isset($item_vals['Dialup-Access'][0]) && $attrmap['Dialup-Access'] != '' && $attrmap['Dialup-Access'] != 'none'))
	$msg =<<<EON
<font color=red><b> The user account is locked </b></font>
EON;
else
	$msg =<<<EON
user can login for <font color="$log_color"> <b>$remaining $extra_msg</font>
EON;
$lock_msg = $item_vals['Dialup-Lock-Msg'][0];
if ($lock_msg != '')
	$descr =<<<EON
<font color=red><b>$lock_msg </b</font>
EON;
else
	$descr = '-';

$expiration = $default_vals['Expiration'][0];
if ($item_vals['Expiration'][0] != '')
	$expiration = $item_vals['Expiration'][0];
if ($expiration != ''){
	$expiration = strtotime($expiration);
	if ($expiration != -1 && $expiration < time())
		$descr = <<<EOM
<font color=red><b>User Account has expired</b></font>
EOM;
}

require('../html/user_admin.html.php3');
