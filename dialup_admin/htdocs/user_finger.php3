<html>
<head>
<title>
User Finger Facility
</title>
<link rel="stylesheet" href="style.css">
</head>

<?php
require('../conf/config.php3');
require('../lib/functions.php3');
require("../lib/$config[general_lib_type]/functions.php3");

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo <<<EOM
<body bgcolor="#80a040" background="images/greenlines1.gif" link="black" alink="black">
<center>
<b>Could not include SQL library functions. Aborting</b>
</body>
</html>
EOM;
	exit();
}

$date = strftime('%A, %e %B %Y, %T %Z');

$link = @da_sql_pconnect($config);
$link2 = connect2db($config);
if ($link){
	$h = 21;
	while(1){
		$i++;
		$num = 0;
		$nas = 'nas' . $i;
		$name = $nas . '_name';
		$model = $nas . '_model';
		$community = $nas . '_community';
		$ip = $nas . '_ip';
		$portnum = $nas . '_port_num';

		if ($config[$name] == ''){
			$i--;
			break;
		}
		$name_data = $config[$ip];
		$community_data = $config[$community];
		$server_name[$i] = $config[$name];
		$server_model[$i] = $config[$model];
		if ($config[general_ld_library_path] != '')
			putenv("LD_LIBRARY_PATH=$config[general_ld_library_path]");
		$extra = "";
		if ($config[general_finger_type] == 'snmp'){
			$users=exec("$config[general_snmpfinger_bin] $name_data $community_data");
			if (strlen($users))
				$extra = "AND UserName IN ($users)";
		}
		$search = @da_sql_query($link,$config,
		"SELECT DISTINCT UserName,AcctStartTime,FramedIPAddress,CallingStationId
		FROM $config[sql_accounting_table] WHERE
		AcctStopTime = '0' AND NASIPAddress = '$name_data' $extra
		GROUP BY UserName ORDER BY AcctStartTime;");
		if ($search){
			while($row = @da_sql_fetch_array($search,$config)){
				$num++;
				$h += 21;
				$user = $row['UserName'];
				$finger_info[$i][$num]['ip'] = $row['FramedIPAddress'];
				if ($finger_info[$i][$num]['ip'] == '')
					$finger_info[$i][$num]['ip'] = '-';
				$session_time = $row['AcctStartTime'];
				$session_time = date2timediv($session_time);
				$finger_info[$i][$num]['session_time'] = time2strclock($session_time);
				$finger_info[$i][$num]['user'] = $user;
				$finger_info[$i][$num]['callerid'] = $row['CallingStationId'];
				if ($finger_info[$i][$num]['callerid'] == '')
					$finger_info[$i][$num]['callerid'] = '-';
				if ($user_info["$user"] == ''){
					$user_info["$user"] = get_user_info($link2,$user,$config);
					if ($user_info["$user"] == '' || $user_info["$user"] == ' ')
						$user_info["$user"] = 'Unknown User';
				}
			}
			$height[$i] = $h;
		}
		$server_loggedin[$i] = $num;
		$server_rem[$i] = ($config[$portnum]) ? ($config[$portnum] - $num) : 'unknown';
	}
}
?>

<body bgcolor="#80a040" background="images/greenlines1.gif" link="black" alink="black">
<center>
<table border=0 width=550 cellpadding=0 cellspacing=0>
<tr valign=top>
<td align=center><img src="images/title2.gif"></td>
</tr>
</table>
<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Online Users</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
<?php
echo <<<EOM
	<b>$date</b>
EOM;
	for($j = 1; $j <= $i; $j++){
		echo <<<EOM
<p>
	<table width=100% cellpadding=0 height=30><tr>
	<th align=left>$server_name[$j]<br><font color="green">$server_model[$j]</font></th><th align=right><font color="red">$server_loggedin[$j] users connected</font></th><th><font color="green">$server_rem[$j] free lines</font></th>
	</tr>
	</table>
	<div height="$height[$j]" style="height:$height[$j];overflow:auto;">
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
	<tr bgcolor="#d0ddb0">
	<th>#</th><th>user</th><th>ip address</th><th>caller id</th><th>name</th><th>duration</th>
	</tr>
EOM;
	for( $k = 1; $k <= $server_loggedin[$j]; $k++){
		$user = $finger_info[$j][$k][user];
		$time = $finger_info[$j][$k][session_time];
		$ip = $finger_info[$j][$k][ip];
		$cid = $finger_info[$j][$k][callerid];
		$inf = $user_info[$user];
		echo <<<EOM
	<tr align=center>
	<td>$k</td><td><a href="user_admin.php3?login=$user" title="Edit User $user">$user</a></td><td>$ip</td><td>$cid</td><td>$inf</td><td>$time</td>
	</tr>
EOM;
	}

	echo <<<EOM
	</table>
	</div>
EOM;
}
?>
	</td></tr>
	</table>
</td></tr>
</table>
<p>
</html>
