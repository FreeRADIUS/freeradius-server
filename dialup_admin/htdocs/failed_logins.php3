<?php
require('../conf/config.php3');
?>
<html>
<?php

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo <<<EOM
<title>Failed logins</title>
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

$now = time();
if ($last == 0)
	$last = ($config[general_most_recent_fl]) ? $config[general_most_recent_fl] : 5;
$start = $now - ($last*60);
$now_str = date($config[sql_full_date_format],$now);
$prev_str = date($config[sql_full_date_format],$start);
$pagesize = ($pagesize) ? $pagesize : 10;
$limit = ($pagesize == 'all') ? '' : "LIMIT $pagesize";
$selected[$pagesize] = 'selected';
$order = ($order != '') ? $order : $config[general_accounting_info_order];
if ($order != 'desc' && $order != 'asc')
	$order = 'desc';
$selected[$order] = 'selected';
if ($callerid != '')
	$callerid_str = "AND CallingStationId = '$callerid'";
if ($server != '' && $server != 'all')
	$server_str = "AND NASIPAddress = '$server'";

?>

<head>
<title>Failed Logins</title>
<link rel="stylesheet" href="style.css">
</head>
<body bgcolor="#80a040" background="images/greenlines1.gif" link="black" alink="black">
<center>
<table border=0 width=550 cellpadding=0 cellspacing=0>
<tr valign=top>
<td align=center><img src="images/title2.gif"></td>
</tr>
</table>
<table border=0 width=400 cellpadding=0 cellspacing=2>
</table>
<br>
<table border=0 width=840 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=65%></td>
<td bgcolor="black" width=35%>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Failed Logins</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
<?php
echo <<<EOM
<b>$prev_str</b> up to <b>$now_str</b>
EOM;
?>

<p>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
	<tr bgcolor="#d0ddb0">
	<th>#</th><th>login</th><th>time</th><th>server</th><th>terminate cause</th><th>callerid</th>
	</tr>

<?php
$link = @da_sql_pconnect($config);
if ($link){
	$search = @da_sql_query($link,$config,
	"SELECT AcctStopTime,UserName,NASIPAddress,NASPortId,AcctTerminateCause,CallingStationId
	FROM $config[sql_accounting_table]
	WHERE AcctStopTime <= '$now_str' AND AcctStopTime >= '$prev_str'
	AND (AcctTerminateCause LIKE 'Login-Incorrect%' OR
	AcctTerminateCause LIKE 'Invalid-User%' OR
	AcctTerminateCause LIKE 'Multiple-Logins%') $callerid_str $server_str
	ORDER BY AcctStopTime $order $limit;");
	if ($search){
		while( $row = @da_sql_fetch_array($search,$config) ){
			$num++;
			$acct_login = $row[UserName];
			if ($acct_login == '')
				$acct_login = '-';
			else
				$acct_login = "<a href=\"user_admin.php3?login=$acct_login\" title=\"Edit user $acct_login\">$acct_login</a>";
			$acct_time = $row[AcctStopTime];
			$acct_server = $row[NASIPAddress];
			if ($acct_server != ''){
				$acct_server = $da_name_cache[$acct_server];
				if (!isset($acct_server)){
					$acct_server = $row[NASIPAddress];
					$acct_server = gethostbyaddr($acct_server);
					if (!isset($da_name_cache) && $config[general_use_session] == 'yes'){
						$da_name_cache[$row[NASIPAddress]] = $acct_server;
						session_register('da_name_cache');
					}
					else
						$da_name_cache[$row[NASIPAddress]] = $acct_server;
				}
			}
			else
				$acct_server = '-';
			$acct_server = "$acct_server:$row[NASPortId]";
			$acct_terminate_cause = "$row[AcctTerminateCause]";
			if ($acct_terminate_cause == '')
				$acct_terminate_cause = '-';
			$acct_callerid = "$row[CallingStationId]";
			if ($acct_callerid == '')
				$acct_callerid = '-';
			echo <<<EOM
			<tr align=center bgcolor="white">
				<td>$num</td>
				<td>$acct_login</td>
				<td>$acct_time</td>
				<td>$acct_server</td>
				<td>$acct_terminate_cause</td>
				<td>$acct_callerid</td>
			</tr>
EOM;
		}
	}
}
echo <<<EOM
	</table>
<tr><td>
<hr>
<tr><td align="left">
	<form action="failed_logins.php3" method="get" name="master">
	<table border=0>
		<tr valign="bottom">
			<td><small><b>time back (mins)</td><td><small><b>pagesize</td><td><small><b>caller id</td><td><b>order</td>
	<tr valign="middle"><td>
<input type="text" name="last" size="11" value="$last"></td>
<td><select name="pagesize">
<option $selected[5] value="5" >05
<option $selected[10] value="10">10
<option $selected[15] value="15">15
<option $selected[20] value="20">20
<option $selected[40] value="40">40
<option $selected[80] value="80">80
<option $selected[all] value="all">all
</select>
</td>
<td>
<input type="text" name="callerid" size="11" value="$callerid"></td>
<td><select name="order">
<option $selected[asc] value="asc">older first
<option $selected[desc] value="desc">recent first
</select>
</td>
EOM;
?>

<td><input type="submit" class=button value="show"></td></tr>
<tr><td>
<b>On Access Server:</b>
</td></tr><tr><td>
<select name="server">
<?php
while(1){
	$i++;
	$name = 'nas' . $i . '_name';
	if ($config[$name] == ''){
		$i--;
		break;
	}
	$name_ip = 'nas' . $i . '_ip';
	if ($server == $config[$name_ip])
		echo "<option selected value=\"$config[$name_ip]\">$config[$name]\n";
	else
		echo "<option value=\"$config[$name_ip]\">$config[$name]\n";
}
if ($server == '' || $server == 'all')
	echo "<option selected value=\"all\">all\n";
?>
</select>
</td></tr>
</table></td></tr></form>
</table>
</tr>
</table>
</body>
</html>
