<html>
<?php
require('../conf/config.php3');
require('../lib/functions.php3');

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo <<<EOM
<title>subscription analysis for $login ($cn)</title>
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
$now_str = ($now_str != '') ? "$now_str" : date($config[sql_date_format],$now + 86400);
$prev_str = ($prev_str != '') ? "$prev_str" : date($config[sql_date_format], $now - 604800 );
$num = 0;
$pagesize = ($pagesize) ? $pagesize : 10;
$limit = ($pagesize == 'all') ? '' : "LIMIT $pagesize";
$selected[$pagesize] = 'selected';
$order = ($order) ? $order : $config[general_accounting_info_order];
if ($order != 'desc' && $order != 'asc')
	$order = 'desc';
$selected[$order] = 'selected';


echo <<<EOM
<head>
<title>subscription analysis for $login ($cn)</title>
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
EOM;

include("../html/user_toolbar.html.php3");

print <<<EOM
</table>
<br>
<table border=0 width=840 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=65%></td>
<td bgcolor="black" width=35%>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Subscription Analysis for $login</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
<b>$prev_str</b> up to <b>$now_str</b>
EOM;
?>

<p>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
	<tr bgcolor="#d0ddb0">
	<th>#</th><th>type</th><th>logged in</th><th>session time</th><th>ip address</th>
	<th>upload</th><th>download</th><th>server</th><th>terminate cause</th><th>callerid</th>
	</tr>

<?php
$link = @da_sql_pconnect($config);
if ($link){
	$search = @da_sql_query($link,$config,
	"SELECT * FROM $config[sql_accounting_table]
	WHERE UserName = '$login' AND AcctStartTime <= '$now_str'
	AND AcctStartTime >= '$prev_str' ORDER BY AcctStartTime $order $limit;");
	if ($search){
		while( $row = @da_sql_fetch_array($search,$config) ){
			$tr_color='white';
			$num++;
			$acct_type = "$row[FramedProtocol]/$row[NASPortType]";
			$acct_logedin = $row[AcctStartTime];
			$acct_sessiontime = $row[AcctSessionTime];
			$acct_sessiontime_sum += $acct_sessiontime;
			$acct_sessiontime = time2str($acct_sessiontime);
			$acct_ip = $row[FramedIPAddress];
			if ($acct_ip == '')
				$acct_ip = '-';
			$acct_upload = $row[AcctInputOctets];
			$acct_upload_sum += $acct_upload;
			$acct_upload = bytes2str($acct_upload);
			$acct_download = $row[AcctOutputOctets];
			$acct_download_sum += $acct_download;
			$acct_download = bytes2str($acct_download);
			$acct_server = $da_name_cache[$row[NASIPAddress]];
			if (!isset($acct_server)){
				$acct_server = gethostbyaddr($row[NASIPAddress]);
				$da_name_cache[$row[NASIPAddress]] = $acct_server;
			}
			$acct_server = "$acct_server:$row[NASPortId]";
			$acct_terminate_cause = "$row[AcctTerminateCause]";
			if ($acct_terminate_cause == '')
				$acct_terminate_cause = '-';
			if (ereg('Login-Incorrect',$acct_terminate_cause) ||
				ereg('Multiple-Logins', $acct_terminate_cause) || ereg('Invalid-User',$acct_terminate_cause))
				$tr_color='#ffe8e0';
			$acct_callerid = "$row[CallingStationId]";
			if ($acct_callerid == '')
				$acct_callerid = '-';
			echo <<<EOM
			<tr align=center bgcolor="$tr_color">
				<td>$num</td>
				<td>$acct_type</td>
				<td>$acct_logedin</td>
				<td>$acct_sessiontime</td>
				<td>$acct_ip</td>
				<td>$acct_upload</td>
				<td>$acct_download</td>
				<td>$acct_server</td>
				<td>$acct_terminate_cause</td>
				<td>$acct_callerid</td>
			</tr>
EOM;
		}
		$acct_sessiontime_sum = time2str($acct_sessiontime_sum);
		$acct_upload_sum = bytes2str($acct_upload_sum);
		$acct_download_sum = bytes2str($acct_download_sum);
	}
}
echo <<<EOM
			<tr bgcolor="lightyellow">
			<td colspan=3 align="right">Page Total</td>
				<td align="center"><b>$acct_sessiontime_sum</td>
				<td>&nbsp;</td>
				<td align="right" nowrap><b>$acct_upload_sum</td>
				<td align="right" nowrap><b>$acct_download_sum</td>
				<td>&nbsp;</td>
				<td>&nbsp;</td>
				<td>&nbsp;</td>
				</tr>
	</table>
<tr><td>
<hr>
<tr><td align="center">
	<form action="user_accounting.php3" method="get" name="master">
	<table border=0>
		<tr><td colspan=6></td>
			<td rowspan=3 valign="bottom">
				<small>
				the <b>from</b> date matches any login after the 00:00 that day,
				and the <b>to</b> date any login before the 23:59 that day.
				the default values shown are the <b>current week</b>.
			</td>
		</tr>
		<tr valign="bottom">
			<td><small><b>user</td><td><small><b>from date</td><td><small><b>to date</td><td><small><b>pagesize</td><td><b>order</td>
	<tr valign="middle"><td>
<input type="text" name="login" size="11" value="$login"></td>
<td><input type="text" name="prev_str" size="11" value="$prev_str"></td>
<td><input type="text" name="now_str" size="11" value="$now_str"></td>
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
<td><select name="order">
<option $selected[asc] value="asc">older first
<option $selected[desc] value="desc">recent first
</select>
</td>
EOM;
?>

<td><input type="submit" class=button value="show"></td></tr>
</table></td></tr></form>
</table>
</tr>
</table>
</body>
</html>
