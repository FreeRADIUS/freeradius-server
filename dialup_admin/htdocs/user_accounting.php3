<?php
require('../conf/config.php3');
?>
<html>
<?php
require('../lib/functions.php3');
require('../lib/sql/functions.php3');
require('../lib/attrshow.php3');

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo <<<EOM
<title>subscription analysis for $login</title>
<meta http-equiv="Content-Type" content="text/html; charset=$config[general_charset]">
<link rel="stylesheet" href="style.css">
</head>
<body>
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
if (!is_numeric($pagesize) && $pagesize != 'all')
	$pagesize = 10;
$limit = ($pagesize == 'all') ? '' : "$pagesize";
$selected[$pagesize] = 'selected';
$order = ($order != '') ? $order : $config[general_accounting_info_order];
if ($order != 'desc' && $order != 'asc')
	$order = 'desc';
$selected[$order] = 'selected';
$now_str = da_sql_escape_string($now_str);
$prev_str = da_sql_escape_string($prev_str);

unset($da_name_cache);
if (isset($_SESSION['da_name_cache']))
	$da_name_cache = $_SESSION['da_name_cache'];


echo <<<EOM
<head>
<title>subscription analysis for $login</title>
<meta http-equiv="Content-Type" content="text/html; charset=$config[general_charset]">
<link rel="stylesheet" href="style.css">
</head>
<body>
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
	<th>#</th>
<?php
for($i=1;$i<=9;$i++){
	if ($acct_attrs['ua']["$i"] != '')
		echo "<th>" . $acct_attrs['ua']["$i"] . "</th>\n";
}
$sql_extra_query = '';
if ($config[sql_accounting_extra_query] != '')
	$sql_extra_query = xlat($config[sql_accounting_extra_query],$login,$config);
?>
	</tr>

<?php
$link = @da_sql_pconnect($config);
if ($link){
	$search = @da_sql_query($link,$config,
	"SELECT " . da_sql_limit($limit,0,$config) . " * FROM $config[sql_accounting_table]
	WHERE username = '$login' AND acctstarttime <= '$now_str'
	AND acctstarttime >= '$prev_str' $sql_extra_query " . da_sql_limit($limit,1,$config) .
	" ORDER BY acctstarttime $order " . da_sql_limit($limit,2,$config). " ;");
	if ($search){
		while( $row = @da_sql_fetch_array($search,$config) ){
			$tr_color='white';
			$num++;
			$acct_type = "$row[framedprotocol]/$row[nasporttype]";
			if ($acct_type == '')
				$acct_type = '-';
			$acct_logedin = $row[acctstarttime];
			$acct_sessiontime = $row[acctsessiontime];
			$acct_sessiontime_sum += $acct_sessiontime;
			$acct_sessiontime = time2str($acct_sessiontime);
			$acct_ip = $row[framedipaddress];
			if ($acct_ip == '')
				$acct_ip = '-';
			$acct_upload = $row[acctinputoctets];
			$acct_upload_sum += $acct_upload;
			$acct_upload = bytes2str($acct_upload);
			$acct_download = $row[acctoutputoctets];
			$acct_download_sum += $acct_download;
			$acct_download = bytes2str($acct_download);
			$acct_server = $row[nasipaddress];
			if ($acct_server != ''){
				$acct_server = $da_name_cache[$row[nasipaddress]];
				if (!isset($acct_server)){
					$acct_server = @gethostbyaddr($row[nasipaddress]);
					if (!isset($da_name_cache) && $config[general_use_session] == 'yes'){
						$da_name_cache[$row[nasipaddress]] = $acct_server;
						session_register('da_name_cache');
					}
					else
						$da_name_cache[$row[nasipaddress]] = $acct_server;
				}
			}
			else
				$acct_server = '-';
			$acct_server = "$acct_server:$row[nasportid]";
			$acct_terminate_cause = "$row[acctterminatecause]";
			if ($acct_terminate_cause == '')
				$acct_terminate_cause = '-';
			if (ereg('Login-Incorrect',$acct_terminate_cause) ||
				ereg('Multiple-Logins', $acct_terminate_cause) || ereg('Invalid-User',$acct_terminate_cause))
				$tr_color='#ffe8e0';
			$acct_callerid = "$row[callingstationid]";
			if ($acct_callerid == '')
				$acct_callerid = '-';
			echo <<<EOM
			<tr align=center bgcolor="$tr_color">
				<td>$num</td>
EOM;
				if ($acct_attrs[ua][1] != '') echo "<td>$acct_type</td>\n";
				if ($acct_attrs[ua][2] != '') echo "<td>$acct_logedin</td>\n";
				if ($acct_attrs[ua][3] != '') echo "<td>$acct_sessiontime</td>\n";
				if ($acct_attrs[ua][4] != '') echo "<td>$acct_ip</td>\n";
				if ($acct_attrs[ua][5] != '') echo "<td>$acct_upload</td>\n";
				if ($acct_attrs[ua][6] != '') echo "<td>$acct_download</td>\n";
				if ($acct_attrs[ua][7] != '') echo "<td>$acct_server</td>\n";
				if ($acct_attrs[ua][8] != '') echo "<td>$acct_terminate_cause</td>\n";
				if ($acct_attrs[ua][9] != '') echo "<td>$acct_callerid</td>\n";
			echo "</tr>\n";
		}
		$acct_sessiontime_sum = time2str($acct_sessiontime_sum);
		$acct_upload_sum = bytes2str($acct_upload_sum);
		$acct_download_sum = bytes2str($acct_download_sum);
	}
	else
		echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
$colspan = 3;
if ($acct_attrs[ua][1] == '')
	$colspan--;
if ($acct_attrs[ua][2] == '')
	$colspan--;
echo <<<EOM
			<tr bgcolor="lightyellow">
			<td colspan=$colspan align="right">Page Total</td>
EOM;
				if ($acct_attrs[ua][3] != '') echo "<td align=\"center\"><b>$acct_sessiontime_sum</td>\n";
				if ($acct_attrs[ua][4] != '') echo "<td>&nbsp;</td>\n";
				if ($acct_attrs[ua][5] != '') echo "<td align=\"right\" nowrap><b>$acct_upload_sum</td>\n";
				if ($acct_attrs[ua][6] != '') echo "<td align=\"right\" nowrap><b>$acct_download_sum</td>\n";
				if ($acct_attrs[ua][7] != '') echo "<td>&nbsp;</td>\n";
				if ($acct_attrs[ua][8] != '') echo "<td>&nbsp;</td>\n";
				if ($acct_attrs[ua][9] != '') echo "<td>&nbsp;</td>\n";
?>
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
<?php
	echo <<<EOM
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
