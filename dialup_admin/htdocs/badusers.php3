<?php
require('../conf/config.php3');
require('../lib/functions.php3');
?>
<html>
<?php

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo <<<EOM
<title>Unauthorized Service Usage History for $login</title>
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
$prev_str = ($prev_str != '') ? "$prev_str" : "0000-00-00 00:00:00";
$num = 0;
$pagesize = ($pagesize) ? $pagesize : 10;
$limit = ($pagesize == 'all') ? '' : "LIMIT $pagesize";
$selected[$pagesize] = 'selected';
$login = ($login != '') ? $login : 'anyone';
$usercheck = ($login == 'anyone') ? "LIKE '%'" : "= '$login'";

echo <<<EOM
<head>
<title>Unauthorized Service Usage History for $login</title>
<link rel="stylesheet" href="style.css">
</head>
<body bgcolor="#80a040" background="images/greenlines1.gif" link="black" alink="black">
<center>
<table border=0 width=550 cellpadding=0 cellspacing=0>
<tr valign=top>
<td align=center><img src="images/title2.gif"></td>
</tr>
</table>
EOM;

if ($login != 'anyone'){
	echo <<<EOM
<table border=0 width=400 cellpadding=0 cellspacing=2>
EOM;

include("../html/user_toolbar.html.php3");

print <<<EOM
</table>
EOM;
}

echo <<<EOM
<br><br>
<table border=0 width=740 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=55%></td>
<td bgcolor="black" width=45%>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Unauthorized Service Usage History for $login</font>&nbsp;
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
	<th>#</th><th>user</th><th>date</th><th>admin</th><th>reason</th>
	</tr>

<?php
$link = @da_sql_pconnect($config);
if ($link){
	$search = @da_sql_query($link,$config,
	"SELECT * FROM $config[sql_badusers_table]
	WHERE UserName $usercheck AND Date <= '$now_str'
	AND Date >= '$prev_str' ORDER BY Date ASC $limit;");
	if ($search){
		while( $row = @da_sql_fetch_array($search,$config) ){
			$num++;
			$user = "$row[UserName]";
			$date = "$row[Date]";
			$reason = "$row[Reason]";
			$admin = "$row[Admin]";
			if ($admin == '')
				$admin = '-';
			if ($reason == '')
				$reason = '-';
			echo <<<EOM
			<tr align=center>
				<td>$num</td>
				<td><a href="user_admin.php3?login=$user" title="Edit user $user">$user</a></td>
				<td>$date</td>
				<td>$admin</td>
				<td>$reason</td>
			</tr>
EOM;
		}
	}
	else
		echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
echo <<<EOM
	</table>
<tr><td>
<hr>
<tr><td align="center">
	<form action="badusers.php3" method="get" name="master">
	<table border=0>
		<tr><td colspan=5></td>
			<td rowspan=3 valign="bottom">
				<small>
				the <b>from</b> date matches any login after the 00:00 that day,
				and the <b>to</b> date any login before the 23:59 that day.
				the default values shown are the <b>current week</b>.
			</td>
		</tr>
		<tr valign="bottom">
			<td><small><b>user</td><td><small><b>from date</td><td><small><b>to date</td><td><small><b>pagesize</td><td>
&nbsp;</td>
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
EOM;
?>

<td><input type="submit" class=button value="show"></td></tr>
</table></td></tr></form>
</table>
</tr>
</table>
</body>
</html>
