<?php
require('../conf/config.php3');
require('../lib/xlat.php3');
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo <<<EOM
<title>Clear Open User Sessions for $login</title>
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

echo <<<EOM
<html>
<head>
<title>Clear Open User Sessions for $login</title>
<meta http-equiv="Content-Type" content="text/html; charset=$config[general_charset]">
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

$open_sessions = 0;

$sql_extra_query = '';
if ($config[sql_accounting_extra_query] != '')
	$sql_extra_query = xlat($config[sql_accounting_extra_query],$login,$config);

print <<<EOM
</table>

<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Clear open sessions for $login</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
EOM;
   
if ($clear_sessions == 1){
	$link = @da_sql_pconnect($config);
	if ($link){
		$res = @da_sql_query($link,$config,
		"DELETE FROM $config[sql_accounting_table]
		WHERE username='$login' AND acctstoptime = 0 $sql_extra_query;");
		if ($res)
			echo "<b>Deleted open sessions from accounting table</b><br>\n";
		else
			echo "<b>Error deleting open sessions for user" . da_sql_error($link,$config) . "</b><br>\n";
        }
	else
		echo "<b>Could not connect to SQL database</b><br>\n";
	echo <<<EOM
</td></tr>
</table>
</tr>
</table>
</body>
</html>
EOM;
	exit();
}
else{
	$link = @da_sql_pconnect($config);
	if ($link){
		$search = @da_sql_query($link,$config,
		"SELECT COUNT(*) AS counter FROM $config[sql_accounting_table]
		WHERE username = '$login' AND acctstoptime IS NULL $sql_extra_query;");
		if ($search){
			if ($row = @da_sql_fetch_array($search,$config))
				$open_sessions = $row[counter];
		}
		else
			echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
        }
	else
		echo "<b>Could not connect to SQL database</b><br>\n";
}
?>
   <form method=post>
      <input type=hidden name=login value=<?php print $login ?>>
      <input type=hidden name=clear_sessions value="0">
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
<tr>
<td align=center>
User <?php echo $login; ?> has <i><?php echo $open_sessions; ?></i> open sessions<br><br>
Are you sure you want to clear all open user sessions?
</td>
</tr>
	</table>
<br>
<input type=submit class=button value="Yes Clear" OnClick="this.form.clear_sessions.value=1">
</form>
</td></tr>
</table>
</tr>
</table>
</body>
</html>
