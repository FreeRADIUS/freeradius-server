<html>
<?php
require('../conf/config.php3');

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo <<<EOM
<title>User Groups</title>
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
?>
<head>
<title>User Groups</title>
<link rel="stylesheet" href="style.css">
</head>
<body bgcolor="#80a040" background="images/greenlines1.gif" link="black" alink="black">
<center>
<table border=0 width=550 cellpadding=0 cellspacing=0>
<tr valign=top>
<td align=center><img src="images/title2.gif"></td>
</tr>
</table>

<br><br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=55%></td>
<td bgcolor="black" width=45%>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">User Groups</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
<p>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
	<tr bgcolor="#d0ddb0">
	<th>#</th><th>group</th><th># of members</th>
	</tr>

<?php
$link = @da_sql_pconnect($config);
if ($link){
	$search = @da_sql_query($link,$config,
	"SELECT COUNT(*),GroupName FROM usergroup Group by GroupName ORDER BY GroupName;");
	if ($search){
		if (@da_sql_num_rows($search,$config)){
			while( $row = @da_sql_fetch_array($search,$config) ){
				$num++;
				$group = $row[GroupName];
				$num_members = $row['COUNT(*)'];
				echo <<<EOM
		<tr align=center>
			<td>$num</td>
			<td><a href="group_admin.php3?login=$group" title="Edit group $group">$group</a></td>
			<td>$num_members</td>
		</tr>
EOM;
			}
		}
		else
			echo "<b>Could not find any groups</b><br>\n";
	}
	else
		echo "<b>Search failed. SQL Error</b><br>\n";
}
?>
	</table>
</table>
</tr>
</table>
</body>
</html>
