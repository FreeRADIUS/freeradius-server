<html>
<head>
<link rel="stylesheet" href="style.css">
<script>
function myin(a) {
	eval ( "document.all.menu" + a + ".style.backgroundColor='#cac060';" );
	eval ( "document.all.a" + a + ".style.color='#ffffff';" );
}
function myout(a) {
	eval ( "document.all.menu" + a + ".style.backgroundColor='#ffffd0';" );
	eval ( "document.all.a" + a + ".style.color='#000000';" );
}
</script>
</head>
<body>
<form action="user_admin.php" method=get target="content">
<table border=0 width=100 cellpadding=1 cellspacing=1>
<tr><td align=center>
<img src="images/logo2.gif" vspace=2>
</td></tr>
<?php
if ($_SERVER["PHP_AUTH_USER"])
	echo "<tr valign=top><td align=center><b>Logged in as " . $_SERVER["PHP_AUTH_USER"] . "...</b><br><br></td></tr>\n";
?>
<tr bgcolor="black" valign=top><td>
<table border=0 width=100% cellpadding=2 cellspacing=0>
<tr bgcolor="#907030" align=center valign=top><th>
<font color="white">Main Menu</font>
</th></tr>
</table>
</td></tr>
<tr bgcolor="black" valign=top><td>
<table border=0 width=100% height=100% cellpadding=0 cellspacing=0>
<tr bgcolor="#ffffd0" valign=top><td>
	<table border=0 width=100% height=100% cellpadding=4 cellspacing=2>
	<tr align=left><td id="menu0" onmouseover='myin("0");' onmouseout='myout("0");'>
	<a id="a0" href="content.html" target="content">Home</a>
	</td></tr>
	<tr align=left><td id="menu1" onmouseover='myin("1");' onmouseout='myout("1");'>
	<a id="a1" href="accounting.php" target="content" title="Accounting Report Generator">Accounting</a>
	</td></tr>
	<tr align=left><td id="menu2" onmouseover='myin("2");' onmouseout='myout("2");'>
	<a id="a2" href="stats.php" target="content" title="Dialup Statistics">Statistics</a>
	</td></tr>
	<tr align=left><td id="menu17" onmouseover='myin("17");' onmouseout='myout("17");'>
	<a id="a17" href="user_stats.php" target="content" title="Show User Statistics">User Statistics</a>
	</td></tr>
	<tr align=left><td id="menu3" onmouseover='myin("3");' onmouseout='myout("3");'>
	<a id="a3" href="user_finger.php" target="content" title="Show Online Users">Online Users</a>
	</td></tr>
	<tr align=left><td id="menu18" onmouseover='myin("18");' onmouseout='myout("18");'>
	<a id="a18" href="nas_admin.php" target="content" title="Administer RADIUS Clients">RADIUS Clients</a>
	</td></tr>
	<tr align=left><td id="menu7" onmouseover='myin("7");' onmouseout='myout("7");'>
	<a id="a7" href="badusers.php?login=anyone" target="content" title="Show Bad Users">Bad Users</a>
	</td></tr>
	<tr align=left><td id="menu16" onmouseover='myin("16");' onmouseout='myout("16");'>
	<a id="a16" href="failed_logins.php" target="content" title="Show Most Recent Failed Logins">Failed Logins</a>
	</td></tr>
	<tr align=left><td id="menu14" onmouseover='myin("14");' onmouseout='myout("14");'>
	<a id="a14" href="find.php" target="content" title="Find User">Find User</a>
	</td></tr>
	<tr align=left><td id="menu4" onmouseover='myin("4");' onmouseout='myout("4");'>
	<a id="a4">Edit User</a>
	<img align=top src="images/black.gif" vspace=7 hspace=0 width=1 height=1><br>
	<input type="text" size=11 name="login" target="content">
	</td></tr>
	<tr align=left><td id="menu9" onmouseover='myin("9");' onmouseout='myout("9");'>
	<a id="a9" href="user_new.php" target="content" title="Create New User">New User</a>
	</td></tr>
	<tr align=left><td><img src="images/black.gif" vspace=2 hspace=0 width=80 height=1></td></tr>
</form>
<form action="group_admin.php" method=get target="content">
	<tr align=left><td id="menu13" onmouseover='myin("13");' onmouseout='myout("13");'>
	<a id="a13" href="show_groups.php" target="content" title="Show User Groups">Show Groups</a>
	</td></tr>
	<tr align=left><td id="menu11" onmouseover='myin("11");' onmouseout='myout("11");'>
	<a id="a11" href="group_admin.php" target="content" title="Group Administration">Edit Group</a>
	<img align=top src="images/black.gif" vspace=7 hspace=0 width=1 height=1><br>
	<input type="text" size=11 name="login" target="content">
	</td></tr>
	<tr align=left><td id="menu12" onmouseover='myin("12");' onmouseout='myout("12");'>
	<a id="a12" href="group_new.php" target="content" title="Create New Group">New Group</a>
	</td></tr>
	<tr align=left><td><img src="images/black.gif" vspace=2 hspace=0 width=80 height=1></td></tr>
	<tr align=left><td id="menu10" onmouseover='myin("10");' onmouseout='myout("10");'>
	<a id="a10" href="user_test.php?login=da_server_test&test_user=1" target="content" title="Check Server Response">Check Server</a>
	</td></tr>
<?php
include('../conf/config.php');
if ($config[general_use_session] == 'yes')
	echo <<<EOM
	<tr align=left><td><img src="images/black.gif" vspace=2 hspace=0 width=80 height=1></td></tr>
	<tr align=left><td id="menu15" onmouseover='myin("15");' onmouseout='myout("15");'>
	<a id="a15" href="session_destroy.php" target="content" title="Clear Session Cache">Clear Cache</a>
	</td></tr>
EOM;
?>
	<tr align=left><td><img src="images/black.gif" vspace=2 hspace=0 width=80 height=1></td></tr>
	<tr align=left><td id="menu5" onmouseover='myin("5");' onmouseout='myout("5");' nowrap>
	<a id="a5" href="help/help.php" target="content" title="Show Help">Help</a>
	</td></tr>
	<tr align=left><td id="menu6" onmouseover='myin("6");' onmouseout='myout("6");'>
	<a id="a6" href="about.html" target="content" title="About dialup_admin">About</a>
	</td></tr>
	</table>
</td></tr>
<tr bgcolor="#ffffd0" align=right valign=bottom><td><img vspace=0 hspace=0 src="images/bg.gif"></td></tr>
</table>
</td></tr>
</table>
</form>
</html>
