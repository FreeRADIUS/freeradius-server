<form name="master" action="user_admin.php#pass" method="post">
<input type=hidden name=login value=<?php echo $login ?>>
<input type=hidden name=action value=checkpass>
<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Check Password</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
	<tr><td align=center bgcolor="#d0ddb0">Password</td><td><input type="password" name="passwd" value="">&nbsp;<input type="submit" class=button value="check"></td></tr>
	</table>
	</table>
</table>
