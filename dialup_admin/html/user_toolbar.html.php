<?php
$Login = urlencode($login);
print <<<EOM
<tr valign=top>
<td align=center bgcolor="black" width=100>
<a href="user_admin.php?login=$Login" title="Show User Information"><font color="white"><b>SHOW</b></font></a></td>
<td align=center bgcolor="black" width=100>
<a href="user_edit.php?login=$Login" title="Change User Dialup Settings"><font color="white"><b>EDIT</b></font></a></td>
<td align=center bgcolor="black" width=200 colspan=2>
<a href="user_info.php?login=$Login" title="Change User Personal Information"><font color="white"><b>USER INFO</b></font></a></td>
</tr>
<tr valign=top>
<td align=center bgcolor="black" width=100>
<a href="user_accounting.php?login=$Login" title="Show User Accounting Information"><font color="white"><b>ACCOUNTING</b></font></a></td>
<td align=center bgcolor="black" width=100>
<a href="badusers.php?login=$Login" title="Show User Unauthorized Actions"><font color="white"><b>BADUSERS</b></font></a></td>
<td align=center bgcolor="black" width=100>
<a href="user_delete.php?login=$Login" title="Delete User"><font color="white"><b>DELETE</b></font></a></td>
<td align=center bgcolor="black" width=100>
<a href="user_test.php?login=$Login" title="Test User"><font color="white"><b>TEST</b></font></a></td>
</tr>
<tr valign=top>
<td align=center width=100></td>
<td align=center bgcolor="black" width=200 colspan=2>
<a href="clear_opensessions.php?login=$Login" title="Clear Open User Sessions"><font color="white"><b>OPEN SESSIONS</b></font></a></td>
<td align=center width=100></td>
</tr>
EOM;
?>
