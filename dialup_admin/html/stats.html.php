<form action="stats.php" method="get">
<table border=0 width=600 cellpadding=2 cellspacing=0>
<tr>
	<td align=left>
	<table border=0 cellspacing=0 cellpadding=2>
	<tr valign=bottom>
		<td><small><b>from date</td>
		<td><small><b>to date</td>
		<td><small><b>user</td>
		<td><small><b>on server</td>
		<td>&nbsp;</td>
		</tr>
	<tr background="images/greenlines1.gif" valign=middle>
<?php
echo <<<EOM
		<td valign=middle><input type="text" name="after"  size="12" value="$after" ></td>
		<td valign=middle><input type="text" name="before" size="12" value="$before"></td>
		<td valign=middle><input type="text" name="login"  size="12" value="$login" ></td>
		<td valign=middle><select name="server" size=1>
EOM;
foreach($servers as $key => $val)
	echo <<<EOM
	<option value="$val">$key
EOM;
?>
		</select></td>
		<td valign=middle><input type="submit" class=button value="Go"></td>
		</tr>
	</table>
	</td>
</tr>
<tr>
<td><hr size=1 noshade></td>
</tr>
<tr>
	<td valign=top>
	<table border=0 width="100%">
	<tr>	<td align=center valign=top width="45%">
		<small>
		<font color="darkblue"><b><?php echo $date ?></b></font>
		</td>
		<td align=center valign=top width="10%">&nbsp;</td>
		<td align=center valign=top width="45%"><small>
		statistics period:<br>
<?php
echo <<<EOM
		<b>$after</b> up to <b>$before</b>
EOM;
?>
		</td>
		</tr>
	</table>
	</td>
</tr>
<tr>
	<td align=center><h1><b>access statistics</td>
</tr>
<tr>
	<td valign=top>
	<table border=0 width="100%">
	<tr>
		<td colspan=2>
		<center>
		statistics for
<?php
if ($login == '')
	echo <<<EOM
<b><font color="darkblue">all</font></b> users
EOM;
else
	echo <<<EOM
user <b><font color="darkblue">$login</font></b>
EOM;
?>
	</td>
	</tr>
	</table>
	</td>
</tr>

<tr>
	<td>
	<table border=0 cellpadding=0 cellspacing=0 width="100%">
	<tr>	<td colspan=2><hr size=1 noshade>
		</td>
		</tr>

	</table>
	</td>
	</tr>
<tr>
	<td align="center">
	<table border=0 cellpadding=0 cellspacing=1 width="100%">
<?php
echo <<<EOM
	<tr>
		<td colspan=10 align=center nowrap><select name="column1">
		<option $selected1[sessions] value="sessions">sessions
		<option $selected1[usage] value="usage">total usage time
		<option value="upload">------------------
		<option $selected1[upload] value="upload">uploads
		<option $selected1[download] value="download">downloads
	</select> <select name="column2">
		<option $selected2[sessions] value="sessions">sessions
		<option $selected2[usage] value="usage">total usage time
		<option	value="upload">------------------
		<option $selected2[upload] value="upload">uploads
		<option $selected2[download] value="download">downloads
	</select> <select name="column3">
		<option $selected3[sessions] value="sessions">sessions
		<option $selected3[usage] value="usage">total usage time
		<option value="upload">------------------
		<option $selected3[upload] value="upload">uploads
		<option $selected3[download] value="download">downloads
EOM;
?>
		</select>
		</td>
	</tr>
	<tr>
		<td colspan=10 background="images/greenlines1.gif" align=center valign=middle>
		<table border=0 width="100%">
		<tr>
			<td width=50% align=left>
			<table border=0 cellpadding=0 cellspacing=0>
			<tr>
			<td align=right><input type="submit" class=button value="Refresh"></td>
			</tr>
			</table>
			</td>
		</tr>
		</table>
		</td>
	</tr>
	</table>
	</td>
	<tr>
	<td colspan=10 height=20><img src="images/pixel.gif"></td>
	</tr>
	<tr>
		<td colspan=10 height=20 align=center>
		<table border=0 width=640 cellpadding=1 cellspacing=1>
		<tr valign=top>
				<td width=440></td>
				<td bgcolor="black" width=200>
					<table border=0 width=100% cellpadding=2 cellspacing=0>
					<tr bgcolor="#907030" align=right valign=top><th>
							<font color="white">Daily Analysis</font>&nbsp;
					</th></tr>
					</table>
				</td></tr>
		<tr valign=top><td colspan=2>
			<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
			<tr><td>
				<p>
				<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
				<tr bgcolor="#d0ddb0">
					<th>date</th>
<?php
echo <<<EOM
	<th colspan=3>$message[$column1]</th>
	<th colspan=3>$message[$column2]</th>
	<th colspan=3>$message[$column3]</th>
EOM;
?>
				</tr>
<?php
	for($i = 0; $i <= $num_days; $i++){
		$day = $days[$i];
		$trcolor = ($i % 2) ? "#f7f7e4" : "#efefe4";
		echo <<<EOM
	<tr align=center bgcolor="$trcolor">
		<td>$day</td>
		<td>{$data[$day][1]}</td>
		<td>{$perc[$day][1]}</td>
		<td align=left height=14>
			<table border=0 cellpadding=0>
			<tr>
				<td bgcolor="{$color[$day][1]}" width={$width[$day][1]}><img border=0 height=14 width={$width[$day][1]} src="images/pixel.gif" alt="the $message[$column1] for $day is {$data[$day][1]}"></td>
			</tr>
			</table>
		</td>
		<td>{$data[$day][2]}</td>
		<td>{$perc[$day][2]}</td>
		<td align=left height=14>
			<table border=0 cellpadding=0>
			<tr>
				<td bgcolor="{$color[$day][2]}" width={$width[$day][2]}><img border=0 height=14 width={$width[$day][2]} src="images/pixel.gif" alt="the $message[$column3] for $day is {$data[$day][2]}"></td>
			</tr>
			</table>
		</td>
		<td>{$data[$day][3]}</td>
		<td>{$perc[$day][3]}</td>
		<td align=left height=14>
			<table border=0 cellpadding=0>
			<tr>
			<td bgcolor="{$color[$day][3]}" width={$width[$day][3]}><img border=0 height=14 width={$width[$day][3]} src="images/pixel.gif" alt="the $message[$column3] for $day is {$data[$day][3]}"></td>
			</tr>
			</table>
		</td>
		</tr>
EOM;
}
?>
</table>
</td></tr>
</table>
</td></tr>
</table>
</td></tr>
</table>
<p>
<table border=0 width=640 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=440></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Daily Summary</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
<p>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ff
ffe0" valign=top>
	<tr bgcolor="#d0ddb0">
	<th>&nbsp;</th>
<?php
echo <<<EOM
	<th>$message[$column1]</th>
	<th>$message[$column2]</th>
	<th>$message[$column3]</th>
EOM;
?>
	</tr>
<?php
echo <<<EOM
		<tr align=center bgcolor="#efefe4">
			<td>maximum</td>
			<td>{$data[max][1]}</td>
			<td>{$data[max][2]}</td>
			<td>{$data[max][3]}</td>
			</tr>
		<tr align=center bgcolor="#f7f7e4">
			<td>average</td>
			<td>{$data[avg][1]}</td>
			<td>{$data[avg][2]}</td>
			<td>{$data[avg][3]}</td>
			</tr>
		<tr align=center bgcolor="#efefe4">
			<td>sum</td>
			<td>{$data[sum][1]}</td>
			<td>{$data[sum][2]}</td>
			<td>{$data[sum][3]}</td>
			</tr>
EOM;
?>
</table>
		</table>
		</td></tr>
	</table>
	</td></tr>
</table>
</form>
</center>
</body>
</html>
