<?php
echo <<<EOM
	<tr><td align=center bgcolor="#d0ddb0">
	Server
	</td><td>
	<b>$lastlog_server_name</b> ($lastlog_server_ip)
	</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">
	Server Port
	</td><td>
	$lastlog_server_port
	</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">
	Workstation
	</td><td>
	$lastlog_callerid
	</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">
	Upload
	</td><td>
	$lastlog_input
	</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">
	Download
	</td><td>
	$lastlog_output
	</td></tr>
EOM;
?>
