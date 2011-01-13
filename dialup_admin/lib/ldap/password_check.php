<?php
require('password.php');

if ($action == 'checkpass'){
	$ds=@ldap_connect("$config[ldap_server]");  // must be a valid ldap server!
	if ($ds){
		if ($dn != ''){
			if ($passwd == '')
				$passwd = 'not_exist';
			$r = @ldap_bind($ds,$dn,$passwd);
			if ($r)
				$msg = '<font color=blue><b>YES It is that</b></font>';
			else
				$msg = '<font color=red><b>NO It is wrong</b></font>';
		}
		else
			$msg = 'User DN is not available. Check your configuration';
		@ldap_close($ds);
	}
	else
		$msg = '<font color=red><b>Could not connect to LDAP server</b></font>';
	echo "<tr><td colspan=3 align=center>$msg</td></tr>\n";
}
?>
</form>
