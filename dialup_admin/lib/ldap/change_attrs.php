<?php
require_once('../lib/functions.php3');
require_once('../lib/ldap/functions.php3');
	if ($config[ldap_write_server])
		$ds = @ldap_connect($config[ldap_write_server]);
	else
		$ds = @ldap_connect($config[ldap_server]);
	if ($ds){
		$r = @da_ldap_bind($ds,$config);
		if ($r){

			foreach($show_attrs as $key => $attr){
				if ($attrmap["$key"] == 'none')
					continue;
				$i = 0;
				$j = -1;
				$name = $attrmap["$key"] . $i;

				while (isset($$name)){
					$val = $$name;
					$i++;
					$j++;
					$name = $attrmap["$key"] . $i;
//
//	if value is the same as the default and the corresponding attribute in ldap does not exist or
//	the value is the same as that in ldap then continue
//
					if ( (check_defaults($val,'',$default_vals["$key"]) && !isset($item_vals["$key"][$j])) || $val == $item_vals["$key"][$j])
						continue;
//
//	if value is null and ldap attribute does not exist then continue
//
					if ($val == '' && !isset($item_vals["$key"][$j]))
						continue;
//
//	if values is the same as the default or if the value is null and the ldap attribute exists
//	then delete them
//
					if ((check_defaults($val,'',$default_vals["$key"]) || $val == '') &&
						isset($item_vals["$key"][$j]))
						$del[$attrmap["$key"]][] = $item_vals["$key"][$j];
//
//	else modify the ldap attribute
//
					else{
						if (isset($item_vals["$key"][$j])){
							$del[$attrmap["$key"]][] = $item_vals["$key"][$j];
							$add_r[$attrmap["$key"]][] = $val;
						}
						else{
							$add_r[$attrmap["$key"]][] = $val;
						}
					}
				}
			}
			if (isset($del)){
			       if ($config[ldap_debug] == 'true'){
					print "<b>DEBUG(LDAP): ldap_mod_del(): DN='$dn'</b><br>\n";
					print "<b>DEBUG(LDAP): ldap_mod_del(): Data:";
					print_r($del);
					print "</b><br>\n";
				}
				@ldap_mod_del($ds,$dn,$del);
			}
			if (isset($add_r)){
			       if ($config[ldap_debug] == 'true'){
					print "<b>DEBUG(LDAP): ldap_mod_add(): DN='$dn'</b><br>\n";
					print "<b>DEBUG(LDAP): ldap_mod_add(): Data:";
					print_r($add_r);
					print "</b><br>\n";
				}
				@ldap_mod_add($ds,$dn,$add_r);
			}
		}
		if (@ldap_error($ds) == 'Success')
			echo "<b>The changes were successfully commited to the directory</b><br>\n";
		else
			echo "<b>LDAP ERROR: " . ldap_error($ds) . "</b><br>\n";
		@ldap_close($ds);
	}
?>
