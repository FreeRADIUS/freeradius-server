<?php
require('../lib/functions.php3');
	$ds = @ldap_connect($config[ldap_server]);
	if ($ds){
		$r = @ldap_bind($ds,"$config[ldap_binddn]",$config[ldap_bindpw]);
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
							$mod[$attrmap["$key"]][] = $item_vals["$key"][$j];
							$add_r[$attrmap["$key"]][] = $val;
						}
						else{
							$add_r[$attrmap["$key"]][] = $val;
						}
					}
				}
			}
			if (isset($mod)){
				@ldap_mod_del($ds,$dn,$mod);
			}
			if (isset($add_r)){
				@ldap_mod_add($ds,$dn,$add_r);
			}
			if (isset($del)){
				@ldap_mod_del($ds,$dn,$del);
			}
		}
		if (@ldap_error($ds) == 'Success')
			echo "<b>The changes were successfully commited to the directory</b><br>\n";
		else
			echo "<b>LDAP ERROR: " . ldap_error($ds) . "</b><br>\n";
		@ldap_close($ds);
	}
?>
