<?php
require_once('../lib/ldap/functions.php3');
if ($config[ldap_default_dn] != ''){
	include('../lib/ldap/attrmap.php3');
	$regular_profile_attr = $config[ldap_regular_profile_attr];
	$ds=@ldap_connect("$config[ldap_server]");  // must be a valid ldap server!
	if ($ds) {
       		$r=@da_ldap_bind($ds,$config);
		if ($config[ldap_debug] == 'true')
			print "<b>DEBUG(LDAP): Search Query: BASE='$config[ldap_default_dn]',FILTER='objectclass=*'</b><br>\n";
       		$sr=@ldap_search($ds,"$config[ldap_default_dn]", 'objectclass=*');
       		if ($info = @ldap_get_entries($ds, $sr)){
       			$dn = $info[0]['dn'];
       			if ($dn != ''){
               			foreach($attrmap as $key => $val){
						if ($info[0]["$val"][0] != '' && $key != 'Dialup-Access'){
							if ($attrmap[generic]["$key"] == 'generic'){
								for($i=0;$i<$info[0]["$val"][count];$i++)
									$default_vals["$key"][] = $info[0]["$val"][$i];
								$default_vals["$key"][count] += $info[0]["$val"][count];
							}
							else
								$default_vals["$key"] = $info[0]["$val"];
						}
				}
			}
		}
		if ($regular_profile_attr != ''){
			$get_attrs = array("$regular_profile_attr");
			if ($config[ldap_filter] != '')
				$filter = xlat($config[ldap_filter],$login,$config);
			else
				$filter = 'uid=' . $login;
			if ($config[ldap_debug] == 'true')
				print "<b>DEBUG(LDAP): Search Query: BASE='$config[ldap_base]',FILTER='$filter'</b><br>\n";
			$sr=@ldap_search($ds,"$config[ldap_base]",$filter,$get_attrs);
			if ($info = @ldap_get_entries($ds,$sr)){
				for($i=0;$i<$info[0][$regular_profile_attr]["count"];$i++){
					$dn2 = $info[0][$regular_profile_attr][$i];
					if ($dn2 != ''){
						if ($config[ldap_debug] == 'true')
							print "<b>DEBUG(LDAP): Search Query: BASE='$dn2',FILTER='objectclass=*'</b><br>\n";
						$sr2=@ldap_search($ds,"$dn2",'objectclass=*');
						if ($info2 = @ldap_get_entries($ds,$sr2)){
							$dn3 = $info2[0]['dn'];
							if ($dn3 != ''){
								foreach($attrmap as $key => $val){
									if ($info2[0]["$val"][0] != '' && $key != 'Dialup-Access'){
										if (!isset($default_vals["$key"]))
											$default_vals["$key"] = array();
										if ($attrmap[generic]["$key"] == 'generic'){
											for($j=0;$j<$info2[0]["$val"][count];$j++)
												$default_vals["$key"][] = $info2[0]["$val"][$j];
											$default_vals["$key"][count] += $info2[0]["$val"][count];
										}
										else
											$default_vals["$key"] = $info2[0]["$val"];
									}
								}
							}
						}
					}
				}
			}
		}
		@ldap_close($ds);
	}
}

?>
