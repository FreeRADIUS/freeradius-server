<?php
$auth_user = $_SERVER["PHP_AUTH_USER"];
if ($auth_user){
	if (is_file("../html/buttons/$auth_user/buttons.html.php"))
		include("../html/buttons/$auth_user/buttons.html.php");
	else{
		if (is_file("../html/buttons/default/buttons.html.php"))
			include("../html/buttons/default/buttons.html.php");
	}
}
else{
	if (is_file("../html/buttons/default/buttons.html.php"))
		include("../html/buttons/default/buttons.html.php");
}
?>
