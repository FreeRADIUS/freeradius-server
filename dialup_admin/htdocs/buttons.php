<?php
$auth_user = $_SERVER["PHP_AUTH_USER"];
if ($auth_user){
	if (is_file("../html/buttons/$auth_user/buttons.html.php3"))
		include("../html/buttons/$auth_user/buttons.html.php3");
	else{
		if (is_file("../html/buttons/default/buttons.html.php3"))
			include("../html/buttons/default/buttons.html.php3");
	}
}
else{
	if (is_file("../html/buttons/default/buttons.html.php3"))
		include("../html/buttons/default/buttons.html.php3");
}
?>
