<?php
$op_eq = '=';
$op_set = ':=';
$op_add = '+=';
$op_eq2 = '==';
$op_ne = '!=';
$op_gt = '>';
$op_ge = '>=';
$op_lt = '<';
$op_le = '<=';
$op_regeq = '=~';
$op_regne = '!~';
$op_exst = '=*';
$op_nexst = '!*';

// Check the operator if it is allowed for this type of
// attribute (check or reply).
// Arguments:
// $op: The operator
// $type: 1(check),2(reply)
// Return value:0 for OK, -1 for error
function check_operator($op,$type)
{
	switch($op){
		case '=':
		case ':=':
		case '+=':
			return 0;
		case '==':
		case '!=':
		case '>':
		case '>=':
		case '<':
		case '<=':
		case '=~':
		case '!~':
		case '=*':
		case '!*':
			return ($type == 1) ? 0 : -1;
	}
}
?>
