dnl  stolen from the GNU m4 manual.  -chad
define(`forloop', `pushdef(`$1', `$2')_forloop(`$1', `$2', `$3', `$4')popdef(`$1')')dnl
define(`_forloop', `$4`'ifelse($1, `$3', , `define(`$1', incr($1))_forloop(`$1', `$2', `$3', `$4')')')dnl
dnl
define(`undivertblock', `forloop(`i', 0, 10, `undivert(eval($1 + i))')')dnl
dnl
define(`PLACE_MODULES', `undivertblock(10)')dnl
define(`PLACE_AUTHENTICATION', `undivertblock(20)')dnl
define(`PLACE_AUTHORIZATION', `undivertblock(30)')dnl
define(`PLACE_PREACCOUNTING', `undivertblock(40)')dnl
define(`PLACE_ACCOUNTING', `undivertblock(50)')dnl
define(`PLACE_SESSIONING', `undivertblock(60)')dnl
dnl
define(`INSERT_GLOBAL_CONFIG', `divert(eval(0 + $1))')dnl
define(`INSERT_MODULE_INSTANTIATION', `divert(eval(10 + $1))')dnl
define(`INSERT_DEF_AUTHENTICATION', `divert(eval(20 + $1))')dnl
define(`INSERT_DEF_AUTHORIZATION', `divert(eval(30 + $1))')dnl
define(`INSERT_DEF_PREACCOUNTING', `divert(eval(40 + $1))')dnl
define(`INSERT_DEF_ACCOUNTING', `divert(eval(50 + $1))')dnl
define(`INSERT_DEF_SESSION', `divert(eval(60 + $1))')dnl
dnl
