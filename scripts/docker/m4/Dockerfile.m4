dnl  Look up the OS codename, docker base image etc before including
dnl  the main Dockerfile template.
dnl
dnl  This top-level template is used by both the docker makefile
dnl  (scripts/docker/docker.mk) and the crossbuild makefile
dnl  (scripts/crossbuild/crossbuild.mk), but the Dockerfile templates
dnl  they use are different - see the m4 directories for each.
dnl
dnl  Two macros must be defined for this template:
dnl    D_NAME - the OS codename, see the table below, e.g. debian11
dnl    D_TYPE - the type of template, 'docker' or 'crossbuild'
dnl
divert(`-1')
changequote(`[', `]')
define([p_SET], [
	define([PKG_TYPE],	[$1])
	define([OS_NAME],	[$2])
	define([OS_VER],	[$3])
	define([OS_CODENAME],	[$4])
	define([DOCKER_IMAGE],	[$5])
])
dnl		D_NAME		PKG_TYPE      OS_NAME	OS_VER	OS_CODENAME	DOCKER_IMAGE
ifelse(
	D_NAME, [debian12],	[p_SET([deb], [debian],	[12],	[bookworm],	[debian:bookworm])],
	D_NAME, [debiansid],	[p_SET([deb], [debian],	[99],	[sid],		[debian:sid])],
	D_NAME, [ubuntu22],	[p_SET([deb], [ubuntu],	[22],	[jammy],	[ubuntu:22.04])],
	D_NAME, [ubuntu24],	[p_SET([deb], [ubuntu],	[24],	[noble],	[ubuntu:24.04])],
	D_NAME, [rocky9],	[p_SET([rpm], [rocky],	[9],	[9],		[rockylinux/rockylinux:9])],
	D_NAME, [rocky10],	[p_SET([rpm], [rocky],	[10],	[10],		[rockylinux/rockylinux:10])],
	[errprint(error: OS 'D_NAME' not defined[,] see __file__
)m4exit(1)]
)
undefine([p_SET])
divert[]dnl
[#] Auto generated for D_NAME
[#] from scripts/docker/m4/D_TYPE.PKG_TYPE.m4
[#]
[#] Rebuild this file with `make D_TYPE.D_NAME.regen`
[#]
changequote([`], ['])dnl
include(D_TYPE.PKG_TYPE.m4)dnl
