/*
 * compat.h   Compability library for systems that don't have some
 *              of the routines that we would like to use...
 *
 * Version: cache.c  0.99  04-13-1999  jeff@apex.net
 */
#ifndef _COMPAT_H
#define _COMPAT_H

#ifdef HAVE_GETSPNAM
#if defined(M_UNIX)

	typedef struct passwd shadow_pwd_t;
#define GET_SP_NAME(sp) ((sp)->pw_name)
#define GET_SP_PWD(sp) ((sp)->pw_passwd)

#else /* M_UNIX */

	typedef struct spwd shadow_pwd_t;
#define GET_SP_NAME(sp)  ((sp)->sp_namp)
#define GET_SP_PWD(sp)    ((sp)->sp_pwdp)
#define GET_SP_LSTCHG(sp) ((sp)->sp_lstchg)
#define GET_SP_MIN(sp)    ((sp)->sp_min)
#define GET_SP_MAX(sp)    ((sp)->sp_max)
#define GET_SP_WARN(sp)   ((sp)->sp_warn)
#define GET_SP_INACT(sp)  ((sp)->sp_inact)
#define GET_SP_EXPIRE(sp) ((sp)->sp_expire)

#endif	/* M_UNIX */

#else /* HAVE_GETSPNAM */

typedef struct my_shadow_t {
	char *sp_namp;
	char *sp_pwdp;
	long int sp_lstchg;         /* Date of last change.  */
	long int sp_min;
	long int sp_max;
	long int sp_warn;
	long int sp_inact;
	long int sp_expire;
} shadow_pwd_t;
#define GET_SP_NAME(sp)  ((sp)->sp_namp)
#define GET_SP_PWD(sp)    ((sp)->sp_pwdp)
#define GET_SP_LSTCHG(sp) ((sp)->sp_lstchg)
#define GET_SP_MIN(sp)    ((sp)->sp_min)
#define GET_SP_MAX(sp)    ((sp)->sp_max)
#define GET_SP_WARN(sp)   ((sp)->sp_warn)
#define GET_SP_INACT(sp)  ((sp)->sp_inact)
#define GET_SP_EXPIRE(sp) ((sp)->sp_expire)

#endif	/* HAVE_GETSPNAM */




#ifndef HAVE_FGETPWENT
extern struct passwd *rad_fgetpwent(FILE *pwhandle);
static inline struct passwd *fgetpwent(FILE *pw) {
	return rad_fgetpwent(pw);
}
#endif /* HAVE_FGETPWENT */

#ifndef HAVE_FGETSPENT
extern shadow_pwd_t *rad_fgetspent(FILE *sphandle);
static inline shadow_pwd_t *fgetspent(FILE *sp) {
	return rad_fgetspent(sp);
}
#endif /* HAVE_FGETSPENT */

#ifndef HAVE_FGETGRENT
extern struct group *rad_fgetgrent(FILE *grhandle);
static inline struct group *fgetgrent(FILE *gr) {
	return rad_fgetgrent(gr);
}
#endif /* HAVE_FGETGRENT */

#endif /* _COMPAT_H */
