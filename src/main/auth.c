/*
 * auth.c	User authentication.
 *
 *
 * Version:	@(#)auth.c  1.87  08-Aug-1999  miquels@cistron.nl
 *
 */
char auth_sccsid[] =
"@(#)auth.c	1.87 Copyright 1998-1999 Cistron Internet Services B.V.";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/time.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<time.h>
#include	<unistd.h>
#include	<errno.h>

#if HAVE_MALLOC_H
#  include <malloc.h>
#endif

#if HAVE_SHADOW_H
#  include	<shadow.h>
#endif

#if HAVE_CRYPT_H
#  include <crypt.h>
#endif

#ifdef OSFC2
#  include	<sys/security.h>
#  include	<prot.h>
#endif

#include	"radiusd.h"
#include	"modules.h"

#if !HAVE_CRYPT_H
  extern char *crypt();
#endif


/*
 *	Return a short string showing the terminal server, port
 *	and calling station ID.
 */
char *auth_name(REQUEST *request, int do_cli)
{
	static char	buf[300];
	VALUE_PAIR	*cli;
	VALUE_PAIR	*pair;
	int		port = 0;

	if ((cli = pairfind(request->packet->vps, PW_CALLING_STATION_ID)) == NULL)
		do_cli = 0;
	if ((pair = pairfind(request->packet->vps, PW_NAS_PORT_ID)) != NULL)
		port = pair->lvalue;

	sprintf(buf, "from nas %.128s/S%d%s%.128s",
		nas_name2(request->packet), port,
		do_cli ? " cli " : "", do_cli ? cli->strvalue : "");

	return buf;
}


/*
 *	Check if account has expired, and if user may login now.
 */
static int check_expiration(VALUE_PAIR *check_item, char *umsg, char **user_msg)
{
	int result;

	result = 0;
	while (result == 0 && check_item != (VALUE_PAIR *)NULL) {

		/*
		 *	Check expiration date if we are doing password aging.
		 */
		if (check_item->attribute == PW_EXPIRATION) {
			/*
			 *	Has this user's password expired
			 */
			if (check_item->lvalue < time(NULL)) {
				result = -1;
				*user_msg = "Password Has Expired\r\n";
				break;
			}
		}
		check_item = check_item->next;
	}
	return result;
}


/*
 *	Check password.
 *
 *	Returns:	0  OK
 *			-1 Password fail
 *			-2 Rejected (Auth-Type = Reject, send Port-Message back)
 *			1  End check & return, don't reply
 *
 *	NOTE: NOT the same as the RLM_ values !
 */
static int rad_check_password(REQUEST *request, int activefd,
	VALUE_PAIR *check_item,
	VALUE_PAIR *namepair,
	char **user_msg, char *userpass)
{
	VALUE_PAIR	*auth_type_pair;
	VALUE_PAIR	*password_pair;
	VALUE_PAIR	*auth_item;
	VALUE_PAIR	*tmp;
	char		string[MAX_STRING_LEN];
	char		chap_digest[16];
	char		*ptr;
	int		auth_type = -1;
	int		i;
	int		result;

	/*
	 *	cjd 19980706 --
	 *	pampair contains the pair of PAM_AUTH_ATTR
	 *	pamauth is the actual string
	 */
        VALUE_PAIR      *pampair;
	char		*pamauth = NULL;

	result = 0;
	userpass[0] = 0;
	string[0] = 0;

	/*
	 *	Look for matching check items. We skip the whole lot
	 *	if the authentication type is PW_AUTHTYPE_ACCEPT or
	 *	PW_AUTHTYPE_REJECT.
	 */
	if ((auth_type_pair = pairfind(check_item, PW_AUTHTYPE)) != NULL)
		auth_type = auth_type_pair->lvalue;

	if (auth_type == PW_AUTHTYPE_ACCEPT)
		return 0;

	if (auth_type == PW_AUTHTYPE_REJECT) {
		*user_msg = NULL;
		return -2;
	}

	/*
	 *	cjd 19980706 --
	 *	Fish out the the PAM_AUTH_ATTR info for this match and
	 *	get the string for pamauth.
	 *	Pamauth is passed to pam_pass so we can have selective
	 *	pam configuration.
	 */
        if ((pampair = pairfind(check_item, PAM_AUTH_ATTR)) != NULL) {
		pamauth = pampair->strvalue;
        }

	/*
	 *	Find the password sent by the user. It SHOULD be there,
	 *	if it's not authentication fails.
	 *
	 *	FIXME: add MS-CHAP support ?
	 */
	if (!(auth_item = pairfind(request->packet->vps, PW_CHAP_PASSWORD)))
		auth_item = pairfind(request->packet->vps, PW_PASSWORD);
	if (auth_item == NULL)
		return -1;

	/*
	 *	Find the password from the users file.
	 */
	if ((password_pair = pairfind(check_item, PW_CRYPT_PASSWORD)) != NULL)
		auth_type = PW_AUTHTYPE_CRYPT;
	else
		password_pair = pairfind(check_item, PW_PASSWORD);

	/*
	 *	For backward compatibility, we check the
	 *	password to see if it is the magic value
	 *	UNIX if auth_type was not set.
	 */
	if (auth_type < 0) {
		if (password_pair && !strcmp(password_pair->strvalue, "UNIX"))
			auth_type = PW_AUTHTYPE_SYSTEM;
		else if(password_pair && !strcmp(password_pair->strvalue,"PAM"))
			auth_type = PW_AUTHTYPE_PAM;
		else
			auth_type = PW_AUTHTYPE_LOCAL;
	}

	/*
	 *	Decrypt the password.
	 */
	if (auth_item != NULL && auth_item->attribute == PW_PASSWORD) {
		memcpy(string, auth_item->strvalue, auth_item->length);
		rad_pwdecode(string, auth_item->length,
			request->secret, request->packet->vector);
		strcpy(userpass, string);
	}

#if 0 /* DEBUG */
	printf("auth_type=%d, string=%s, namepair=%s, password_pair=%s\n",
		auth_type, string,
		namepair ? namepair->strvalue : "",
		password_pair ? password_pair->strvalue : "");
#endif

	switch(auth_type) {
		case PW_AUTHTYPE_CRYPT:
			DEBUG2("  auth: Crypt");
			if (password_pair == NULL) {
				result = string[0] ? -1 : 0;
				break;
			}
			if (strcmp(password_pair->strvalue,
			    crypt(string, password_pair->strvalue)) != 0)
					result = -1;
			break;
		case PW_AUTHTYPE_LOCAL:
			DEBUG2("  auth: Local");
			/*
			 *	Local password is just plain text.
	 		 */
			if (auth_item->attribute != PW_CHAP_PASSWORD) {
				/*
				 *	Plain text password.
				 */
				if (password_pair == NULL ||
				    strcmp(password_pair->strvalue, string)!=0)
					result = -1;
				break;
			}

			/*
			 *	CHAP - calculate MD5 sum over CHAP-ID,
			 *	plain-text password and the Chap-Challenge.
			 *	Compare to Chap-Response (strvalue + 1).
			 *
			 *	FIXME: might not work with Ascend because
			 *	we use vp->length, and Ascend gear likes
			 *	to send an extra '\0' in the string!
			 */
			strcpy(string, "{chap-password}");
			if (password_pair == NULL) {
				result= -1;
				break;
			}
			i = 0;
			ptr = string;
			*ptr++ = *auth_item->strvalue;
			i++;
			memcpy(ptr, password_pair->strvalue,
				password_pair->length);
			ptr += password_pair->length;
			i += password_pair->length;
			/*
			 *	Use Chap-Challenge pair if present,
			 *	Request-Authenticator otherwise.
			 */
			if ((tmp = pairfind(request->packet->vps,
			    PW_CHAP_CHALLENGE)) != NULL) {
				memcpy(ptr, tmp->strvalue, tmp->length);
				i += tmp->length;
			} else {
				memcpy(ptr, request->packet->vector,
					AUTH_VECTOR_LEN);
				i += AUTH_VECTOR_LEN;
			}
			librad_md5_calc(chap_digest, string, i);

			/*
			 *	Compare them
			 */
			if (memcmp(chap_digest, auth_item->strvalue + 1,
					CHAP_VALUE_LENGTH) != 0)
				result = -1;
			else
				strcpy(userpass, password_pair->strvalue);
			break;
		default:
			/*
			 *	See if there is a module that handles
			 *	this type, and turn the RLM_ return
			 *	status into the values as defined at
			 *	the top of this function.
			 */
			result = module_authenticate(auth_type, request,
				namepair->strvalue, string);
			switch (result) {
				case RLM_AUTH_FAIL:
					result = 1;
					break;
				case RLM_AUTH_REJECT:
					result = -1;
					break;
				case RLM_AUTH_OK:
					result = 0;
					break;
				case RLM_AUTH_HANDLED:
					result = 1;
					break;
			}
			break;
	}

	if (result < 0)
		*user_msg = NULL;

	return result;
}


/*
 *	Mangle username if needed, and copy the resulting username
 *	to request->username.
 *
 *	FIXME: what is this doing here. Move to better place.
 */
int rad_mangle(REQUEST *request)
{
	VALUE_PAIR	*namepair;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	*tmp;
#ifdef WITH_NTDOMAIN_HACK
	char		newname[MAX_STRING_LEN];
#endif
#if defined(WITH_NTDOMAIN_HACK) || defined(WITH_SPECIALIX_JETSTREAM_HACK)
	char		*ptr;
#endif

	/*
	 *	Get the username from the request
	 */
	request_pairs = request->packet->vps;
	namepair = pairfind(request_pairs, PW_USER_NAME);

	if ((namepair == (VALUE_PAIR *)NULL) || 
	   (strlen(namepair->strvalue) <= 0)) {
		log(L_ERR, "No username: [] (from nas %s)",
			nas_name2(request->packet));
		request_free(request);
		return -1;
	}

#ifdef WITH_NTDOMAIN_HACK
	/*
	 *	Windows NT machines often authenticate themselves as
	 *	NT_DOMAIN\username. Try to be smart about this.
	 *
	 *	FIXME: should we handle this as a REALM ?
	 */
	if ((ptr = strchr(namepair->strvalue, '\\')) != NULL) {
		strncpy(newname, ptr + 1, sizeof(newname));
		newname[sizeof(newname) - 1] = 0;
		strcpy(namepair->strvalue, newname);
		namepair->length = strlen(newname);
	}
#endif /* WITH_NTDOMAIN_HACK */

#ifdef WITH_SPECIALIX_JETSTREAM_HACK
	/*
	 *	Specialix Jetstream 8500 24 port access server.
	 *	If the user name is 10 characters or longer, a "/"
	 *	and the excess characters after the 10th are
	 *	appended to the user name.
	 *
	 *	Reported by Lucas Heise <root@laonet.net>
	 */
	if (strlen(namepair->strvalue) > 10 && namepair->strvalue[10] == '/') {
		for (ptr = namepair->strvalue + 11; *ptr; ptr++)
			*(ptr - 1) = *ptr;
		*(ptr - 1) = 0;
		namepair->length = strlen(namepair->strvalue);
	}
#endif
	/*
	 *	Small check: if Framed-Protocol present but Service-Type
	 *	is missing, add Service-Type = Framed-User.
	 */
	if (pairfind(request_pairs, PW_FRAMED_PROTOCOL) != NULL &&
	    pairfind(request_pairs, PW_SERVICE_TYPE) == NULL) {
		if (!(tmp = paircreate(PW_SERVICE_TYPE, PW_TYPE_INTEGER))) {
			tmp->lvalue = PW_FRAMED_USER;
			pairmove(&request_pairs, &tmp);
		}
	}

	strncpy(request->username, namepair->strvalue,
		sizeof(request->username));
	request->username[sizeof(request->username) - 1] = 0;

#if 0
	/*
	 *	FIXME: find some substitute for this, or
	 *	drop the log_auth_detail option all together.
	 */
	if (log_auth_detail)
		rad_accounting_orig(request, -1, "detail.auth");
#endif

	return 0;
}

/*
 *	Process and reply to an authentication request
 */
int rad_authenticate(REQUEST *request, int activefd)
{
	RADIUS_PACKET	*rp;
	VALUE_PAIR	*namepair;
	VALUE_PAIR	*check_item;
	VALUE_PAIR	*reply_item;
	VALUE_PAIR	*auth_item;
	VALUE_PAIR	*user_check;
	VALUE_PAIR	*user_reply;
	VALUE_PAIR	*tmp;
	int		result, r;
	char		userpass[MAX_STRING_LEN];
	char		umsg[MAX_STRING_LEN];
	char		*user_msg;
	char		*ptr;
	char		*exec_program;
	int		exec_wait;
	int		seen_callback_id;

	user_check = NULL;
	user_reply = NULL;

	/*
	 *	If this request got proxied to another server, we need
	 *	to add an initial Auth-Type: Auth-Accept for success,
	 *	Auth-Reject for fail. We also need to add the reply
	 *	pairs from the server to the initial reply.
	 */
	if (request->proxy) {
		if (request->proxy->code == PW_AUTHENTICATION_REJECT ||
		    request->proxy->code == PW_AUTHENTICATION_ACK) {
			user_check = paircreate(PW_AUTHTYPE, PW_TYPE_INTEGER);
			if (user_check == NULL) {
				log(L_ERR|L_CONS, "no memory");
				exit(1);
			}
		}
		if (request->proxy->code == PW_AUTHENTICATION_REJECT)
			user_check->lvalue = PW_AUTHTYPE_REJECT;
		if (request->proxy->code == PW_AUTHENTICATION_ACK)
			user_check->lvalue = PW_AUTHTYPE_ACCEPT;

		if (request->proxy->vps) {
			user_reply = request->proxy->vps;
			request->proxy->vps = NULL;
		}
	}

	/*
	 *	Get the username from the request.
	 */
	namepair = pairfind(request->packet->vps, PW_USER_NAME);
	if (namepair == NULL || namepair->strvalue[0] == 0) {
		log(L_ERR, "zero length username not permitted\n");
		r = RLM_AUTZ_NOTFOUND;
	} else {
		/*
		 *	Get the user from the database
		 */
		r = module_authorize(request, namepair->strvalue,
			&user_check, &user_reply);
	}
	if (r != RLM_AUTZ_OK) {
		if (r != RLM_AUTZ_FAIL && r != RLM_AUTZ_HANDLED) {
			log(L_AUTH, "Invalid user: [%s] (%s)",
				namepair ? namepair->strvalue : "",
				auth_name(request, 1));
			rp = build_reply(PW_AUTHENTICATION_REJECT,
					request, NULL, NULL);
			rad_send(rp, activefd, request->secret);
			rad_free(rp);
		}
		pairfree(user_reply);
		request->finished = TRUE;
		return r;
	}

	/*
	 *	Perhaps there is a Stripped-Username now.
	 */
	if ((tmp=pairfind(request->packet->vps, PW_STRIPPED_USERNAME)) != NULL)
		namepair = tmp;

	/*
	 *	Validate the user
	 */
	user_msg = NULL;
	userpass[0] = 0;
	do {
		if ((result = check_expiration(user_check, umsg, &user_msg))<0)
				break;
		result = rad_check_password(request, activefd, user_check,
			namepair, &user_msg, userpass);
		if (result > 0) {
			pairfree(user_reply);
			request->finished = TRUE;
			return -1;
		}
		if (result == -2) {
			if ((reply_item = pairfind(user_reply,
			     PW_REPLY_MESSAGE)) != NULL)
				user_msg = reply_item->strvalue;
		}
	} while(0);

	if (result < 0) {
		/*
		 *	Failed to validate the user.
		 */
		rp = build_reply(PW_AUTHENTICATION_REJECT, request,
			NULL, user_msg);
		rad_send(rp, activefd, request->secret);
		rad_free(rp);
		if (log_auth) {
			log(L_AUTH,
				"Login incorrect: [%s/%s] (%s)",
				namepair->strvalue, userpass,
				auth_name(request, 1));
		}
	}

	if (result >= 0 &&
	   (check_item = pairfind(user_check, PW_SIMULTANEOUS_USE)) != NULL) {
		/*
		 *	User authenticated O.K. Now we have to check
		 *	for the Simultaneous-Use parameter.
		 */
		if ((r = radutmp_checksimul(namepair->strvalue,
		    request->packet->vps, check_item->lvalue)) != 0) {

			if (check_item->lvalue > 1) {
				sprintf(umsg,
		"\r\nYou are already logged in %d times  - access denied\r\n\n",
					(int)check_item->lvalue);
				user_msg = umsg;
			} else {
				user_msg =
		"\r\nYou are already logged in - access denied\r\n\n";
			}
			rp = build_reply(PW_AUTHENTICATION_REJECT, request,
				NULL, user_msg);
			rad_send(rp, activefd, request->secret);
			rad_free(rp);
		log(L_ERR, "Multiple logins: [%s] (%s) max. %d%s",
				namepair->strvalue,
				auth_name(request, 1),
				check_item->lvalue,
				r == 2 ? " [MPP attempt]" : "");
			result = -1;
		}
	}

	if (result >= 0 &&
	   (check_item = pairfind(user_check, PW_LOGIN_TIME)) != NULL) {

		/*
		 *	Authentication is OK. Now see if this
		 *	user may login at this time of the day.
		 */
		r = timestr_match(check_item->strvalue, time(NULL));
		if (r < 0) {
			/*
			 *	User called outside allowed time interval.
			 */
			result = -1;
			user_msg =
			"You are calling outside your allowed timespan\r\n";
			rp = build_reply(PW_AUTHENTICATION_REJECT, request,
				NULL, user_msg);
			rad_send(rp, activefd, request->secret);
			rad_free(rp);
			log(L_ERR, "Outside allowed timespan: [%s]"
				   " (%s) time allowed: %s",
					namepair->strvalue,
					auth_name(request, 1),
					check_item->strvalue);
		} else if (r > 0) {
			/*
			 *	User is allowed, but set Session-Timeout.
			 */
			if ((reply_item = pairfind(user_reply,
			    PW_SESSION_TIMEOUT)) != NULL) {
				if (reply_item->lvalue > r)
					reply_item->lvalue = r;
			} else {
				if ((reply_item = paircreate(
				    PW_SESSION_TIMEOUT,
				    PW_TYPE_INTEGER)) == NULL) {
					log(L_ERR|L_CONS, "no memory");
					exit(1);
				}
				reply_item->lvalue = r;
				pairadd(&user_reply, reply_item);
			}
		}
	}

	/*
	 *	Result should be >= 0 here - if not, we return.
	 */
	if (result < 0) {
		pairfree(user_check);
		pairfree(user_reply);
		request->finished = TRUE;
		return 0;
	}

	/*
	 *	See if we need to execute a program.
	 *	FIXME: somehow cache this info, and only execute the
	 *	program when we receive an Accounting-START packet.
	 *	Only at that time we know dynamic IP etc.
	 */
	exec_program = NULL;
	exec_wait = 0;
	if ((auth_item = pairfind(user_reply, PW_EXEC_PROGRAM)) != NULL) {
		exec_wait = 0;
		exec_program = strdup(auth_item->strvalue);
		pairdelete(&user_reply, PW_EXEC_PROGRAM);
	}
	if ((auth_item = pairfind(user_reply, PW_EXEC_PROGRAM_WAIT)) != NULL) {
		exec_wait = 1;
		exec_program = strdup(auth_item->strvalue);
		pairdelete(&user_reply, PW_EXEC_PROGRAM_WAIT);
	}

	/*
	 *	Hack - allow % expansion in certain value strings.
	 *	This is nice for certain Exec-Program programs.
	 */
	seen_callback_id = 0;
	if ((auth_item = pairfind(user_reply, PW_CALLBACK_ID)) != NULL) {
		seen_callback_id = 1;
		ptr = radius_xlate(auth_item->strvalue,
			request->packet->vps, user_reply);
		strcpy(auth_item->strvalue, ptr);
		auth_item->length = strlen(auth_item->strvalue);
	}


	/*
	 *	If we want to exec a program, but wait for it,
	 *	do it first before sending the reply.
	 */
	if (exec_program && exec_wait) {
		if (radius_exec_program(exec_program,
		    request->packet->vps, &user_reply, exec_wait, &user_msg) != 0) {
			/*
			 *	Error. radius_exec_program() returns -1 on
			 *	fork/exec errors, or >0 if the exec'ed program
			 *	had a non-zero exit status.
			 */
			if (user_msg == NULL)
		user_msg = "\r\nAccess denied (external check failed).";
			rp = build_reply(PW_AUTHENTICATION_REJECT, request,
				NULL, user_msg);
			rad_send(rp, activefd, request->secret);
			rad_free(rp);
			if (log_auth) {
				log(L_AUTH,
					"Login incorrect: [%s] (%s) "
					"(external check failed)",
					namepair->strvalue,
					auth_name(request, 1));
			}
			pairfree(user_check);
			pairfree(user_reply);
			request->finished = TRUE;
			return 0;
		}
	}

	/*
	 *	Delete "normal" A/V pairs when using callback.
	 *
	 *	FIXME: This is stupid. The portmaster should accept
	 *	these settings instead of insisting on using a
	 *	dialout location.
	 *
	 *	FIXME2: Move this into the above exec thingy?
	 *	(if you knew how I use the exec_wait, you'd understand).
	 */
	if (seen_callback_id) {
		pairdelete(&user_reply, PW_FRAMED_PROTOCOL);
		pairdelete(&user_reply, PW_FRAMED_IP_ADDRESS);
		pairdelete(&user_reply, PW_FRAMED_IP_NETMASK);
		pairdelete(&user_reply, PW_FRAMED_ROUTE);
		pairdelete(&user_reply, PW_FRAMED_MTU);
		pairdelete(&user_reply, PW_FRAMED_COMPRESSION);
		pairdelete(&user_reply, PW_FILTER_ID);
		pairdelete(&user_reply, PW_PORT_LIMIT);
		pairdelete(&user_reply, PW_CALLBACK_NUMBER);
	}

	/*
	 *	Filter Reply-Message value through radius_xlate
	 *
	 *	FIXME: handle multiple Reply-Messages
	 */
	if (user_msg == NULL) {
		if ((reply_item = pairfind(user_reply,
		    PW_REPLY_MESSAGE)) != NULL) {
			user_msg = radius_xlate(reply_item->strvalue,
				request->packet->vps, user_reply);
			strcpy(reply_item->strvalue, user_msg);
			reply_item->length = strlen(reply_item->strvalue);
			user_msg = NULL;
		}
	}

	rp = build_reply(PW_AUTHENTICATION_ACK, request, user_reply, user_msg);
	rad_send(rp, activefd, request->secret);
	rad_free(rp);

	if (log_auth) {
#if 1 /* Hide the password for `miquels' :) */
		if (strcmp(namepair->strvalue, "miquels") == 0)
			strcpy(userpass, "guess");
#endif
		log(L_AUTH,
			"Login OK: [%s%s%s] (%s)",
			namepair->strvalue,
			log_auth_pass ? "/" : "",
			log_auth_pass ? userpass : "",
			auth_name(request, 0));
	}
	if (exec_program && !exec_wait) {
		/*
		 *	No need to check the exit status here.
		 */
		radius_exec_program(exec_program,
			request->packet->vps, &user_reply, exec_wait, NULL);
	}

	if (exec_program) free(exec_program);
	pairfree(user_check);
	pairfree(user_reply);
	request->finished = TRUE;
	return 0;
}

