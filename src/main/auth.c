/*
 * auth.c	User authentication.
 *
 *
 * Version:	$Id$
 *
 */
static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/time.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<time.h>
#include	<unistd.h>
#include	<errno.h>
#include	<ctype.h>

#if HAVE_MALLOC_H
#  include <malloc.h>
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
		(do_cli ? " cli " : ""), (do_cli ? (char *)cli->strvalue : ""));

	return buf;
}


/*
 *	Check if account has expired, and if user may login now.
 */
static int check_expiration(VALUE_PAIR *check_item, char *umsg, const char **user_msg)
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
			if (check_item->lvalue < (unsigned) time(NULL)) {
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
static int rad_check_password(REQUEST *request,
	VALUE_PAIR *check_item,
	VALUE_PAIR *namepair,
	const char **user_msg)
{
	VALUE_PAIR	*auth_type_pair;
	VALUE_PAIR	*password_pair;
	VALUE_PAIR	*auth_item;
	char		string[MAX_STRING_LEN];
	int		auth_type = -1;
	int		result;
	result = 0;

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
	 *	Find the password sent by the user. It SHOULD be there,
	 *	if it's not authentication fails.
	 *
	 *	FIXME: add MS-CHAP support ?
	 */
	auth_item = request->password;
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
				result = auth_item->strvalue ? -1 : 0;
				break;
			}
			if (strcmp(password_pair->strvalue,
			    crypt(auth_item->strvalue,
				  password_pair->strvalue)) != 0)
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
				    strcmp(password_pair->strvalue,
					   auth_item->strvalue)!=0)
					result = -1;
				break;
			}

			/*
			 *	CHAP - calculate MD5 sum over CHAP-ID,
			 *	plain-text password and the Chap-Challenge.
			 *	Compare to Chap-Response (strvalue + 1).
			 */
			if (password_pair == NULL) {
				result= -1;
				break;
			}
			rad_chap_encode(request->packet, string,
					*auth_item->strvalue, password_pair);

			/*
			 *	Compare them
			 */
			if (memcmp(string + 1, auth_item->strvalue + 1,
					CHAP_VALUE_LENGTH) != 0)
				result = -1;
			break;
		default:
			/*
			 *	See if there is a module that handles
			 *	this type, and turn the RLM_ return
			 *	status into the values as defined at
			 *	the top of this function.
			 */
			result = module_authenticate(auth_type, request);
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
 *	Process and reply to an authentication request
 */
int rad_authenticate(REQUEST *request)
{
	VALUE_PAIR	*namepair;
	VALUE_PAIR	*check_item;
	VALUE_PAIR	*reply_item;
	VALUE_PAIR	*auth_item;
	VALUE_PAIR	*user_reply;
	VALUE_PAIR	*tmp;
	int		result, r;
	char		umsg[MAX_STRING_LEN + 1];
	const char	*user_msg;
	char		*ptr;
	const char	*password;
	char		*exec_program;
	int		exec_wait;
	int		seen_callback_id;

	user_reply = NULL;
	password = "";
	if (request->config_items) {
	  pairfree(request->config_items);
	  request->config_items = NULL;
	}

	/*
	 *	If this request got proxied to another server, we need
	 *	to add an initial Auth-Type: Auth-Accept for success,
	 *	Auth-Reject for fail. We also need to add the reply
	 *	pairs from the server to the initial reply.
	 */
	if (request->proxy) {
		if (request->proxy->code == PW_AUTHENTICATION_REJECT ||
		    request->proxy->code == PW_AUTHENTICATION_ACK) {
			request->config_items = paircreate(PW_AUTHTYPE, PW_TYPE_INTEGER);
			if (request->config_items == NULL) {
				log(L_ERR|L_CONS, "no memory");
				exit(1);
			}
		}
		if (request->proxy->code == PW_AUTHENTICATION_REJECT)
			request->config_items->lvalue = PW_AUTHTYPE_REJECT;
		if (request->proxy->code == PW_AUTHENTICATION_ACK)
			request->config_items->lvalue = PW_AUTHTYPE_ACCEPT;

		if (request->proxy->vps) {
			user_reply = request->proxy->vps;
			request->proxy->vps = NULL;
		}
	}

	/*
	 *	Get the username from the request.
	 */
	namepair = request->username;
	if ((namepair == NULL) || (namepair->length <= 0)) {
		log(L_ERR, "zero length username not permitted\n");
		request->reply = build_reply(PW_AUTHENTICATION_REJECT,
					     request, NULL, NULL);
		return RLM_AUTZ_NOTFOUND;
	}

	/*
	 *	Decrypt the password, and remove trailing NULL's.
	 */
	auth_item = pairfind(request->packet->vps, PW_PASSWORD);
	if (auth_item != NULL && auth_item->attribute == PW_PASSWORD) {
		int i;

		rad_pwdecode(auth_item->strvalue, auth_item->length,
			     request->secret, request->packet->vector);
		for (i = auth_item->length; i >=0; i--) {
		  if (auth_item->strvalue[i]) {
		    break;
		  } else {
		    auth_item->length = i;
		  }
		}
		password = auth_item->strvalue;
	}

	/*
	 *	Maybe there's a CHAP-Password?
	 */
	if (auth_item == NULL) {
		auth_item = pairfind(request->packet->vps, PW_CHAP_PASSWORD);
	}

	/*
	 *	Update the password with OUR preference for the
	 *	password.
	 */
	request->password = auth_item;

	/*
	 *	Get the user's authorization information from the database
	 */
	r = module_authorize(request, &request->config_items, &user_reply);
	if (r != RLM_AUTZ_OK) {
		if (r != RLM_AUTZ_FAIL && r != RLM_AUTZ_HANDLED) {
			log(L_AUTH, "Invalid user: [%s%s%s] (%s)",
				namepair->strvalue,
				log_auth_pass ? "/" : "",
				log_auth_pass ? password : "",
				auth_name(request, 1));
			request->reply = build_reply(PW_AUTHENTICATION_REJECT,
						     request, NULL, NULL);
		}
		pairfree(user_reply);
		return r;
	}

	/*
	 *	Perhaps there is a Stripped-User-Name now.
	 */
	tmp=pairfind(request->packet->vps, PW_STRIPPED_USER_NAME);
	if (tmp != NULL)
		namepair = tmp;

	/*
	 *	Validate the user
	 */
	user_msg = NULL;
	do {
		if ((result = check_expiration(request->config_items, umsg, &user_msg))<0)
				break;
		result = rad_check_password(request, request->config_items,
			namepair, &user_msg);
		if (result > 0) {
			/* don't reply! */
			pairfree(user_reply);
			return -1;
		}
		if (result == -2) {
			reply_item = pairfind(user_reply, PW_REPLY_MESSAGE);
			if (reply_item != NULL)
				user_msg = reply_item->strvalue;
		}
	} while(0);

	if (result < 0) {
		/*
		 *	Failed to validate the user.
		 */
		request->reply = build_reply(PW_AUTHENTICATION_REJECT, request,
					     NULL, user_msg);
		if (log_auth) {
			u_char clean_buffer[1024];
			u_char *p;

			if (auth_item->attribute == PW_CHAP_PASSWORD) {
			  strcpy(clean_buffer, "CHAP-Password");
			} else {
			  librad_safeprint(auth_item->strvalue,
					   auth_item->length,
					   clean_buffer, sizeof(clean_buffer));
			}
			log(L_AUTH,
				"Login incorrect: [%s/%s] (%s)%s",
				namepair->strvalue, clean_buffer,
				auth_name(request, 1),
				((result == -2) ? " reject" : ""));
			/* double check: maybe the secret is wrong? */
			if (debug_flag > 1) {
			  p = auth_item->strvalue;
			  while (*p) {
			    if (!isprint(*p)) {
			      log_debug("  WARNING: Unprintable characters in the password.\n           Double-check the shared secret on the server and the NAS!");
			      break;
			    }
			    p++;
			  }
			}
		}
	}

	if (result >= 0 &&
	   (check_item = pairfind(request->config_items, PW_SIMULTANEOUS_USE)) != NULL) {
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
			request->reply = build_reply(PW_AUTHENTICATION_REJECT,
						     request, NULL, user_msg);
		log(L_ERR, "Multiple logins: [%s] (%s) max. %d%s",
				namepair->strvalue,
				auth_name(request, 1),
				check_item->lvalue,
				r == 2 ? " [MPP attempt]" : "");
			result = -1;
		}
	}

	if (result >= 0 &&
	   (check_item = pairfind(request->config_items, PW_LOGIN_TIME)) != NULL) {

		/*
		 *	Authentication is OK. Now see if this
		 *	user may login at this time of the day.
		 */
		r = timestr_match(check_item->strvalue, request->timestamp);
		/*
		 *	Session-Timeout needs to be at least
		 *	60 seconds, some terminal servers
		 *	ignore smaller values.
		 */
		if (r < 60) {
			/*
			 *	User called outside allowed time interval.
			 */
			result = -1;
			user_msg =
			"You are calling outside your allowed timespan\r\n";
			request->reply = build_reply(PW_AUTHENTICATION_REJECT,
						     request, NULL, user_msg);
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
				if (reply_item->lvalue > (unsigned) r)
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
		pairfree(user_reply);
		return 0;
	}

	/*
	 *	We might need this later.  The 'password' string
	 *	is NOT used anywhere below here, except for logging,
	 *	so it should be safe...
	 */
	if (auth_item->attribute == PW_CHAP_PASSWORD) {
		password = "CHAP-Password";
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
		strNcpy(auth_item->strvalue, ptr, sizeof(auth_item->strvalue));
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
			request->reply = build_reply(PW_AUTHENTICATION_REJECT,
						     request, NULL, user_msg);
			if (log_auth) {
				log(L_AUTH,
					"Login incorrect: [%s] (%s) "
					"(external check failed)",
					namepair->strvalue,
					auth_name(request, 1));
			}
			pairfree(user_reply);
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
	 *	Filter (possibly multiple) Reply-Message attributes
	 *	through radius_xlate
	 */
	if (user_msg == NULL) {
	  reply_item = pairfind(user_reply, PW_REPLY_MESSAGE);
	  while (reply_item) {
			user_msg = radius_xlate(reply_item->strvalue,
				request->packet->vps, user_reply);
			strNcpy(reply_item->strvalue, user_msg,
				sizeof(reply_item->strvalue));
			reply_item->length = strlen(reply_item->strvalue);
			user_msg = NULL;
			reply_item = pairfind(reply_item->next,
					      PW_REPLY_MESSAGE);
	  }
	}

	request->reply = build_reply(PW_AUTHENTICATION_ACK, request,
				     user_reply, user_msg);

	if (log_auth) {
		log(L_AUTH,
			"Login OK: [%s%s%s] (%s)",
			namepair->strvalue,
			log_auth_pass ? "/" : "",
			log_auth_pass ? password : "",
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
	pairfree(user_reply);
	return 0;
}

