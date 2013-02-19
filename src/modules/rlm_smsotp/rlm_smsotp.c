/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
 
/**
 * $Id$
 * @file rlm_smsotp.c
 * @brief Supports OTP authentication using SMS.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2009  Siemens AG, Holger Wolff holger.wolff@siemens.com
 */
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <sys/un.h>

#include "rlm_smsotp.h"

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */

static const CONF_PARSER module_config[] = {
  { "socket", PW_TYPE_STRING_PTR, offsetof(rlm_smsotp_t, smsotp_socket), NULL, SMSOTP_SOCKET },
  { "challenge_message", PW_TYPE_STRING_PTR, offsetof(rlm_smsotp_t, smsotp_challengemessage), NULL, SMSOTP_CHALLENGEMESSAGE },
  { "challenge_type", PW_TYPE_STRING_PTR, offsetof(rlm_smsotp_t, smsotp_authtype), NULL, SMSOTP_AUTHTYPE },

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};


/* socket forward declarations begin */
static int smsotp_connect(const char *path);
static smsotp_fd_t * smsotp_getfd(const rlm_smsotp_t *opt);
static void smsotp_putfd(smsotp_fd_t *fdp, int disconnect);
static int smsotp_read(smsotp_fd_t *fdp, char *buf, size_t len);
static int smsotp_write(smsotp_fd_t *fdp, const char *buf, size_t len);
/* socket forward declarations end */


/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int smsotp_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_smsotp_t *data;

	/*
	 *	Set up a storage area for instance data
	 */
	*instance = data = talloc_zero(conf, rlm_smsotp_t);
	if (!data) return -1;

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		return -1;
	}

	return 0;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t smsotp_authenticate(void *instance, REQUEST *request)
{
	VALUE_PAIR *state;
	VALUE_PAIR *reply;
	rlm_smsotp_t *opt = instance;
	char SocketReply[1000];
	int SocketReplyLen;

	/* quiet the compiler */
	instance = instance;
	request = request;

  smsotp_fd_t *fdp;

  fdp = smsotp_getfd(instance);
  if (!fdp || fdp->fd == -1)
    return RLM_MODULE_FAIL;

	/* Get greeting */
	SocketReplyLen = smsotp_read(fdp, (char *) SocketReply, sizeof(SocketReply));

	/*
	 *  Look for the 'state' attribute.
	 */
	state = pairfind(request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (state != NULL) {
		DEBUG("rlm_smsotp: Found reply to access challenge");
		
		/* set username */
		smsotp_write(fdp, "check otp for ", 14);
		smsotp_write(fdp, (const char *) request->username->vp_strvalue, sizeof(request->username->vp_strvalue));
		smsotp_write(fdp, "\n", 1);
		SocketReplyLen = smsotp_read(fdp, (char *) SocketReply, sizeof(SocketReply));
		
		/* set otp password */
		smsotp_write(fdp, "user otp is ", 12);
		smsotp_write(fdp, (const char *) request->password->vp_strvalue, sizeof(request->password->vp_strvalue));
		smsotp_write(fdp, "\n", 1);
		SocketReplyLen = smsotp_read(fdp, (char *) SocketReply, sizeof(SocketReply));
		
		/* set uuid */
		smsotp_write(fdp, "otp id is ", 10);
		smsotp_write(fdp, (const char *) state->vp_strvalue, 36); /* smsotp_write(fdp, (const char *) state->vp_strvalue, sizeof(state->vp_strvalue)); */
		smsotp_write(fdp, "\n", 1);
		SocketReplyLen = smsotp_read(fdp, (char *) SocketReply, sizeof(SocketReply));
		
		/* now check the otp */
		smsotp_write(fdp, "get check result\n", 17);
		SocketReplyLen = smsotp_read(fdp, (char *) SocketReply, sizeof(SocketReply));
		
		/* end the sesssion */
		smsotp_write(fdp, "quit\n", 5);
		smsotp_putfd(fdp, 1);
		
		(void) radlog(L_AUTH, "rlm_smsotp: SocketReply is %s ",SocketReply);
		
		if (strcmp(SocketReply,"OK") == 0)
			return RLM_MODULE_OK;
		return RLM_MODULE_FAIL;
	}

	DEBUG("rlm_smsotp: Generate OTP");
  
	/* set username */
  smsotp_write(fdp, "generate otp for ", 17);
  smsotp_write(fdp, (const char *) request->username->vp_strvalue, sizeof(request->username->vp_strvalue));
  smsotp_write(fdp, "\n", 1);
	SocketReplyLen = smsotp_read(fdp, (char *) SocketReply, sizeof(SocketReply));

	/* end the sesssion */
  smsotp_write(fdp, "quit\n", 5);
	smsotp_putfd(fdp, 1);

	(void) radlog(L_AUTH, "rlm_smsotp: Uniq id is %s ",SocketReply);

	/* check the return string */
	if (strcmp(SocketReply,"FAILED") == 0) { /* smsotp script returns a error */
		return RLM_MODULE_FAIL;
	} else {
		/*
		 *  Create the challenge, and add it to the reply.
		 */
		
		reply = pairmake("Reply-Message", opt->smsotp_challengemessage, T_OP_EQ);
		pairadd(&request->reply->vps, reply);
		state = pairmake("State", SocketReply, T_OP_EQ);
		pairadd(&request->reply->vps, state);
	
		/*
		 *  Mark the packet as an Access-Challenge packet.
		 *
		 *  The server will take care of sending it to the user.
		 */
		request->reply->code = PW_ACCESS_CHALLENGE;
		DEBUG("rlm_smsotp: Sending Access-Challenge.");
	
		return RLM_MODULE_HANDLED;
	}
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t smsotp_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR *state;
	rlm_smsotp_t *opt = instance;

	/* quiet the compiler */
	instance = instance;
	request = request;

	/*
	 *  Look for the 'state' attribute.
	 */
	state = pairfind(request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (state != NULL) {
		DEBUG("rlm_smsotp: Found reply to access challenge (AUTZ), Adding Auth-Type '%s'",opt->smsotp_authtype);
		
		pairdelete(&request->config_items, PW_AUTH_TYPE, 0, TAG_ANY); /* delete old auth-type */
		pairadd(&request->config_items, pairmake("Auth-Type", opt->smsotp_authtype, T_OP_SET));
	}

	return RLM_MODULE_OK;
}

/* forward declarations */
static smsotp_fd_t *smsotp_fd_head = NULL;
static pthread_mutex_t smsotp_fd_head_mutex = PTHREAD_MUTEX_INITIALIZER;
/* forward declarations end */

/* socket functions begin */
/* connect to socket and return fd */
static int smsotp_connect(const char *path)
{
  int fd;
  struct sockaddr_un sa;
  size_t sp_len;		/* sun_path length (strlen) */

  /* setup for unix domain socket */
  sp_len = strlen(path);
  if (sp_len > sizeof(sa.sun_path) - 1) {
    (void) radlog(L_ERR, "rlm_smsotp: %s: socket name too long", __func__);
    return -1;
  }
  sa.sun_family = AF_UNIX;
  (void) strcpy(sa.sun_path, path);

  /* connect to socket */
  if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
    (void) radlog(L_ERR, "rlm_smsotp: %s: socket: %s", __func__, strerror(errno));
    return -1;
  }
  if (connect(fd, (struct sockaddr *) &sa, sizeof(sa.sun_family) + sp_len) == -1) {
    (void) radlog(L_ERR, "rlm_smsotp: %s: connect(%s): %s", __func__, path, strerror(errno));
    (void) close(fd);
    return -1;
  }
  return fd;
}

/*
 * Retrieve an fd (from pool) to use for socket connection.
 * It'd be simpler to use TLS but FR can have lots of threads
 * and we don't want to waste fd's that way.
 * We can't have a global fd because we'd then be pipelining
 * requests to otpd and we have no way to demultiplex
 * the responses.
 */
static smsotp_fd_t * smsotp_getfd(const rlm_smsotp_t *opt)
{
  int rc;
  smsotp_fd_t *fdp;

  /* walk the connection pool looking for an available fd */
  for (fdp = smsotp_fd_head; fdp; fdp = fdp->next) {
    rc = smsotp_pthread_mutex_trylock(&fdp->mutex);
    if (!rc)
      if (!strcmp(fdp->path, opt->smsotp_socket))	/* could just use == */
        break;
  }

  if (!fdp) {
    /* no fd was available, add a new one */
    fdp = rad_malloc(sizeof(*fdp));
    smsotp_pthread_mutex_init(&fdp->mutex, NULL);
    smsotp_pthread_mutex_lock(&fdp->mutex);
    /* insert new fd at head */
    smsotp_pthread_mutex_lock(&smsotp_fd_head_mutex);
    fdp->next = smsotp_fd_head;
    smsotp_fd_head = fdp;
    smsotp_pthread_mutex_unlock(&smsotp_fd_head_mutex);
    /* initialize */
    fdp->path = opt->smsotp_socket;
    fdp->fd = -1;
  }

  /* establish connection */
  if (fdp->fd == -1)
    fdp->fd = smsotp_connect(fdp->path);

  return fdp;
}

/* release fd, and optionally disconnect from otpd */
static void smsotp_putfd(smsotp_fd_t *fdp, int disconnect)
{
  if (disconnect) {
    (void) close(fdp->fd);
    fdp->fd = -1;
  }

  /* make connection available to another thread */
  smsotp_pthread_mutex_unlock(&fdp->mutex);
}

/*
 * Full read with logging, and close on failure.
 * Returns nread on success, 0 on EOF, -1 on other failures.
 */
static int smsotp_read(smsotp_fd_t *fdp, char *buf, size_t len)
{
  ssize_t n;
  size_t nread = 0;	/* bytes read into buf */
  
  fd_set rfds;
  struct timeval tv;
  int retval;
  FD_ZERO(&rfds);
  FD_SET(fdp->fd, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 0;

  while (nread < len) {
    if ((n = read(fdp->fd, &buf[nread], len - nread)) == -1) {
      if (errno == EINTR) {
        continue;
      } else {
        (void) radlog(L_ERR, "rlm_smsotp: %s: read from socket: %s", __func__, strerror(errno));
        smsotp_putfd(fdp, 1);
        return -1;
      }
    }
    if (!n) {
      (void) radlog(L_ERR, "rlm_smsotp: %s: socket disconnect", __func__);
      smsotp_putfd(fdp, 1);
      return 0;
    }
    nread += n;
//    DEBUG("smsotp_read ... read more ?");
    
    // check if more data is avalible
		retval = select(1, &rfds, NULL, NULL, &tv);
		if (!retval) {
			buf[nread]= '\0';
			break;
		}
//    DEBUG("smsotp_read ... read more ! YES !");

  } /*while (more to read) */

  return nread;
}

/*
 * Full write with logging, and close on failure.
 * Returns 0 on success, errno on failure.
 */
static int smsotp_write(smsotp_fd_t *fdp, const char *buf, size_t len)
{
  size_t nleft = len;
  ssize_t nwrote;

  while (nleft) {
    if ((nwrote = write(fdp->fd, &buf[len - nleft], nleft)) == -1) {
      if (errno == EINTR || errno == EPIPE) {
        continue;
      } else {
        (void) radlog(L_ERR, "rlm_smsotp: %s: write to socket: %s", __func__, strerror(errno));
        smsotp_putfd(fdp, 1);
        return errno;
      }
    }
    nleft -= nwrote;
  }

  return 0;
}
/* socket functions end */


/* mutex functions begin*/
/* guaranteed initialization */
static void _smsotp_pthread_mutex_init(pthread_mutex_t *mutexp, const pthread_mutexattr_t *attr, const char *caller)
{
  int rc;

  if ((rc = pthread_mutex_init(mutexp, attr))) {
    (void) radlog(L_ERR, "rlm_smsotp: %s: pthread_mutex_init: %s", caller, strerror(rc));
    exit(1);
  }
}

/* guaranteed lock */
static void _smsotp_pthread_mutex_lock(pthread_mutex_t *mutexp, const char *caller)
{
  int rc;

  if ((rc = pthread_mutex_lock(mutexp))) {
    (void) radlog(L_ERR, "rlm_smsotp: %s: pthread_mutex_lock: %s", caller, strerror(rc));
    exit(1);
  }
}

/* guaranteed trylock */
static int _smsotp_pthread_mutex_trylock(pthread_mutex_t *mutexp, const char *caller)
{
  int rc;

  rc = pthread_mutex_trylock(mutexp);
  if (rc && rc != EBUSY) {
    (void) radlog(L_ERR, "rlm_smsotp: %s: pthread_mutex_trylock: %s", caller, strerror(rc));
    exit(1);
  }

  return rc;
}

/* guaranteed unlock */
static void _smsotp_pthread_mutex_unlock(pthread_mutex_t *mutexp, const char *caller)
{
  int rc;

  if ((rc = pthread_mutex_unlock(mutexp))) {
    (void) radlog(L_ERR, "rlm_smsotp: %s: pthread_mutex_unlock: %s", caller, strerror(rc));
    exit(1);
  }
}
/* mutex functions end */


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_smsotp = {
	RLM_MODULE_INIT,
	"smsotp",
	RLM_TYPE_THREAD_SAFE,		/* type */
	smsotp_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		smsotp_authenticate,	/* authentication */
		smsotp_authorize,	/* authorization */
		NULL,	/* preaccounting */
		NULL,	/* accounting */
		NULL,	/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
