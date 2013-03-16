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

typedef struct rlm_smsotp_t {
	char		*socket;
	char		*challenge;
	char		*authtype;
	fr_connection_pool_t *pool;
} rlm_smsotp_t;

static const CONF_PARSER module_config[] = {
	{ "socket", PW_TYPE_STRING_PTR,
	  offsetof(rlm_smsotp_t, socket),
	  NULL, "/var/run/smsotp_socket" },
	{ "challenge_message", PW_TYPE_STRING_PTR,
	  offsetof(rlm_smsotp_t, challenge), NULL, "Enter Mobile PIN" },
	{ "challenge_type", PW_TYPE_STRING_PTR,
	  offsetof(rlm_smsotp_t, authtype),
	  NULL, "smsotp-reply" },
	
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


static void *conn_create(void *ctx)
{
	int fd;
	struct sockaddr_un sa;
	rlm_smsotp_t *inst = ctx;
	socklen_t socklen = sizeof(sa);
	int *fdp;

	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, inst->socket, sizeof(sa.sun_path));

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		radlog(L_ERR, "Failed opening SMSOTP file %s: %s",
		       inst->socket, strerror(errno));
		return NULL;
	}

	if (connect(fd, (struct sockaddr *) &sa, socklen) < -1) {
		radlog(L_ERR, "Failed connecting to SMSOTP file %s: %s",
		       inst->socket, strerror(errno));
		return NULL;
	}

	fdp = rad_malloc(sizeof(*fdp));
	*fdp = fd;

	return fdp;
}

static int conn_delete(UNUSED void *ctx, void *connection)
{
	int *fdp = connection;

	close(*fdp);
	free(fdp);
	return 0;
}


/*
 * Full read with logging, and close on failure.
 * Returns nread on success, 0 on EOF, -1 on other failures.
 */
static size_t read_all(int *fdp, char *buf, size_t len)
{
	ssize_t n;
	size_t total = 0;
	
	fd_set fds;
	struct timeval tv;
	int retval;

	FD_ZERO(&fds);
	FD_SET(*fdp, &fds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	
	while (total < len) {
		n = read(*fdp, &buf[total], len - total);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}

		/*
		 *	Socket was closed.  Don't try to re-open it.
		 */
		if (n == 0) return 0;
		total += n;

		/*
		 *	Check if there's more data.  If not, return
		 *	now.
		 */
		retval = select(1, &fds, NULL, NULL, &tv);
		if (!retval) {
			buf[total]= '\0';
			break;
		}
	}
	
	return total;
}


/*
 *	Write all of the data, taking care of EINTR, etc.
 */
static int write_all(int *fdp, const char *buf, size_t len)
{
	size_t left = len;
	ssize_t n;

	while (left) {
		n = write(*fdp, &buf[len - left], left);
		if (n < 0) {
			if ((errno == EINTR) || (errno == EPIPE)) {
				continue;
			}
			return -1;
		}
		left -= n;
	}

	return 0;
}


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
	rlm_smsotp_t *inst;
	struct sockaddr_un sa;

	/*
	 *	Set up a storage area for instance data
	 */
	*instance = inst = talloc_zero(conf, rlm_smsotp_t);
	if (!inst) return -1;

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		return -1;
	}

	if (strlen(inst->socket) > (sizeof(sa.sun_path) - 1)){
		cf_log_err(cf_sectiontoitem(conf), "Socket filename is too long");
		return -1;
	}


	/*
	 *	Initialize the socket pool.
	 */
	inst->pool = fr_connection_pool_init(conf, inst,
					     conn_create,
					     NULL,
					     conn_delete);
	if (!inst->pool) {
		return -1;
	}

	return 0;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t smsotp_authenticate(void *instance, REQUEST *request)
{
	rlm_smsotp_t *inst = instance;
	VALUE_PAIR *state;
	VALUE_PAIR *reply;
	int bufsize;
	int *fdp;
	rlm_rcode_t rcode = RLM_MODULE_FAIL;
	char buffer[1000];
	char output[1000];

	fdp = fr_connection_get(inst->pool);
	if (!fdp) {
		RDEBUGE("Failed to get handle from connection pool");
		return RLM_MODULE_FAIL;
	}
	
	/* Get greeting */
	bufsize = read_all(fdp, buffer, sizeof(buffer));
	if (bufsize <= 0) {
		RDEBUGE("Failed reading from socket");
		goto done;
	}

	/*
	 *  Look for the 'state' attribute.
	 */
#define WRITE_ALL(_a,_b,_c) if (write_all(_a,_b,_c) < 0) goto done;
	state = pairfind(request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (!state) {
		RDEBUG("Found reply to access challenge");
		
		/* send username */
		snprintf(output, sizeof(output), "check otp for %s\n",
			 request->username->vp_strvalue);
		WRITE_ALL(fdp, output, strlen(output));

		bufsize = read_all(fdp, buffer, sizeof(buffer));
		
		/* send password */
		snprintf(output, sizeof(output), "user otp is %s\n",
			 request->password->vp_strvalue);
		WRITE_ALL(fdp, output, strlen(output));

		bufsize = read_all(fdp, buffer, sizeof(buffer));
		
		/* set uuid */
		snprintf(output, sizeof(output), "otp id is %s\n",
			 state->vp_strvalue);
		WRITE_ALL(fdp, output, strlen(output));

		bufsize = read_all(fdp, buffer, sizeof(buffer));
		
		/* now check the otp */
		WRITE_ALL(fdp, "get check result\n", 17);

		bufsize = read_all(fdp, buffer, sizeof(buffer));
		
		/* end the sesssion */
		WRITE_ALL(fdp, "quit\n", 5);

		RDEBUG("answer is %s", buffer);
		if (strcmp(buffer,"OK") == 0) {
			rcode = RLM_MODULE_OK;
		}

		goto done;
	}

	RDEBUG("Generating OTP");

	/* set username */
	snprintf(output, sizeof(output), "generate otp for %s\n",
		 request->username->vp_strvalue);
	WRITE_ALL(fdp, output, strlen(output));

	bufsize = read_all(fdp, buffer, sizeof(buffer));

	/* end the sesssion */
	WRITE_ALL(fdp, "quit\n", 5);

	RDEBUG("Unique ID is %s", buffer);

	/* check the return string */
	if (strcmp(buffer,"FAILED") == 0) { /* smsotp script returns a error */
		goto done;
	}

	/*
	 *	Create the challenge, and add it to the reply.
	 */
		
	reply = pairmake("Reply-Message", inst->challenge, T_OP_EQ);
	pairadd(&request->reply->vps, reply);

	state = pairmake("State", buffer, T_OP_EQ);
	pairadd(&request->reply->vps, state);
	
	/*
	 *  Mark the packet as an Access-Challenge packet.
	 *
	 *  The server will take care of sending it to the user.
	 */
	request->reply->code = PW_ACCESS_CHALLENGE;
	DEBUG("rlm_smsotp: Sending Access-Challenge.");
	
	rcode = RLM_MODULE_HANDLED;

done:
	fr_connection_release(inst->pool, fdp);
	return rcode;
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
	rlm_smsotp_t *inst = instance;

	/* quiet the compiler */
	instance = instance;
	request = request;

	/*
	 *  Look for the 'state' attribute.
	 */
	state = pairfind(request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (state != NULL) {
		DEBUG("rlm_smsotp: Found reply to access challenge (AUTZ), Adding Auth-Type '%s'",inst->authtype);
		
		pairdelete(&request->config_items, PW_AUTH_TYPE, 0, TAG_ANY); /* delete old auth-type */
		pairadd(&request->config_items, pairmake("Auth-Type", inst->authtype, T_OP_SET));
	}

	return RLM_MODULE_OK;
}


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
