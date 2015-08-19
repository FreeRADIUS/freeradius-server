/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <sys/un.h>

typedef struct rlm_smsotp_t {
	char const	*socket;
	char const	*challenge;
	char const	*authtype;
	fr_connection_pool_t *pool;
} rlm_smsotp_t;

static const CONF_PARSER module_config[] = {
	{ "socket", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_smsotp_t, socket), "/var/run/smsotp_socket" },
	{ "challenge_message", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_smsotp_t, challenge), "Enter Mobile PIN" },
	{ "challenge_type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_smsotp_t, authtype), "smsotp-reply" },
	CONF_PARSER_TERMINATOR
};

static int _mod_conn_free(int *fdp)
{
	close(*fdp);
	return 0;
}

static void *mod_conn_create(TALLOC_CTX *ctx, void *instance)
{
	int fd;
	struct sockaddr_un sa;
	rlm_smsotp_t *inst = instance;
	socklen_t socklen = sizeof(sa);
	int *fdp;

	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, inst->socket, sizeof(sa.sun_path));

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		ERROR("Failed opening SMSOTP file %s: %s",
		       inst->socket, fr_syserror(errno));
		return NULL;
	}

	if (connect(fd, (struct sockaddr *) &sa, socklen) < -1) {
		ERROR("Failed connecting to SMSOTP file %s: %s",
		       inst->socket, fr_syserror(errno));
		return NULL;
	}

	fdp = talloc_zero(ctx, int);
	talloc_set_destructor(fdp, _mod_conn_free);
	*fdp = fd;

	return fdp;
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
static int write_all(int *fdp, char const *buf, size_t len)
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
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_smsotp_t *inst = instance;
	struct sockaddr_un sa;
	if (strlen(inst->socket) > (sizeof(sa.sun_path) - 1)) {
		cf_log_err_cs(conf, "Socket filename is too long");
		return -1;
	}

	/*
	 *	Initialize the socket pool.
	 */
	inst->pool = fr_connection_pool_module_init(conf, inst, mod_conn_create, NULL, NULL);
	if (!inst->pool) {
		return -1;
	}

	return 0;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_smsotp_t *inst = instance;
	VALUE_PAIR *state;
	int bufsize;
	int *fdp;
	rlm_rcode_t rcode = RLM_MODULE_FAIL;
	char buffer[1000];
	char output[1000];

	fdp = fr_connection_get(inst->pool);
	if (!fdp) return RLM_MODULE_FAIL;

	/* Get greeting */
	bufsize = read_all(fdp, buffer, sizeof(buffer));
	if (bufsize <= 0) {
		REDEBUG("Failed reading from socket");
		goto done;
	}

	/*
	 *  Look for the 'state' attribute.
	 */
#define WRITE_ALL(_a,_b,_c) if (write_all(_a,_b,_c) < 0) goto done;
	state = fr_pair_find_by_num(request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (state) {
		RDEBUG("Found reply to access challenge");

		/* send username */
		snprintf(output, sizeof(output), "check otp for %s\n",
			 request->username->vp_strvalue);
		WRITE_ALL(fdp, output, strlen(output));

		(void) read_all(fdp, buffer, sizeof(buffer));

		/* send password */
		snprintf(output, sizeof(output), "user otp is %s\n",
			 request->password->vp_strvalue);
		WRITE_ALL(fdp, output, strlen(output));

		(void) read_all(fdp, buffer, sizeof(buffer));

		/* set uuid */
		snprintf(output, sizeof(output), "otp id is %s\n",
			 state->vp_strvalue);
		WRITE_ALL(fdp, output, strlen(output));

		(void) read_all(fdp, buffer, sizeof(buffer));

		/* now check the otp */
		WRITE_ALL(fdp, "get check result\n", 17);

		(void) read_all(fdp, buffer, sizeof(buffer));

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

	(void) read_all(fdp, buffer, sizeof(buffer));

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

	pair_make_reply("Reply-Message", inst->challenge, T_OP_EQ);
	pair_make_reply("State", buffer, T_OP_EQ);

	/*
	 *  Mark the packet as an Access-Challenge packet.
	 *
	 *  The server will take care of sending it to the user.
	 */
	request->reply->code = PW_CODE_ACCESS_CHALLENGE;
	DEBUG("rlm_smsotp: Sending Access-Challenge");

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
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR *state;
	rlm_smsotp_t *inst = instance;

	/*
	 *  Look for the 'state' attribute.
	 */
	state = fr_pair_find_by_num(request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (state != NULL) {
		DEBUG("rlm_smsotp: Found reply to access challenge (AUTZ), Adding Auth-Type '%s'",inst->authtype);

		fr_pair_delete_by_num(&request->config, PW_AUTH_TYPE, 0, TAG_ANY); /* delete old auth-type */
		pair_make_config("Auth-Type", inst->authtype, T_OP_SET);
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
extern module_t rlm_smsotp;
module_t rlm_smsotp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "smsotp",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_smsotp_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize
	},
};
