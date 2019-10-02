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
 * @file rlm_magic.c
 * @brief Middleware to pass along an authentication attempt to a Magic Gateway for verification
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2019 Magic Foundation (hello@magic.co)
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct
{
	unsigned short port;
	char const *socket_address;
	bool is_local;
} rlm_magic_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{"port", FR_CONF_OFFSET(PW_TYPE_SHORT, rlm_magic_t, port), "12345"},
	{"is_local", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_magic_t, is_local), false},
	{"socket-address", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_magic_t, socket_address), "127.0.0.1"},
	CONF_PARSER_TERMINATOR};

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 */
static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	rlm_magic_t *inst = instance;
	DEBUG2("Creating Magic module");

	if (inst->is_local)
	{
		#ifndef HAVE_SYS_UN_H
			ERROR("Trying to use local unix sockets on a system that does not support it");
			return -1;
		#endif
		DEBUG2("Using local Unix socket %s for authentication", inst->socket_address);
	}
	else
	{
		DEBUG2("Using remote server %s:%i for authentication", inst->socket_address, inst->port);
	}

	return 0;
}

/*
 *	Don't currently do anything here
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_NOOP;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	// The instance variables
	rlm_magic_t *inst = instance;

	//Socket related vars
	char buffer[BUFSIZ];
	int sockfd;

	DEBUG2("Attempting Magic Authentication");

	if (inst->is_local)
	{
		sockfd = fr_socket_client_unix(inst->socket_address, false);
		if (sockfd == -1)
		{
			fr_perror("socket");
			return RLM_MODULE_FAIL;
		}
	}
	else
	{
		fr_ipaddr_t address_info;
		address_info.af = AF_INET;
		struct hostent *hostent;
		
		hostent = gethostbyname(inst->socket_address);
		if (hostent == NULL)
		{
			fprintf(stderr, "error: gethostbyname(\"%s\")\n", inst->socket_address);
			return RLM_MODULE_FAIL;
		}
		in_addr_t in_addr = inet_addr(inet_ntoa(*(struct in_addr *)*(hostent->h_addr_list)));
		if (in_addr == (in_addr_t)-1)
		{
			fprintf(stderr, "error: inet_addr(\"%s\")\n", *(hostent->h_addr_list));
			return RLM_MODULE_FAIL;
		}
		address_info.ipaddr.ip4addr.s_addr = in_addr;

		sockfd = fr_socket_client_tcp(NULL, &address_info, inst->port, false);
	}
	// Create our message which needs to be in this format
	// '{"address": "username", "password": "password", "sessionId": ""}\n'
	char *socket_message = talloc_array(request, char, BUFSIZ);
	strlcpy(socket_message, "{\"address\": \"", BUFSIZ);
	strlcat(socket_message, request->username->vp_strvalue, BUFSIZ);
	strlcat(socket_message, "\", \"password\": \"", BUFSIZ);
	strlcat(socket_message, request->password->vp_strvalue, BUFSIZ);
	strlcat(socket_message, "\", \"sessionId\": \"\"}\n", BUFSIZ);

	// Write to the socket
	if (write(sockfd, socket_message, BUFSIZ) == -1)
	{
		perror("write");
		return RLM_MODULE_FAIL;
	}
	if (shutdown(sockfd, SHUT_WR) != 0)
	{
		perror("shutdown socket");
		return RLM_MODULE_FAIL;
	}
	talloc_free(socket_message);

	// read from the socket
	int nbytes_read = read(sockfd, buffer, BUFSIZ);
	close(sockfd);
	if (nbytes_read <= 0)
	{
		perror("read");
		return RLM_MODULE_FAIL;
	}

	if (buffer[0] == 1)
	{
		return RLM_MODULE_OK;
	}

	return RLM_MODULE_FAIL;
}

#ifdef WITH_ACCOUNTING
/*
 *	Massage the request before recording it or proxying it
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}
#endif

#ifdef WITH_COA
/*
 *	Massage the request before recording it or proxying it
 */
static rlm_rcode_t CC_HINT(nonnull) mod_recv_coa(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_send_coa(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}
#endif

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(UNUSED void *instance)
{
	/* free things here */
	return 0;
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
extern module_t rlm_magic;
module_t rlm_magic = {
	.magic = RLM_MODULE_INIT,
	.name = "Magic",
	.type = RLM_TYPE_THREAD_SAFE,
	.inst_size = sizeof(rlm_magic_t),
	.config = module_config,
	.instantiate = mod_instantiate,
	.detach = mod_detach,
	.methods = {
		[MOD_AUTHENTICATE] = mod_authenticate,
		[MOD_AUTHORIZE] = mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_PREACCT] = mod_preacct,
		[MOD_ACCOUNTING] = mod_accounting,
#endif
#ifdef WITH_COA
		[MOD_RECV_COA] = mod_recv_coa,
		[MOD_SEND_COA] = mod_send_coa
#endif
	},
};
