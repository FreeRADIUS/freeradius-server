/*
 * proxy.c	Proxy stuff.
 *
 * Version:	$Id$
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<string.h>
#include	<time.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"


static int	proxy_id = 1;
static REQUEST	*proxy_requests;

static int allowed [] = {
	PW_SERVICE_TYPE,
	PW_FRAMED_PROTOCOL,
	PW_FILTER_ID,
	PW_FRAMED_MTU,
	PW_FRAMED_COMPRESSION,
	PW_LOGIN_SERVICE,
	PW_REPLY_MESSAGE,
	PW_SESSION_TIMEOUT,
	PW_IDLE_TIMEOUT,
	PW_PORT_LIMIT,
	0,
};

static int trusted_allowed [] = {
	PW_SERVICE_TYPE,
	PW_FRAMED_PROTOCOL,
	PW_FILTER_ID,
	PW_FRAMED_MTU,
	PW_FRAMED_COMPRESSION,
	PW_FRAMED_IP_ADDRESS,
	PW_FRAMED_IP_NETMASK,
	PW_FRAMED_ROUTING,
	PW_FRAMED_ROUTE,
	PW_LOGIN_SERVICE,
	PW_REPLY_MESSAGE,
	PW_SESSION_TIMEOUT,
	PW_IDLE_TIMEOUT,
	PW_PORT_LIMIT,
	0,
};


/*
 *	Cleanup old outstanding requests.
 */
static void proxy_cleanup(void)
{
	REQUEST 		*a, *last, *next;
	time_t			now;

	last = NULL;
	now  = time(NULL);

	for (a = proxy_requests; a; a = next) {
		next = a->next;
		if (a->timestamp + MAX_REQUEST_TIME < now) {
			if (last)
				last->next = a->next;
			else
				proxy_requests = a->next;
			request_free(a);
			continue;
		}
		last = a;
	}
}

/*
 *	Add a proxy-pair to the end of the request.
 */
static void proxy_addinfo(RADIUS_PACKET *rp)
{
	VALUE_PAIR		*proxy_pair, *vp;

	if  (!(proxy_pair = paircreate(PW_PROXY_STATE, PW_TYPE_STRING))) {
		log(L_ERR|L_CONS, "no memory");
		exit(1);
	}
	sprintf(proxy_pair->strvalue, "%04x", rp->id);
	proxy_pair->length = 4;

	for (vp = rp->vps; vp && vp->next; vp = vp->next)
		;
	vp->next = proxy_pair;
}

/*
 *	Add the request to the list.
 */
static int proxy_addrequest(REQUEST *request, int *proxied_packet_id)
{
	REQUEST		*a, *last = NULL;
	int		id = -1;

	/*
	 *	See if we already have a similar outstanding request.
	 */
	for (a = proxy_requests; a; a = a->next) {
		if (a->packet->src_ipaddr == request->packet->src_ipaddr &&
		    a->packet->id == request->packet->id &&
		    !memcmp(a->packet->vector, request->packet->vector, 16))
			break;
		last = a;
	}
	if (a) {
		/*
		 *	Yes, this is a retransmit so delete the
		 *	old request.
		 */
		id = a->proxy->id;
		if (last)
			last->next = a->next;
		else
			proxy_requests = a->next;
		request_free(a);
		free(a);
	}
	if (id < 0) {
		id = (*proxied_packet_id)++;
		*proxied_packet_id &= 0xFFFF;
	}

	request->next = NULL;
	request->child_pid = -1;
	request->timestamp = time(NULL);

	request->next = proxy_requests;
	proxy_requests = request;

	return id;
}


/*
 *	Relay the request to a remote server.
 *	Returns:  1 success (we reply, caller returns without replying)
 *	          0 fail (caller falls through to normal processing)
 *		 -1 fail (we don't reply, caller returns without replying)
 */
int proxy_send(REQUEST *request)
{
	VALUE_PAIR		*namepair;
	VALUE_PAIR		*passpair;
	VALUE_PAIR		*vp, *vps;
	CLIENT			*client;
	REALM			*realm;
	char			*realmname;

	/*
	 *	First cleanup old outstanding requests.
	 */
	proxy_cleanup();

	/*
	 *	Copy the request, then look up
	 *	name and (encrypted) password in the copy.
	 */
	vps = paircopy(request->packet->vps);
	namepair = pairfind(vps, PW_USER_NAME);
	if (namepair == NULL) {
		pairfree(vps);
		return 0;
	}
	passpair = pairfind(vps, PW_PASSWORD);

	/*
	 *	Use the original username if available. The one
	 *	in the A/V pairs might have been stripped already.
	 */
	if (request->username[0]) {
		strncpy(namepair->strvalue, request->username,
			sizeof(namepair->strvalue));
		namepair->strvalue[sizeof(namepair->strvalue) - 1] = 0;
	}

	/*
	 *	Now check if we know this realm!
	 *	A NULL realm is OK.
	 *	If not found, we treat it as usual.
	 *	Find the realm from the _end_ so that we can
	 *	cascade realms: user@realm1@realm2.
	 */
	if ((realmname = strrchr(namepair->strvalue, '@')) != NULL)
		realmname++;
	if ((realm = realm_find(realmname ? realmname : "NULL")) == NULL) {
		pairfree(vps);
		return 0;
	}
	if (realmname != NULL && realm->striprealm)
			realmname[-1] = 0;
	namepair->length = strlen(namepair->strvalue);
	pairadd(&request->packet->vps,
		pairmake("Realm", realm->realm, T_OP_EQ));


	/*
	 *	Perhaps accounting proxying was turned off.
	 */
	if (request->packet->code == PW_ACCOUNTING_REQUEST &&
	    realm-acct_port == 0) {
		pairfree(vps);
		return 0;
	}

	/*
	 *	The special server LOCAL ?
	 */
	if (strcmp(realm->server, "LOCAL") == 0) {
		pairfree(vps);
		namepair = pairfind(request->packet->vps, PW_USER_NAME);
		if (realm->striprealm &&
		    ((realmname = strrchr(namepair->strvalue, '@')) != NULL)) {
			*realmname = 0;
			namepair->length = strlen(namepair->strvalue);
		}
		return 0;
	}

	/*
	 *	Find the remote server in the "client" list-
	 *	we need the secret.
	 */
	if ((client = client_find(realm->ipaddr)) == NULL) {
		log(L_PROXY, "cannot find secret for server %s in clients file",
			realm->server);
		pairfree(vps);
		return 0;
	}

	/*
	 *	Now build a new RADIUS_PACKET and send it.
	 *
	 *	FIXME: it could be that the id wraps around too fast if
	 *	we have a lot of requests, it might be better to keep
	 *	a seperate ID value per remote server.
	 *
	 *	OTOH the remote radius server should be smart enough to
	 *	compare _both_ ID and vector. Right ?
	 */
	if ((request->proxy = rad_alloc(0)) == NULL) {
		log(L_ERR|L_CONS, "no memory");
		exit(1);
	}

	/*
	 *	This net line works, but it's not the best thing to do.
	 *
	 *	Proxied requests should REALLY be sent out their own FD.
	 */
	request->proxy->sockfd = request->packet->sockfd;

	request->proxy->code = request->packet->code;
	request->proxy->dst_ipaddr = realm->ipaddr;
	if (request->packet->code == PW_AUTHENTICATION_REQUEST)
		request->proxy->dst_port = realm->auth_port;
	else
		request->proxy->dst_port = realm->acct_port;
	request->proxy->vps = vps;

	printf("Destination port: %d, server %s (%d/%d)\n",
		request->proxy->dst_port, realm->server,
		realm->auth_port, realm->acct_port);

	/*
	 *	XXX: we re-use the vector from the original request
	 *	here, since that's easy for retransmits ...
	 */
	memcpy(request->proxy->vector, request->packet->vector,
		AUTH_VECTOR_LEN);

	/*
	 *	Add the request to the list of outstanding requests.
	 *	Note that request->proxy->id is a 16 bits value,
	 *	while rad_send sends only the 8 least significant
	 *	bits of that same value.
	 */
	request->proxy->id = proxy_addrequest(request, &proxy_id);

	/*
	 *	Add PROXY_STATE attribute.
	 */
	proxy_addinfo(request->proxy);

	/*
	 *	We need to decode the password with the secret.
	 *	rad_send() will re-encode it for us.
	 */
	if (passpair) {
		rad_pwdecode(passpair->strvalue, passpair->length,
			request->secret, request->packet->vector);
	}

	/*
	 *	If there is no PW_CHAP_CHALLENGE attribute but there
	 *	is a PW_CHAP_PASSWORD we need to add it since we can't
	 *	use the request authenticator anymore - we changed it.
	 */
	if (pairfind(vps, PW_CHAP_PASSWORD) &&
	    pairfind(vps, PW_CHAP_CHALLENGE) == NULL) {
		if (!(vp = paircreate(PW_CHAP_CHALLENGE, PW_TYPE_STRING))) {
			log(L_ERR|L_CONS, "no memory");
			exit(1);
		}
		vp->length = AUTH_VECTOR_LEN;
		memcpy(vp->strvalue, request->packet->vector, AUTH_VECTOR_LEN);
		pairadd(&vps, vp);
	}

	/*
	 *	Send the request.
	 */
	rad_send(request->proxy, client->secret);

	/*
	 *	We can free proxy->vps now, not needed anymore.
	 */
	pairfree(request->proxy->vps);
	request->proxy->vps = NULL;

	return 1;
}


/*
 *	We received a response from a remote radius server.
 *	Find the original request, then return.
 *	Returns:   0 proxy found
 *		  -1 error don't reply
 */
int proxy_receive(REQUEST *request)
{
	VALUE_PAIR	*vp, *last, *prev, *x;
	VALUE_PAIR	*allowed_pairs;
	REQUEST	*oldreq, *lastreq;
	char		*s;
	int		pp = -1;
	int		i;
	VALUE_PAIR	*namepair;
        REALM                   *realm;
        char                    *realmname;

	/*
	 *	First cleanup old outstanding requests.
	 */
	proxy_cleanup();

	/*
	 *	FIXME: calculate md5 checksum!
	 */

	/*
	 *	Find the last PROXY_STATE attribute.
	 */
	oldreq  = NULL;
	lastreq = NULL;
	last    = NULL;
	x       = NULL;
	prev    = NULL;

	for (vp = request->packet->vps; vp; vp = vp->next) {
		if (vp->attribute == PW_PROXY_STATE) {
			prev = x;
			last = vp;
		}
		x = vp;
	}
	if (last && last->strvalue) {
		/*
		 *	Merit really rapes the Proxy-State attribute.
		 *	See if it still is a valid 4-digit hex number.
		 */
		s = last->strvalue;
		if (strlen(s) == 4 && isxdigit(s[0]) && isxdigit(s[1]) &&
		    isxdigit(s[2]) && isxdigit(s[3])) {
			pp = strtol(last->strvalue, NULL, 16);
		} else {
			log(L_PROXY, "server %s mangled Proxy-State attribute",
			client_name(request->packet->src_ipaddr));
		}
	}

	/*
	 *	Now find it in the list of outstanding requests.
	 */

	for (oldreq = proxy_requests; oldreq; oldreq = oldreq->next) {
		/*
		 *	Some servers drop the proxy pair. So
		 *	compare in another way if needed.
		 */
		if (pp >= 0 && pp == oldreq->proxy->id)
			break;
		if (pp < 0 &&
		    request->packet->src_ipaddr == oldreq->proxy->dst_ipaddr &&
		    request->packet->id     == (oldreq->proxy->id & 0xFF))
			break;
		lastreq = oldreq;
	}

	if (oldreq == NULL) {
		log(L_PROXY, "Unrecognized proxy reply from server %s - ID %d",
			client_name(request->packet->src_ipaddr),
			request->packet->id);
		return -1;
	}

	/*
	 *	Remove oldreq from list.
	 */
	if (lastreq)
		lastreq->next = oldreq->next;
	else
		proxy_requests = oldreq->next;

	/*
	 *	Remove proxy pair from list.
	 */
	if (last) {
		if (prev)
			prev->next = last->next;
		else
			request->packet->vps = last->next;
	}

        namepair = pairfind(oldreq->packet->vps, PW_USER_NAME);
        if ((realmname = strrchr(namepair->strvalue, '@')) != NULL)
                realmname++;
        realm = realm_find(realmname ? realmname : "NULL");
	if (realm->trusted) {
	/*
	 *	Only allow some attributes to be propagated from
	 *	the remote server back to the NAS, for security.
	 */
	allowed_pairs = NULL;
	for(i = 0; trusted_allowed[i]; i++)
		pairmove2(&allowed_pairs, &(request->packet->vps), trusted_allowed[i]);
	} else {
	/*
	 *	Only allow some attributes to be propagated from
	 *	the remote server back to the NAS, for security.
	 */
	allowed_pairs = NULL;
	for(i = 0; allowed[i]; i++)
		pairmove2(&allowed_pairs, &(request->packet->vps), allowed[i]);
	}

	/*
	 *	Now rebuild the AUTHREQ struct, so that the
	 *	normal functions can process it.
	 */
	request->proxy = oldreq->proxy;
	oldreq->proxy = NULL;
	request->proxy->vps  = allowed_pairs;
	request->proxy->code = request->packet->code;

	pairfree(request->packet->vps);
	free(request->packet);
	request->packet = oldreq->packet;
	oldreq->packet = NULL;

	request->timestamp = oldreq->timestamp;

	request_free(oldreq);

	return 0;
}

