/*
 * radeapclient.c	EAP specific radius packet debug tool.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#include <ctype.h>

#if HAVE_GETOPT_H
#	include <getopt.h>
#endif

#include <freeradius-devel/conf.h>
#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/md5.h>

#include "eap_types.h"
#include "eap_sim.h"

extern int sha1_data_problems;

static int retries = 10;
static float timeout = 3;
static char const *secret = NULL;
static int do_output = 1;
static int do_summary = 0;
static bool filedone = false;
static int totalapp = 0;
static int totaldeny = 0;
static char filesecret[256];
char const *radius_dir = NULL;
char const *dict_dir = NULL;
char const *progname = "radeapclient";
/* fr_randctx randctx; */

struct main_config_t main_config;
char const *radiusd_version = "";

#ifdef WITH_TLS
#include <freeradius-devel/tls.h>
#endif

log_debug_t debug_flag = 0;
char password[256];

struct eapsim_keys eapsim_mk;

static void map_eap_methods(RADIUS_PACKET *req);
static void unmap_eap_methods(RADIUS_PACKET *rep);
static int map_eapsim_types(RADIUS_PACKET *r);
static int unmap_eapsim_types(RADIUS_PACKET *r);

static void NEVER_RETURNS usage(void)
{
	fprintf(stdout, "Usage: radeapclient [options] server[:port] <command> [<secret>]");

	fprintf(stdout, " <command>    One of auth, acct, status, or disconnect.");
	fprintf(stdout, " -d raddb     Set dictionary directory.");
	fprintf(stdout, " -f file      Read packets from file, not stdin.");
	fprintf(stdout, " -r retries   If timeout, retry sending the packet 'retries' times.");
	fprintf(stdout, " -t timeout   Wait 'timeout' seconds before retrying (may be a floating point number).");
	fprintf(stdout, " -h	       Print usage help information.");
	fprintf(stdout, " -i id        Set request id to 'id'.  Values may be 0..255");
	fprintf(stdout, " -S file      read secret from file, not command line.");
	fprintf(stdout, " -q	       Do not print anything out.");
	fprintf(stdout, " -s	       Print out summary information of auth results.");
	fprintf(stdout, " -v	       Show program version information.");
	fprintf(stdout, " -x	       Debugging mode.");
	fprintf(stdout, " -4	       Use IPv4 address of server");
	fprintf(stdout, " -6	       Use IPv6 address of server.");

	exit(1);
}
int rad_virtual_server(REQUEST UNUSED *request)
{
  /*We're not the server so we cannot do this*/
  abort();
}

static uint16_t getport(char const *name)
{
	struct	servent		*svp;

	svp = getservbyname (name, "udp");
	if (!svp) {
		return 0;
	}

	return ntohs(svp->s_port);
}

#define R_RECV (0)
#define R_SENT (1)
static void debug_packet(RADIUS_PACKET *packet, int direction)
{
	VALUE_PAIR *vp;
	char buffer[1024];
	char const *received, *from;
	fr_ipaddr_t const *ip;
	uint16_t port;

	if (!packet) return;

	if (direction == 0) {
		received = "Received";
		from = "from";	/* what else? */
		ip = &packet->src_ipaddr;
		port = packet->src_port;

	} else {
		received = "Sending";
		from = "to";	/* hah! */
		ip = &packet->dst_ipaddr;
		port = packet->dst_port;
	}

	/*
	 *	Client-specific debugging re-prints the input
	 *	packet into the client log.
	 *
	 *	This really belongs in a utility library
	 */
	if (is_radius_code(packet->code)) {
		DEBUG("%s %s packet %s host %s port %d, id=%d, length=%d",
		       received, fr_packet_codes[packet->code], from,
		       inet_ntop(ip->af, &ip->ipaddr, buffer, sizeof(buffer)),
		       port, packet->id, (int) packet->data_len);
	} else {
		DEBUG("%s packet %s host %s port %d code=%d, id=%d, length=%d",
		       received, from,
		       inet_ntop(ip->af, &ip->ipaddr, buffer, sizeof(buffer)),
		       port,
		       packet->code, packet->id, (int) packet->data_len);
	}

	for (vp = packet->vps; vp != NULL; vp = vp->next) {
		vp_prints(buffer, sizeof(buffer), vp);
		DEBUG("\t%s", buffer);
	}
	fflush(stdout);
}


static int send_packet(RADIUS_PACKET *req, RADIUS_PACKET **rep)
{
	int i;
	struct timeval	tv;

	if (!req || !rep) return -1;

	for (i = 0; i < retries; i++) {
		fd_set		rdfdesc;

		debug_packet(req, R_SENT);

		if (rad_send(req, NULL, secret) < 0) {
			ERROR("%s", fr_strerror());
			exit(1);
		}

		/* And wait for reply, timing out as necessary */
		FD_ZERO(&rdfdesc);
		FD_SET(req->sockfd, &rdfdesc);

		tv.tv_sec = (int)timeout;
		tv.tv_usec = 1000000 * (timeout - (int) timeout);

		/* Something's wrong if we don't get exactly one fd. */
		if (select(req->sockfd + 1, &rdfdesc, NULL, NULL, &tv) != 1) {
			continue;
		}

		*rep = rad_recv(req->sockfd, 0);
		if (*rep != NULL) {
			/*
			 *	If we get a response from a machine
			 *	which we did NOT send a request to,
			 *	then complain.
			 */
			if (((*rep)->src_ipaddr.af != req->dst_ipaddr.af) ||
			    (memcmp(&(*rep)->src_ipaddr.ipaddr,
				    &req->dst_ipaddr.ipaddr,
				    ((req->dst_ipaddr.af == AF_INET ? /* AF_INET6? */
				      sizeof(req->dst_ipaddr.ipaddr.ip4addr) : /* FIXME: AF_INET6 */
				      sizeof(req->dst_ipaddr.ipaddr.ip6addr)))) != 0) ||
			    ((*rep)->src_port != req->dst_port)) {
				char src[128], dst[128];

				ip_ntoh(&(*rep)->src_ipaddr, src, sizeof(src));
				ip_ntoh(&req->dst_ipaddr, dst, sizeof(dst));
				ERROR("ERROR: Sent request to host %s port %d, got response from host %s port %d!",
					dst, req->dst_port,
					src, (*rep)->src_port);
				exit(1);
			}
			break;
		} else {	/* NULL: couldn't receive the packet */
			ERROR("%s", fr_strerror());
			exit(1);
		}
	}

	/* No response or no data read (?) */
	if (i == retries) {
		ERROR("rad_client: no response from server");
		exit(1);
	}

	/*
	 *	FIXME: Discard the packet & listen for another.
	 *
	 *	Hmm... we should really be using eapol_test, which does
	 *	a lot more than radeapclient.
	 */
	if (rad_verify(*rep, req, secret) != 0) {
		ERROR("rad_verify: %s", fr_strerror());
		exit(1);
	}

	if (rad_decode(*rep, req, secret) != 0) {
		ERROR("rad_decode: %s", fr_strerror());
		exit(1);
	}

	/* libradius debug already prints out the value pairs for us */
	if (!fr_debug_flag && do_output) {
		debug_packet(*rep, R_RECV);
	}
	if((*rep)->code == PW_CODE_ACCESS_ACCEPT) {
		totalapp++;
	} else if ((*rep)->code == PW_CODE_ACCESS_REJECT) {
		totaldeny++;
	}

	return 0;
}

static void cleanresp(RADIUS_PACKET *resp)
{
	VALUE_PAIR *vpnext, *vp, **last;


	/*
	 * maybe should just copy things we care about, or keep
	 * a copy of the original input and start from there again?
	 */
	pairdelete(&resp->vps, PW_EAP_MESSAGE, 0, TAG_ANY);
	pairdelete(&resp->vps, PW_EAP_TYPE_BASE+PW_EAP_IDENTITY, 0, TAG_ANY);

	last = &resp->vps;
	for(vp = *last; vp != NULL; vp = vpnext)
	{
		vpnext = vp->next;

		if((vp->da->attr > PW_EAP_TYPE_BASE &&
		    vp->da->attr <= PW_EAP_TYPE_BASE+256) ||
		   (vp->da->attr > PW_EAP_SIM_BASE &&
		    vp->da->attr <= PW_EAP_SIM_BASE+256))
		{
			*last = vpnext;
			talloc_free(vp);
		} else {
			last = &vp->next;
		}
	}
}

/*
 * we got an EAP-Request/Sim/Start message in a legal state.
 *
 * pick a supported version, put it into the reply, and insert a nonce.
 */
static int process_eap_start(RADIUS_PACKET *req,
			     RADIUS_PACKET *rep)
{
	VALUE_PAIR *vp, *newvp;
	VALUE_PAIR *anyidreq_vp, *fullauthidreq_vp, *permanentidreq_vp;
	uint16_t const *versions;
	uint16_t selectedversion;
	unsigned int i,versioncount;

	/* form new response clear of any EAP stuff */
	cleanresp(rep);

	if((vp = pairfind(req->vps, PW_EAP_SIM_VERSION_LIST, 0, TAG_ANY)) == NULL) {
		ERROR("illegal start message has no VERSION_LIST");
		return 0;
	}

	versions = (uint16_t const *) vp->vp_strvalue;

	/* verify that the attribute length is big enough for a length field */
	if(vp->length < 4)
	{
		ERROR("start message has illegal VERSION_LIST. Too short: %u", (unsigned int) vp->length);
		return 0;
	}

	versioncount = ntohs(versions[0])/2;
	/* verify that the attribute length is big enough for the given number
	 * of versions present.
	 */
	if((unsigned)vp->length <= (versioncount*2 + 2))
	{
		ERROR("start message is too short. Claimed %d versions does not fit in %u bytes", versioncount, (unsigned int) vp->length);
		return 0;
	}

	/*
	 * record the versionlist for the MK calculation.
	 */
	eapsim_mk.versionlistlen = versioncount*2;
	memcpy(eapsim_mk.versionlist, (unsigned char const *)(versions+1),
	       eapsim_mk.versionlistlen);

	/* walk the version list, and pick the one we support, which
	 * at present, is 1, EAP_SIM_VERSION.
	 */
	selectedversion=0;
	for(i=0; i < versioncount; i++)
	{
		if(ntohs(versions[i+1]) == EAP_SIM_VERSION)
		{
			selectedversion=EAP_SIM_VERSION;
			break;
		}
	}
	if(selectedversion == 0)
	{
		ERROR("eap-sim start message. No compatible version found. We need %d", EAP_SIM_VERSION);
		for(i=0; i < versioncount; i++)
		{
			ERROR("\tfound version %d",
				ntohs(versions[i+1]));
		}
	}

	/*
	 * now make sure that we have only FULLAUTH_ID_REQ.
	 * I think that it actually might not matter - we can answer in
	 * anyway we like, but it is illegal to have more than one
	 * present.
	 */
	anyidreq_vp = pairfind(req->vps, PW_EAP_SIM_ANY_ID_REQ, 0, TAG_ANY);
	fullauthidreq_vp = pairfind(req->vps, PW_EAP_SIM_FULLAUTH_ID_REQ, 0, TAG_ANY);
	permanentidreq_vp = pairfind(req->vps, PW_EAP_SIM_PERMANENT_ID_REQ, 0, TAG_ANY);

	if(!fullauthidreq_vp ||
	   anyidreq_vp != NULL ||
	   permanentidreq_vp != NULL) {
		ERROR("start message has %sanyidreq, %sfullauthid and %spermanentid. Illegal combination.",
			(anyidreq_vp != NULL ? "a ": "no "),
			(fullauthidreq_vp != NULL ? "a ": "no "),
			(permanentidreq_vp != NULL ? "a ": "no "));
		return 0;
	}

	/* okay, we have just any_id_req there, so fill in response */

	/* mark the subtype as being EAP-SIM/Response/Start */
	newvp = paircreate(rep, PW_EAP_SIM_SUBTYPE, 0);
	newvp->vp_integer = EAPSIM_START;
	pairreplace(&(rep->vps), newvp);

	/* insert selected version into response. */
	{
		uint16_t no_versions;

		no_versions = htons(selectedversion);

		newvp = paircreate(rep, PW_EAP_SIM_SELECTED_VERSION, 0);
		pairmemcpy(newvp, (uint8_t *) &no_versions, 2);
		pairreplace(&(rep->vps), newvp);

		/* record the selected version */
		memcpy(eapsim_mk.versionselect, &no_versions, 2);
	}

	vp = newvp = NULL;

	{
		uint32_t nonce[4];
		uint8_t *p;
		/*
		 * insert a nonce_mt that we make up.
		 */
		nonce[0]=fr_rand();
		nonce[1]=fr_rand();
		nonce[2]=fr_rand();
		nonce[3]=fr_rand();

		newvp = paircreate(rep, PW_EAP_SIM_NONCE_MT, 0);

		p = talloc_zero_array(newvp, uint8_t, 18); /* 18 = 16 bytes of nonce + padding */
		memcpy(&p[2], nonce, 16);
		pairmemsteal(newvp, p);

		pairreplace(&(rep->vps), newvp);

		/* also keep a copy of the nonce! */
		memcpy(eapsim_mk.nonce_mt, nonce, 16);
	}

	{
		uint16_t idlen;
		uint8_t *p;
		uint16_t no_idlen;

		/*
		 * insert the identity here.
		 */
		vp = pairfind(rep->vps, PW_USER_NAME, 0, TAG_ANY);
		if(!vp)
		{
			ERROR("eap-sim: We need to have a User-Name attribute!");
			return 0;
		}
		newvp = paircreate(rep, PW_EAP_SIM_IDENTITY, 0);

		idlen = strlen(vp->vp_strvalue);
		p = talloc_zero_array(newvp, uint8_t, idlen + 2);
		no_idlen = htons(idlen);
		memcpy(p, &no_idlen, 2);
		memcpy(p + 2, vp->vp_strvalue, idlen);
		pairmemsteal(newvp, p);

		pairreplace(&(rep->vps), newvp);

		/* record it */
		memcpy(eapsim_mk.identity, vp->vp_strvalue, idlen);
		eapsim_mk.identitylen = idlen;
	}

	return 1;
}

/*
 * we got an EAP-Request/Sim/Challenge message in a legal state.
 *
 * use the RAND challenge to produce the SRES result, and then
 * use that to generate a new MAC.
 *
 * for the moment, we ignore the RANDs, then just plug in the SRES
 * values.
 *
 */
static int process_eap_challenge(RADIUS_PACKET *req, RADIUS_PACKET *rep)
{
	VALUE_PAIR *newvp;
	VALUE_PAIR *mac, *randvp;
	VALUE_PAIR *sres1,*sres2,*sres3;
	VALUE_PAIR *Kc1, *Kc2, *Kc3;
	uint8_t calcmac[20];

	/* look for the AT_MAC and the challenge data */
	mac   = pairfind(req->vps, PW_EAP_SIM_MAC, 0, TAG_ANY);
	randvp= pairfind(req->vps, PW_EAP_SIM_RAND, 0, TAG_ANY);
	if(!mac || !randvp) {
		ERROR("challenge message needs to contain RAND and MAC");
		return 0;
	}

	/*
	 * compare RAND with randX, to verify this is the right response
	 * to this challenge.
	 */
	{
	  VALUE_PAIR *randcfgvp[3];
	  uint8_t const *randcfg[3];

	  randcfg[0] = &randvp->vp_octets[2];
	  randcfg[1] = &randvp->vp_octets[2+EAPSIM_RAND_SIZE];
	  randcfg[2] = &randvp->vp_octets[2+EAPSIM_RAND_SIZE*2];

	  randcfgvp[0] = pairfind(rep->vps, PW_EAP_SIM_RAND1, 0, TAG_ANY);
	  randcfgvp[1] = pairfind(rep->vps, PW_EAP_SIM_RAND2, 0, TAG_ANY);
	  randcfgvp[2] = pairfind(rep->vps, PW_EAP_SIM_RAND3, 0, TAG_ANY);

	  if(!randcfgvp[0] ||
	     !randcfgvp[1] ||
	     !randcfgvp[2]) {
	    ERROR("needs to have rand1, 2 and 3 set.");
	    return 0;
	  }

	  if(memcmp(randcfg[0], randcfgvp[0]->vp_octets, EAPSIM_RAND_SIZE)!=0 ||
	     memcmp(randcfg[1], randcfgvp[1]->vp_octets, EAPSIM_RAND_SIZE)!=0 ||
	     memcmp(randcfg[2], randcfgvp[2]->vp_octets, EAPSIM_RAND_SIZE)!=0) {
	    int rnum,i,j;

	    ERROR("one of rand 1,2,3 didn't match");
	    for(rnum = 0; rnum < 3; rnum++) {
	      ERROR("received   rand %d: ", rnum);
	      j=0;
	      for (i = 0; i < EAPSIM_RAND_SIZE; i++) {
		if(j==4) {
		  DEBUG("_");
		  j=0;
		}
		j++;

		ERROR("%02x", randcfg[rnum][i]);
	      }
	      ERROR("configured rand %d: ", rnum);
	      j=0;
	      for (i = 0; i < EAPSIM_RAND_SIZE; i++) {
		if(j==4) {
		  DEBUG("_");
		  j=0;
		}
		j++;

		ERROR("%02x", randcfgvp[rnum]->vp_octets[i]);
	      }
	    }
	    return 0;
	  }
	}

	/*
	 * now dig up the sres values from the response packet,
	 * which were put there when we read things in.
	 *
	 * Really, they should be calculated from the RAND!
	 *
	 */
	sres1 = pairfind(rep->vps, PW_EAP_SIM_SRES1, 0, TAG_ANY);
	sres2 = pairfind(rep->vps, PW_EAP_SIM_SRES2, 0, TAG_ANY);
	sres3 = pairfind(rep->vps, PW_EAP_SIM_SRES3, 0, TAG_ANY);

	if(!sres1 ||
	   !sres2 ||
	   !sres3) {
		ERROR("needs to have sres1, 2 and 3 set.");
		return 0;
	}
	memcpy(eapsim_mk.sres[0], sres1->vp_strvalue, sizeof(eapsim_mk.sres[0]));
	memcpy(eapsim_mk.sres[1], sres2->vp_strvalue, sizeof(eapsim_mk.sres[1]));
	memcpy(eapsim_mk.sres[2], sres3->vp_strvalue, sizeof(eapsim_mk.sres[2]));

	Kc1 = pairfind(rep->vps, PW_EAP_SIM_KC1, 0, TAG_ANY);
	Kc2 = pairfind(rep->vps, PW_EAP_SIM_KC2, 0, TAG_ANY);
	Kc3 = pairfind(rep->vps, PW_EAP_SIM_KC3, 0, TAG_ANY);

	if(!Kc1 ||
	   !Kc2 ||
	   !Kc3) {
		ERROR("needs to have Kc1, 2 and 3 set.");
		return 0;
	}
	memcpy(eapsim_mk.Kc[0], Kc1->vp_strvalue, sizeof(eapsim_mk.Kc[0]));
	memcpy(eapsim_mk.Kc[1], Kc2->vp_strvalue, sizeof(eapsim_mk.Kc[1]));
	memcpy(eapsim_mk.Kc[2], Kc3->vp_strvalue, sizeof(eapsim_mk.Kc[2]));

	/* all set, calculate keys */
	eapsim_calculate_keys(&eapsim_mk);

	if(debug_flag) {
	  eapsim_dump_mk(&eapsim_mk);
	}

	/* verify the MAC, now that we have all the keys. */
	if(eapsim_checkmac(NULL, req->vps, eapsim_mk.K_aut,
			   eapsim_mk.nonce_mt, sizeof(eapsim_mk.nonce_mt),
			   calcmac)) {
		DEBUG("MAC check succeed");
	} else {
		int i, j;
		j=0;
		DEBUG("calculated MAC (");
		for (i = 0; i < 20; i++) {
			if(j==4) {
				printf("_");
				j=0;
			}
			j++;

			DEBUG("%02x", calcmac[i]);
		}
		DEBUG("did not match");
		return 0;
	}

	/* form new response clear of any EAP stuff */
	cleanresp(rep);

	/* mark the subtype as being EAP-SIM/Response/Start */
	newvp = paircreate(rep, PW_EAP_SIM_SUBTYPE, 0);
	newvp->vp_integer = EAPSIM_CHALLENGE;
	pairreplace(&(rep->vps), newvp);

	{
		uint8_t *p;
		/*
		 * fill the SIM_MAC with a field that will in fact get appended
		 * to the packet before the MAC is calculated
		 */
		newvp = paircreate(rep, PW_EAP_SIM_MAC, 0);

		p = talloc_zero_array(newvp, uint8_t, EAPSIM_SRES_SIZE*3);
		memcpy(p+EAPSIM_SRES_SIZE * 0, sres1->vp_strvalue, EAPSIM_SRES_SIZE);
		memcpy(p+EAPSIM_SRES_SIZE * 1, sres2->vp_strvalue, EAPSIM_SRES_SIZE);
		memcpy(p+EAPSIM_SRES_SIZE * 2, sres3->vp_strvalue, EAPSIM_SRES_SIZE);
		pairmemsteal(newvp, p);

		pairreplace(&(rep->vps), newvp);
	}

	newvp = paircreate(rep, PW_EAP_SIM_KEY, 0);
	pairmemcpy(newvp, eapsim_mk.K_aut, EAPSIM_AUTH_SIZE);

	pairreplace(&(rep->vps), newvp);

	return 1;
}

/*
 * this code runs the EAP-SIM client state machine.
 * the *request* is from the server.
 * the *reponse* is to the server.
 *
 */
static int respond_eap_sim(RADIUS_PACKET *req, RADIUS_PACKET *resp)
{
	enum eapsim_clientstates state, newstate;
	enum eapsim_subtype subtype;
	VALUE_PAIR *vp, *statevp, *radstate, *eapid;
	char statenamebuf[32], subtypenamebuf[32];

	if ((radstate = paircopy_by_num(NULL, req->vps, PW_STATE, 0, TAG_ANY)) == NULL)
	{
		return 0;
	}

	if ((eapid = paircopy_by_num(NULL, req->vps, PW_EAP_ID, 0, TAG_ANY)) == NULL)
	{
		return 0;
	}

	/* first, dig up the state from the request packet, setting
	 * outselves to be in EAP-SIM-Start state if there is none.
	 */

	if((statevp = pairfind(resp->vps, PW_EAP_SIM_STATE, 0, TAG_ANY)) == NULL)
	{
		/* must be initial request */
		statevp = paircreate(resp, PW_EAP_SIM_STATE, 0);
		statevp->vp_integer = EAPSIM_CLIENT_INIT;
		pairreplace(&(resp->vps), statevp);
	}
	state = statevp->vp_integer;

	/*
	 * map the attributes, and authenticate them.
	 */
	unmap_eapsim_types(req);

	if((vp = pairfind(req->vps, PW_EAP_SIM_SUBTYPE, 0, TAG_ANY)) == NULL)
	{
		return 0;
	}
	subtype = vp->vp_integer;

	/*
	 * look for the appropriate state, and process incoming message
	 */
	switch(state) {
	case EAPSIM_CLIENT_INIT:
		switch(subtype) {
		case EAPSIM_START:
			newstate = process_eap_start(req, resp);
			break;

		case EAPSIM_CHALLENGE:
		case EAPSIM_NOTIFICATION:
		case EAPSIM_REAUTH:
		default:
			ERROR("sim in state %s message %s is illegal. Reply dropped.",
				sim_state2name(state, statenamebuf, sizeof(statenamebuf)),
				sim_subtype2name(subtype, subtypenamebuf, sizeof(subtypenamebuf)));
			/* invalid state, drop message */
			return 0;
		}
		break;

	case EAPSIM_CLIENT_START:
		switch(subtype) {
		case EAPSIM_START:
			/* NOT SURE ABOUT THIS ONE, retransmit, I guess */
			newstate = process_eap_start(req, resp);
			break;

		case EAPSIM_CHALLENGE:
			newstate = process_eap_challenge(req, resp);
			break;

		default:
			ERROR("sim in state %s message %s is illegal. Reply dropped.",
				sim_state2name(state, statenamebuf, sizeof(statenamebuf)),
				sim_subtype2name(subtype, subtypenamebuf, sizeof(subtypenamebuf)));
			/* invalid state, drop message */
			return 0;
		}
		break;


	default:
		ERROR("sim in illegal state %s",
			sim_state2name(state, statenamebuf, sizeof(statenamebuf)));
		return 0;
	}

	/* copy the eap state object in */
	pairreplace(&(resp->vps), eapid);

	/* update stete info, and send new packet */
	map_eapsim_types(resp);

	/* copy the radius state object in */
	pairreplace(&(resp->vps), radstate);

	statevp->vp_integer = newstate;
	return 1;
}

static int respond_eap_md5(RADIUS_PACKET *req,
			   RADIUS_PACKET *rep)
{
	VALUE_PAIR *vp, *id, *state;
	size_t valuesize;
	uint8_t identifier;
	uint8_t const *value;
	FR_MD5_CTX	context;
	uint8_t    response[16];

	cleanresp(rep);

	if ((state = paircopy_by_num(NULL, req->vps, PW_STATE, 0, TAG_ANY)) == NULL)
	{
		ERROR("no state attribute found");
		return 0;
	}

	if ((id = paircopy_by_num(NULL, req->vps, PW_EAP_ID, 0, TAG_ANY)) == NULL)
	{
		ERROR("no EAP-ID attribute found");
		return 0;
	}
	identifier = id->vp_integer;

	if ((vp = pairfind(req->vps, PW_EAP_TYPE_BASE+PW_EAP_MD5, 0, TAG_ANY)) == NULL)
	{
		ERROR("no EAP-MD5 attribute found");
		return 0;
	}

	/* got the details of the MD5 challenge */
	valuesize = vp->vp_octets[0];
	value = &vp->vp_octets[1];

	/* sanitize items */
	if(valuesize > vp->length)
	{
		ERROR("md5 valuesize if too big (%u > %u)",
			(unsigned int) valuesize, (unsigned int) vp->length);
		return 0;
	}

	/* now do the CHAP operation ourself, rather than build the
	 * buffer. We could also call rad_chap_encode, but it wants
	 * a CHAP-Challenge, which we don't want to bother with.
	 */
	fr_md5_init(&context);
	fr_md5_update(&context, &identifier, 1);
	fr_md5_update(&context, (uint8_t *) password, strlen(password));
	fr_md5_update(&context, value, valuesize);
	fr_md5_final(response, &context);

	{
		uint8_t *p;
		uint8_t lg_response;

		vp = paircreate(rep, PW_EAP_TYPE_BASE+PW_EAP_MD5, 0);
		vp->length = 17;

		p = talloc_zero_array(vp, uint8_t, 17);
		lg_response = 16;
		memcpy(p, &lg_response, 1);
		memcpy(p + 1, response, 16);
		pairmemsteal(vp, p);
	}
	pairreplace(&(rep->vps), vp);

	pairreplace(&(rep->vps), id);

	/* copy the state object in */
	pairreplace(&(rep->vps), state);

	return 1;
}



static int sendrecv_eap(RADIUS_PACKET *rep)
{
	RADIUS_PACKET *req = NULL;
	VALUE_PAIR *vp, *vpnext;
	int tried_eap_md5 = 0;

	if (!rep) return -1;

	/*
	 *	Keep a copy of the the User-Password attribute.
	 */
	if ((vp = pairfind(rep->vps, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY)) != NULL) {
		strlcpy(password, vp->vp_strvalue, sizeof(password));

	} else 	if ((vp = pairfind(rep->vps, PW_USER_PASSWORD, 0, TAG_ANY)) != NULL) {
		strlcpy(password, vp->vp_strvalue, sizeof(password));
		/*
		 *	Otherwise keep a copy of the CHAP-Password attribute.
		 */
	} else if ((vp = pairfind(rep->vps, PW_CHAP_PASSWORD, 0, TAG_ANY)) != NULL) {
		strlcpy(password, vp->vp_strvalue, sizeof(password));
	} else {
		*password = '\0';
	}

 again:
	rep->id++;

	/*
	 * if there are EAP types, encode them into an EAP-Message
	 *
	 */
	map_eap_methods(rep);

	/*
	 *  Fix up Digest-Attributes issues
	 */
	for (vp = rep->vps; vp != NULL; vp = vp->next) {
		switch (vp->da->attr) {
		default:
			break;

		case PW_DIGEST_REALM:
		case PW_DIGEST_NONCE:
		case PW_DIGEST_METHOD:
		case PW_DIGEST_URI:
		case PW_DIGEST_QOP:
		case PW_DIGEST_ALGORITHM:
		case PW_DIGEST_BODY_DIGEST:
		case PW_DIGEST_CNONCE:
		case PW_DIGEST_NONCE_COUNT:
		case PW_DIGEST_USER_NAME:
		/* overlapping! */
		{
			DICT_ATTR const *da;
			uint8_t *p, *q;

			p = talloc_array(vp, uint8_t, vp->length + 2);

			memcpy(p + 2, vp->vp_octets, vp->length);
			p[0] = vp->da->attr - PW_DIGEST_REALM + 1;
			vp->length += 2;
			p[1] = vp->length;

			da = dict_attrbyvalue(PW_DIGEST_ATTRIBUTES, 0);
			vp->da = da;

			/*
			 *	Re-do pairmemsteal ourselves,
			 *	because we play games with
			 *	vp->da, and pairmemsteal goes
			 *	to GREAT lengths to sanitize
			 *	and fix and change and
			 *	double-check the various
			 *	fields.
			 */
			memcpy(&q, &vp->vp_octets, sizeof(q));
			talloc_free(q);

			vp->vp_octets = talloc_steal(vp, p);
			vp->type = VT_DATA;

			VERIFY_VP(vp);
		}
			break;
		}
	}

	/*
	 *	If we've already sent a packet, free up the old
	 *	one, and ensure that the next packet has a unique
	 *	ID and authentication vector.
	 */
	if (rep->data) {
		talloc_free(rep->data);
		rep->data = NULL;
	}

	fr_md5_calc(rep->vector, rep->vector, sizeof(rep->vector));

	if (*password != '\0') {
		if ((vp = pairfind(rep->vps, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY)) != NULL) {
			pairstrcpy(vp, password);

		} else if ((vp = pairfind(rep->vps, PW_USER_PASSWORD, 0, TAG_ANY)) != NULL) {
			pairstrcpy(vp, password);

		} else if ((vp = pairfind(rep->vps, PW_CHAP_PASSWORD, 0, TAG_ANY)) != NULL) {
			pairstrcpy(vp, password);

			uint8_t *p;
			p = talloc_zero_array(vp, uint8_t, 17);
			rad_chap_encode(rep, p, rep->id, vp);
			pairmemsteal(vp, p);
		}
	} /* there WAS a password */

	/* send the response, wait for the next request */
	send_packet(rep, &req);
	if (!req) {
		ERROR("Failed getting response (EAP-Request from server)");
		return -1;
	}

	/* okay got back the packet, go and decode the EAP-Message. */
	unmap_eap_methods(req);

	debug_packet(req, R_RECV);

	/* now look for the code type. */
	for (vp = req->vps; vp != NULL; vp = vpnext) {
		vpnext = vp->next;

		switch (vp->da->attr) {
		default:
			break;

		case PW_EAP_TYPE_BASE + PW_EAP_MD5:
			if (respond_eap_md5(req, rep) && tried_eap_md5 < 3) {
				tried_eap_md5++;
				goto again;
			}
			break;

		case PW_EAP_TYPE_BASE + PW_EAP_SIM:
			if (respond_eap_sim(req, rep)) {
				goto again;
			}
			break;
		}
	}

	return 1;
}


void set_radius_dir(TALLOC_CTX *ctx, char const *path)
{
	if (radius_dir) {
		char *p;

		memcpy(&p, &radius_dir, sizeof(p));
		talloc_free(p);
		radius_dir = NULL;
	}
	if (path) radius_dir = talloc_strdup(ctx, path);
}


int main(int argc, char **argv)
{
	RADIUS_PACKET *req;
	char *p;
	int c;
	uint16_t port = 0;
	char *filename = NULL;
	FILE *fp;
	int id;
	int force_af = AF_UNSPEC;

	static fr_log_t radclient_log = {
		.colourise = true,
		.fd = STDOUT_FILENO,
		.dst = L_DST_STDOUT,
		.file = NULL,
		.debug_file = NULL,
	};

	radlog_init(&radclient_log, false);

	/*
	 *	We probably don't want to free the talloc autofree context
	 *	directly, so we'll allocate a new context beneath it, and
	 *	free that before any leak reports.
	 */
	TALLOC_CTX *autofree = talloc_init("main");

	id = ((int)getpid() & 0xff);
	fr_debug_flag = 0;

	set_radius_dir(autofree, RADIUS_DIR);

	while ((c = getopt(argc, argv, "46c:d:D:f:hi:qst:r:S:xXv")) != EOF)
	{
		switch(c) {
		case '4':
			force_af = AF_INET;
			break;
		case '6':
			force_af = AF_INET6;
			break;
		case 'd':
			set_radius_dir(autofree, optarg);
			break;
		case 'D':
			main_config.dictionary_dir = talloc_typed_strdup(NULL, optarg);
			break;
		case 'f':
			filename = optarg;
			break;
		case 'q':
			do_output = 0;
			break;
		case 'x':
			debug_flag++;
			fr_debug_flag++;
			break;

		case 'X':
#if 0
		  sha1_data_problems = 1; /* for debugging only */
#endif
		  break;



		case 'r':
			if (!isdigit((int) *optarg))
				usage();
			retries = atoi(optarg);
			break;
		case 'i':
			if (!isdigit((int) *optarg))
				usage();
			id = atoi(optarg);
			if ((id < 0) || (id > 255)) {
				usage();
			}
			break;
		case 's':
			do_summary = 1;
			break;
		case 't':
			if (!isdigit((int) *optarg))
				usage();
			timeout = atof(optarg);
			break;
		case 'v':
			printf("$Id$ built on "__DATE__ "at "__TIME__ "");
			exit(0);
			break;
	       case 'S':
		       fp = fopen(optarg, "r");
		       if (!fp) {
			       ERROR("Error opening %s: %s",
				       optarg, fr_syserror(errno));
			       exit(1);
		       }
		       if (fgets(filesecret, sizeof(filesecret), fp) == NULL) {
			       ERROR("Error reading %s: %s",
				       optarg, fr_syserror(errno));
			       exit(1);
		       }
		       fclose(fp);

		       /* truncate newline */
		       p = filesecret + strlen(filesecret) - 1;
		       while ((p >= filesecret) &&
			      (*p < ' ')) {
			       *p = '\0';
			       --p;
		       }

		       if (strlen(filesecret) < 2) {
			       ERROR("Secret in %s is too short", optarg);
			       exit(1);
		       }
		       secret = filesecret;
		       break;
		case 'h':
		default:
			usage();
			break;
		}
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if ((argc < 3)  ||
	    ((!secret) && (argc < 4))) {
		usage();
	}


	if (!main_config.dictionary_dir) {
		main_config.dictionary_dir = DICTDIR;
	}

	/*
	 *	Read the distribution dictionaries first, then
	 *	the ones in raddb.
	 */
	DEBUG2("including dictionary file %s/%s", main_config.dictionary_dir, RADIUS_DICTIONARY);
	if (dict_init(main_config.dictionary_dir, RADIUS_DICTIONARY) != 0) {
		ERROR("Errors reading dictionary: %s", fr_strerror());
		exit(1);
	}

	/*
	 *	It's OK if this one doesn't exist.
	 */
	int rcode = dict_read(radius_dir, RADIUS_DICTIONARY);
	if (rcode == -1) {
		ERROR("Errors reading %s/%s: %s", radius_dir, RADIUS_DICTIONARY, fr_strerror());
		exit(1);
	}

	/*
	 *	We print this after reading it.  That way if
	 *	it doesn't exist, it's OK, and we don't print
	 *	anything.
	 */
	if (rcode == 0) {
		DEBUG2("Including dictionary file %s/%s", radius_dir, RADIUS_DICTIONARY);
	}

	req = rad_alloc(NULL, true);
	if (!req) {
		ERROR("%s", fr_strerror());
		exit(1);
	}
	req->id = id;

	/*
	 *	Resolve hostname.
	 */
	if (force_af == AF_UNSPEC) force_af = AF_INET;
	req->dst_ipaddr.af = force_af;
	if (strcmp(argv[1], "-") != 0) {
		char const *hostname = argv[1];
		char const *portname = argv[1];
		char buffer[256];

		if (*argv[1] == '[') { /* IPv6 URL encoded */
			p = strchr(argv[1], ']');
			if ((size_t) (p - argv[1]) >= sizeof(buffer)) {
				usage();
			}

			memcpy(buffer, argv[1] + 1, p - argv[1] - 1);
			buffer[p - argv[1] - 1] = '\0';

			hostname = buffer;
			portname = p + 1;

		}
		p = strchr(portname, ':');
		if (p && (strchr(p + 1, ':') == NULL)) {
			*p = '\0';
			portname = p + 1;
		} else {
			portname = NULL;
		}

		if (ip_hton(&req->dst_ipaddr, force_af, hostname, false) < 0) {
			ERROR("Failed to find IP address for host %s: %s", hostname, fr_syserror(errno));
			exit(1);
		}

		/*
		 *	Strip port from hostname if needed.
		 */
		if (portname) port = atoi(portname);
	}

	/*
	 *	See what kind of request we want to send.
	 */
	if (strcmp(argv[2], "auth") == 0) {
		if (port == 0) port = getport("radius");
		if (port == 0) port = PW_AUTH_UDP_PORT;
		req->code = PW_CODE_ACCESS_REQUEST;

	} else if (strcmp(argv[2], "acct") == 0) {
		if (port == 0) port = getport("radacct");
		if (port == 0) port = PW_ACCT_UDP_PORT;
		req->code = PW_CODE_ACCOUNTING_REQUEST;
		do_summary = 0;

	} else if (strcmp(argv[2], "status") == 0) {
		if (port == 0) port = getport("radius");
		if (port == 0) port = PW_AUTH_UDP_PORT;
		req->code = PW_CODE_STATUS_SERVER;

	} else if (strcmp(argv[2], "disconnect") == 0) {
		if (port == 0) port = PW_POD_UDP_PORT;
		req->code = PW_CODE_DISCONNECT_REQUEST;

	} else if (isdigit((int) argv[2][0])) {
		if (port == 0) port = getport("radius");
		if (port == 0) port = PW_AUTH_UDP_PORT;
		req->code = atoi(argv[2]);
	} else {
		usage();
	}
	req->dst_port = port;

	/*
	 *	Add the secret.
	 */
	if (argv[3]) secret = argv[3];

	/*
	 *	Read valuepairs.
	 *	Maybe read them, from stdin, if there's no
	 *	filename, or if the filename is '-'.
	 */
	if (filename && (strcmp(filename, "-") != 0)) {
		fp = fopen(filename, "r");
		if (!fp) {
			ERROR("Error opening %s: %s", filename, fr_syserror(errno));
			exit(1);
		}
	} else {
		fp = stdin;
	}

	/*
	 *	Send request.
	 */
	if ((req->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		ERROR("socket: %s", fr_syserror(errno));
		exit(1);
	}

	while (!filedone) {
		if (req->vps) pairfree(&req->vps);
		if (readvp2(&req->vps, NULL, fp, &filedone) < 0) {
			ERROR("%s", fr_strerror());
			break;
		}

		sendrecv_eap(req);
	}

	if (do_summary) {
		INFO("\n\t   Total approved auths:  %d", totalapp);
		INFO("\t     Total denied auths:  %d", totaldeny);
	}

	talloc_free(autofree);

	return 0;
}

/*
 * given a radius request with some attributes in the EAP range, build
 * them all into a single EAP-Message body.
 *
 * Note that this function will build multiple EAP-Message bodies
 * if there are multiple eligible EAP-types. This is incorrect, as the
 * recipient will in fact concatenate them.
 *
 * XXX - we could break the loop once we process one type. Maybe this
 *       just deserves an assert?
 *
 */
static void map_eap_methods(RADIUS_PACKET *req)
{
	VALUE_PAIR *vp, *vpnext;
	int id, eapcode;
	int eap_method;

	eap_packet_t *pt_ep = talloc_zero(req, eap_packet_t);

	vp = pairfind(req->vps, PW_EAP_ID, 0, TAG_ANY);
	if(!vp) {
		id = ((int)getpid() & 0xff);
	} else {
		id = vp->vp_integer;
	}

	vp = pairfind(req->vps, PW_EAP_CODE, 0, TAG_ANY);
	if(!vp) {
		eapcode = PW_EAP_REQUEST;
	} else {
		eapcode = vp->vp_integer;
	}

	for(vp = req->vps; vp != NULL; vp = vpnext) {
		/* save it in case it changes! */
		vpnext = vp->next;

		if(vp->da->attr >= PW_EAP_TYPE_BASE &&
		   vp->da->attr < PW_EAP_TYPE_BASE+256) {
			break;
		}
	}

	if(!vp) {
		return;
	}

	eap_method = vp->da->attr - PW_EAP_TYPE_BASE;

	switch(eap_method) {
	case PW_EAP_IDENTITY:
	case PW_EAP_NOTIFICATION:
	case PW_EAP_NAK:
	case PW_EAP_MD5:
	case PW_EAP_OTP:
	case PW_EAP_GTC:
	case PW_EAP_TLS:
	case PW_EAP_LEAP:
	case PW_EAP_TTLS:
	case PW_EAP_PEAP:
	default:
		/*
		 * no known special handling, it is just encoded as an
		 * EAP-message with the given type.
		 */

		/* nuke any existing EAP-Messages */
		pairdelete(&req->vps, PW_EAP_MESSAGE, 0, TAG_ANY);

		pt_ep->code = eapcode;
		pt_ep->id = id;
		pt_ep->type.num = eap_method;
		pt_ep->type.length = vp->length;

		pt_ep->type.data = talloc_memdup(vp, vp->vp_octets, vp->length);
		talloc_set_type(pt_ep->type.data, uint8_t);

		eap_basic_compose(req, pt_ep);
	}
}

/*
 * given a radius request with an EAP-Message body, decode it specific
 * attributes.
 */
static void unmap_eap_methods(RADIUS_PACKET *rep)
{
	VALUE_PAIR *eap1;
	eap_packet_raw_t *e;
	int len;
	int type;

	if (!rep) return;

	/* find eap message */
	e = eap_vp2packet(NULL, rep->vps);

	/* nothing to do! */
	if(!e) return;

	/* create EAP-ID and EAP-CODE attributes to start */
	eap1 = paircreate(rep, PW_EAP_ID, 0);
	eap1->vp_integer = e->id;
	pairadd(&(rep->vps), eap1);

	eap1 = paircreate(rep, PW_EAP_CODE, 0);
	eap1->vp_integer = e->code;
	pairadd(&(rep->vps), eap1);

	switch(e->code) {
	default:
	case PW_EAP_SUCCESS:
	case PW_EAP_FAILURE:
		/* no data */
		break;

	case PW_EAP_REQUEST:
	case PW_EAP_RESPONSE:
		/* there is a type field, which we use to create
		 * a new attribute */

		/* the length was decode already into the attribute
		 * length, and was checked already. Network byte
		 * order, just pull it out using math.
		 */
		len = e->length[0]*256 + e->length[1];

		/* verify the length is big enough to hold type */
		if(len < 5)
		{
			talloc_free(e);
			return;
		}

		type = e->data[0];

		type += PW_EAP_TYPE_BASE;
		len -= 5;

		if (len > MAX_STRING_LEN) {
			len = MAX_STRING_LEN;
		}

		eap1 = paircreate(rep, type, 0);
		pairmemcpy(eap1, e->data + 1, len);

		pairadd(&(rep->vps), eap1);
		break;
	}

	talloc_free(e);
	return;
}

static int map_eapsim_types(RADIUS_PACKET *r)
{
	int ret;

	eap_packet_t *pt_ep = talloc_zero(r, eap_packet_t);

	ret = map_eapsim_basictypes(r, pt_ep);

	if(ret != 1) {
		return ret;
	}

	eap_basic_compose(r, pt_ep);

	return 1;
}

static int unmap_eapsim_types(RADIUS_PACKET *r)
{
	VALUE_PAIR	     *esvp;
	uint8_t *eap_data;
	int rcode_unmap;

	esvp = pairfind(r->vps, PW_EAP_TYPE_BASE+PW_EAP_SIM, 0, TAG_ANY);
	if (!esvp) {
		ERROR("eap: EAP-Sim attribute not found");
		return 0;
	}

	eap_data = talloc_memdup(esvp, esvp->vp_octets, esvp->length);
	talloc_set_type(eap_data, uint8_t);

	rcode_unmap = unmap_eapsim_basictypes(r, eap_data, esvp->length);

	talloc_free(eap_data);
	return rcode_unmap;
}

#ifdef TEST_CASE

#include <assert.h>

char const *radius_dir = RADDBDIR;

main(int argc, char *argv[])
{
	int filedone;
	RADIUS_PACKET *req,*req2;
	VALUE_PAIR *vp, *vpkey, *vpextra;
	extern unsigned int sha1_data_problems;

	req = NULL;
	req2 = NULL;
	filedone = 0;

	if(argc>1) {
	  sha1_data_problems = 1;
	}

	if (dict_init(radius_dir, RADIUS_DICTIONARY) < 0) {
		ERROR("%s", fr_strerror());
		return 1;
	}

	req = rad_alloc(NULL, true)
	if (!req) {
		ERROR("%s", fr_strerror());
		exit(1);
	}

	req2 = rad_alloc(NULL, true);
	if (!req2) {
		ERROR("%s", fr_strerror());
		exit(1);
	}

	while(!filedone) {
		if (req->vps) pairfree(&req->vps);
		if (req2->vps) pairfree(&req2->vps);

		if (readvp2(&req->vps, NULL, stdin, &filedone) < 0) {
			ERROR("%s", fr_strerror());
			break;
		}

		if (fr_debug_flag > 1) {
			DEBUG("Read:");
			vp_printlist(stdout, req->vps);
		}

		map_eapsim_types(req);
		map_eap_methods(req);

		if (fr_debug_flag > 1) {
			DEBUG("Mapped to:");
			vp_printlist(stdout, req->vps);
		}

		/* find the EAP-Message, copy it to req2 */
		vp = paircopy_by_num(NULL, req->vps, PW_EAP_MESSAGE, 0, TAG_ANY);

		if(!vp) continue;

		pairadd(&req2->vps, vp);

		/* only call unmap for sim types here */
		unmap_eap_methods(req2);
		unmap_eapsim_types(req2);

		if (fr_debug_flag > 1) {
			DEBUG("Unmapped to:");
			vp_printlist(stdout, req2->vps);
		}

		vp = pairfind(req2->vps, PW_EAP_SIM_MAC, 0, TAG_ANY);
		vpkey   = pairfind(req->vps, PW_EAP_SIM_KEY, 0, TAG_ANY);
		vpextra = pairfind(req->vps, PW_EAP_SIM_EXTRA, 0, TAG_ANY);

		if(vp != NULL && vpkey != NULL && vpextra!=NULL) {
			uint8_t calcmac[16];

			/* find the EAP-Message, copy it to req2 */

			memset(calcmac, 0, sizeof(calcmac));
			DEBUG("Confirming MAC...");
			if(eapsim_checkmac(req2->vps, vpkey->vp_strvalue,
					   vpextra->vp_strvalue, vpextra->length,
					   calcmac)) {
				DEBUG("succeed");
			} else {
				int i, j;

				DEBUG("calculated MAC (");
				for (i = 0; i < 20; i++) {
					if(j==4) {
						DEBUG("_");
						j=0;
					}
					j++;

					DEBUG("%02x", calcmac[i]);
				}
				DEBUG("did not match");
			}
		}

		fflush(stdout);
	}
}
#endif

