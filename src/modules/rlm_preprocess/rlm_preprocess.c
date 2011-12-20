/*
 * rlm_preprocess.c
 *		Contains the functions for the "huntgroups" and "hints"
 *		files.
 *
 * Version:     $Id$
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
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>

#include	<ctype.h>

typedef struct rlm_preprocess_t {
	char		*huntgroup_file;
	char		*hints_file;
	PAIR_LIST	*huntgroups;
	PAIR_LIST	*hints;
	int		with_ascend_hack;
	int		ascend_channels_per_line;
	int		with_ntdomain_hack;
	int		with_specialix_jetstream_hack;
	int		with_cisco_vsa_hack;
	int		with_alvarion_vsa_hack;
} rlm_preprocess_t;

static const CONF_PARSER module_config[] = {
	{ "huntgroups",			PW_TYPE_FILENAME,
	  offsetof(rlm_preprocess_t,huntgroup_file), NULL,
	  "${raddbdir}/huntgroups" },
	{ "hints",			PW_TYPE_FILENAME,
	  offsetof(rlm_preprocess_t,hints_file), NULL,
	  "${raddbdir}/hints" },
	{ "with_ascend_hack",		PW_TYPE_BOOLEAN,
	  offsetof(rlm_preprocess_t,with_ascend_hack), NULL, "no" },
	{ "ascend_channels_per_line",   PW_TYPE_INTEGER,
	  offsetof(rlm_preprocess_t,ascend_channels_per_line), NULL, "23" },

	{ "with_ntdomain_hack",		PW_TYPE_BOOLEAN,
	  offsetof(rlm_preprocess_t,with_ntdomain_hack), NULL, "no" },
	{ "with_specialix_jetstream_hack",  PW_TYPE_BOOLEAN,
	  offsetof(rlm_preprocess_t,with_specialix_jetstream_hack), NULL,
	  "no" },
	{ "with_cisco_vsa_hack",        PW_TYPE_BOOLEAN,
	  offsetof(rlm_preprocess_t,with_cisco_vsa_hack), NULL, "no" },
	{ "with_alvarion_vsa_hack",        PW_TYPE_BOOLEAN,
	  offsetof(rlm_preprocess_t,with_alvarion_vsa_hack), NULL, "no" },

	{ NULL, -1, 0, NULL, NULL }
};

/*
 *     See if a VALUE_PAIR list contains Fall-Through = Yes
 */
static int fallthrough(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = pairfind(vp, PW_FALL_THROUGH);

	return tmp ? tmp->lvalue : 0;
}

/*
 *	dgreer --
 *	This hack changes Ascend's wierd port numberings
 *	to standard 0-??? port numbers so that the "+" works
 *	for IP address assignments.
 */
static void ascend_nasport_hack(VALUE_PAIR *nas_port, int channels_per_line)
{
	int service;
	int line;
	int channel;

	if (!nas_port) {
		return;
	}

	if (nas_port->vp_integer > 9999) {
		service = nas_port->vp_integer/10000; /* 1=digital 2=analog */
		line = (nas_port->vp_integer - (10000 * service)) / 100;
		channel = nas_port->vp_integer-((10000 * service)+(100 * line));
		nas_port->vp_integer =
			(channel - 1) + (line - 1) * channels_per_line;
	}
}

/*
 *	ThomasJ --
 *	This hack strips out Cisco's VSA duplicities in lines
 *	(Cisco not implemented VSA's in standard way.
 *
 *	Cisco sends it's VSA attributes with the attribute name *again*
 *	in the string, like:  H323-Attribute = "h323-attribute=value".
 *	This sort of behaviour is nonsense.
 */
static void cisco_vsa_hack(VALUE_PAIR *vp)
{
	int		vendorcode;
	char		*ptr;
	char		newattr[MAX_STRING_LEN];

	for ( ; vp != NULL; vp = vp->next) {
		vendorcode = VENDOR(vp->attribute);
		if (!((vendorcode == 9) || (vendorcode == 6618))) continue; /* not a Cisco or Quintum VSA, continue */

		if (vp->type != PW_TYPE_STRING) continue;

		/*
		 *  No weird packing.  Ignore it.
		 */
		ptr = strchr(vp->vp_strvalue, '='); /* find an '=' */
		if (!ptr) continue;

		/*
		 *	Cisco-AVPair's get packed as:
		 *
		 *	Cisco-AVPair = "h323-foo-bar = baz"
		 *	Cisco-AVPair = "h323-foo-bar=baz"
		 *
		 *	which makes sense only if you're a lunatic.
		 *	This code looks for the attribute named inside
		 *	of the string, and if it exists, adds it as a new
		 *	attribute.
		 */
		if ((vp->attribute & 0xffff) == 1) {
			const char *p;
			DICT_ATTR	*dattr;

			p = vp->vp_strvalue;
			gettoken(&p, newattr, sizeof(newattr));

			if ((dattr = dict_attrbyname(newattr)) != NULL) {
				VALUE_PAIR *newvp;

				/*
				 *  Make a new attribute.
				 */
				newvp = pairmake(newattr, ptr + 1, T_OP_EQ);
				if (newvp) {
					pairadd(&vp, newvp);
				}
			}
		} else {	/* h322-foo-bar = "h323-foo-bar = baz" */
			/*
			 *	We strip out the duplicity from the
			 *	value field, we use only the value on
			 *	the right side of the '=' character.
			 */
			strlcpy(newattr, ptr + 1, sizeof(newattr));
			strlcpy((char *)vp->vp_strvalue, newattr,
				sizeof(vp->vp_strvalue));
			vp->length = strlen((char *)vp->vp_strvalue);
		}
	}
}


/*
 *	Don't even ask what this is doing...
 */
static void alvarion_vsa_hack(VALUE_PAIR *vp)
{
	int		vendorcode;
	int		number = 1;

	for ( ; vp != NULL; vp = vp->next) {
		DICT_ATTR *da;

		vendorcode = VENDOR(vp->attribute);
		if (vendorcode != 12394) continue;
		if (vp->type != PW_TYPE_STRING) continue;

		da = dict_attrbyvalue(number | (12394 << 16));
		if (!da) continue;

		vp->attribute = da->attr;
		vp->name = da->name;

		number++;
	}
}

/*
 *	Mangle username if needed, IN PLACE.
 */
static void rad_mangle(rlm_preprocess_t *data, REQUEST *request)
{
	int		num_proxy_state;
	VALUE_PAIR	*namepair;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	*tmp;

	/*
	 *	Get the username from the request
	 *	If it isn't there, then we can't mangle the request.
	 */
	request_pairs = request->packet->vps;
	namepair = pairfind(request_pairs, PW_USER_NAME);
	if ((namepair == NULL) ||
	    (namepair->length <= 0)) {
	  return;
	}

	if (data->with_ntdomain_hack) {
		char		*ptr;
		char		newname[MAX_STRING_LEN];

		/*
		 *	Windows NT machines often authenticate themselves as
		 *	NT_DOMAIN\username. Try to be smart about this.
		 *
		 *	FIXME: should we handle this as a REALM ?
		 */
		if ((ptr = strchr(namepair->vp_strvalue, '\\')) != NULL) {
			strlcpy(newname, ptr + 1, sizeof(newname));
			/* Same size */
			strcpy(namepair->vp_strvalue, newname);
			namepair->length = strlen(newname);
		}
	}

	if (data->with_specialix_jetstream_hack) {
		char		*ptr;

		/*
		 *	Specialix Jetstream 8500 24 port access server.
		 *	If the user name is 10 characters or longer, a "/"
		 *	and the excess characters after the 10th are
		 *	appended to the user name.
		 *
		 *	Reported by Lucas Heise <root@laonet.net>
		 */
		if ((strlen((char *)namepair->vp_strvalue) > 10) &&
		    (namepair->vp_strvalue[10] == '/')) {
			for (ptr = (char *)namepair->vp_strvalue + 11; *ptr; ptr++)
				*(ptr - 1) = *ptr;
			*(ptr - 1) = 0;
			namepair->length = strlen((char *)namepair->vp_strvalue);
		}
	}

	/*
	 *	Small check: if Framed-Protocol present but Service-Type
	 *	is missing, add Service-Type = Framed-User.
	 */
	if (pairfind(request_pairs, PW_FRAMED_PROTOCOL) != NULL &&
	    pairfind(request_pairs, PW_SERVICE_TYPE) == NULL) {
		tmp = radius_paircreate(request, &request->packet->vps,
					PW_SERVICE_TYPE, PW_TYPE_INTEGER);
		tmp->vp_integer = PW_FRAMED_USER;
	}

	num_proxy_state = 0;
	for (tmp = request->packet->vps; tmp != NULL; tmp = tmp->next) {
		if (tmp->vendor != 0) continue;
		if (tmp->attribute != PW_PROXY_STATE) continue;

		num_proxy_state++;
	}

	if (num_proxy_state > 10) {
		DEBUG("WARNING: There are more than 10 Proxy-State attributes in the request.");
		DEBUG("WARNING: You have likely configured an infinite proxy loop.");
	}
}

/*
 *	Compare the request with the "reply" part in the
 *	huntgroup, which normally only contains username or group.
 *	At least one of the "reply" items has to match.
 */
static int hunt_paircmp(REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check)
{
	VALUE_PAIR	*check_item = check;
	VALUE_PAIR	*tmp;
	int		result = -1;

	if (check == NULL) return 0;

	while (result != 0 && check_item != NULL) {

		tmp = check_item->next;
		check_item->next = NULL;

		result = paircompare(req, request, check_item, NULL);

		check_item->next = tmp;
		check_item = check_item->next;
	}

	return result;
}


/*
 *	Add hints to the info sent by the terminal server
 *	based on the pattern of the username, and other attributes.
 */
static int hints_setup(PAIR_LIST *hints, REQUEST *request)
{
	char		*name;
	VALUE_PAIR	*add;
	VALUE_PAIR	*tmp;
	PAIR_LIST	*i;
	VALUE_PAIR *request_pairs;
	int		updated = 0, ft;


	request_pairs = request->packet->vps;

	if (hints == NULL || request_pairs == NULL)
		return RLM_MODULE_NOOP;

	/*
	 *	Check for valid input, zero length names not permitted
	 */
	if ((tmp = pairfind(request_pairs, PW_USER_NAME)) == NULL)
		name = NULL;
	else
		name = (char *)tmp->vp_strvalue;

	if (name == NULL || name[0] == 0)
		/*
		 *	No name, nothing to do.
		 */
		return RLM_MODULE_NOOP;

	for (i = hints; i; i = i->next) {
		/*
		 *	Use "paircompare", which is a little more general...
		 */
		if (((strcmp(i->name, "DEFAULT") == 0) ||
		     (strcmp(i->name, name) == 0)) &&
		    (paircompare(request, request_pairs, i->check, NULL) == 0)) {
			RDEBUG2("  hints: Matched %s at %d",
			       i->name, i->lineno);
			/*
			 *	Now add all attributes to the request list,
			 *	except PW_STRIP_USER_NAME and PW_FALL_THROUGH
			 *	and xlat them.
			 */
			add = paircopy(i->reply);
			ft = fallthrough(add);
			pairdelete(&add, PW_STRIP_USER_NAME);
			pairdelete(&add, PW_FALL_THROUGH);
			pairxlatmove(request, &request->packet->vps, &add);
			pairfree(&add);
			updated = 1;
			if (!ft) break;
		}
	}

	if (updated == 0) return RLM_MODULE_NOOP;

	return RLM_MODULE_UPDATED;
}

/*
 *	See if we have access to the huntgroup.
 */
static int huntgroup_access(REQUEST *request, PAIR_LIST *huntgroups)
{
	PAIR_LIST	*i;
	int		r = RLM_MODULE_OK;
	VALUE_PAIR	*request_pairs = request->packet->vps;

	/*
	 *	We're not controlling access by huntgroups:
	 *	Allow them in.
	 */
	if (huntgroups == NULL)
		return RLM_MODULE_OK;

	for(i = huntgroups; i; i = i->next) {
		/*
		 *	See if this entry matches.
		 */
		if (paircompare(request, request_pairs, i->check, NULL) != 0)
			continue;

		/*
		 *	Now check for access.
		 */
		r = RLM_MODULE_REJECT;
		if (hunt_paircmp(request, request_pairs, i->reply) == 0) {
			VALUE_PAIR *vp;

			/*
			 *  We've matched the huntgroup, so add it in
			 *  to the list of request pairs.
			 */
			vp = pairfind(request_pairs, PW_HUNTGROUP_NAME);
			if (!vp) {
				vp = radius_paircreate(request,
						       &request->packet->vps,
						       PW_HUNTGROUP_NAME,
						       PW_TYPE_STRING);
				strlcpy(vp->vp_strvalue, i->name,
					sizeof(vp->vp_strvalue));
				vp->length = strlen(vp->vp_strvalue);
			}
			r = RLM_MODULE_OK;
		}
		break;
	}

	return r;
}

/*
 *	If the NAS wasn't smart enought to add a NAS-IP-Address
 *	to the request, then add it ourselves.
 */
static int add_nas_attr(REQUEST *request)
{
	VALUE_PAIR *nas;

	switch (request->packet->src_ipaddr.af) {
	case AF_INET:
		nas = pairfind(request->packet->vps, PW_NAS_IP_ADDRESS);
		if (!nas) {
			nas = radius_paircreate(request, &request->packet->vps,
						PW_NAS_IP_ADDRESS,
						PW_TYPE_IPADDR);
			nas->vp_ipaddr = request->packet->src_ipaddr.ipaddr.ip4addr.s_addr;
		}
		break;

	case AF_INET6:
		nas = pairfind(request->packet->vps, PW_NAS_IPV6_ADDRESS);
		if (!nas) {
			nas = radius_paircreate(request, &request->packet->vps,
						PW_NAS_IPV6_ADDRESS,
						PW_TYPE_IPV6ADDR);
			memcpy(nas->vp_strvalue,
			       &request->packet->src_ipaddr.ipaddr,
			       sizeof(request->packet->src_ipaddr.ipaddr));
		}
		break;

	default:
		radlog(L_ERR, "Unknown address family for packet");
		return -1;
	}

	return 0;
}


/*
 *	Initialize.
 */
static int preprocess_instantiate(CONF_SECTION *conf, void **instance)
{
	int	rcode;
	rlm_preprocess_t *data;

	/*
	 *	Allocate room to put the module's instantiation data.
	 */
	data = (rlm_preprocess_t *) rad_malloc(sizeof(*data));
	memset(data, 0, sizeof(*data));

	/*
	 *	Read this modules configuration data.
	 */
        if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
                return -1;
        }

	data->huntgroups = NULL;
	data->hints = NULL;

	/*
	 *	Read the huntgroups file.
	 */
	if (data->huntgroup_file) {
		rcode = pairlist_read(data->huntgroup_file,
				      &(data->huntgroups), 0);
		if (rcode < 0) {
			radlog(L_ERR|L_CONS, "rlm_preprocess: Error reading %s",
			       data->huntgroup_file);
			return -1;
		}
	}

	/*
	 *	Read the hints file.
	 */
	if (data->hints_file) {
		rcode = pairlist_read(data->hints_file, &(data->hints), 0);
		if (rcode < 0) {
			radlog(L_ERR|L_CONS, "rlm_preprocess: Error reading %s",
			       data->hints_file);
			return -1;
		}
	}

	/*
	 *	Save the instantiation data for later.
	 */
	*instance = data;

	return 0;
}

/*
 *	Preprocess a request.
 */
static int preprocess_authorize(void *instance, REQUEST *request)
{
	int r;
	rlm_preprocess_t *data = (rlm_preprocess_t *) instance;

	/*
	 *	Mangle the username, to get rid of stupid implementation
	 *	bugs.
	 */
	rad_mangle(data, request);

	if (data->with_ascend_hack) {
		/*
		 *	If we're using Ascend systems, hack the NAS-Port-Id
		 *	in place, to go from Ascend's weird values to something
		 *	approaching rationality.
		 */
		ascend_nasport_hack(pairfind(request->packet->vps,
					     PW_NAS_PORT),
				    data->ascend_channels_per_line);
	}

	if (data->with_cisco_vsa_hack) {
	 	/*
		 *	We need to run this hack because the h323-conf-id
		 *	attribute should be used.
		 */
		cisco_vsa_hack(request->packet->vps);
	}

	if (data->with_alvarion_vsa_hack) {
	 	/*
		 *	We need to run this hack because the Alvarion
		 *	people are crazy.
		 */
		alvarion_vsa_hack(request->packet->vps);
	}

	/*
	 *	Note that we add the Request-Src-IP-Address to the request
	 *	structure BEFORE checking huntgroup access.  This allows
	 *	the Request-Src-IP-Address to be used for huntgroup
	 *	comparisons.
	 */
	if (add_nas_attr(request) < 0) {
		return RLM_MODULE_FAIL;
	}

	hints_setup(data->hints, request);

	/*
	 *      If there is a PW_CHAP_PASSWORD attribute but there
	 *      is PW_CHAP_CHALLENGE we need to add it so that other
	 *	modules can use it as a normal attribute.
	 */
	if (pairfind(request->packet->vps, PW_CHAP_PASSWORD) &&
	    pairfind(request->packet->vps, PW_CHAP_CHALLENGE) == NULL) {
		VALUE_PAIR *vp;

		vp = radius_paircreate(request, &request->packet->vps,
				       PW_CHAP_CHALLENGE, PW_TYPE_OCTETS);
		vp->length = AUTH_VECTOR_LEN;
		memcpy(vp->vp_strvalue, request->packet->vector, AUTH_VECTOR_LEN);
	}

	if ((r = huntgroup_access(request,
				  data->huntgroups)) != RLM_MODULE_OK) {
		char buf[1024];
		radlog_request(L_AUTH, 0, request, "No huntgroup access: [%s] (%s)",
		       request->username ? request->username->vp_strvalue : "<NO User-Name>",
		       auth_name(buf, sizeof(buf), request, 1));
		return r;
	}

	return RLM_MODULE_OK; /* Meaning: try next authorization module */
}

/*
 *	Preprocess a request before accounting
 */
static int preprocess_preaccounting(void *instance, REQUEST *request)
{
	int r;
	rlm_preprocess_t *data = (rlm_preprocess_t *) instance;

	/*
	 *  Ensure that we have the SAME user name for both
	 *  authentication && accounting.
	 */
	rad_mangle(data, request);

	if (data->with_cisco_vsa_hack) {
	 	/*
		 *	We need to run this hack because the h323-conf-id
		 *	attribute should be used.
		 */
		cisco_vsa_hack(request->packet->vps);
	}

	if (data->with_alvarion_vsa_hack) {
	 	/*
		 *	We need to run this hack because the Alvarion
		 *	people are crazy.
		 */
		alvarion_vsa_hack(request->packet->vps);
	}

	/*
	 *  Ensure that we log the NAS IP Address in the packet.
	 */
	if (add_nas_attr(request) < 0) {
		return RLM_MODULE_FAIL;
	}

	hints_setup(data->hints, request);

	if ((r = huntgroup_access(request,
				  data->huntgroups)) != RLM_MODULE_OK) {
		char buf[1024];
		radlog_request(L_INFO, 0, request, "No huntgroup access: [%s] (%s)",
		       request->username ? request->username->vp_strvalue : "<NO User-Name>",
		       auth_name(buf, sizeof(buf), request, 1));
		return r;
	}

	return r;
}

/*
 *      Clean up the module's instance.
 */
static int preprocess_detach(void *instance)
{
	rlm_preprocess_t *data = (rlm_preprocess_t *) instance;

	pairlist_free(&(data->huntgroups));
	pairlist_free(&(data->hints));

	free(data);

	return 0;
}

/* globally exported name */
module_t rlm_preprocess = {
	RLM_MODULE_INIT,
	"preprocess",
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	preprocess_instantiate,	/* instantiation */
	preprocess_detach,	/* detach */
	{
		NULL,			/* authentication */
		preprocess_authorize,	/* authorization */
		preprocess_preaccounting, /* pre-accounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};

