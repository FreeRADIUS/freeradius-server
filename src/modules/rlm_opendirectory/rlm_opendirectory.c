/*
 * rlm_opendirectory.c
 *		authentication: Apple Open Directory authentication
 *		authorization:  enforces ACLs
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2 only, as published by
 *   the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License version 2
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2007-2010 Apple Inc.  All rights reserved.
 */

/*
 * 	For a typical Makefile, add linker flag like this:
 *	LDFLAGS = -framework OpenDirectory
 */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <uuid/uuid.h>

#include <OpenDirectory/OpenDirectory.h>
#include <membership.h>

#if HAVE_APPLE_SPI
#include <membershipPriv.h>
#else
int mbr_check_service_membership(const uuid_t user, const char *servicename, int *ismember);
int mbr_check_membership_refresh(const uuid_t user, uuid_t group, int *ismember);
#endif

/* RADIUS service ACL constants */
#define kRadiusSACLName		"com.apple.access_radius"
#define kRadiusServiceName	"radius"

#define kAuthType               "opendirectory"

/*
 * Finds the record in given node.
 *
 * Can return NULL.  If non-NULL is returned, caller must CFRelease() the
 * returned value.
 */
static ODRecordRef od_find_rec(REQUEST* request, ODNodeRef node, CFStringRef recName, const char* recNameStr)
{
    if (!node || !recName) return NULL;

    ODRecordRef rec = NULL;

    ODQueryRef query = ODQueryCreateWithNode(kCFAllocatorDefault,
                                             node,
                                             kODRecordTypeUsers,
                                             kODAttributeTypeRecordName,
                                             kODMatchEqualTo,
                                             recName,
                                             NULL,
                                             0,
                                             NULL);

    if (!query) {
        RDEBUG2("Unable to create OD query for %s", recNameStr);
    } else {
        CFArrayRef queryResults = ODQueryCopyResults(query, false, NULL);
        if (queryResults == NULL || CFArrayGetCount(queryResults) == 0) {
            RDEBUG2("Unable to find record '%s' in OD", recNameStr);
        } else {
            rec = (ODRecordRef)CFArrayGetValueAtIndex(queryResults, 0);
            CFRetain(rec);
            CFRelease(queryResults);
        }

        CFRelease(query);
    }

    return rec;
}

/*
 *	Check the users password against OD.
 */
static int od_authenticate(UNUSED void *instance, REQUEST *request)
{
	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!request->username) {
		RDEBUG("ERROR: Request does not contain a User-Name attribute!");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Can't do OpenDirectory if there's no password.
	 */
	if (!request->password ||
	    (request->password->attribute != PW_PASSWORD)) {
		RDEBUG("ERROR: Request does not contain a User-Password attribute!");
		return RLM_MODULE_INVALID;
	}
	
	/* Open Search node for querying. */
	ODNodeRef searchNode = ODNodeCreateWithName(kCFAllocatorDefault, kODSessionDefault, CFSTR("/Search"), NULL);
	if (!searchNode) {
		RDEBUG2("Unable to open OD search node");
		return RLM_MODULE_FAIL;
	}

	CFStringRef username = CFStringCreateWithCString(kCFAllocatorDefault,
							 request->username->vp_strvalue,
							 kCFStringEncodingUTF8);

	CFStringRef password = CFStringCreateWithCString(kCFAllocatorDefault,
							 request->password->vp_strvalue,
							 kCFStringEncodingUTF8);

	int status = RLM_MODULE_REJECT;
	CFErrorRef error = NULL;
	ODRecordRef rec = od_find_rec(request, searchNode, username, request->username->vp_strvalue);
	if (rec) {
		if (ODRecordVerifyPassword(rec, password, &error)) {
			status = RLM_MODULE_OK;
		} else {
			if (error == NULL) {
				RDEBUG2("Authentication failed for %s", request->username->vp_strvalue);
			} else {
				char* desc_str = NULL;
				CFStringRef desc = CFErrorCopyDescription(error);
				if (desc) {
					size_t desc_str_size = CFStringGetLength(desc) + 1;
					desc_str = malloc(desc_str_size);
					if (desc_str) {
						CFStringGetCString(desc,
								   desc_str,
								   desc_str_size,
								   kCFStringEncodingUTF8);
					}
				}

				RDEBUG2("Authentication failed for %s: error %d: %s",
					request->username->vp_strvalue, CFErrorGetCode(error),
					desc_str ? desc_str : "unknown error");

				CFRelease(error);
			}
		}

		CFRelease(rec);
	}

	if (username) CFRelease(username);
	if (password) CFRelease(password);
	CFRelease(searchNode);

	return status;
}


/*
 *	member of the radius group?
 */
static int od_authorize(UNUSED void *instance, REQUEST *request)
{
	struct group *groupdata = NULL;
	int ismember = 0;
	RADCLIENT *rad_client = NULL;
	uuid_t uuid;
	uuid_t guid_sacl;
	uuid_t guid_nasgroup;
	int err;
	char host_ipaddr[128] = {0};
	
	if (!request || !request->username) {
		RDEBUG("OpenDirectory requires a User-Name attribute.");
		return RLM_MODULE_NOOP;
	}
	
	/* resolve SACL */
	uuid_clear(guid_sacl);
	groupdata = getgrnam(kRadiusSACLName);
	if (groupdata != NULL) {
		err = mbr_gid_to_uuid(groupdata->gr_gid, guid_sacl);
		if (err != 0) {
			radlog(L_ERR, "rlm_opendirectory: The group \"%s\" does not have a GUID.", kRadiusSACLName);
			return RLM_MODULE_FAIL;
		}		
	}
	else {
		RDEBUG("The SACL group \"%s\" does not exist on this system.", kRadiusSACLName);
	}
	
	/* resolve client access list */
	uuid_clear(guid_nasgroup);

	rad_client = request->client;
#if 0
	if (rad_client->community[0] != '\0' )
	{
		/*
		 *	The "community" can be a GUID (Globally Unique ID) or
		 *	a group name
		 */
		if (uuid_parse(rad_client->community, guid_nasgroup) != 0) {
			/* attempt to resolve the name */
			groupdata = getgrnam(rad_client->community);
			if (groupdata == NULL) {
				radlog(L_AUTH, "rlm_opendirectory: The group \"%s\" does not exist on this system.", rad_client->community);
				return RLM_MODULE_FAIL;
			}
			err = mbr_gid_to_uuid(groupdata->gr_gid, guid_nasgroup);
			if (err != 0) {
				radlog(L_AUTH, "rlm_opendirectory: The group \"%s\" does not have a GUID.", rad_client->community);
				return RLM_MODULE_FAIL;
			}
		}
	}
	else
#endif
	{
		if (rad_client == NULL) {
			RDEBUG("The client record could not be found for host %s.",
					ip_ntoh(&request->packet->src_ipaddr,
						host_ipaddr, sizeof(host_ipaddr)));
		}
		else {
			RDEBUG("The host %s does not have an access group.",
					ip_ntoh(&request->packet->src_ipaddr,
						host_ipaddr, sizeof(host_ipaddr)));
		}
	}
	
	/* resolve user */
	uuid_clear(uuid);

	ODNodeRef searchNode = ODNodeCreateWithName(kCFAllocatorDefault, kODSessionDefault, CFSTR("/Search"), NULL);
	if (!searchNode) {
		RDEBUG2("Unable to open OD search node");
		return RLM_MODULE_FAIL;
	}

	CFStringRef username = CFStringCreateWithCString(kCFAllocatorDefault,
							 request->username->vp_strvalue,
							 kCFStringEncodingUTF8);

	ODRecordRef rec = od_find_rec(request, searchNode, username, request->username->vp_strvalue);
	if (!rec) {
		RDEBUG("User %s does not exist in OD", request->username->vp_strvalue);
	} else {
		RDEBUG("User %s exists in OD", request->username->vp_strvalue);
		CFArrayRef vals = ODRecordCopyValues(rec, kODAttributeTypeGUID, NULL);
		if (!vals || CFArrayGetCount(vals) == 0) {
			RDEBUG("Could not find GUID for user %s", request->username->vp_strvalue);
		} else {
		    CFTypeRef user_guid = CFArrayGetValueAtIndex(vals, 0);
			if (CFGetTypeID(user_guid) == CFStringGetTypeID()) {
				size_t len = CFStringGetLength(user_guid) + 1;
				char* user_guid_str = malloc(len);
				if (user_guid_str) {
					CFStringGetCString(user_guid, user_guid_str, len, kCFStringEncodingUTF8);
					uuid_parse(user_guid_str, uuid);
				}
			}
			CFRelease(vals);
		    }
		CFRelease(rec);
	}
	if (username) CFRelease(username);
	CFRelease(searchNode);

	/*
	 * Check the user membership in the access groups (if they exist).
	 */

	if (uuid_is_null(uuid)) {
		radius_pairmake(request, &request->packet->vps,
				"Module-Failure-Message", "Could not get the user's uuid", T_OP_EQ);
		return RLM_MODULE_NOTFOUND;
	}
	
	if (!uuid_is_null(guid_sacl)) {
		err = mbr_check_service_membership(uuid, kRadiusServiceName, &ismember);
		if (err != 0) {
			radius_pairmake(request, &request->packet->vps,
					"Module-Failure-Message", "Failed to check group membership", T_OP_EQ);
			return RLM_MODULE_FAIL;
		}
		
		if (ismember == 0) {
			RDEBUG("User %s is not a member of the RADUIS SACL", request->username->vp_strvalue);
			radius_pairmake(request, &request->packet->vps,
					"Module-Failure-Message", "User is not authorized", T_OP_EQ);
			return RLM_MODULE_REJECT;
		}

		RDEBUG("User %s is a member of the RADUIS SACL", request->username->vp_strvalue);
	}
	
	if (!uuid_is_null(guid_nasgroup)) {
		err = mbr_check_membership_refresh(uuid, guid_nasgroup, &ismember);
		if (err != 0) {
			radius_pairmake(request, &request->packet->vps,
					"Module-Failure-Message", "Failed to check group membership", T_OP_EQ);
			return RLM_MODULE_FAIL;
		}
		
		if (ismember == 0) {
			RDEBUG("User %s is not a member of the host access group", request->username->vp_strvalue);
			radius_pairmake(request, &request->packet->vps,
					"Module-Failure-Message", "User is not authorized", T_OP_EQ);
			return RLM_MODULE_REJECT;
		}

		RDEBUG("User %s is a member of the hostaccess group", request->username->vp_strvalue);
	}
	
	if (uuid_is_null(guid_sacl) && uuid_is_null(guid_nasgroup)) {
		RDEBUG("no access control groups, all OD users allowed.");
	}

	if (pairfind(request->config_items, PW_AUTH_TYPE) == NULL) {
		pairadd(&request->config_items, pairmake("Auth-Type", kAuthType, T_OP_EQ));
		RDEBUG("Setting Auth-Type = %s", kAuthType);
	}

	return RLM_MODULE_OK;
}


/* globally exported name */
module_t rlm_opendirectory = {
	RLM_MODULE_INIT,
	"opendirectory",
	RLM_TYPE_THREAD_SAFE,	/* type */
	NULL,			/* instantiation */
	NULL,               	/* detach */
	{
		od_authenticate, /* authentication */
		od_authorize,	/* authorization */
		NULL,		/* preaccounting */
		NULL,		/* accounting */
		NULL,		/* checksimul */
		NULL,		/* pre-proxy */
		NULL,		/* post-proxy */
		NULL		/* post-auth */
	},
};
