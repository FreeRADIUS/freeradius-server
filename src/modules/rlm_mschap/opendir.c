#ifdef __APPLE__
/*
 * Open Directory support from Apple Inc.
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

#include        <freeradius-devel/ident.h>
RCSID("$Id$")

#include        <freeradius-devel/radiusd.h>
#include        <freeradius-devel/modules.h>
#include        <freeradius-devel/rad_assert.h>
#include        <freeradius-devel/md5.h>

#include        <ctype.h>

#include        "mschap.h"

#include        <OpenDirectory/OpenDirectory.h>
#include        <nt/ntlm.h>


extern void mschap_add_reply(REQUEST *request, VALUE_PAIR** vp, unsigned char ident,
                             const char* name, const char* value, int len);

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
            RDEBUG2("Unable to find record %s in OD", recNameStr);
        } else {
            rec = (ODRecordRef)CFArrayGetValueAtIndex(queryResults, 0);
            CFRetain(rec);
            CFRelease(queryResults);
        }

        CFRelease(query);
    }

    return rec;
}


static CFErrorRef create_nt_error(uint32_t nt_status)
{
    CFStringRef desc = NULL;
    switch (nt_status) {
        case 0xC000005E: // STATUS_NO_LOGON_SERVERS
            desc = CFSTR("no logon servers");
            break;
        case 0xC0000064: // STATUS_NO_SUCH_USER
            desc = CFSTR("no such user");
            break;
        case 0xC000006A: // STATUS_WRONG_PASSWORD
            desc = CFSTR("no wrong password");
            break;
        case 0xC000006D: // STATUS_LOGON_FAILURE
            desc = CFSTR("logon failure");
            desc = CFStringCreateCopy(kCFAllocatorDefault, desc);
            break;
        case 0xC000006F: // STATUS_INVALID_LOGON_HOURS
            desc = CFSTR("invalid logon hours");
            break;
        case 0xC0000070: // STATUS_INVALID_WORKSTATION
            desc = CFSTR("invalid workstation");
            break;
        case 0xC0000071: // STATUS_PASSWORD_EXPIRED
            desc = CFSTR("password expired");
            break;
        case 0xC0000072: // STATUS_ACCOUNT_DISABLED
            desc = CFSTR("account disabled");
            break;
        case 0xC000000D: // STATUS_INVALID_PARAMETER
            desc = CFSTR("invalid parameter");
            break;
        default:
            desc = CFSTR("unknown error");
            break;
    }

    return CFErrorCreateWithUserInfoKeysAndValues(kCFAllocatorDefault,
                                                  CFSTR("com.apple.netlogon.freeradius"),
                                                  nt_status,
                                                  (const void* const*)&kCFErrorDescriptionKey,
                                                  (const void* const*)&desc,
                                                  1);
}

/*
 * Handles NT auth for AD users.
 */
static int od_nt_auth(REQUEST*    request,
                      VALUE_PAIR* response,
                      VALUE_PAIR* challenge,
                      ODNodeRef   node,
                      ODRecordRef rec,
                      CFStringRef recName,
                      const char* username_string,
                      CFErrorRef* error)
{
    int status = RLM_MODULE_REJECT;

    NTLM_LOGON_REQ logonReq = {
        .Version = NTLM_LOGON_REQ_VERSION,
        .LogonDomainName = NULL,
        .UserName = username_string,
        .Workstation = NULL,
        .LmChallenge = { 0 },
        .LmChallengeResponseLength = 0,
        .LmChallengeResponse = NULL,
        .NtChallengeResponseLength = 24,
        .NtChallengeResponse = response->vp_octets + 26
    };

    char *accountName = NULL;
    char *accountDomain = NULL;
    uint32_t userFlags = 0;
    uint8_t sessionKey[16] = { 0 };
    
    CFDataRef serverChallenge = NULL;
    if (challenge->length == 8) {
        serverChallenge = CFDataCreate(kCFAllocatorDefault, (UInt8*)challenge->vp_strvalue, 8);
    } else if (challenge->length == 16) {
        uint8_t buffer[32];
        mschap_challenge_hash(response->vp_octets + 2,
                              challenge->vp_octets,
                              username_string,
                              buffer);

        serverChallenge = CFDataCreate(kCFAllocatorDefault, (UInt8*)buffer, 8);
    }

    if (serverChallenge) {
        memcpy(logonReq.LmChallenge, CFDataGetBytePtr(serverChallenge), 8);
    }

    uint32_t auth_status = NTLMLogon(&logonReq, NULL, NULL, &accountName, &accountDomain, sessionKey, &userFlags);
    if (auth_status != 0) {
        *error = create_nt_error(auth_status);
    } else {
        char mschap_reply[42];
        memset(mschap_reply, 0, sizeof(mschap_reply));

        mschap_auth_response(username_string, /* without the domain */
                             sessionKey, /* nt-hash-hash */
                             response->vp_octets + 26, /* peer response */
                             response->vp_octets + 2, /* peer challenge */
                             challenge->vp_octets, /* our challenge */
                             mschap_reply); /* calculated MPPE key */
        mschap_add_reply(request, &request->reply->vps, *response->vp_octets,
                         "MS-CHAP2-Success", mschap_reply, 42);

        status = RLM_MODULE_OK;
    }

    CFRelease(serverChallenge);
    return status;
}

/*
 * Handles MSCHAPv2 auths for OD users.
 */
static int od_mschap_auth(REQUEST*    request,
                          VALUE_PAIR* response,
                          VALUE_PAIR* challenge,
                          ODNodeRef   node,
                          ODRecordRef rec,
                          CFStringRef recName,
                          CFErrorRef* error)
{
    int status = RLM_MODULE_REJECT;

    /* Create the array of auth-specific data to pass to OD and do the auth. */
    CFMutableArrayRef authItems = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if (authItems) {
        CFArrayInsertValueAtIndex(authItems, 0, recName);

        CFDataRef serverChallenge = CFDataCreate(kCFAllocatorDefault, (UInt8*)challenge->vp_strvalue, 16);
        CFArrayInsertValueAtIndex(authItems, 1, serverChallenge);
        CFRelease(serverChallenge);

        CFDataRef peerChallenge = CFDataCreate(kCFAllocatorDefault, (UInt8*)&response->vp_strvalue[2], 16);
        CFArrayInsertValueAtIndex(authItems, 2, peerChallenge);
        CFRelease(peerChallenge);

        CFDataRef p24 = CFDataCreate(kCFAllocatorDefault, (UInt8*)&response->vp_strvalue[26], 24);
        CFArrayInsertValueAtIndex(authItems, 3, p24);
        CFRelease(p24);

        CFArrayInsertValueAtIndex(authItems, 4, recName);
        CFArrayRef returnedItems = NULL;
        if (ODRecordVerifyPasswordExtended(rec, kODAuthenticationTypeMSCHAP2, authItems, &returnedItems, NULL, error) &&
            returnedItems && CFArrayGetCount(returnedItems) == 1)
        {
            /* Extract the data from OD and create the reply. */
            unsigned char* respData = NULL;
            size_t respDataLen = 0;
            CFTypeRef cfRespData = CFArrayGetValueAtIndex(returnedItems, 0);
            if (CFGetTypeID(cfRespData) == CFStringGetTypeID()) {
                respDataLen = CFStringGetLength(cfRespData);
                respData = malloc(respDataLen + 1);
                CFStringGetCString(cfRespData, (char*)respData, respDataLen+1, kCFStringEncodingUTF8);
            } else if (CFGetTypeID(cfRespData) == CFDataGetTypeID()) {
                respDataLen = CFDataGetLength(cfRespData);
                respData = malloc(respDataLen);
                CFDataGetBytes(cfRespData, CFRangeMake(0, respDataLen), respData);
            }

            if (respData) {
                if (respDataLen == 40) {
                    char mschap_reply[42];
                    memset(mschap_reply, 0, sizeof(mschap_reply));
                    mschap_reply[0] = 'S';
                    mschap_reply[1] = '=';
                    memcpy(&mschap_reply[2], respData, respDataLen);
                    mschap_add_reply(request,
                                     &request->reply->vps,
                                     *response->vp_strvalue,
                                     "MS-CHAP2-Success",
                                     mschap_reply,
                                     42);
                    status = RLM_MODULE_OK;
                }

                free(respData);
            }
        }

        if (returnedItems) CFRelease(returnedItems);
        CFRelease(authItems);
    }

    return status;
}


/*
 * Handles auths for both AD & OD users.
 */
int do_od_mschap(REQUEST*    request,
                 VALUE_PAIR* response,
                 VALUE_PAIR* challenge,
                 const char* username_string)
{
    RDEBUG2("Using OpenDirectory to authenticate");

    /* Open Search node for querying. */
    ODNodeRef searchNode = ODNodeCreateWithName(kCFAllocatorDefault, kODSessionDefault, CFSTR("/Search"), NULL);
    if (!searchNode) {
        RDEBUG2("Unable to open OD search node");
        return RLM_MODULE_FAIL;
    }

    /* Find the record to be used for the auth attempt. */
    int         status  = RLM_MODULE_FAIL;
    CFErrorRef  error   = NULL;
    CFStringRef recName = CFStringCreateWithCString(kCFAllocatorDefault, username_string, kCFStringEncodingUTF8);
    ODRecordRef rec     = od_find_rec(request, searchNode, recName, username_string);
    if (rec) {
        CFArrayRef vals = ODRecordCopyValues(rec, kODAttributeTypeMetaNodeLocation, NULL);
        if (vals && CFArrayGetCount(vals) != 0) {
            /* opendirectoryd supports MSCHAPv2 for OD users but not for AD
             * users.  Use netlogon for AD users.
             */
            CFStringRef metaNodeLoc = CFArrayGetValueAtIndex(vals, 0);
            if (CFStringFind(metaNodeLoc, CFSTR("/Active Directory/"), 0).location == kCFNotFound) {
                RDEBUG2("Doing OD MSCHAPv2 auth");
                status = od_mschap_auth(request, response, challenge, searchNode, rec, recName, &error);
            } else {
                RDEBUG2("Doing AD netlogon auth");
                status = od_nt_auth(request, response, challenge, searchNode, rec, recName, username_string, &error);
            }
        }
        CFRelease(rec);
    }

    if (recName) CFRelease(recName);
    CFRelease(searchNode);

    /* On success the auth functions have already created the response
     * data since the work differs for AD & OD. Handle the error response
     * here since it's common.
     */
    if (status == RLM_MODULE_OK) {
        RDEBUG2("Successful authentication for %s", username_string);
    } else {
        mschap_add_reply(request, &request->reply->vps,
                         *response->vp_octets,
                         "MS-CHAP-Error", "E=691 R=1", 9);
        if (error == NULL) {
            RDEBUG2("Authentication failed for %s", username_string);
        } else {
            char* desc_str = NULL;
            CFDictionaryRef userInfo = CFErrorCopyUserInfo(error);
            if (userInfo) {
                CFStringRef desc = CFDictionaryGetValue(userInfo, kCFErrorDescriptionKey);
                if (desc) {
                    size_t desc_str_size = CFStringGetLength(desc) + 1;
                    desc_str = malloc(desc_str_size);
                    if (desc_str) {
                        if (!CFStringGetCString(desc, desc_str, desc_str_size, kCFStringEncodingUTF8)) {
                            free(desc_str);
                            desc_str = NULL;
                        }
                    }
                }
                CFRelease(userInfo);
            }
            RDEBUG2("Authentication failed for %s: error %d (0x%x): %s",
                    username_string,
                    CFErrorGetCode(error),
                    CFErrorGetCode(error),
                    desc_str ? desc_str : "unknown error");

            if (desc_str) free(desc_str);
            CFRelease(error);
        }
    }

    return status;
}

#endif /* __APPLE__ */
