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
 * @copyright 2007 Apple Inc.
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/md5.h>

#include <ctype.h>

#include "smbdes.h"
#include "rlm_mschap.h"
#include "mschap.h"

#include <DirectoryService/DirectoryService.h>

#define kActiveDirLoc "/Active Directory/"

/*
 *	Only used by rlm_mschap.c
 */
rlm_rcode_t od_mschap_auth(REQUEST *request, VALUE_PAIR *challenge, VALUE_PAIR * usernamepair);


static rlm_rcode_t getUserNodeRef(REQUEST *request, char* inUserName, char **outUserName,
				  tDirNodeReference* userNodeRef, tDirReference dsRef)
{
	tDataBuffer	     	*tDataBuff	= NULL;
	tDirNodeReference       nodeRef		= 0;
	long		    	status		= eDSNoErr;
	char const		*what		= NULL;
	char			*status_name	= NULL;
	tContextData	    	context		= 0;
	uint32_t	   	nodeCount	= 0;
	uint32_t		attrIndex	= 0;
	tDataList	       *nodeName	= NULL;
	tAttributeEntryPtr      pAttrEntry	= NULL;
	tDataList	       *pRecName	= NULL;
	tDataList	       *pRecType	= NULL;
	tDataList	       *pAttrType	= NULL;
	uint32_t	   	recCount	= 0;
	tRecordEntry	    	*pRecEntry	= NULL;
	tAttributeListRef       attrListRef	= 0;
	char		    	*pUserLocation	= NULL;
	tAttributeValueListRef  valueRef	= 0;
	tDataList	       *pUserNode	= NULL;
	rlm_rcode_t		result		= RLM_MODULE_FAIL;

	if (!inUserName) {
		REDEBUG("getUserNodeRef(): No username");
		return RLM_MODULE_FAIL;
	}

	tDataBuff = dsDataBufferAllocate(dsRef, 4096);
	if (!tDataBuff) {
		REDEBUG("Failed allocating buffer");
		return RLM_MODULE_FAIL;
	}

	do {
		/* find on search node */
		status = dsFindDirNodes(dsRef, tDataBuff, NULL,
					eDSAuthenticationSearchNodeName,
					&nodeCount, &context);
#define OPEN_DIR_ERROR(_x) do if (status != eDSNoErr) { \
				what = _x; \
				goto error; \
			} while (0)

		OPEN_DIR_ERROR("Failed to find directory");

		if (nodeCount < 1) {
			what = "No directories found.";
			goto error;
		}

		status = dsGetDirNodeName(dsRef, tDataBuff, 1, &nodeName);
		OPEN_DIR_ERROR("Failed getting directory name");

		status = dsOpenDirNode(dsRef, nodeName, &nodeRef);
		dsDataListDeallocate(dsRef, nodeName);
		free(nodeName);
		nodeName = NULL;

		OPEN_DIR_ERROR("Failed opening directory");

		pRecName = dsBuildListFromStrings(dsRef, inUserName, NULL);
		pRecType = dsBuildListFromStrings(dsRef, kDSStdRecordTypeUsers,
						  NULL);
		pAttrType = dsBuildListFromStrings(dsRef,
						   kDSNAttrMetaNodeLocation,
						   kDSNAttrRecordName, NULL);

		recCount = 1;
		status = dsGetRecordList(nodeRef, tDataBuff, pRecName,
					 eDSExact, pRecType, pAttrType, 0,
					 &recCount, &context);
		OPEN_DIR_ERROR("Failed getting record list");

		if (recCount == 0) {
			what = "No user records returned";
			goto error;
		}

		status = dsGetRecordEntry(nodeRef, tDataBuff, 1,
					  &attrListRef, &pRecEntry);
		OPEN_DIR_ERROR("Failed getting record entry");

		for (attrIndex = 1; (attrIndex <= pRecEntry->fRecordAttributeCount) && (status == eDSNoErr); attrIndex++) {
			status = dsGetAttributeEntry(nodeRef, tDataBuff, attrListRef, attrIndex, &valueRef, &pAttrEntry);
			if (status == eDSNoErr && pAttrEntry != NULL) {
				tAttributeValueEntry    *pValueEntry	= NULL;

				if (strcmp(pAttrEntry->fAttributeSignature.fBufferData, kDSNAttrMetaNodeLocation) == 0) {
					status = dsGetAttributeValue(nodeRef, tDataBuff, 1, valueRef, &pValueEntry);
					if (status == eDSNoErr && pValueEntry != NULL) {
						pUserLocation = talloc_zero_array(request, char, pValueEntry->fAttributeValueData.fBufferLength + 1);
						memcpy(pUserLocation, pValueEntry->fAttributeValueData.fBufferData, pValueEntry->fAttributeValueData.fBufferLength);
					}
				} else if (strcmp(pAttrEntry->fAttributeSignature.fBufferData, kDSNAttrRecordName) == 0) {
					status = dsGetAttributeValue(nodeRef, tDataBuff, 1, valueRef, &pValueEntry);
					if (status == eDSNoErr && pValueEntry != NULL) {
						*outUserName = talloc_array(request, char, pValueEntry->fAttributeValueData.fBufferLength + 1);
						memcpy(*outUserName, pValueEntry->fAttributeValueData.fBufferData, pValueEntry->fAttributeValueData.fBufferLength);
					}
				}

				if (pValueEntry) {
					dsDeallocAttributeValueEntry(dsRef, pValueEntry);
					pValueEntry = NULL;
				}

				dsDeallocAttributeEntry(dsRef, pAttrEntry);
				pAttrEntry = NULL;
				dsCloseAttributeValueList(valueRef);
				valueRef = 0;
			}
		}

		if (!pUserLocation) {
			DEBUG2("[mschap] OpenDirectory has no user location");
			result = RLM_MODULE_NOOP;
			break;
		}

		/* OpenDirectory doesn't support mschapv2 authentication against
		 * Active Directory.  AD users need to be authenticated using the
		 * normal freeradius AD path (i.e. ntlm_auth).
		 */
		if (strncmp(pUserLocation, kActiveDirLoc, strlen(kActiveDirLoc)) == 0) {
			DEBUG2("[mschap] OpenDirectory authentication returning noop.  OD doesn't support MSCHAPv2 for ActiveDirectory users");
			result = RLM_MODULE_NOOP;
			break;
		}

		pUserNode = dsBuildFromPath(dsRef, pUserLocation, "/");
		if (!pUserNode) {
			RERROR("Failed building user from path");
			result = RLM_MODULE_FAIL;
			break;
		}

		status = dsOpenDirNode(dsRef, pUserNode, userNodeRef);
		dsDataListDeallocate(dsRef, pUserNode);
		free(pUserNode);

		if (status != eDSNoErr) {
		error:
			status_name = dsCopyDirStatusName(status);
			RERROR("%s: status = %s", what, status_name);
			free(status_name);
			result = RLM_MODULE_FAIL;
			break;
		}

		result = RLM_MODULE_OK;
	} while (0);

	if (pRecEntry != NULL) dsDeallocRecordEntry(dsRef, pRecEntry);

	if (tDataBuff != NULL) dsDataBufferDeAllocate(dsRef, tDataBuff);

	if (pUserLocation != NULL)
		talloc_free(pUserLocation);

	if (pRecName != NULL) {
		dsDataListDeallocate(dsRef, pRecName);
		free(pRecName);
	}
	if (pRecType != NULL) {
		dsDataListDeallocate(dsRef, pRecType);
		free(pRecType);
	}
	if (pAttrType != NULL) {
		dsDataListDeallocate(dsRef, pAttrType);
		free(pAttrType);
	}
	if (nodeRef != 0) dsCloseDirNode(nodeRef);

	return  result;
}

rlm_rcode_t od_mschap_auth(REQUEST *request, VALUE_PAIR *challenge, VALUE_PAIR * usernamepair)
{
	rlm_rcode_t		rcode		 = RLM_MODULE_OK;
	tDirStatus		status		 = eDSNoErr;
	tDirReference		dsRef		 = 0;
	tDirNodeReference	userNodeRef	 = 0;
	tDataBuffer		*tDataBuff	 = NULL;
	tDataBuffer		*pStepBuff	 = NULL;
	tDataNode		*pAuthType	 = NULL;
	uint32_t		uiCurr		 = 0;
	uint32_t		user_id_len		 = 0;
	char			*username_string = NULL;
	char			*short_user_name	 = NULL;
	VALUE_PAIR		*response;
#ifndef NDEBUG
	unsigned int t;
#endif

	response = fr_pair_find_by_da(request->packet->vps, attr_ms_chap2_response, TAG_ANY);

	username_string = talloc_array(request, char, usernamepair->vp_length + 1);
	if (!username_string) return RLM_MODULE_FAIL;

	strlcpy(username_string, usernamepair->vp_strvalue, usernamepair->vp_length + 1);

	status = dsOpenDirService(&dsRef);
	if (status != eDSNoErr) {
		talloc_free(username_string);
		RERROR("Failed opening directory service");
		return RLM_MODULE_FAIL;
	}

	rcode = getUserNodeRef(request, username_string, &short_user_name, &userNodeRef, dsRef);
	if (rcode != RLM_MODULE_OK) {
		if (rcode != RLM_MODULE_NOOP) {
			RDEBUG2("od_mschap_auth: getUserNodeRef() failed");
		}
		if (username_string != NULL)
			talloc_free(username_string);
		if (dsRef != 0)
			dsCloseDirService(dsRef);
		return rcode;
	}

	/* We got a node; fill the stepBuffer
	   kDSStdAuthMSCHAP2
	   MS-CHAPv2 authentication method. The Open Directory plug-in generates the reply data for the client.
	   The input buffer format consists of
	   a four byte length specifying the length of the user name that follows, the user name,
	   a four byte value specifying the length of the server challenge that follows, the server challenge,
	   a four byte value specifying the length of the peer challenge that follows, the peer challenge,
	   a four byte value specifying the length of the client's digest that follows, and the client's digest.
	   The output buffer consists of a four byte value specifying the length of the return digest for the client's challenge.
	   r = FillAuthBuff(pAuthBuff, 5,
	   strlen(inName), inName,						// Directory Services long or short name
	   strlen(schal), schal,						// server challenge
	   strlen(peerchal), peerchal,					// client challenge
	   strlen(p24), p24,							// P24 NT-Response
	   4, "User");									// must match the username that was used for the hash

	   inName		= 	username_string
	   schal		=   challenge->vp_strvalue
	   peerchal	=   response->vp_strvalue + 2 (16 octets)
	   p24			=   response->vp_strvalue + 26 (24 octets)
	*/
	pStepBuff = dsDataBufferAllocate(dsRef, 4096);
	tDataBuff = dsDataBufferAllocate(dsRef, 4096);
	pAuthType = dsDataNodeAllocateString(dsRef, kDSStdAuthMSCHAP2);
	uiCurr = 0;

	user_id_len = (uint32_t)short_user_name ? strlen(short_user_name) : 0;

	RDEBUG2("OD username_string = %s, OD short_user_name=%s (length = %u)",
		username_string, short_user_name, user_id_len);

	/* User name length + username */
	memcpy(&(tDataBuff->fBufferData[uiCurr]), &user_id_len, sizeof(user_id_len));
	uiCurr += sizeof(user_id_len);
	memcpy(&(tDataBuff->fBufferData[uiCurr]), short_user_name, user_id_len);
	uiCurr += user_id_len;
#ifndef NDEBUG
	RINDENT();
	RDEBUG2("Stepbuf server challenge : ");
	for (t = 0; t < challenge->vp_length; t++) {
		fprintf(stderr, "%02x", challenge->vp_strvalue[t]);
	}
	fprintf(stderr, "\n");
#endif

	/* server challenge (ie. my (freeRADIUS) challenge) */
	user_id_len = 16;
	memcpy(&(tDataBuff->fBufferData[uiCurr]), &user_id_len, sizeof(user_id_len));
	uiCurr += sizeof(user_id_len);
	memcpy(&(tDataBuff->fBufferData[uiCurr]), &(challenge->vp_strvalue[0]),
	       user_id_len);
	uiCurr += user_id_len;

#ifndef NDEBUG
	RDEBUG2("Stepbuf peer challenge   : ");
	for (t = 2; t < 18; t++) {
		fprintf(stderr, "%02x", response->vp_strvalue[t]);
	}
	fprintf(stderr, "\n");
#endif

	/* peer challenge (ie. the client-generated response) */
	user_id_len = 16;
	memcpy(&(tDataBuff->fBufferData[uiCurr]), &user_id_len, sizeof(user_id_len));
	uiCurr += sizeof(user_id_len);
	memcpy(&(tDataBuff->fBufferData[uiCurr]), &(response->vp_strvalue[2]),
	       user_id_len);
	uiCurr += user_id_len;

#ifndef NDEBUG
	RDEBUG2("Stepbuf p24              : ");
	REXDENT();
	for (t = 26; t < 50; t++) {
		fprintf(stderr, "%02x", response->vp_strvalue[t]);
	}
	fprintf(stderr, "\n");
#endif

	/* p24 (ie. second part of client-generated response) */
	user_id_len =  24; /* strlen(&(response->vp_strvalue[26])); may contain NULL byte in the middle. */
	memcpy(&(tDataBuff->fBufferData[uiCurr]), &user_id_len, sizeof(user_id_len));
	uiCurr += sizeof(user_id_len);

	memcpy(&(tDataBuff->fBufferData[uiCurr]), &(response->vp_strvalue[26]), user_id_len);
	uiCurr += user_id_len;

	/* Client generated use name (short name?) */
	user_id_len =  (uint32_t)strlen(username_string);
	memcpy(&(tDataBuff->fBufferData[uiCurr]), &user_id_len, sizeof(user_id_len));
	uiCurr += sizeof(user_id_len);
	memcpy(&(tDataBuff->fBufferData[uiCurr]), username_string, user_id_len);
	uiCurr += user_id_len;

	tDataBuff->fBufferLength = uiCurr;

	status = dsDoDirNodeAuth(userNodeRef, pAuthType, 1, tDataBuff, pStepBuff, NULL);
	if (status == eDSNoErr) {
		if (pStepBuff->fBufferLength > 4) {
			size_t len;

			memcpy(&len, pStepBuff->fBufferData, sizeof(len));
			if (len == 40) {
				char mschap_reply[42] = { '\0' };
				pStepBuff->fBufferData[len+4] = '\0';
				mschap_reply[0] = 'S';
				mschap_reply[1] = '=';
				memcpy(&(mschap_reply[2]), &(pStepBuff->fBufferData[4]), len);
				mschap_add_reply(request,
						 *response->vp_strvalue,
						 attr_ms_chap2_success,
						 mschap_reply, len + 2);
				RDEBUG2("dsDoDirNodeAuth returns stepbuff: %s (len=%zu)\n", mschap_reply, len);
			}
		}
	}

	/* clean up */
	if (username_string != NULL)
		talloc_free(username_string);
	if (short_user_name != NULL)
		talloc_free(short_user_name);

	if (tDataBuff != NULL)
		dsDataBufferDeAllocate(dsRef, tDataBuff);
	if (pStepBuff != NULL)
		dsDataBufferDeAllocate(dsRef, pStepBuff);
	if (pAuthType != NULL)
		dsDataNodeDeAllocate(dsRef, pAuthType);
	if (userNodeRef != 0)
		dsCloseDirNode(userNodeRef);
	if (dsRef != 0)
		dsCloseDirService(dsRef);

	if (status != eDSNoErr) {
		char *status_name = dsCopyDirStatusName(status);
		RERROR("Authentication failed - status = %s", status_name);
		free(status_name);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

#endif /* __APPLE__ */
