/*
 *   This software is Copyright (C) 2006,2007 FH Hannover
 *
 *   Portions of this code unrelated to FreeRADIUS are available
 *   separately under a commercial license.  If you require an
 *   implementation of EAP-TNC that is not under the GPLv2, please
 *   contact tnc@inform.fh-hannover.de for details.
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
 */
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include "tncs_connect.h"
#include <ltdl.h>
#include <stdlib.h>
#include <stdio.h>
#include <eap.h>

     /*
      *	FIXME: This linking should really be done at compile time.
      */
static lt_dlhandle handle = NULL;

static ExchangeTNCCSMessagePointer callTNCS = NULL;

/*
 * returns the function-pointer to a function of a shared-object
 * 
 * soHandle: handle to a shared-object
 * name: name of the requested function
 * 
 * return: the procAddress if found, else NULL
 */
static void *getProcAddress(lt_dlhandle soHandle, const char *name){
	void *proc = lt_dlsym(soHandle, name);
	DEBUG("Searching for function %s", name);
	if(proc == NULL){
		DEBUG("rlm_eap_tnc: Failed to resolve symbol %s: %s",
		      name, lt_dlerror());
	}
	return proc;
}


/*
 * establishs the connection to the TNCCS without calling functionality.
 * That means that the TNCS-shared-object is loaded and the function-pointer
 * to "exchangeTNCCSMessages" is explored.
 * 
 * return: -1 if connect failed, 0 if connect was successful
 */
int connectToTncs(char *pathToSO){
	int state = -1;
	if(handle==NULL){
		handle = lt_dlopen(pathToSO);
		DEBUG("OPENED HANDLE!");
	}
	
	if(handle==NULL){
		DEBUG("HANDLE IS NULL");
        DEBUG("rlm_eap_tnc: Failed to link to library %s: %s",
	      pathToSO, lt_dlerror());
	}else{
		DEBUG("SO %s found!", pathToSO);
		if(callTNCS==NULL){
			callTNCS = (ExchangeTNCCSMessagePointer) getProcAddress(handle, "exchangeTNCCSMessages");
		}
		if(callTNCS!=NULL){
			DEBUG("TNCS is connected");
			state = 0;
//			int ret = callTNCS2(2, "Bla", NULL);
	//		DEBUG("GOT %d from exchangeTNCCSMessages", ret);
		}else{
			DEBUG("Could not find exchangeTNCCSMessages");
		}

	}
	return state;	
}

/*
 * Accesspoint to the TNCS for sending and receiving TNCCS-Messages.
 * -pathToSO: Path to TNCCS-Shared Object 
 * -connId: identifies the client which the passed message belongs to.
 * -isAcknoledgement: 1 if acknoledgement received (then all following in-parameters unimportant
 * -input: input-TNCCS-message received from the client with connId
 * -inputLength: length of input-TNCCS-message
 * -isFirst: 1 if first message in fragmentation else 0
 * -moreFragments: are there more Fragments to come (yes: 1, no: 0)?
 * -overallLength: length of all fragments together (only set if fragmentation)
 * -output: answer-TNCCS-message from the TNCS to the client
 * -outputLength: length of answer-TNCCS-message
 * -answerIsFirst: returned answer is first in row
 * -moreFragmentsFollow: more fragments after this answer
 * -overallLengthOut: length of all fragments together (only set if fragmentation) as answer
 * 
 * return: state of connection as result of the exchange
 */
TNC_ConnectionState exchangeTNCCSMessages(/*in*/ char *pathToSO,
                                          /*in*/ TNC_ConnectionID connId, 
                                          /*in*/ int isAcknoledgement,
					  /*in*/ TNC_BufferReference input, 
                                          /*in*/ TNC_UInt32 inputLength,
                                          /*in*/ int isFirst, 
                                          /*in*/ int moreFragments,
                                          /*in*/ TNC_UInt32 overallLength,
					  /*out*/ TNC_BufferReference *output,
                                          /*out*/ TNC_UInt32 *outputLength,
                                          /*out*/ int *answerIsFirst,
                                          /*out*/ int *moreFragmentsFollow,
                                          /*out*/ TNC_UInt32 *overallLengthOut){
	TNC_ConnectionState state = TNC_CONNECTION_STATE_ACCESS_NONE;
	int connectStatus = connectToTncs(pathToSO);
    if(connectStatus!=-1){
		state = callTNCS(connId,
                            isAcknoledgement,
                            input,
                            inputLength, 
                            isFirst, 
                            moreFragments, 
                            overallLength, 
                            output, 
                            outputLength, 
                            answerIsFirst, 
                            moreFragmentsFollow, 
                            overallLengthOut);
        DEBUG("GOT TNC_ConnectionState (juhuuu): %u", (unsigned int) state);
	}else{
		DEBUG("CAN NOT CONNECT TO TNCS");
	}
	return state;
}
