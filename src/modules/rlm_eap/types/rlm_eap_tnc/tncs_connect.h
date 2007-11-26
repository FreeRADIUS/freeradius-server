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

#ifndef _TNCS_CONNECT_H_
#define _TNCS_CONNECT_H_

#include "tncs.h"

/*
 * establishs the connection to the TNCCS without calling functionality.
 * That means that the TNCS-shared-object is loaded and the function-pointer
 * to "exchangeTNCCSMessages" is explored.
 * 
 * return: -1 if connect failed, 0 if connect was successful
 */
int connectToTncs(char *pathToSO);
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
                                          /*out*/ TNC_UInt32 *overallLengthOut);

#endif //_TNCS_CONNECT_H_
