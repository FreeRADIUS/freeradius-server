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

#ifndef _TNCS_H_
#define _TNCS_H_



#ifdef __cplusplus
extern "C" {
#endif 

/*
 * copied from tncimv.h:
 */
typedef unsigned long TNC_UInt32;
typedef TNC_UInt32 TNC_ConnectionState;
typedef unsigned char *TNC_BufferReference;
typedef TNC_UInt32 TNC_ConnectionID;

#define TNC_CONNECTION_STATE_CREATE 0
#define TNC_CONNECTION_STATE_HANDSHAKE 1
#define TNC_CONNECTION_STATE_ACCESS_ALLOWED 2
#define TNC_CONNECTION_STATE_ACCESS_ISOLATED 3
#define TNC_CONNECTION_STATE_ACCESS_NONE 4
#define TNC_CONNECTION_STATE_DELETE 5
#define TNC_CONNECTION_EAP_ACKNOWLEDGEMENT 6

/*
 * Accesspoint (as function-pointer) to the TNCS for sending and receiving 
 * TNCCS-Messages.
 * 
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
typedef TNC_ConnectionState (*ExchangeTNCCSMessagePointer)(/*in*/ TNC_ConnectionID connId, 
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
                                          /*out*/ TNC_UInt32 *overallLengthOut
);

#ifdef __cplusplus
}
#endif
#endif //_TNCS_H_
