/*
 *   eap_tnc.c  EAP TNC functionality.
 *
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


/*
 *
 *  MD5 Packet Format in EAP Type-Data
 *  --- ------ ------ -- --- ---------
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Value-Size   |  Value ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Name ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * EAP-TNC Packet Format in EAP Type-Data
 * 
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Flags  |Ver  | Data Length ...                                   
 * |L M S R R|=1   |                                               
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |...            |  Data ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "eap.h"

#include "eap_tnc.h"

     /*
      *	WTF is wrong with htonl ?
      */
static uint32_t ByteSwap2 (uint32_t nLongNumber)
{
   return (((nLongNumber&0x000000FF)<<24)+((nLongNumber&0x0000FF00)<<8)+
   ((nLongNumber&0x00FF0000)>>8)+((nLongNumber&0xFF000000)>>24));
}

/*
 *      Allocate a new TNC_PACKET
 */
TNC_PACKET *eaptnc_alloc(void)
{
	TNC_PACKET   *rp;

	if ((rp = malloc(sizeof(TNC_PACKET))) == NULL) {
		radlog(L_ERR, "rlm_eap_tnc: out of memory");
		return NULL;
	}
	memset(rp, 0, sizeof(TNC_PACKET));
	return rp;
}

/*
 *      Free TNC_PACKET
 */
void eaptnc_free(TNC_PACKET **tnc_packet_ptr)
{
	TNC_PACKET *tnc_packet;

	if (!tnc_packet_ptr) return;
	tnc_packet = *tnc_packet_ptr;
	if (tnc_packet == NULL) return;

	if (tnc_packet->data) free(tnc_packet->data);

	free(tnc_packet);

	*tnc_packet_ptr = NULL;
}

/*
 *	We expect only RESPONSE for which REQUEST, SUCCESS or FAILURE is sent back
 */
TNC_PACKET *eaptnc_extract(EAP_DS *eap_ds)
{
	tnc_packet_t	*data;
	TNC_PACKET	*packet;
	/*
	 *	We need a response, of type EAP-TNC
     */
	if (!eap_ds 					 ||
	    !eap_ds->response 				 ||
	    (eap_ds->response->code != PW_TNC_RESPONSE)	 ||
	    eap_ds->response->type.type != PW_EAP_TNC	 ||
	    !eap_ds->response->type.data 		 ||
	    (eap_ds->response->length <= TNC_HEADER_LEN) ||
	    (eap_ds->response->type.data[0] <= 0)) {
		radlog(L_ERR, "rlm_eap_tnc: corrupted data");
		return NULL;
	}
	packet = eaptnc_alloc();
	if (!packet) return NULL;


	packet->code = eap_ds->response->code;
	packet->id = eap_ds->response->id;
	packet->length = eap_ds->response->length; 

	data = (tnc_packet_t *)eap_ds->response->type.data;
	/*
	 *	Already checked the size above.
	 */
    packet->flags_ver = data->flags_ver;
    unsigned char *ptr = (unsigned char*)data;


	DEBUG2("Flags/Ver: %x\n", packet->flags_ver);
	int thisDataLength;
    int dataStart;
    if(TNC_LENGTH_INCLUDED(packet->flags_ver)){
        DEBUG2("data_length included\n");
//        memcpy(&packet->flags_ver[1], &data->flags_ver[1], 4);
        //packet->data_length = data->data_length;
        memcpy(&packet->data_length, &ptr[1], TNC_DATA_LENGTH_LENGTH);
        DEBUG2("data_length: %x\n", packet->data_length);
        DEBUG2("data_length: %d\n", packet->data_length);
        DEBUG2("data_length: %x\n", ByteSwap2(packet->data_length));
        DEBUG2("data_length: %d\n", ByteSwap2(packet->data_length));
        packet->data_length = ByteSwap2(packet->data_length);
		thisDataLength = packet->length-TNC_PACKET_LENGTH; //1: we need space for flags_ver
        dataStart = TNC_DATA_LENGTH_LENGTH+TNC_FLAGS_VERSION_LENGTH;
    }else{
        DEBUG2("no data_length included\n");
	 	thisDataLength = packet->length-TNC_PACKET_LENGTH_WITHOUT_DATA_LENGTH;
        packet->data_length = 0;
        dataStart = TNC_FLAGS_VERSION_LENGTH;
        
    }
	/*
	 *	Allocate room for the data, and copy over the data.
	 */
	packet->data = malloc(thisDataLength);
	if (packet->data == NULL) {
		radlog(L_ERR, "rlm_eap_tnc: out of memory");
		eaptnc_free(&packet);
		return NULL;
	}
    
    memcpy(packet->data, &(eap_ds->response->type.data[dataStart]), thisDataLength);

	return packet;
}


/*
 *	Compose the portions of the reply packet specific to the
 *	EAP-TNC protocol, in the EAP reply typedata
 */
int eaptnc_compose(EAP_DS *eap_ds, TNC_PACKET *reply)
{
	uint8_t *ptr;


	if (reply->code < 3) {
		//fill: EAP-Type (0x888e)
		eap_ds->request->type.type = PW_EAP_TNC;
        DEBUG2("TYPE: EAP-TNC set\n");
		rad_assert(reply->length > 0);
		
		//alloc enough space for whole TNC-Packet (from Code on)
		eap_ds->request->type.data = calloc(reply->length, sizeof(unsigned char*));
        DEBUG2("Malloc %d bytes for packet\n", reply->length);
		if (eap_ds->request->type.data == NULL) {
			radlog(L_ERR, "rlm_eap_tnc: out of memory");
			return 0;
		}
		//put pointer at position where data starts (behind Type)
		ptr = eap_ds->request->type.data;
		//*ptr = (uint8_t)(reply->data_length & 0xFF);

		//ptr++;
		*ptr = reply->flags_ver;
        DEBUG2("Set Flags/Version: %d\n", *ptr);
		if(reply->data_length!=0){
            DEBUG2("Set data-length: %d\n", reply->data_length);
			ptr++; //move to start-position of "data_length"
            DEBUG2("Set data-length: %x\n", reply->data_length);
            DEBUG2("Set data-length (swapped): %x\n", ByteSwap2(reply->data_length));
            unsigned long swappedDataLength = ByteSwap2(reply->data_length);
            //DEBUG2("DATA-length: %d", reply->data_
            memcpy(ptr, &swappedDataLength, 4);
			//*ptr = swappedDataLength;
		}
		uint16_t thisDataLength=0;
		if(reply->data!=NULL){
            DEBUG2("Adding TNCCS-Data ");
			int offset;
			//if data_length-Field present
			if(reply->data_length !=0){
                DEBUG2("with Fragmentation\n");
				offset = TNC_DATA_LENGTH_LENGTH; //length of data_length-field: 4
				thisDataLength = reply->length-TNC_PACKET_LENGTH;
			}else{ //data_length-Field not present
                DEBUG2("without Fragmentation\n");
				offset = 1;
				thisDataLength = reply->length-TNC_PACKET_LENGTH_WITHOUT_DATA_LENGTH;
			}
            DEBUG2("TNCCS-Datalength: %d\n", thisDataLength);
			ptr=ptr+offset; //move to start-position of "data"
			memcpy(ptr,reply->data, thisDataLength);
		}else{
            DEBUG2("No TNCCS-Data present");
        }

		//the length of the TNC-packet (behind Type)
        if(reply->data_length!=0){
    		eap_ds->request->type.length = TNC_DATA_LENGTH_LENGTH+TNC_FLAGS_VERSION_LENGTH+thisDataLength; //4:data_length, 1: flags_ver
        }else{
            eap_ds->request->type.length = TNC_FLAGS_VERSION_LENGTH+thisDataLength; //1: flags_ver
        }
        DEBUG2("Packet built\n");

	} else {
		eap_ds->request->type.length = 0;
	}
	eap_ds->request->code = reply->code;

	return 1;
}
