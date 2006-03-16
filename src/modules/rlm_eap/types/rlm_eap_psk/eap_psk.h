/* $Id$ */

/*
 * eap_psk.h
 *
 * Implementation of the EAP-PSK packet management
 *
 * 
 * Copyright (C) France Télécom R&D (DR&D/MAPS/NSS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */



#ifndef _EAP_PSK_H
#define _EAP_PSK_H

#include "eap.h"

#if defined(__cplusplus)
extern "C"
{
#endif

// EAP-PSK Type
#define EAPPSK_TYPE 255

// EXT_Payload maximum length in bytes
#define EXT_PAYLOAD_MAX_LEN 977

#define PSK_PCHANNEL_REPLAY_COUNTER_SIZE sizeof(unsigned long int) // size in octets
#define PSK_KEY_SIZE (PSK_AK_SIZE+PSK_KDK_SIZE)                    // size in octets
#define PSK_AK_SIZE 16                                             // size in octets
#define PSK_KDK_SIZE 16                                            // size in octets
#define PSK_TEK_SIZE 16                                            // size in octets
#define PSK_MSK_SIZE 64                                            // size in octets
#define PSK_EMSK_SIZE 64                                           // size in octets
#define PSK_RANDOM_NUMBER_SIZE 16                                  // size in octets
#define PSK_MAC_SIZE 16                                            // size in octets
#define EAP_HEADER_SIZE 5                                          // size in octets
#define PSK_SIZE 16



// EAP-PSK attribute flags
#define PSK_STATUS_CONT            0x40
#define PSK_STATUS_DONE_FAILURE    0xC0
#define PSK_STATUS_DONE_SUCCESS    0x80

#define PSK_IS_EXT                 0x20


// the EAP-PSK configuration parameters
typedef struct eap_psk_conf {
  unsigned char	*privateKey;           // the server private key
  unsigned char	*id_s;                 // the server name
  unsigned int	ldapSupport;           // if an LDAP directory is used
  unsigned char	*peerNaiAttribute;     // the LDAP attribute name which corresponds to the peer NAI
  unsigned char	*peerKeyAttribute;     // the LDAP attribute name which corresponds to the peer Key = AK || KDK
  unsigned char  *usersFilePath;       // the EAP-PSK users file path
  unsigned int   nbRetry;              // the number of bad authorized responses while the EAP-PSK authentication
  unsigned int   maxDelay;	     	   // the maximum interval in seconds between two correct responses
} PSK_CONF;

  
// data format of the first EAP-PSK message
typedef struct psk_message_1 {
  unsigned char rand_s[PSK_RANDOM_NUMBER_SIZE];
}psk_message_1;

// data format of the second EAP-PSK message
typedef struct psk_message_2 {
  unsigned char rand_p[PSK_RANDOM_NUMBER_SIZE];
  unsigned char mac_p[16];
  unsigned char *id_p;
}psk_message_2;

// data format of the third EAP-PSK message
typedef struct psk_message_3 {
  unsigned char mac_s[16];
  unsigned long int nonce;
  unsigned char tag[16];
  unsigned char flags;
  unsigned char ext_type;
  unsigned char *extPayload;
}psk_message_3;

// data format of the fourth EAP-PSK message
typedef struct psk_message_4 {
  unsigned long int nonce;
  unsigned char tag[16];
  unsigned char flags;
  unsigned char ext_type;
  unsigned char *ext_payload;
}psk_message_4;


/** 
 *@memo		this function converts a string into hexa
 *@param    inbytes, pointer to a string
 *@param    outstr, pointer to the hexa conversion
 *@param    numbytes, number of bytes to convert
 *@return	0 if an error has occured
 */
int pskConvertHex(char *inbytes, char *outstr, int numbytes);


/**
 *@memo		this function converts a string which contains hexa characters into hexa
 *@param    inbytes, the string to convert
 *@param	outstr, the conversion in hexa
 *@param	numbytes, the number of bytes to convert
 *@return	0 if an error has occured
 */
int pskHex2Bin(const char *hex, unsigned char *bin, int numbytes);


/** 
 *@memo		this function delivers random bytes
 *@param    buf, pointer to the buffer to fill
 *@param    nbytes, number of bytes to generate
 *@return   0 if an error has occured
 */
int pskGetRandomBytes(void *buf, int nbytes);
  

#if defined(__cplusplus)
}
#endif

#endif /*_EAP_PSK_H*/
