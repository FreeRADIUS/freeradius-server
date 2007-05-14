/**
 *@memo 	Implementation of the modified counter mode
 *@doc
 *@author 	A. MAGNIEZ (FT R&D - DTL/SSR)
 *
 * Copyright 2006 The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include "SOBMMO.h"
#include <stdlib.h>
#include <string.h>
#include "eap_psk.h"

/**
 *@memo		default constructor
 */
SOBMMO::SOBMMO():sizeBlock(0),nbOutputBlocks(0),outputBlocks(NULL) {
}

/**
 *@memo		default destructor
 */
SOBMMO::~SOBMMO() {
  if(outputBlocks!=NULL) {
    free(outputBlocks);
  }
}

/**
 *@memo		this function initializes the modified counter mode
 *@param	K, the dedicated key (its size must be equal to the block size of E)
 *@param	E, the block cipher context
 *@param	inputBlock, the input block (its size must be equal to the block size of E)
 *@param	nb, the number of wanted output blocks
 *@param	counterValues, the counter values (its size must be nbOutputBlock*sizeBlock)
 *@return	1 if the output blocks have been produced, 0 in the other cases.
 */
int SOBMMO::initialize(const byte* K, BlockCipher* E,const byte* inputBlock,int nb,const byte* counterValues){
  int i; // iterator
  char hexstr[1024];
  byte buf[16];

  sizeBlock=E->blockSize();
  nbOutputBlocks=nb;


  // allocate memory for the output blocks
  outputBlocks=(byte *)malloc(sizeBlock*nbOutputBlocks);
  if(outputBlocks==NULL){
    return 0;
  }

  // debug traces
  pskConvertHex((char *)K, (char *)&hexstr, sizeBlock);
  DEBUG2("SOBMMO::initialize: K=");
  DEBUG2((char *)&hexstr);

  pskConvertHex((char *)inputBlock, (char *)&hexstr, sizeBlock);
  DEBUG2("SOBMMO::initialize: inputBlock=");
  DEBUG2((char *)&hexstr);

  pskConvertHex((char *)counterValues, (char *)&hexstr, sizeBlock*nbOutputBlocks);
  DEBUG2("SOBMMO::initialize: counterValues=");
  DEBUG2((char *)&hexstr);

  E->makeKey(K,sizeBlock,DIR_ENCRYPT);
  E->encrypt(inputBlock,outputBlocks);

  // duplicate the first result
  for(i=1;i<nbOutputBlocks;i++)
    {
      memcpy(outputBlocks+i*sizeBlock,outputBlocks,sizeBlock);
    }

  pskConvertHex((char *)outputBlocks, (char *)&hexstr, nbOutputBlocks*sizeBlock);
  DEBUG2("SOBMMO::initialize: outputBlocks before XOR=");
  DEBUG2((char *)&hexstr);

  // XOR counter values
  for(i=0;i<(nbOutputBlocks*sizeBlock);i++)
    {
      *(outputBlocks+i)=(*(outputBlocks+i))^(*(counterValues+i));
    }

  pskConvertHex((char *)outputBlocks, (char *)&hexstr, nbOutputBlocks*sizeBlock);
  DEBUG2("SOBMMO::initialize: outputBlocks after XOR=");
  DEBUG2((char *)&hexstr);

  // in order to check that AES(K,M) is valid
  E->encrypt(outputBlocks,buf);
  pskConvertHex((char *)buf, (char *)&hexstr, 16);
  DEBUG2("SOBMMO::initialize: buf=");
  DEBUG2((char *)&hexstr);

  // produce each output block
  for(i=0;i<nbOutputBlocks;i++)
    {
      E->encrypt(outputBlocks+i*sizeBlock,outputBlocks+i*sizeBlock); // Be careful, pt=ct !!! TBTested
    }

  pskConvertHex((char *)outputBlocks, (char *)&hexstr, nbOutputBlocks*sizeBlock);
  DEBUG2("SOBMMO::initialize: produced output blocks=");
  DEBUG2((char *)&hexstr);

  return 1;

}


/**
 *@memo		this function returns an output block
 *@param	id, the number of the wanted output block (the numerotation begins at 1 !!)
 */
byte* SOBMMO::getOutputBlock(int id){
  byte* output=NULL;

  if(id<1 || id>nbOutputBlocks) {
    return NULL;
  }

  output=(byte*)malloc(sizeBlock);
  if(output==NULL){
    return NULL;
  }
  memcpy(output,outputBlocks+(id-1)*sizeBlock,sizeBlock);
  return output;
}
