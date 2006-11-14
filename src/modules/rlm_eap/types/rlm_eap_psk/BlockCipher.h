/**
 * BlockCipher.h
 *
 * A simple abstraction for the basic functionality of a block cipher engine.
 *
 * @author Paulo S. L. M. Barreto
 *
 * @version 2.0
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __BLOCKCIPHER_H
#define __BLOCKCIPHER_H

#include <freeradius-devel/ident.h>
RCSIDH(BlockCipher_h, "$Id$")

#include "/usr/include/sys/types.h"

#ifndef USUAL_TYPES
#define USUAL_TYPES
typedef unsigned char   byte;
//typedef unsigned long   uint;   /* assuming sizeof(uint) == 4 */
#endif /* USUAL_TYPES */

#define DIR_NONE    0
#define DIR_ENCRYPT 1
#define DIR_DECRYPT 2
#define DIR_BOTH    (DIR_ENCRYPT | DIR_DECRYPT) /* both directions */

class BlockCipher {
public:

    /**
     * Cipher's block size in bits.
     */
    virtual uint blockBits() const = 0;

    /**
     * Cipher's block size in bytes.
     */
	virtual uint blockSize() const = 0;

    /**
     * Cipher's key size in bits.
     */
	virtual uint keyBits() const = 0;

    /**
     * Cipher's key size in bytes.
     */
    virtual uint keySize() const = 0;

    /**
     * Setup the key schedule for encryption, decryption, or both.
     *
     * @param   cipherKey   the cipher key.
     * @param   keyBits     size of the cipher key in bits.
     * @param   direction   cipher direction (DIR_ENCRYPT, DIR_DECRYPT, or DIR_BOTH).
     */
    virtual void makeKey(const byte *cipherKey, uint keyBits, uint dir) = 0;

    /**
     * Encrypt exactly one block of plaintext.
     *
     * @param   pt          plaintext block.
     * @param   ct          ciphertext block.
     */
    virtual void encrypt(const byte *pt, byte *ct) = 0;

    /**
     * Decrypt exactly one block of ciphertext.
     *
     * @param   ct          ciphertext block.
     * @param   pt          plaintext block.
     */
    virtual void decrypt(const byte *ct, byte *pt) = 0;

};

#endif /* __BLOCKCIPHER_H */
