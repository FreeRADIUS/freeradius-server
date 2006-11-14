/*
 * CTR.h
 *
 * The counter (CTR) mode of operation for block ciphers.
 *
 * @author Paulo S. L. M. Barreto
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
#ifndef __CTR_H
#define __CTR_H

#include <freeradius-devel/ident.h>
RCSIDH(CTR_h, "$Id$")

#include "BlockCipher.h"

#ifndef USUAL_TYPES
#define USUAL_TYPES
typedef unsigned char   byte;
typedef unsigned long   uint;   /* assuming sizeof(uint) == 4 */
#endif /* USUAL_TYPES */

class CTR {
public:

    CTR(BlockCipher* E);
    virtual ~CTR();

    /**
     * Start encrypting/decrypting a message using a given nonce.
     *
     * @param   N   the normalized nonce (initial counter value)
     */
    void init(const byte* N);

    /**
     * Either encrypt or decrypt a message chunk.
     *
     * @param   M   message chunk
     * @param   m   its length in bytes
     * @param   C   the resulting encrypted/decrypted message chunk
     */
    void update(const byte* M, uint m, byte* C);

private:
    BlockCipher *E; // block cipher context
    uint block_size;
    byte* N;        // CTR counter  (block_size bytes)
    byte* S;        // CTR mask     (block_size bytes)
    uint s;         // available mask bytes on S
};

#endif /* __CTR_H */

