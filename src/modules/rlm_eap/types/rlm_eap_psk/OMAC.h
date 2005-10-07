/*
 * OMAC.h
 *
 * The One-key CBC MAC (OMAC) message authentication code,
 * designed by T. Iwata and K. Kurosawa.
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
#ifndef __OMAC_H
#define __OMAC_H

#include "BlockCipher.h"

#ifndef USUAL_TYPES
#define USUAL_TYPES
typedef unsigned char   byte;
typedef unsigned long   uint;   /* assuming sizeof(uint) == 4 */
#endif /* USUAL_TYPES */

#define OMAC_MAXBLOCKSIZE   16

class OMAC {
public:

    OMAC();

    virtual ~OMAC();

    /**
     * Start computing an OMAC tag by selecting the underlying block cipher.
     *
     * @param   E   block cipher underlying OMAC computation.
     *              CAVEAT: in the current implementation the block size
     *              must be either 16 or 8.
     */
    void init(BlockCipher* E);

    /**
     * Update the OMAC tag computation with a message chunk.
     *
     * @param   M   message chunk
     * @param   m   its length in bytes
     */
    void update(const byte* M, uint m);

    /**
     * Complete the computation of the OMAC tag, or simply
     * get the finished OMAC tag if available.
     *
     * @return  the OMAC tag.
     */
    void final(byte *tag);

    /**
     * Get the default tag size for the underlying block cipher.
     *
     * @return the default tag size in bytes.
     */
    uint tagSize() {
        return block_size;
    }

private:
    BlockCipher *_E;            // block cipher context
    uint block_size;
    uint t;                     // remaining space on T, in bytes
    uint mask;
    uint ready;
    byte L[OMAC_MAXBLOCKSIZE];  // OMAC padding (block_size bytes): B = 2L, P = 4L
    byte T[OMAC_MAXBLOCKSIZE];  // OMAC tag     (block_size bytes)
};

#endif /* __OMAC_H */

