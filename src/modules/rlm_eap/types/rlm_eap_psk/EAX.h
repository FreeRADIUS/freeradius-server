/*
 * EAX.h
 *
 * The EAX authenticated encryption mode of operation,
 * designed by M. Bellare, P. Rogaway and D. Wagner.
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
#ifndef __EAX_H
#define __EAX_H

#include <freeradius-devel/ident.h>
RCSIDH(EAX_h, "$Id$")

#include "BlockCipher.h"
#include "OMAC.h"
#include "CTR.h"

#ifndef USUAL_TYPES
#define USUAL_TYPES
typedef unsigned char   byte;
typedef unsigned long   uint;   /* assuming sizeof(uint) == 4 */
#endif /* USUAL_TYPES */

class EAX {
public:

	EAX();

    /**
     * Key and parameter setup to init a EAX context data structure.
     */
    void initialize(const byte* K, uint k, uint t, BlockCipher* E);

    /**
     * Session is over; destroy all key material and cleanup!
     */
    virtual ~EAX();

    /*********************************************************************
     * Calls common to incremental and non-incremental API
     ********************************************************************/

    /**
     * Supply a message header. The header "grows" with each call
     * until a eax_provide_header() call is made that follows a
     * eax_encrypt(), eax_decrypt(), eax_provide_plaintext(),
     * eax_provide_ciphertext() or eax_compute_plaintext() call.
     * That starts reinitializes the header.
     */
    void provideHeader(const byte* H, uint h);


    /*********************************************************************
     * All-in-one, non-incremental interface
     ********************************************************************/

    /**
     * Encrypt the given message with the given key, nonce and header.
     * Specify the header (if nonempty) with eax_provide_header().
     */
    void encrypt(
            const byte* N,  // the nonce and
            uint n,         // its length (in bytes), and
            const byte* M,  // the plaintext and
            uint m,         // its length (in bytes).
            byte* C,        // The m-byte ciphertext
            byte* T);

    /**
     * Decrypt the given ciphertext with the given key, nonce and header.
     * Specify the header (if nonempty) with eax_provide_header().
     * Returns 1 for a valid ciphertext, 0 for an invalid ciphertext and for invalid or missing parameters.
     */
    bool decrypt(
            const byte* N,  // the nonce and
            uint n,         // its length (in bytes), and
            const byte* C,  // the ciphertext and
            uint c,         // its length (in bytes), and
            const byte* T,  // the tag.
            byte* P);


    /*********************************************************************
     * Incremental interface
     ********************************************************************/

    /**
     * Provide a nonce. For encryption, do this before calling
     * eax_compute_ciphertext() and eax_compute_tag();
     * for decryption, do this before calling
     * eax_provide_ciphertext(), eax_check_tag, or eax_compute_plaintext().
     */
    void provideNonce(const byte* N, uint n);

    /**
     * Encrypt a message or a part of a message.
     * The nonce needs already to have been
     * specified by a call to eax_provide_nonce().
     */
    void computeCiphertext(const byte* M, uint m, byte* C);

    /**
     * Message and header finished: compute the authentication tag that is a part
     * of the complete ciphertext.
     */
    void computeTag(byte* T);

    /**
     * Supply the ciphertext, or the next piece of ciphertext.
     * This is used to check for the subsequent authenticity check eax_check_tag().
     */
    void provideCiphertext(const byte* C, uint c);

    /**
     * The nonce, ciphertext and header have all been fully provided; check if
     * they are valid for the given tag.
     * Returns true for a valid ciphertext, false for an invalid ciphertext
     * (in which case plaintext/ciphertext might be zeroized as well).
     */
    bool checkTag(const byte* T);

    /**
     * Recover the plaintext from the provided ciphertext.
     * A call to eax_provide_nonce() needs to precede this call.
     * The caller is responsible for separately checking if the ciphertext is valid.
     * Normally this would be done before computing the plaintext with
     * eax_compute_plaintext().
     */
    void computePlaintext(const byte* C, uint c, byte* P);

private:
    BlockCipher* _E;// block cipher context
    uint tag_size;
    uint block_size;
    byte* t_n;      // [t]_n
    OMAC _N;        // nonce OMAC
    OMAC _H;        // header OMAC
    OMAC _M;        // message OMAC
    CTR* _C;        // CTR context
    byte* nt;
    byte* ht;
    byte* mt;
};

#endif /* __EAX_H */

