/*
 * EAX.cpp
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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "EAX.h"

EAX::EAX() {
	_E = 0; // block cipher context
	tag_size = 0;
	block_size = 0;
	t_n = 0;      // [t]_n
	_C = 0;       // CTR context
	nt = 0;
	ht = 0;
	mt = 0;
}

/*********************************************************************
 * Calls common to incremental and non-incremental API
 ********************************************************************/

void EAX::initialize(const byte* K, uint k, uint t, BlockCipher* E) {
	if (E == 0) {
		throw "Invalid cipher";
	}
    if (K == 0) {
        throw "Invalid key size";
    }
    if (t > E->blockSize()) {
        throw "Invalid tag size";
    }
    _E = E;
    _E->makeKey(K, k, DIR_ENCRYPT);
    _C = new CTR(_E);
    tag_size = t;
    block_size = _E->blockSize();
    t_n = (byte *)calloc(block_size, 1);
    nt = (byte *)calloc(block_size, 1);
    ht = (byte *)calloc(block_size, 1);
    mt = (byte *)calloc(block_size, 1);
}

/**
 * Session is over; destroy all key material and cleanup!
 */
EAX::~EAX() {
	if (_E != 0) {
		t_n[block_size - 1] = 0;
		delete _C;
		memset(nt, (byte)0, block_size);
		memset(ht, (byte)0, block_size);
		memset(mt, (byte)0, block_size);
	}
}

/**
 * Supply a message header. The header "grows" with each call
 * until a eax_provide_header() call is made that follows a
 * eax_encrypt(), eax_decrypt(), eax_provide_plaintext(),
 * eax_provide_ciphertext() or eax_compute_plaintext() call.
 * That starts reinitializes the header.
 */
void EAX::provideHeader(const byte* H, uint h) {
    if (H == 0 && h > 0) {
        throw "Invalid header";
    }
    _H.update(H, h);
}


/*********************************************************************
 * All-in-one, non-incremental interface
 ********************************************************************/

/**
 * Encrypt the given message with the given key, nonce and header.
 * Specify the header (if nonempty) with eax_provide_header().
 */
void EAX::encrypt(
        const byte* N,  // the nonce and
        uint n,         // its length (in bytes), and
        const byte* M,  // the plaintext and
        uint m,         // its length (in bytes).
        byte* C,        // The m-byte ciphertext
        byte* T) {      // and the tag T are returned.
    provideNonce(N, n);
    computeCiphertext(M, m, C);
    if (T != 0) {
        computeTag(T);
    }
}

/**
 * Decrypt the given ciphertext with the given key, nonce and header.
 * Specify the header (if nonempty) with eax_provide_header().
 * Returns 1 for a valid ciphertext, 0 for an invalid ciphertext and for invalid or missing parameters.
 */
bool EAX::decrypt(
        const byte* N,  // the nonce and
        uint n,         // its length (in bytes), and
        const byte* C,  // the ciphertext and
        uint c,         // its length (in bytes), and
        const byte* T,  // the tag.
        byte* P) {      // if valid, return the c-byte plaintext.
    provideNonce(N, n);
    provideCiphertext(C, c);
    if (checkTag(T)) {
        computePlaintext(C, c, P);
        return true;
    } else {
        return false;
    }
}


/*********************************************************************
 * Incremental interface
 ********************************************************************/

/**
 * Provide a nonce. For encryption, do this before calling
 * eax_compute_ciphertext() and eax_compute_tag();
 * for decryption, do this before calling
 * eax_provide_ciphertext(), eax_check_tag, or eax_compute_plaintext().
 */
void EAX::provideNonce(const byte* N, uint n) {
    if (N == 0 && n > 0) {
        throw "Invalid nonce";
    }
    // nonce OMAC:
    t_n[block_size - 1] = 0;
    _N.init(_E);
    _N.update(t_n, block_size);
    _N.update(N, n);
    _N.final(nt);
    _C->init(nt); // N <- OMAC_K^0(N)
    memset(nt, (byte)0, block_size);
    // header OMAC:
    t_n[block_size - 1] = 1;
    _H.init(_E);
    _H.update(t_n, block_size);
    // message OMAC:
    t_n[block_size - 1] = 2;
    _M.init(_E);
    _M.update(t_n, block_size);
}

/**
 * Encrypt a message or a part of a message.
 * The nonce needs already to have been
 * specified by a call to eax_provide_nonce().
 */
void EAX::computeCiphertext(const byte* M, uint m, byte* C) {
    if (M == 0 && m > 0 ||
        C == 0) {
        throw "Invalid buffer(s)";
    }
    _C->update(M, m, C);
    _M.update(C, m);
}

/**
 * Message and header finished: compute the authentication tag that is a part
 * of the complete ciphertext.
 */
void EAX::computeTag(byte* T) {     // compute the tag T.
    if (T == 0 && tag_size > 0) {
        throw "Invalid tag";
    }
    //assert(M.t < block_size);   // at least [t]_n must have been provided
    _N.final(nt);
    _H.final(ht);
    _M.final(mt);
    for (uint i = 0; i < tag_size; i++) {
        T[i] = (byte)(nt[i] ^ ht[i] ^ mt[i]);
    }
}

/**
 * Supply the ciphertext, or the next piece of ciphertext.
 * This is used to check for the subsequent authenticity check eax_check_tag().
 */
void EAX::provideCiphertext(const byte* C, uint c) {
    if (C == 0 && c > 0) {
        throw "Invalid ciphertext";
    }
    _M.update(C, c);
}

/**
 * The nonce, ciphertext and header have all been fully provided; check if
 * they are valid for the given tag.
 * Returns true for a valid ciphertext, false for an invalid ciphertext
 * (in which case plaintext/ciphertext might be zeroized as well).
 */
bool EAX::checkTag(const byte* T) {
    if (T == 0 && tag_size > 0) {
        throw "Invalid tag";
    }
    //assert(M.t < block_size);   // at least [t]_n must have been provided
    _N.final(nt);
    _H.final(ht);
    _M.final(mt);
    for (uint i = 0; i < tag_size; i++) {
        if (T[i] != (byte)(nt[i] ^ ht[i] ^ mt[i])) {
            return false;
        }
    }
    return true;
}

/**
 * Recover the plaintext from the provided ciphertext.
 * A call to eax_provide_nonce() needs to precede this call.
 * The caller is responsible for separately checking if the ciphertext is valid.
 * Normally this would be done before computing the plaintext with
 * eax_compute_plaintext().
 */
void EAX::computePlaintext(const byte* C, uint c, byte* P) {
    if (C == 0 && c > 0 ||
        P == 0) {
        throw "Invalid buffer(s)";
    }
    _C->update(C, c, P);
}

