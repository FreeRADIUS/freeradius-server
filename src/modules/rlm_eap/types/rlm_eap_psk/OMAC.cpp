/*
 * OMAC.cpp
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
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "OMAC.h"

OMAC::OMAC() {
    _E = 0;
    block_size = 0;
    t = 0;
    mask = 0;
    ready = 0;
    memset(L, (byte)0, sizeof(L));
    memset(T, (byte)0, sizeof(L));
}

OMAC::~OMAC() {
    _E = 0;
    block_size = 0;
    t = 0;
    mask = 0;
    ready = 0;
    memset(L, (byte)0, sizeof(L));
    memset(T, (byte)0, sizeof(L));
}

void OMAC::init(BlockCipher* E) {
    if (E == 0) {
        throw "Invalid block cipher";
    }
    _E = E;
    t = block_size = _E->blockSize();
    if (block_size != 16 && block_size != 8) {
        throw "Block size not supported";
    }
    mask = (block_size == 16) ? 0x87 : 0x1B;
    // compute padding mask:
    memset(L, (byte)0, block_size);
    _E->encrypt(L, L); // L = E_K(0^n)
    uint c = L[0] & 0x80; // carry
    for (uint b = 0; b < block_size - 1; b++) {
        L[b] = (byte)((L[b] << 1) | ((L[b + 1] & 0xff) >> 7));
    }
    L[block_size - 1] = (byte)((L[block_size - 1] << 1) ^ (c != 0 ? mask : 0)); // B = 2L
    // initialize tag accumulator
    memset(T, (byte)0, block_size);
    ready = 0;
}

void OMAC::update(const byte* M, uint m) {
    if (_E == 0) {
        throw "OMAC computation not initialized";
    }
    uint i = block_size - t;
    uint j = 0;
    while (m > t) { // N.B. m is strictly larger than t!
        // complete tag block:
        for (uint b = 0; b < t; b++) {
            T[i + b] ^= M[j + b];
        }
        _E->encrypt(T, T); // since there is more data, no padding applies
        // proceed to the next block:
        m -= t;
        j += t;
        t = block_size;
        i = 0;
        //assert(m > 0);
    }
    // process remaining chunk (m bytes):
    for (uint b = 0; b < m; b++) {
        T[i + b] ^= M[j + b];
    }
    t -= m;
    //assert(m == 0 || t < block_size); // m == 0 here only occurs if m == 0 from the very beginning
}

void OMAC::final(byte* tag) {
    if (_E != 0) {
        // compute padding:
        if (t > 0) {
            // compute special padding mask:
            uint c = L[0] & 0x80; // carry
            for (uint b = 0; b < block_size - 1; b++) {
                L[b] = (byte)((L[b] << 1) | ((L[b + 1] & 0xff) >> 7));
            }
            L[block_size - 1] = (byte)((L[block_size - 1] << 1) ^ (c != 0 ? mask : 0)); // P = 4L
            // pad incomplete block:
            T[block_size - t] ^= 0x80; // padding toggle
            t = 0;
        }
        for (uint b = 0; b < block_size; b++) {
            T[b] ^= L[b];
        }
        _E->encrypt(T, T); // T contains the complete tag
        ready = 1; // OMAC tag available
        _E = 0; // OMAC computation is complete; context no longer initialized
    } else if (!ready) {
        throw "OMAC computation not initialized";
    }
    memcpy(tag, T, block_size);
}

