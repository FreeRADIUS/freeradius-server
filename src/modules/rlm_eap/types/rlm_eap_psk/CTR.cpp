/*
 * CTR.cpp
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
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "CTR.h"

CTR::CTR(BlockCipher* E) {
    this->E = E;
    block_size = E->blockSize();
    N = (byte *)calloc(block_size, 1);
    S = (byte *)calloc(block_size, 1);
    s = 0;
}

CTR::~CTR() {
    memset(N, (byte)0, block_size); free(N);
    memset(S, (byte)0, block_size); free(S);
}

void CTR::init(const byte* N) {
    // initialize nonce:
    memcpy(this->N, N, block_size);
    E->encrypt(N, S); // S = E_K(N)
    s = block_size;
}

void CTR::update(const byte* M, uint m, byte* C) {
    uint i = block_size - s;
    uint j = 0;
    while (m >= s) {
        for (uint b = 0; b < s; b++) {
            C[j + b] = (byte)(M[j + b] ^ S[i + b]);
        }
        // proceed to the next block:
        m -= s;
        j += s;
        // increment the nonce:
        for (uint n = block_size - 1; n >= 0; n--) {
            if ((++N[n] & 0xff) != 0) {
                break;
            }
        }
        E->encrypt(N, S);
        s = block_size;
        i = 0;
    }
    //assert(m < s);
    // process remaining chunk (m bytes):
    for (uint b = 0; b < m; b++) {
        C[j + b] = (byte)(M[j + b] ^ S[i + b]);
    }
    s -= m;
    //assert(0 < s && s <= block_size);
}

