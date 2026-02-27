#include <stdint.h>
#include <string.h>
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/base32.h>
#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/sbuff.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    uint8_t decoded[4096];
    char encoded[8192];

    fr_dbuff_t decode_dbuff, input_dbuff;
    fr_sbuff_t encode_sbuff, input_sbuff;
    fr_sbuff_parse_error_t err;

    /*
     * BASE64 TESTS (4 variants)
     * Vulnerable: fr_base64_alphabet_decode[UINT8_MAX] - off-by-one error
     */

    // Test 1: Decode with standard base64 alphabet
    fr_sbuff_init_in(&input_sbuff, (char const *)data, size);
    fr_dbuff_init(&decode_dbuff, decoded, sizeof(decoded));
    (void)fr_base64_decode_nstd(&err, &decode_dbuff, &input_sbuff, 
                                true, true, fr_base64_alphabet_decode);

    // Test 2: Decode with URL-safe base64 alphabet
    fr_sbuff_init_in(&input_sbuff, (char const *)data, size);
    fr_dbuff_init(&decode_dbuff, decoded, sizeof(decoded));
    (void)fr_base64_decode_nstd(&err, &decode_dbuff, &input_sbuff, 
                                false, false, fr_base64_url_alphabet_decode);

    // Test 3: Encode with standard base64 alphabet (limit input size)
    if (size <= 2048) {
        fr_dbuff_init(&input_dbuff, data, size);
        fr_sbuff_init_out(&encode_sbuff, encoded, sizeof(encoded));
        (void)fr_base64_encode_nstd(&encode_sbuff, &input_dbuff, 
                                    true, fr_base64_alphabet_encode);
    }

    // Test 4: Encode with URL-safe base64 alphabet (limit input size)
    if (size <= 2048) {
        fr_dbuff_init(&input_dbuff, data, size);
        fr_sbuff_init_out(&encode_sbuff, encoded, sizeof(encoded));
        (void)fr_base64_encode_nstd(&encode_sbuff, &input_dbuff, 
                                    false, fr_base64_url_alphabet_encode);
    }

    /*
     * BASE32 TESTS (4 variants)
     * Vulnerable: fr_base32_alphabet_decode[UINT8_MAX] - off-by-one error
     */

    // Test 5: Decode with standard base32 alphabet
    fr_sbuff_init_in(&input_sbuff, (char const *)data, size);
    fr_dbuff_init(&decode_dbuff, decoded, sizeof(decoded));
    (void)fr_base32_decode_nstd(&err, &decode_dbuff, &input_sbuff,
                                true, true, fr_base32_alphabet_decode);

    // Test 6: Decode with base32hex alphabet
    fr_sbuff_init_in(&input_sbuff, (char const *)data, size);
    fr_dbuff_init(&decode_dbuff, decoded, sizeof(decoded));
    (void)fr_base32_decode_nstd(&err, &decode_dbuff, &input_sbuff,
                                false, false, fr_base32_hex_alphabet_decode);

    // Test 7: Encode with standard base32 alphabet (limit input size)
    if (size <= 2048) {
        fr_dbuff_init(&input_dbuff, data, size);
        fr_sbuff_init_out(&encode_sbuff, encoded, sizeof(encoded));
        (void)fr_base32_encode_nstd(&encode_sbuff, &input_dbuff,
                                    true, fr_base32_alphabet_encode);
    }

    // Test 8: Encode with base32hex alphabet (limit input size)
    if (size <= 2048) {
        fr_dbuff_init(&input_dbuff, data, size);
        fr_sbuff_init_out(&encode_sbuff, encoded, sizeof(encoded));
        (void)fr_base32_encode_nstd(&encode_sbuff, &input_dbuff,
                                    false, fr_base32_hex_alphabet_encode);
    }

    /*
     * BASE16 TESTS (3 variants)
     * NOT vulnerable: fr_base16_alphabet_decode_mc[UINT8_MAX + 1] - correct size!
     * Testing to ensure the fix is correct and no regressions
     */

    // Test 9: Decode with mixed-case base16 alphabet
    fr_sbuff_init_in(&input_sbuff, (char const *)data, size);
    fr_dbuff_init(&decode_dbuff, decoded, sizeof(decoded));
    (void)fr_base16_decode_nstd(&err, &decode_dbuff, &input_sbuff,
                                true, fr_base16_alphabet_decode_mc);

    // Test 10: Encode with lowercase base16 alphabet (limit input size)
    if (size <= 2048) {
        fr_dbuff_init(&input_dbuff, data, size);
        fr_sbuff_init_out(&encode_sbuff, encoded, sizeof(encoded));
        (void)fr_base16_encode_nstd(&encode_sbuff, &input_dbuff,
                                    fr_base16_alphabet_encode_lc);
    }

    // Test 11: Encode with uppercase base16 alphabet (limit input size)
    if (size <= 2048) {
        fr_dbuff_init(&input_dbuff, data, size);
        fr_sbuff_init_out(&encode_sbuff, encoded, sizeof(encoded));
        (void)fr_base16_encode_nstd(&encode_sbuff, &input_dbuff,
                                    fr_base16_alphabet_encode_uc);
    }

    return 0;
}
