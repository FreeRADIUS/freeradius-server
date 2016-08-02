int eap_fast_encrypt(uint8_t const *plaintext, size_t plaintext_len,
		     uint8_t const *aad, size_t aad_len,
		     uint8_t const *key, uint8_t *iv, unsigned char *ciphertext,
		     uint8_t *tag);

int eap_fast_decrypt(uint8_t const *ciphertext, size_t ciphertext_len,
		     uint8_t const *aad, size_t aad_len,
		     uint8_t const *tag, uint8_t const *key, uint8_t const *iv, uint8_t *plaintext);
