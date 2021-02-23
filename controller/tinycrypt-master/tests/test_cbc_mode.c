/* test_cbc_mode.c - TinyCrypt implementation of some AES-CBC tests */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * DESCRIPTION
 * This module tests the following AES-CBC Mode routines:
 *
 * Scenarios tested include:
 * - AES128 CBC mode encryption SP 800-38a tests
 */

/*
 * NIST test vectors from SP 800-38a:
 *
 * Block #1
 * Plaintext 6bc1bee22e409f96e93d7e117393172a
 * Input Block 6bc0bce12a459991e134741a7f9e1925
 * Output Block 7649abac8119b246cee98e9b12e9197d
 * Ciphertext 7649abac8119b246cee98e9b12e9197d
 * Block #2
 * Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
 * Input Block d86421fb9f1a1eda505ee1375746972c
 * Output Block 5086cb9b507219ee95db113a917678b2
 * Ciphertext 5086cb9b507219ee95db113a917678b2
 * Block #3
 * Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
 * Input Block 604ed7ddf32efdff7020d0238b7c2a5d
 * Output Block 73bed6b8e3c1743b7116e69e22229516
 * Ciphertext 73bed6b8e3c1743b7116e69e22229516
 * Block #4
 * Plaintext f69f2445df4f9b17ad2b417be66c3710
 * Input Block 8521f2fd3c8eef2cdc3da7e5c44ea206
 * Output Block 3ff1caa1681fac09120eca307586e1a7
 * Ciphertext 3ff1caa1681fac09120eca307586e1a7
 */

/*
 * NIST SP 800-38a CBC Test for encryption and decryption.
 */
/*
const uint8_t ciphertext[80] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f, 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
	0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b,
	0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
	0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e,
	0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
	0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};
*/

// #include <tinycrypt/constants.h>
// #include <test_utils.h>

//#include <tinycrypt/cbc_mode.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifndef __TC_CBC_MODE_H__
#define __TC_CBC_MODE_H__

//#include <tinycrypt/aes.h>
#ifndef __TC_AES_H__
#define __TC_AES_H__

#ifdef __cplusplus
extern "C" {
#endif

#define Nb (4)  /* number of columns (32-bit words) comprising the state */
#define Nk (4)  /* number of 32-bit words comprising the key */
#define Nr (10) /* number of rounds */
#define TC_AES_BLOCK_SIZE (Nb*Nk)
#define TC_AES_KEY_SIZE (Nb*Nk)

typedef struct tc_aes_key_sched_struct {
	unsigned int words[Nb*(Nr+1)];
} *TCAesKeySched_t;

/**
 *  @brief Set AES-128 encryption key
 *  Uses key k to initialize s
 *  @return  returns TC_CRYPTO_SUCCESS (1)
 *           returns TC_CRYPTO_FAIL (0) if: s == NULL or k == NULL
 *  @note       This implementation skips the additional steps required for keys
 *              larger than 128 bits, and must not be used for AES-192 or
 *              AES-256 key schedule -- see FIPS 197 for details
 *  @param      s IN/OUT -- initialized struct tc_aes_key_sched_struct
 *  @param      k IN -- points to the AES key
 */
int tc_aes128_set_encrypt_key(TCAesKeySched_t s, const uint8_t *k);

/**
 *  @brief AES-128 Encryption procedure
 *  Encrypts contents of in buffer into out buffer under key;
 *              schedule s
 *  @note Assumes s was initialized by aes_set_encrypt_key;
 *              out and in point to 16 byte buffers
 *  @return  returns TC_CRYPTO_SUCCESS (1)
 *           returns TC_CRYPTO_FAIL (0) if: out == NULL or in == NULL or s == NULL
 *  @param out IN/OUT -- buffer to receive ciphertext block
 *  @param in IN -- a plaintext block to encrypt
 *  @param s IN -- initialized AES key schedule
 */
int tc_aes_encrypt(uint8_t *out, const uint8_t *in, 
		   const TCAesKeySched_t s);

/**
 *  @brief Set the AES-128 decryption key
 *  Uses key k to initialize s
 *  @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if: s == NULL or k == NULL
 *  @note       This is the implementation of the straightforward inverse cipher
 *              using the cipher documented in FIPS-197 figure 12, not the
 *              equivalent inverse cipher presented in Figure 15
 *  @warning    This routine skips the additional steps required for keys larger
 *              than 128, and must not be used for AES-192 or AES-256 key
 *              schedule -- see FIPS 197 for details
 *  @param s  IN/OUT -- initialized struct tc_aes_key_sched_struct
 *  @param k  IN -- points to the AES key
 */
int tc_aes128_set_decrypt_key(TCAesKeySched_t s, const uint8_t *k);

/**
 *  @brief AES-128 Encryption procedure
 *  Decrypts in buffer into out buffer under key schedule s
 *  @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if: out is NULL or in is NULL or s is NULL
 *  @note   Assumes s was initialized by aes_set_encrypt_key
 *          out and in point to 16 byte buffers
 *  @param out IN/OUT -- buffer to receive ciphertext block
 *  @param in IN -- a plaintext block to encrypt
 *  @param s IN -- initialized AES key schedule
 */
int tc_aes_decrypt(uint8_t *out, const uint8_t *in, 
		   const TCAesKeySched_t s);

#ifdef __cplusplus
}
#endif

#endif /* __TC_AES_H__ */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @brief CBC encryption procedure
 *  CBC encrypts inlen bytes of the in buffer into the out buffer
 *  using the encryption key schedule provided, prepends iv to out
 *  @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if:
 *                out == NULL or
 *                in == NULL or
 *                ctr == NULL or
 *                sched == NULL or
 *                inlen == 0 or
 *                (inlen % TC_AES_BLOCK_SIZE) != 0 or
 *                (outlen % TC_AES_BLOCK_SIZE) != 0 or
 *                outlen != inlen + TC_AES_BLOCK_SIZE
 *  @note Assumes: - sched has been configured by aes_set_encrypt_key
 *              - iv contains a 16 byte random string
 *              - out buffer is large enough to hold the ciphertext + iv
 *              - out buffer is a contiguous buffer
 *              - in holds the plaintext and is a contiguous buffer
 *              - inlen gives the number of bytes in the in buffer
 *  @param out IN/OUT -- buffer to receive the ciphertext
 *  @param outlen IN -- length of ciphertext buffer in bytes
 *  @param in IN -- plaintext to encrypt
 *  @param inlen IN -- length of plaintext buffer in bytes
 *  @param iv IN -- the IV for the this encrypt/decrypt
 *  @param sched IN --  AES key schedule for this encrypt
 */
int tc_cbc_mode_encrypt(uint8_t *out, unsigned int outlen, const uint8_t *in,
			unsigned int inlen, const uint8_t *iv,
			const TCAesKeySched_t sched);

/**
 * @brief CBC decryption procedure
 * CBC decrypts inlen bytes of the in buffer into the out buffer
 * using the provided encryption key schedule
 * @return returns TC_CRYPTO_SUCCESS (1)
 *         returns TC_CRYPTO_FAIL (0) if:
 *                out == NULL or
 *                in == NULL or
 *                sched == NULL or
 *                inlen == 0 or
 *                outlen == 0 or
 *                (inlen % TC_AES_BLOCK_SIZE) != 0 or
 *                (outlen % TC_AES_BLOCK_SIZE) != 0 or
 *                outlen != inlen + TC_AES_BLOCK_SIZE
 * @note Assumes:- in == iv + ciphertext, i.e. the iv and the ciphertext are
 *                contiguous. This allows for a very efficient decryption
 *                algorithm that would not otherwise be possible
 *              - sched was configured by aes_set_decrypt_key
 *              - out buffer is large enough to hold the decrypted plaintext
 *              and is a contiguous buffer
 *              - inlen gives the number of bytes in the in buffer
 * @param out IN/OUT -- buffer to receive decrypted data
 * @param outlen IN -- length of plaintext buffer in bytes
 * @param in IN -- ciphertext to decrypt, including IV
 * @param inlen IN -- length of ciphertext buffer in bytes
 * @param iv IN -- the IV for the this encrypt/decrypt
 * @param sched IN --  AES key schedule for this decrypt
 *
 */
int tc_cbc_mode_decrypt(uint8_t *out, unsigned int outlen, const uint8_t *in,
			unsigned int inlen, const uint8_t *iv,
			const TCAesKeySched_t sched);

#ifdef __cplusplus
}
#endif

#endif /* __TC_CBC_MODE_H__ */

const uint8_t key[16] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
	0x09, 0xcf, 0x4f, 0x3c
};

const uint8_t iv[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f
};

const uint8_t plaintext[128] = { "012345679abcdef012345679abcdef012345679abcdef012345679abcdef012345679abcdef012345679abcdef012345679abcdef012345679abcdef"
};

static inline void show_str1(const char *label, const uint8_t *s, size_t len)
{
        unsigned int i;

        printf("%s = ", label);
        for (i = 0; i < (unsigned int) len; ++i) {
                printf("%02x", s[i]);
        }
        printf("\n");
}

int test_1(void)
{
	struct tc_aes_key_sched_struct a;
	uint8_t iv_buffer[16];
	uint8_t encrypted[144];
	uint8_t decrypted[128];
	uint8_t *p;
	unsigned int length;
	int result = 0;
	(void)tc_aes128_set_encrypt_key(&a, key);

	(void)memcpy(iv_buffer, iv, 16);

	printf("Plaintext = %s\n", plaintext);
	tc_cbc_mode_encrypt(encrypted, sizeof(plaintext) + 16,
				plaintext, sizeof(plaintext), iv_buffer, &a);
	show_str1("encrypted = ", encrypted, 144);
	(void)tc_aes128_set_decrypt_key(&a, key);
	p = &encrypted[16];
	length = ((unsigned int) sizeof(encrypted));
	tc_cbc_mode_decrypt(decrypted, length, p, length, encrypted, &a);
	printf("Decrypted = %s\n", decrypted);

	(void)tc_aes128_set_decrypt_key(&a, key);

	p = &encrypted[16];
	length = ((unsigned int) sizeof(encrypted));
	tc_cbc_mode_decrypt(decrypted, length, p, length, encrypted, &a);
	return result;
}

/*
 * Main task to test AES
 */
int main(void)
{
	int result = 0;
	result = test_1();
	return result;
}

/*
static inline void show_str1(const char *label, const uint8_t *s, size_t len);

const uint8_t key[16] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
	0x09, 0xcf, 0x4f, 0x3c
};

const uint8_t iv[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f
};

const uint8_t plaintext[64] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// TC_AES_BLOCK_SIZE = 16


int test1(void)
{
	struct tc_aes_key_sched_struct a;
	//uint8_t TC_AES_BLOCK_SIZE_16 = 16;
	uint8_t iv_buffer[16];
	uint8_t msgLen = sizeof(plaintext);
	uint8_t encrypted[80];
	uint8_t decrypted[msgLen];
	uint8_t *p;
	unsigned int length;
	int result = 0; // TC_PASS = 0
	TC_PRINT("CBC test #1 (encryption SP 800-38a tests):\n");
	printf("Plaintext = %s\n", plaintext);
	show_str1("Plaintext", plaintext, sizeof(plaintext));
	(void)tc_aes128_set_encrypt_key(&a, key);
	(void)memcpy(iv_buffer, iv, TC_AES_BLOCK_SIZE); 
	tc_cbc_mode_encrypt(encrypted, sizeof(plaintext) + TC_AES_BLOCK_SIZE, plaintext, sizeof(plaintext), iv_buffer, &a);
	show_str1("Encrypted", encrypted, sizeof(encrypted));

	(void)tc_aes128_set_decrypt_key(&a, key);
	p = &encrypted[TC_AES_BLOCK_SIZE];
	length = ((unsigned int) sizeof(encrypted));
	tc_cbc_mode_decrypt(decrypted, length, p, length, encrypted, &a);
	printf("Decrypted = %s\n", decrypted);
	show_str1("Decrypted", decrypted, sizeof(decrypted));
	return result;
}

int main(void)
{
	int result = 0; // TC_PASS = 0
	printf("Performing AES128 tests:\n");
	printf("Performing CBC tests:\n");
	result = test1();
	return result;
}

static inline void show_str1(const char *label, const uint8_t *s, size_t len)
{
        unsigned int i;

        printf("%s = ", label);
        for (i = 0; i < (unsigned int) len; ++i) {
                printf("%02x", s[i]);
        }
        printf("\n");
}

//result = check_result(1, ciphertext, sizeof(encrypted), encrypted, sizeof(encrypted));
//result = check_result(2, plaintext, sizeof(decrypted), decrypted, sizeof(decrypted));

*/