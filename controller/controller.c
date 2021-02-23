/*
 * 2021 Collegiate eCTF
 * SCEWL Bus Controller implementation
 * Ben Janis
 *
 * (c) 2021 The MITRE Corporation
 *
 * This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 */

#include "controller.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// this will run if EXAMPLE_AES is defined in the Makefile (see line 54)
#ifdef EXAMPLE_AES
#include "aes_tc.h"
#include "cbc_mode.h"
#include "constants.h"
#include "utils.h"
//#include "aes_decrypt.c"
//#include "aes_encrypt.c"
//#include "cbc_mode.c"

int tc_aes128_set_encrypt_key(TCAesKeySched_t s, const uint8_t *k)
{
	const unsigned int rconst[11] = {
		0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
		0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
	};
	unsigned int i;
	unsigned int t;

	if (s == (TCAesKeySched_t) 0) {
		return TC_CRYPTO_FAIL;
	} else if (k == (const uint8_t *) 0) {
		return TC_CRYPTO_FAIL;
	}

	for (i = 0; i < Nk; ++i) {
		s->words[i] = (k[Nb*i]<<24) | (k[Nb*i+1]<<16) |
			      (k[Nb*i+2]<<8) | (k[Nb*i+3]);
	}

	for (; i < (Nb * (Nr + 1)); ++i) {
		t = s->words[i-1];
		if ((i % Nk) == 0) {
			t = subword(rotword(t)) ^ rconst[i/Nk];
		}
		s->words[i] = s->words[i-Nk] ^ t;
	}

	return TC_CRYPTO_SUCCESS;
}

int tc_cbc_mode_encrypt(uint8_t *out, unsigned int outlen, const uint8_t *in,
			    unsigned int inlen, const uint8_t *iv,
			    const TCAesKeySched_t sched)
{

	uint8_t buffer[TC_AES_BLOCK_SIZE];
	unsigned int n, m;

	/* input sanity check: */
	if (out == (uint8_t *) 0 ||
	    in == (const uint8_t *) 0 ||
	    sched == (TCAesKeySched_t) 0 ||
	    inlen == 0 ||
	    outlen == 0 ||
	    (inlen % TC_AES_BLOCK_SIZE) != 0 ||
	    (outlen % TC_AES_BLOCK_SIZE) != 0 ||
	    outlen != inlen + TC_AES_BLOCK_SIZE) {
		return TC_CRYPTO_FAIL;
	}

int tc_aes128_set_decrypt_key(TCAesKeySched_t s, const uint8_t *k)
{
	return tc_aes128_set_encrypt_key(s, k);
}

int tc_cbc_mode_decrypt(uint8_t *out, unsigned int outlen, const uint8_t *in,
			    unsigned int inlen, const uint8_t *iv,
			    const TCAesKeySched_t sched)
{

	uint8_t buffer[TC_AES_BLOCK_SIZE];
	const uint8_t *p;
	unsigned int n, m;

	/* sanity check the inputs */
	if (out == (uint8_t *) 0 ||
	    in == (const uint8_t *) 0 ||
	    sched == (TCAesKeySched_t) 0 ||
	    inlen == 0 ||
	    outlen == 0 ||
	    (inlen % TC_AES_BLOCK_SIZE) != 0 ||
	    (outlen % TC_AES_BLOCK_SIZE) != 0 ||
	    outlen != inlen) {
		return TC_CRYPTO_FAIL;
	}

	/*
	 * Note that in == iv + ciphertext, i.e. the iv and the ciphertext are
	 * contiguous. This allows for a very efficient decryption algorithm
	 * that would not otherwise be possible.
	 */
	p = iv;
	for (n = m = 0; n < outlen; ++n) {
		if ((n % TC_AES_BLOCK_SIZE) == 0) {
			(void)tc_aes_decrypt(buffer, in, sched);
			in += TC_AES_BLOCK_SIZE;
			m = 0;
		}
		*out++ = buffer[m++] ^ *p++;
	}

	return TC_CRYPTO_SUCCESS;
}

int tc_aes128_set_decrypt_key(TCAesKeySched_t s, const uint8_t *k)
{
	return tc_aes128_set_encrypt_key(s, k);
}

int tc_cbc_mode_decrypt(uint8_t *out, unsigned int outlen, const uint8_t *in,
			    unsigned int inlen, const uint8_t *iv,
			    const TCAesKeySched_t sched)
{

	uint8_t buffer[TC_AES_BLOCK_SIZE];
	const uint8_t *p;
	unsigned int n, m;

	/* sanity check the inputs */
	if (out == (uint8_t *) 0 ||
	    in == (const uint8_t *) 0 ||
	    sched == (TCAesKeySched_t) 0 ||
	    inlen == 0 ||
	    outlen == 0 ||
	    (inlen % TC_AES_BLOCK_SIZE) != 0 ||
	    (outlen % TC_AES_BLOCK_SIZE) != 0 ||
	    outlen != inlen) {
		return TC_CRYPTO_FAIL;
	}

	/*
	 * Note that in == iv + ciphertext, i.e. the iv and the ciphertext are
	 * contiguous. This allows for a very efficient decryption algorithm
	 * that would not otherwise be possible.
	 */
	p = iv;
	for (n = m = 0; n < outlen; ++n) {
		if ((n % TC_AES_BLOCK_SIZE) == 0) {
			(void)tc_aes_decrypt(buffer, in, sched);
			in += TC_AES_BLOCK_SIZE;
			m = 0;
		}
		*out++ = buffer[m++] ^ *p++;
	}

	return TC_CRYPTO_SUCCESS;
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

char int2char(uint8_t i) {
  char *hex = "0123456789abcdef";
  return hex[i & 0xf];
}
#endif

#define send_str(M) send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, strlen(M), M)
#define BLOCK_SIZE 16

// message buffer
char buf[SCEWL_MAX_DATA_SZ];


int read_msg(intf_t *intf, char *data, scewl_id_t *src_id, scewl_id_t *tgt_id,
             size_t n, int blocking) {
  scewl_hdr_t hdr;
  int read, max;

  do {
    // clear buffer and header
    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, n);

    // find header start
    do {
      hdr.magicC = 0;

      if (intf_read(intf, (char *)&hdr.magicS, 1, blocking) == INTF_NO_DATA) {
        return SCEWL_NO_MSG;
      }

      // check for SC
      if (hdr.magicS == 'S') {
        do {
          if (intf_read(intf, (char *)&hdr.magicC, 1, blocking) == INTF_NO_DATA) {
            return SCEWL_NO_MSG;
          }
        } while (hdr.magicC == 'S'); // in case of multiple 'S's in a row
      }
    } while (hdr.magicS != 'S' && hdr.magicC != 'C');

    // read rest of header
    read = intf_read(intf, (char *)&hdr + 2, sizeof(scewl_hdr_t) - 2, blocking);
    if(read == INTF_NO_DATA) {
      return SCEWL_NO_MSG;
    }

    // unpack header
    *src_id = hdr.src_id;
    *tgt_id = hdr.tgt_id;

    // read body
    max = hdr.len < n ? hdr.len : n;
    read = intf_read(intf, data, max, blocking);

    // throw away rest of message if too long
    for (int i = 0; hdr.len > max && i < hdr.len - max; i++) {
      intf_readb(intf, 0);
    }

    // report if not blocking and full message not received
    if(read == INTF_NO_DATA || read < max) {
      return SCEWL_NO_MSG;
    }

  } while (intf != CPU_INTF && intf != SSS_INTF &&                       // always valid if from CPU or SSS
           ((hdr.tgt_id == SCEWL_BRDCST_ID && hdr.src_id == SCEWL_ID) || // ignore own broadcast
            (hdr.tgt_id != SCEWL_BRDCST_ID && hdr.tgt_id != SCEWL_ID))); // ignore direct message to other device

  return max;
}


int send_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data) {
  scewl_hdr_t hdr;

  // pack header
  hdr.magicS  = 'S';
  hdr.magicC  = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len    = len;

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  intf_write(intf, data, len);

  return SCEWL_OK;
}


int handle_scewl_recv(char* data, scewl_id_t src_id, uint16_t len) {
  return send_msg(CPU_INTF, src_id, SCEWL_ID, len, data);
}


int handle_scewl_send(char* data, scewl_id_t tgt_id, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data);
}


int handle_brdcst_recv(char* data, scewl_id_t src_id, uint16_t len) {
  return send_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
}


int handle_brdcst_send(char *data, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_BRDCST_ID, len, data);
}   


int handle_faa_recv(char* data, uint16_t len) {
  return send_msg(CPU_INTF, SCEWL_FAA_ID, SCEWL_ID, len, data);
}


int handle_faa_send(char* data, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, data);
}


int handle_registration(char* msg) {
  scewl_sss_msg_t *sss_msg = (scewl_sss_msg_t *)msg;
  if (sss_msg->op == SCEWL_SSS_REG) {
    return sss_register();
  }
  else if (sss_msg->op == SCEWL_SSS_DEREG) {
    return sss_deregister();
  }

  // bad op
  return 0;
}


int sss_register() {
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_REG;
  
  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // receive response
  len = read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_t), 1);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // op should be REG on success
  return msg.op == SCEWL_SSS_REG;
}


int sss_deregister() {
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_DEREG;
  
  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // receive response
  len = read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_t), 1);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // op should be DEREG on success
  return msg.op == SCEWL_SSS_DEREG;
}

int main() {
  int registered = 0, len;
  scewl_hdr_t hdr;
  uint16_t src_id, tgt_id;

  // initialize interfaces
  intf_init(CPU_INTF);
  intf_init(SSS_INTF);
  intf_init(RAD_INTF);

#ifdef EXAMPLE_AES
  /*// example encryption using tiny-AES-c
  struct AES_ctx ctx;
  uint8_t key[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
  uint8_t plaintext[16] = "0123456789abcdef";

  // initialize context
  AES_init_ctx(&ctx, key);

  // encrypt buffer (encryption happens in place)
  AES_ECB_encrypt(&ctx, plaintext);
  send_str("Example encrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)plaintext);

  // decrypt buffer (decryption happens in place)
  AES_ECB_decrypt(&ctx, plaintext);
  send_str("Example decrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)plaintext);
  // end example
  */
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

struct tc_aes_key_sched_struct a;
	uint8_t iv_buffer[16];
	uint8_t encrypted[144];
	uint8_t decrypted[128];
	uint8_t *p;
	unsigned int length;

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

#endif

  // serve forever
  while (1) {
    // register with SSS
    read_msg(CPU_INTF, buf, &hdr.src_id, &hdr.tgt_id, sizeof(buf), 1);

    if (hdr.tgt_id == SCEWL_SSS_ID) {
      registered = handle_registration(buf);
    }

    // server while registered
    while (registered) {
      memset(&hdr, 0, sizeof(hdr));

      // handle outgoing message from CPU
      if (intf_avail(CPU_INTF)) {
        // Read message from CPU
        len = read_msg(CPU_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        if (tgt_id == SCEWL_BRDCST_ID) {
          handle_brdcst_send(buf, len);
        } else if (tgt_id == SCEWL_SSS_ID) {
          registered = handle_registration(buf);
        } else if (tgt_id == SCEWL_FAA_ID) {
          handle_faa_send(buf, len);
        } else {
          handle_scewl_send(buf, tgt_id, len);
        }

        continue;
      }

      // handle incoming radio message
      if (intf_avail(RAD_INTF)) {
        // Read message from antenna
        len = read_msg(RAD_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        if (tgt_id == SCEWL_BRDCST_ID) {
          handle_brdcst_recv(buf, src_id, len);
        } else if (src_id == SCEWL_FAA_ID) {
          handle_faa_recv(buf, len);
        } else {
          handle_scewl_recv(buf, src_id, len);
        }
      }
    }
  }
}
