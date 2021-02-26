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
#include <tinycrypt/constants.h>
//#include <test_utils.h>

#include <tinycrypt/cbc_mode.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

 const uint8_t key[16] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
	0x09, 0xcf, 0x4f, 0x3c
};

const uint8_t iv[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f
};

#ifdef EXAMPLE_AES
#include "aes.h"

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

  //validate data is proper length 

  

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  intf_write(intf, data, len);

  return SCEWL_OK;
}


int handle_scewl_recv(char* data, scewl_id_t src_id, uint16_t len) {
  send_str("recieved message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, data);

  uint8_t encrypted[144] = {0};
  int i;
  for (i = 0; i < sizeof(encrypted); i++) encrypted[i] = data[i];

  struct tc_hmac_state_struct h;
  uint8_t digest[32];
  (void)memset(&h, 0x00, sizeof(h));
  (void)tc_hmac_set_key(&h, key, sizeof(key));
  (void)tc_hmac_init(&h);
  (void)tc_hmac_update(&h, (char *)encrypted, sizeof(encrypted));
  (void)tc_hmac_final(digest, 32, &h);

  send_str("recieved HMAC:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(digest), (char *)digest);


  
  struct tc_aes_key_sched_struct a;
  uint8_t decrypted[128];
  char *p;
	unsigned int length;
  (void)tc_aes128_set_decrypt_key(&a, key);
	p = &data[16];
	//length = ((unsigned int) sizeof(data));
	tc_cbc_mode_decrypt(decrypted, len, (uint8_t *)p, len, (uint8_t *)data, &a);
  send_str("decrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len - 16, (char *)decrypted);

  return send_msg(CPU_INTF, src_id, SCEWL_ID, len - 16, (char *)decrypted);
}


int handle_scewl_send(char* data, scewl_id_t tgt_id, uint16_t len) {
  send_str("origional message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len , data);
  struct tc_aes_key_sched_struct a;
	uint8_t iv_buffer[16];
	uint8_t encrypted[144];
  (void)tc_aes128_set_encrypt_key(&a, key);
	(void)memcpy(iv_buffer, iv, 16);
  tc_cbc_mode_encrypt(encrypted, len + 16,
	(uint8_t *)data, len , iv_buffer, &a);
  send_str("encrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(encrypted), (char *)encrypted);

  struct tc_hmac_state_struct h;
  uint8_t digest[32];
  (void)memset(&h, 0x00, sizeof(h));
  (void)tc_hmac_set_key(&h, key, sizeof(key));
  (void)tc_hmac_init(&h);
  (void)tc_hmac_update(&h, (char *)encrypted, sizeof(encrypted));
  (void)tc_hmac_final(digest, 32, &h);
  send_str("HMAC:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(digest), (char *)digest);


  uint8_t msg[sizeof(encrypted) + 32] = {0};
  int i;
  for (i = 0; i < sizeof(encrypted); i++) msg[i] = encrypted[i];
  for (i = sizeof(encrypted); i < sizeof(encrypted) + 32; i++) msg[i] = digest[i - sizeof(encrypted)];

  send_str("combined:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(msg), (char *)msg);

/*
  uint8_t decrypted[128];
  uint8_t *p;
	unsigned int length;
  (void)tc_aes128_set_decrypt_key(&a, key);
	p = &encrypted[16];
	length = ((unsigned int) sizeof(encrypted));
	tc_cbc_mode_decrypt(decrypted, length, p, length, encrypted, &a);
  //send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)decrypted);
*/
  return send_msg(RAD_INTF, SCEWL_ID, tgt_id, sizeof(encrypted), (char *)msg);
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
/*
  // example encryption using tiny-AES-c
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
/*
 const uint8_t key[16] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
	0x09, 0xcf, 0x4f, 0x3c
};

const uint8_t iv[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f
};

const uint8_t plaintext[128] = { "The encryption algorithm processes the plaintext, and the MAC then hashes the encrypted message to authenticate. So cool right??"
};

 struct tc_aes_key_sched_struct a;
	uint8_t iv_buffer[16];
	uint8_t encrypted[144];
	uint8_t decrypted[128];
	uint8_t *p;
	unsigned int length;
  struct tc_hmac_state_struct h;
        uint8_t digest[32];
	//int result = 0;
	(void)tc_aes128_set_encrypt_key(&a, key);

	(void)memcpy(iv_buffer, iv, 16);

	//printf("Plaintext = %s\n", plaintext);
  send_str("Plaintext message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(plaintext), (char *)plaintext);
	tc_cbc_mode_encrypt(encrypted, sizeof(plaintext) + 16,
				plaintext, sizeof(plaintext), iv_buffer, &a);
    send_str("Encrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(plaintext), (char *)encrypted);
	//show_str1("encrypted = ", encrypted, 144);
        (void)memset(&h, 0x00, sizeof(h));
        (void)tc_hmac_set_key(&h, key, sizeof(key));
        (void)tc_hmac_init(&h);
        (void)tc_hmac_update(&h, plaintext, sizeof(plaintext));
        (void)tc_hmac_final(digest, 32, &h);
  send_str("MAC message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(digest), (char *)digest);

	(void)tc_aes128_set_decrypt_key(&a, key);
	p = &encrypted[16];
	length = ((unsigned int) sizeof(encrypted));
	tc_cbc_mode_decrypt(decrypted, length, p, length, encrypted, &a);
    send_str("Decrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(plaintext), (char *)decrypted);
	//printf("Decrypted = %s\n", decrypted);
  */
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

        if (src_id != SCEWL_ID) { // ignore our own outgoing messages
          if (tgt_id == SCEWL_BRDCST_ID) {
            // receive broadcast message
            handle_brdcst_recv(buf, src_id, len);
          } else if (tgt_id == SCEWL_ID) {
            // receive unicast message
            if (src_id == SCEWL_FAA_ID) {
              handle_faa_recv(buf, len);
            } else {
              handle_scewl_recv(buf, src_id, len);
            }
          }
        }
      }
    }
  }
}
//Zero Proof for authenication
//OAUTH (initial password, then server challenges drones)
//strncpy over strcpy - explicity define num of characters to prevent overflow
/*
Response/challenge means of authentication

To Do:
-Check authenticity of drone in supply chain before distributing key
-Proper comparing of MACs
-Random key generation in SSS post prossessing and distributing key
to drones on registration
-counter or timer (timestamp included in message, only approved in small time window)

-Address buffer overflow attacks (check the size of any input read, 
reject any message too large) *memset *memcpy
-Address side-chain attacks
-Address FAA attacks, must be passed directly to the CPU

-dynamic or static memory for message buffer
-validate data before putting in buffer
-UNIX Sockets - how does our communications/exchange of communications work?

-potenitally modifying build process to address vulnerabilities (safegaurds to gcc compiler)
*/