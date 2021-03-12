/*
 * 2021 Collegiate eCTF
 * Example echo client
 * Ben Janis
 *
 * (c) 2021 The MITRE Corporation
 *
 * This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 */

#include "scewl_bus_driver/scewl_bus.h"

#include <stdio.h>
#include <string.h>

#define BUF_SZ 0x2000

// SCEWL_ID and TGT_ID need to be defined at compile
#ifndef TGT_ID
#warning TGT_ID not defined, using bad default of 0xffff
#define TGT_ID ((scewl_id_t)0xffff)
#endif


// trust me, it's easier to get the boot reference flag by
// following the instructions than to try to untangle this
// NOTE: you're not allowed to do this in your code
typedef uint32_t aErjfkdfru;const uint32_t flag_as[]={0x1ffe4b6,0x3098ac,
0x2f56101,0x11a38bb,0x485124,0x11644a7,0x3c74e8,0x3c74e8,0x2f56101,0x2ca498,
0x3098ac,0x1fbf0a2,0x11a38bb,0x1ffe4b6,0x3098ac,0x3c74e8,0x11a38bb,0x11a38bb,
0x1ffe4b6,0x1ffe4b6,0x1cc7fb2,0x1fbf0a2,0x51bd0,0x51bd0,0x1ffe4b6,0x1d073c6,
0x2179d2e,0};const uint32_t flag_bs[]={0x138e798,0x2cdbb14,0x1f9f376,0x23bcfda,
0x1d90544,0x1cad2d2,0x860e2c,0x860e2c,0x1f9f376,0x25cbe0c,0x2cdbb14,0xc7ea90,
0x23bcfda,0x138e798,0x2cdbb14,0x860e2c,0x23bcfda,0x23bcfda,0x138e798,0x138e798,
0x2b15630,0xc7ea90,0x18d7fbc,0x18d7fbc,0x138e798,0x3225338,0x4431c8,0};
typedef int skerufjp; skerufjp siNfidpL(skerufjp verLKUDSfj){aErjfkdfru 
ubkerpYBd=12+1;skerufjp xUrenrkldxpxx=2253667944%0x432a1f32;aErjfkdfru UfejrlcpD=
1361423303;verLKUDSfj=(verLKUDSfj+0x12345678)%60466176;while(
xUrenrkldxpxx--!=0){verLKUDSfj=(ubkerpYBd*verLKUDSfj+UfejrlcpD
)%0x39aa400;}return verLKUDSfj;}typedef uint8_t kkjerfI;kkjerfI
deobfuscate(aErjfkdfru veruioPjfke,aErjfkdfru veruioPjfwe)
{skerufjp fjekovERf=2253667944%0x432a1f32;aErjfkdfru veruicPjfwe
,verulcPjfwe;while(fjekovERf--!=0){veruioPjfwe=(veruioPjfwe
-siNfidpL(veruioPjfke))%0x39aa400;veruioPjfke=(veruioPjfke-
siNfidpL(veruioPjfwe))%60466176;}veruicPjfwe=(veruioPjfke+
0x39aa400)%60466176;verulcPjfwe=(veruioPjfwe+
60466176)%0x39aa400;return veruicPjfwe*60466176+verulcPjfwe-89;}


int main(void) {
  scewl_id_t src_id, tgt_id;
  uint16_t len;
  char *msg = "The encryption algorithm processes the plaintext, and the MAC then hashes the encrypted message to authenticate. So cool right??Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Adipiscing elit duis tristique sollicitudin nibh sit amet. Morbi tincidunt augue interdum velit euismod in pellentesque massa. Aliquet risus feugiat in ante metus dictum at. Viverra ipsum nunc aliquet bibendum. Sed velit dignissim sodales ut. Etiam non quam lacus suspendisse faucibus interdum. Vestibulum sed arcu non odio euismod. Vitae auctor eu augue ut lectus arcu. Lorem donec massa sapien faucibus et. Praesent semper feugiat nibh sed. Velit scelerisque in dictum non. Sit amet massa vitae tortor condimentum lacinia quis.

Viverra maecenas accumsan lacus vel facilisis volutpat est velit egestas. Ac ut consequat semper viverra nam. Ultricies lacus sed turpis tincidunt. Non consectetur a erat nam at lectus urna duis. Vivamus arcu felis bibendum ut tristique et. Ipsum dolor sit amet consectetur adipiscing elit duis tristique sollicitudin. Gravida cum sociis natoque penatibus et magnis dis. Sem integer vitae justo eget magna. Tristique nulla aliquet enim tortor at. Eu nisl nunc mi ipsum. Sit amet est placerat in. Non sodales neque sodales ut etiam.

Nulla malesuada pellentesque elit eget gravida cum sociis natoque penatibus. Vel orci porta non pulvinar neque laoreet suspendisse. Pellentesque habitant morbi tristique senectus et netus et malesuada. Eu sem integer vitae justo eget magna fermentum. Pharetra vel turpis nunc eget lorem dolor sed viverra. At tempor commodo ullamcorper a lacus vestibulum. Vel pharetra vel turpis nunc eget lorem. Vitae tempus quam pellentesque nec nam aliquam sem et. Nibh venenatis cras sed felis eget velit aliquet sagittis. At in tellus integer feugiat scelerisque varius morbi enim nunc.

Nec nam aliquam sem et tortor. Libero id faucibus nisl tincidunt eget nullam non nisi est. Cras tincidunt lobortis feugiat vivamus at augue eget arcu dictum. Vel turpis nunc eget lorem dolor sed. Nunc non blandit massa enim nec dui nunc mattis. Id semper risus in hendrerit. Neque ornare aenean euismod elementum nisi quis eleifend quam. Sed elementum tempus egestas sed sed risus pretium quam vulputate. Pulvinar pellentesque habitant morbi tristique senectus et netus et malesuada. Dolor purus non enim praesent elementum.

Sapien nec sagittis aliquam malesuada bibendum arcu. Eu turpis egestas pretium aenean pharetra magna. Purus sit amet luctus venenatis lectus magna fringilla. Tempor commodo ullamcorper a lacus vestibulum sed arcu non odio. Nulla aliquet enim tortor at auctor urna nunc id cursus. Ut faucibus pulvinar elementum integer. Tellus in hac habitasse platea dictumst vestibulum rhoncus. Suspendisse potenti nullam ac tortor vitae purus faucibus. Neque aliquam vestibulum morbi blandit. At volutpat diam ut venenatis tellus in. Nisl purus in mollis nunc sed id semper risus in. Sit amet aliquam id diam maecenas. Sed sed risus pretium quam vulputate dignissim suspendisse. Eget nunc lobortis mattis aliquam. Suscipit tellus mauris a diam maecenas sed enim. Tortor at risus viverra adipiscing.

Nisl vel pretium lectus quam id leo in vitae turpis. Et leo duis ut diam quam nulla porttitor massa. Blandit cursus risus at ultrices mi tempus imperdiet nulla. A erat nam at lectus. Tristique risus nec feugiat in fermentum posuere urna. Arcu non sodales neque sodales ut. Nibh venenatis cras sed felis eget velit aliquet. Eleifend mi in nulla posuere sollicitudin. Mi eget mauris pharetra et ultrices. Sed risus pretium quam vulputate. Eget aliquet nibh praesent tristique magna sit amet purus. Habitasse platea dictumst quisque sagittis purus sit.

Posuere morbi leo urna molestie at elementum eu. Volutpat sed cras ornare arcu dui vivamus arcu felis. Euismod quis viverra nibh cras pulvinar. In pellentesque massa placerat duis ultricies. Pretium quam vulputate dignissim suspendisse. Mattis rhoncus urna neque viverra justo. Eget arcu dictum varius duis at consectetur. Egestas maecenas pharetra convallis posuere morbi leo urna. Tempus quam pellentesque nec nam aliquam. Nunc sed augue lacus viverra. Feugiat nisl pretium fusce id velit ut tortor. Viverra maecenas accumsan lacus vel facilisis volutpat est velit egestas. Eu tincidunt tortor aliquam nulla. Ac placerat vestibulum lectus mauris. Commodo sed egestas egestas fringilla. Libero id faucibus nisl tincidunt eget nullam non nisi. Sodales ut etiam sit amet nisl purus in. Vulputate odio ut enim blandit. Neque vitae tempus quam pellentesque nec nam. Eu turpis egestas pretium aenean.

Integer eget aliquet nibh praesent tristique. Non nisi est sit amet facilisis. Nibh sit amet commodo nulla. Turpis tincidunt id aliquet risus feugiat in ante metus dictum. Cras ornare arcu dui vivamus arcu. Duis at tellus at urna condimentum. Risus ultricies tristique nulla aliquet enim tortor. Tempor orci dapibus ultrices in iaculis nunc sed. Nibh venenatis cras sed felis eget velit. Eget est lorem ipsum dolor sit amet consectetur. Urna neque viverra justo nec. Lacus suspendisse faucibus interdum posuere lorem. Interdum velit laoreet id donec ultrices.

Ut diam quam nulla porttitor massa id neque. Ultricies lacus sed turpis tincidunt id aliquet risus feugiat in. Justo nec ultrices dui sapien eget mi proin sed libero. Risus in hendrerit gravida rutrum quisque non tellus orci ac. Mollis nunc sed id semper risus in hendrerit gravida. Blandit libero volutpat sed cras ornare arcu dui vivamus. Ultrices tincidunt arcu non sodales neque. Eget egestas purus viverra accumsan. Venenatis a condimentum vitae sapien pellentesque habitant. Ipsum faucibus vitae aliquet nec ullamcorper. Metus vulputate eu scelerisque felis imperdiet proin fermentum leo. Ornare arcu dui vivamus arcu felis bibendum. Sed viverra ipsum nunc aliquet. Nec dui nunc mattis enim ut tellus. Ac turpis egestas integer eget. Tellus cras adipiscing enim eu turpis egestas. Lobortis elementum nibh tellus molestie nunc non blandit massa. Faucibus a pellentesque sit amet. Tristique magna sit amet purus gravida quis blandit. Sollicitudin aliquam ultrices sagittis orci a scelerisque purus.

Nec dui nunc mattis enim ut tellus elementum sagittis. Pharetra diam sit amet nisl suscipit adipiscing bibendum est ultricies. Euismod in pellentesque massa placerat duis ultricies lacus sed. Ut tortor pretium viverra suspendisse potenti nullam. Feugiat scelerisque varius morbi enim nunc faucibus a pellentesque. Cras sed felis eget velit aliquet sagittis id. Tincidunt dui ut ornare lectus sit amet est placerat in. Dapibus ultrices in iaculis nunc sed augue lacus viverra. Vel fringilla est ullamcorper eget. Quam elementum pulvinar etiam non quam. Pulvinar neque laoreet suspendisse interdum. Cras adipiscing enim eu turpis egestas. Ultricies lacus sed turpis tincidunt id. Fermentum iaculis eu non diam phasellus vestibulum lorem.";
  char data[BUF_SZ];

  // open log file
  FILE *log = stderr;
  // NOTE: you can write to a file inside the Docker container instead:
  // FILE *log = fopen("cpu.log", "a");

  // /initialize SCEWL
  scewl_init();

  // register
  if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  fprintf(log, "Client SED: Sending message...\n");
  scewl_send(SCEWL_BRDCST_ID, strlen(msg) , msg);

/*
  // receive response (block until response received)
  fprintf(log, "Waiting for response...\n");
  scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

  // check if response matches
  
  if (!strcmp(msg, data)) {
    // decode and print flag
    uint8_t flag[32] = {0};
    for (int i = 0; flag_as[i]; i++) {
      flag[i] = deobfuscate(flag_as[i], flag_bs[i]);
      flag[i+1] = 0;
    }
    fprintf(log, "Congrats on booting the system! Press <enter> on the FAA transceiver to view your flag!\n");
    scewl_send(SCEWL_FAA_ID, strlen(flag), flag);
  } else {
    fprintf(log, "Bad response!\n");
  }
  */

  // deregister
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }

  /*if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  fprintf(log, "Client SED: Sending message...\n");
  scewl_send(SCEWL_BRDCST_ID, strlen(msg) , msg);
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }

    if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  fprintf(log, "Client SED: Sending message...\n");
  scewl_send(SCEWL_BRDCST_ID, strlen(msg) , msg);
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }

    if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  fprintf(log, "Client SED: Sending message...\n");
  scewl_send(SCEWL_BRDCST_ID, strlen(msg) , msg);
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }

    if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  fprintf(log, "Client SED: Sending message...\n");
  scewl_send(SCEWL_BRDCST_ID, strlen(msg) , msg);
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }

    if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  fprintf(log, "Client SED: Sending message...\n");
  scewl_send(SCEWL_BRDCST_ID, strlen(msg) , msg);
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  */

  fprintf(log, "Exiting...\n");
}
