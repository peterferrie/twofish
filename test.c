
// test unit for tf.c
// odzhan


#include <stdio.h>
#include <string.h>
#include "twofish.h"

size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
} 

void phex (char *s, void *bin, int len)
{
  int i;
  printf ("\n%s length = %i", s, len);
  for (i=0; i<len; i++) {
    if ((i & 15)==0) putchar ('\n');
    printf (" %02x", ((uint8_t*)bin)[i]);
  }
  putchar('\n');
}

char *tv_key[]=
{ "248A7F3528B168ACFDD1386E3F51E30C2E2158BC3E5FC714C1EEECA0EA696D48",
  "2E2158BC3E5FC714C1EEECA0EA696D48D2DED73E59319A8138E0331F0EA149EA" };
  
char *tv_pt[]=
{ "431058F4DBC7F734DA4F02F04CC4F459",
  "248A7F3528B168ACFDD1386E3F51E30C" };
  
char *tv_ct[]=
{ "37FE26FF1CF66175F5DDF4C33B97A205",
  "431058F4DBC7F734DA4F02F04CC4F459" };
  
int main(void) 
{
  uint8_t key[32], pt1[16], pt2[16], ct[16];
  tf_ctx  ctx;
  int e, d, i;
  
  for (i=0; i<sizeof(tv_key)/sizeof(char*); i++)
  {
    hex2bin (key,  tv_key[i]);
    hex2bin (pt1,  tv_pt[i]);
    hex2bin (pt2,  tv_pt[i]);
    hex2bin (ct,   tv_ct[i]);
  
    memset (&ctx, 0, sizeof (ctx));
  
    tf_setkey (&ctx, key);
  
    //phex ("qbox", ctx.qbox, sizeof(ctx.qbox));
    //phex ("keys", ctx.keys, sizeof(ctx.keys));
    //phex ("sbox", ctx.sbox, sizeof(ctx.sbox));
    phex ("plaintext vector", pt1, 16);
  
    // decrypt/encrypt plaintext
    tf_enc (&ctx, (tf_blk*)pt1, TF_ENCRYPT);
  
    phex ("ciphertext vector", ct,  16);
    phex ("ciphertext result", pt1, 16);
  
    e=memcmp (pt1, ct, 16)==0;
  
    // decrypt ciphertext
    tf_enc (&ctx, (tf_blk*)pt1, TF_DECRYPT);
    d=memcmp (pt1, pt2, 16)==0;
  
    printf ("\nEncryption test #%i %s\nDecryption test #%i %s\n", 
      (i+1), e ? "passed":"failed", (i+1), d ? "passed":"failed");
  }
  return 0;
}

