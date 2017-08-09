/**
  Copyright (C) 2016 Odzhan.
  Copyright (C) 2001, 2014 Marc Schoolderman
  
  All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
#include "twofish.h"

/**
 * core encryption functions start here 
 */
void whiten (tf_blk *in, uint32_t *keys)
{
  int i;
  
  for (i=0; i<4; i++) {
    in->w[i] ^= keys[i];
  }
}

uint32_t mds(uint32_t w)
{
  w32_t    acc, x;
  int      i;
  uint32_t j, x0, y;

// Maximum Distance Separable code
// Twofish uses a single 4-by-4 MDS matrix over GF(2**8).
// Twofish uses 1,91,239 in a non-circulant matrix.
uint8_t matrix[4][4] = 
{ { 0x01, 0xEF, 0x5B, 0x5B },
  { 0x5B, 0xEF, 0xEF, 0x01 },
  { 0xEF, 0x5B, 0x01, 0xEF },
  { 0xEF, 0x01, 0xEF, 0x5B } };
  
  x.w   = w;
  acc.w = 0; 
 
  for (i=0; i<4; i++) 
  {
    for (j=0; j<4; j++) 
    {
      x0 = matrix[i][j];
      y  = x.b[j];
      while (y)
      {
        if (x0 > (x0 ^ 0x169))
          x0 ^= 0x169;
        if (y & 1)
          acc.b[i] ^= x0;
        x0 <<= 1;
        y >>= 1;
      }
    }
  }
  return acc.w;
}

// The G function
uint32_t round_g(tf_ctx *ctx, uint32_t w)
{
  w32_t    x;
  uint32_t i;
  uint8_t  *sbp;
  
  x.w = w;

  sbp=&ctx->sbox[0];
  
  for (i=0; i<4; i++) {
    x.b[i] = sbp[x.b[i]];
    sbp += 256;
  }
  return mds(x.w);
}

// encrypt/decrypt 128-bits of data
// encryption which inlines F function
void tf_enc(tf_ctx *ctx, tf_blk *data, int enc)
{
  int      i;
  uint32_t A, B, C, D, T0, T1;
  uint32_t *keys;

  whiten (data, &ctx->keys[enc*4]);
  
  keys=(uint32_t*)&ctx->keys[8];
  
  if (enc==TF_DECRYPT) {
    keys += 2*14+3;
  }
  
  // load data
  A=data->w[0];
  B=data->w[1];
  C=data->w[2];
  D=data->w[3];
  
  for (i=16; i>0; i--) 
  {
    // apply G function
    T0=round_g(ctx, A);
    T1=round_g(ctx, ROTL32(B, 8));
    
    // apply PHT
    T0 += T1;
    T1 += T0;
    
    // apply F function
    if (enc==TF_ENCRYPT)
    {
      C ^= T0 + *keys++;
      C  = ROTR32(C, 1);
      D  = ROTL32(D, 1);
      D ^= T1 + *keys++;
    } else {
      D ^= T1 + *keys--;
      D  = ROTR32(D, 1);
      C  = ROTL32(C, 1);
      C ^= T0 + *keys--;
    }
    // swap
    T0 = C; T1 = D;
    C  = A;  D = B;
    A  = T0; B = T1;
  }

  // save
  data->w[0]=C;
  data->w[1]=D;
  data->w[2]=A;
  data->w[3]=B;
  
  whiten (data, &ctx->keys[enc==TF_DECRYPT?0:4]);
}

// compute (c * x^4) mod (x^4 + (a + 1/a) * x^3 + a * x^2 + (a + 1/a) * x + 1)
// over GF(256)
uint32_t Mod(uint32_t c)
{
  uint32_t c1, c2;
  
  c2=(c<<1) ^ ((c & 0x80) ? 0x14d : 0);
  c1=c2 ^ (c>>1) ^ ((c & 1) ? (0x14d>>1) : 0);

  return c | (c1 << 8) | (c2 << 16) | (c1 << 24);
}

// compute RS(12,8) code with the above polynomial as generator
// this is equivalent to multiplying by the RS matrix
uint32_t reedsolomon(uint64_t x)
{
  uint32_t i, low, high;
    
  low  = SWAP32(x & 0xFFFFFFFF);
  high = x >> 32;
  
  for (i=0; i<8; i++)
  {
    high = Mod(high >> 24) ^ (high << 8) ^ (low & 255);
    low >>= 8;
  }
  return high;
}

uint8_t gq(uint8_t x, uint8_t *p)
{
  uint8_t a, b, x0, x1, t;
  int8_t i;
  
  for (i=0; i<2; i++)
  {
    a = (x >> 4) ^ (x & 15);
    b = (x >> 4) ^ ((x >> 1) & 15) ^ ((x << 3) & 0x8);
    
    x0 = p[a];
    x1 = p[b+16];
    
    // if first pass, swap
    if (i==0) {
      t = x0; x0 = x1; x1 = t;
    }
    x1 <<= 4;
    x  = x0 | x1;
    p += 32;
  }
  return x;
}
  
/**
 * Computes the Q-tables
 */
void tf_init(tf_ctx *ctx) 
{
  int32_t i, j;
  uint8_t x;
  uint8_t t[256];
  uint8_t *q, *p;
  
uint8_t qb[64]=
{ 0x18, 0xd7, 0xf6, 0x23, 0xb0, 0x95, 0xce, 0x4a,
  0xce, 0x8b, 0x21, 0x53, 0x4f, 0x6a, 0x07, 0xd9,
  0xab, 0xe5, 0xd6, 0x09, 0x8c, 0x3f, 0x42, 0x17,
  0x7d, 0x4f, 0x21, 0xe6, 0xb9, 0x03, 0x58, 0xac,
  0x82, 0xdb, 0x7f, 0xe6, 0x13, 0x49, 0xa0, 0x5c,
  0xe1, 0xb2, 0xc4, 0x73, 0xd6, 0x5a, 0x9f, 0x80,
  0xc4, 0x57, 0x61, 0xa9, 0xe0, 0x8d, 0xb2, 0xf3,
  0x9b, 0x15, 0x3c, 0xed, 0x46, 0xf7, 0x02, 0xa8 };
  
  p = (uint8_t*)&t[0];
  
  for (i=0; i<64; i++) {
    x=qb[i];
    *p++ = x & 15;
    *p++ = x >> 4;
  }
  
  for (i=0; i<256; i++) 
  {
    p=(uint8_t*)&t[0];
    q=(uint8_t*)&ctx->qbox[0][0];
    
    for (j=0; j<2; j++) 
    {
      q[i] = gq((uint8_t)i, p);
      p += 64;
      q += 256;
    }
  }
}

// The H function
uint32_t round_h(tf_ctx *ctx, uint32_t x_in, uint32_t *L)
{
  int    i, j;
  uint32_t r=0x9C53A000;
  w32_t x;
  uint8_t *qbp=(uint8_t*)&ctx->qbox[0][0];
  
  x.w = x_in * 0x01010101;
  
  for (i=4; i>=0; i--) 
  {
    for (j=0; j<4; j++)
    {
      r=ROTL32(r, 1);
      x.b[j] = qbp[((r & 1) << 8) + x.b[j]];
    }
    if (i>0) {
      x.w ^= L[(i-1)*2];
    }
  }
  return x.w;
}

void tf_setkey(tf_ctx *ctx, void *key)
{
  uint32_t key_copy[8];
  w32_t x;
  uint8_t *sbp;
  uint32_t *p=key_copy;
  tf_key *mk=(tf_key*)key;
  uint32_t A, B=0, T, i;
  
  tf_init(ctx);

  // copy key to local space
  memcpy ((uint8_t*)key_copy, key, 32);

  for (i=0; i<40;) 
  {
    p=key_copy;
  calc_mds:
    A = mds(round_h(ctx, i++, p++));
    // swap
    T=A; A=B; B=T;
    if (i & 1) goto calc_mds;
      
    B = ROTL32(B, 8);
    
    A += B;
    B += A;
    
    ctx->keys[i-2] = A;
    ctx->keys[i-1] = ROTL32(B, 9);
  }

  p += 4;

  for (i=0; i<4; i++) {
    *p = reedsolomon(mk->q[i]);
     p-= 2;
  }
  
  p += 2;
  
  for (i=0; i<256; i++) {
    x.w = round_h(ctx, i, p);
    sbp = &ctx->sbox[0];
    do {
      sbp[i] = x.b[0];
      sbp += 256;
      x.w >>= 8;
    } while (x.w!=0);
  }
}
