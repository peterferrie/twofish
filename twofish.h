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
  
#ifndef TF_H
#define TF_H

#include <stdint.h>

#define U8V(v)  ((uint8_t)(v)  & 0xFFU)
#define U16V(v) ((uint16_t)(v) & 0xFFFFU)
#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFFUL)
#define U64V(v) ((uint64_t)(v) & 0xFFFFFFFFFFFFFFFFULL)

#define ROTL8(v, n) \
  (U8V((v) << (n)) | ((v) >> (8 - (n))))

#define ROTL16(v, n) \
  (U16V((v) << (n)) | ((v) >> (16 - (n))))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define ROTL64(v, n) \
  (U64V((v) << (n)) | ((v) >> (64 - (n))))

#define ROTR8(v, n) ROTL8(v, 8 - (n))
#define ROTR16(v, n) ROTL16(v, 16 - (n))
#define ROTR32(v, n) ROTL32(v, 32 - (n))
#define ROTR64(v, n) ROTL64(v, 64 - (n))

#define SWAP16(v) \
  ROTL16(v, 8)

#define SWAP32(v) \
  ((ROTL32(v,  8) & 0x00FF00FFUL) | \
   (ROTL32(v, 24) & 0xFF00FF00UL))

#define SWAP64(v) \
  ((ROTL64(v,  8) & 0x000000FF000000FFULL) | \
   (ROTL64(v, 24) & 0x0000FF000000FF00ULL) | \
   (ROTL64(v, 40) & 0x00FF000000FF0000ULL) | \
   (ROTL64(v, 56) & 0xFF000000FF000000ULL))
   
#ifdef USE_ASM
#define tf_setkey(x, y) tf_setkeyx(x, y)
#define tf_enc(x,y,z) tf_encx(x,y,z)
#endif

#define TF_ENCRYPT 0
#define TF_DECRYPT 1

typedef union _vector_t { 
  uint8_t   v8[4];
  uint16_t v16[2];
  uint32_t v32;
  uint64_t v64;
} vector;

typedef union _tf_key_t {
  uint8_t   v8[32];
  uint16_t v16[16];
  uint32_t v32[8];
  uint64_t v64[4];
} tf_key;

typedef union _tf_blk_t {
  uint8_t  v8[16];
  uint16_t v16[8];
  uint32_t v32[4];
  uint64_t v64[2];
} tf_blk;

#pragma pack(push, 1)
typedef struct _tf_ctx_t {
  uint32_t keys[8+2*16];
  uint8_t  qbox[2][256];
  uint8_t  sbox[4*256];
} tf_ctx;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

  // x86 asm
  void tf_setkeyx (tf_ctx*, void*);
  void tf_encx (tf_ctx*, tf_blk*, int);

  // C code
  void tf_setkey (tf_ctx*, void*);  
  void tf_enc (tf_ctx*, tf_blk*, int);

#ifdef __cplusplus
}
#endif

#endif
