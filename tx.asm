;
;  Copyright © 2016 Odzhan, Peter Ferrie
;  Copyright © 2001, 2014 Marc Schoolderman
;
;  All Rights Reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions are
;  met:
;
;  1. Redistributions of source code must retain the above copyright
;  notice, this list of conditions and the following disclaimer.
;
;  2. Redistributions in binary form must reproduce the above copyright
;  notice, this list of conditions and the following disclaimer in the
;  documentation and/or other materials provided with the distribution.
;
;  3. The name of the author may not be used to endorse or promote products
;  derived from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
;  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
;  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
;  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;  POSSIBILITY OF SUCH DAMAGE.
;
; -----------------------------------------------
; Twofish-256 block cipher in x86 assembly
;
; https://www.schneier.com/cryptography/paperfiles/paper-twofish-paper.pdf
;
; size: 610 bytes
;
; global calls use cdecl convention
;
; -----------------------------------------------

%ifndef BIN
    global _tf_encx
    global _tf_setkeyx
%endif

  bits 32
  
struc pushad_t
  _edi resd 1
  _esi resd 1
  _ebp resd 1
  _esp resd 1
  _ebx resd 1
  _edx resd 1
  _ecx resd 1
  _eax resd 1
  .size:
endstruc
  
struc tf_ctx
  keys resd 8+2*16
  qbox resb 2*256
  sbox resb 4*256
  .size:
endstruc

; The G function
; eax = w
; ebx = ctx->sbox
; ecx = 0 or 1
; uint32_t round_g(tf_ctx *ctx, uint32_t w)
round_g:
    pushad
    mov    cl, 4
    add    ebx, sbox
rg_l1:
    xlatb                   ; sbp[x.v8[i]]
    ror    eax, 8
    add    ebx, 256         ; sbp += 256
    loop   rg_l1
    db     03ch             ; cmp al, xx (mask pushad)
mds:
    pushad
_mdsx_tail:
    xchg   eax, ebx
    mov    ecx, 0357cd3ceh
    xor    edx, edx
mds_l0:
    dec    ecx
mds_l1:
    xor    dl, bl
    mov    al, bl
    shr    al, 1
    jnb    mds_l2
    xor    al, 0b4h
mds_l2:
    shl    ecx, 1
    jnb    mds_l3
    xor    dl, al
mds_l3:
    shr    al, 1
    jnb    mds_l4
    xor    al, 0b4h
mds_l4:
    shl    ecx, 1
    jnb    mds_l5
    xor    dl, al
mds_l5:
    ror    ebx, 8
    test   cl, cl
    jnz    mds_l1
    ror    edx, 8
    dec    cl
    inc    ecx
    jne    mds_l0
mds_l6:
    mov    [esp+_eax], edx
    popad
    ret

; uint32_t round_h(tf_ctx *ctx, uint8_t x_in, uint32_t *L)
;
; ebx = ctx
; ecx = x_in
; esi = L
round_h:
    pushad
    ; r=0x9C53A000;
    mov    ebp, 09C53A000h
    ; x.v32 = x_in * 0x01010101;
    imul   edx, ecx, 01010101h
    ; i=4
    mov    cl, 16
    lea    edi, [ebx+ecx*8+qbox-128]
rh_l1:
    ; j=0
    push   4
    pop    eax
rh_l2:
    movzx  ebx, dl
    add    ebp, ebp
    adc    bh, bh
    mov    dl, [ebx+edi]
    ror    edx, 8
    dec    eax
    jnz    rh_l2
    
    ; if (i>0)
    jecxz  mds_l6
    sub    ecx, 4
    ; x.v32 ^= L[(i-1)*2];
    xor    edx, [esi+ecx*2]
    jmp    rh_l1
 
%define A [esp+12]
%define B [esp+8]
%define C ebp
%define D esi

%define T0 edx
%define T1 eax

; encrypt or decrypt 128-bits of data
; void tf_enc(tf_ctx *ctx, tf_blk *data, int enc)
_tf_encx:
    pushad
    
    lea    esi, [esp+32+4]
    lodsd                    ; ctx
    xchg   ebx, eax
    lodsd                    ; data
    push   eax
    lodsd                    ; enc
    pop    esi
    cdq                      ; i=0
    xchg   ecx, eax
    
    mov    edi, ebx
    mov    dl, 4*4           ; 16
    jecxz  tf_l1             ; if enc==0 encrypt
    add    edi, edx          ; edi = &ctx->keys[4]
tf_l1:
    call   whiten
tf_l2:
    push   edi               ; save pointer to keys
    mov    edi, esi
    
    lodsd
    push   eax               ; A=data->v32[0];
    lodsd
    push   eax               ; B=data->v32[1];
    lodsd
    xchg   eax, C            ; C=data->v32[2];
    lodsd
    xchg   eax, D            ; D=data->v32[3];

    push   edi
    lea    edi, [ebx+edx*2]  ; edi=&ctx->keys[8]
    jecxz  tf_l3

    std                      ; DF=1 to go backwards
    add    edi, (2*14+3)*4
tf_l3:
    push   edx               ; save i
    ; apply G function
    ; T0=round_g(ctx, A);
    mov    eax, A
    call   round_g
    xchg   eax, T0
    
    ; T1=round_g(ctx, ROTL32(B, 8));
    mov    eax, B
    rol    eax, 8
    call   round_g

    ; apply PHT
    add    T0, T1            ; T0 += T1;
    add    T1, T0            ; T1 += T0;
    
    ; apply F function
    jecxz  tf_l4             ; if (ecx==TF_ENCRYPT) goto tf_l4
    
    rol    C, 1              ; C  = ROTL32(C, 1);
    add    T1, [edi]         ; D ^= T1 + *K1--;
    xor    D, T1             
    add    T0, [edi-4]       ; C ^= T0 + *K1--;
    ror    D, 1              ; D  = ROTR32(D, 1);
    xor    C, T0
    jmp    tf_l5
tf_l4:
    add    T0, [edi]
    add    T1, [edi+4]
    xor    C, T0
    ror    C, 1
    rol    D, 1
    xor    D, T1
tf_l5:
    ; edi += 8 or edi -= 8 depending on DF
    scasd
    scasd
    ; swap
    xchg   A, C
    xchg   B, D

    pop    edx               ; restore i
    dec    edx               ; i--
    jnz    tf_l3

    cld                      ; DF=0 to go forward
    pop    edi               ; restore data
    pop    edx
    pop    eax
    push   edi
    ; save
    xchg   eax, C
    stosd                    ; data->v32[0]=C;
    xchg   eax, D
    stosd                    ; data->v32[1]=D;
    xchg   eax, C
    stosd                    ; data->v32[2]=A;
    xchg   eax, edx
    stosd                    ; data->v32[3]=B;
    pop    esi
    pop    edi               ; edi = &ctx->keys[0]
    
    ; add or subtract 16 depending on enc
    add    edi, 16
    jecxz  whiten_tail
    sub    edi, 32
    db     3ch               ; cmp al, xx (mask pushad)

; edi = keys
; esi = in
; void whiten (uint32_t *in, uint32_t *keys)
whiten:
    pushad
whiten_tail:
    mov    cl, 4
w_l1:
    mov    eax, [edi]
    xor    [esi], eax
    cmpsd
    loop   w_l1
    popad
    ret
     
; ***********************************************
; void tf_init(tf_ctx *ctx)
; ***********************************************
tf_init:
    pushad
    mov    cl, 64
    enter  128, 0
    mov    edi, esp          ; edi = p = alloc(128)
    call   ld_qb
; qb:
    db 018h, 0d7h, 0f6h, 023h, 0b0h, 095h, 0ceh, 04ah
    db 0ceh, 08bh, 021h, 053h, 04fh, 06ah, 007h, 0d9h
    db 0abh, 0e5h, 0d6h, 009h, 08ch, 03fh, 042h, 017h
    db 07dh, 04fh, 021h, 0e6h, 0b9h, 003h, 058h, 0ach
    db 082h, 0dbh, 07fh, 0e6h, 013h, 049h, 0a0h, 05ch
    db 0e1h, 0b2h, 0c4h, 073h, 0d6h, 05ah, 09fh, 080h
    db 0c4h, 057h, 061h, 0a9h, 0e0h, 08dh, 0b2h, 0f3h
    db 09bh, 015h, 03ch, 0edh, 046h, 0f7h, 002h, 0a8h
  
ld_qb:
    pop    esi
    push   ecx
tfi_l1:
    lodsb                    ; load byte
    aam    16                ; get 2 bytes
    stosw                    ; store as 16-bit word
    loop   tfi_l1            ; do 64-bytes in esi
    pop    eax

tfi_l2:
    mov    esi, esp          ; esi = &t[0][0][0];
    lea    edi, [ebx+eax*2+32]  ; edi = &ctx->qbox[0][0]
    cdq                      ; j=0
tfi_l3:
;;    call   gq                ; gq(i, p);

; uint8_t gq (uint8_t *p, uint8_t x)
; esi = p
; ecx = x
gq:
    pushad
    xchg   eax, ecx
    xor    ecx, ecx
gq_l2:
    mov    bl, al             ; bl = x
    ; a = (x >> 4) ^ (x & 15);
    aam    16
    xor    al, ah
    ; b = (x >> 4) ^ (x >> 1) & 15 ^ (x << 3) & 0x8;
    imul   edx, ebx, 8
    shr    bl, 1
    xor    bl, ah
    xor    bl, dl
    ; ------------
    and    eax, 15
    and    ebx, 15    
    ; x0 = p[a];
    mov    ah, [esi+eax]
    ; x1 = p[b+16];
    mov    al, [esi+ebx+16]
    jecxz  gq_l3  
    xchg   al, ah
gq_l3:
    ; x1 <<= 4
    ; x = x0 | x1
    aad    16
    ; p += 32
    add    esi, 32
    ; i++
    dec    ecx
    jp     gq_l2            ; i < 2
    ; return x
    mov    byte[esp+_edx+1], al
    popad
;;    ret
    
    mov    [edi+ecx], dh     ; q[i] = gq(i, p);
    add    esi, eax          ; p += 64
    lea    edi, [edi+eax*4]  ; q += 256
    dec    edx               ; j++
    jp     tfi_l3            ; j < 2
    
    inc    cl                ; i++
    jnz    tfi_l2
    
    leave                    ; free stack
    popad
    ret
    
; ***********************************************
; void tf_setkey(tf_ctx *ctx, void *key)
; ***********************************************
tf_setkey:
_tf_setkeyx:
    pushad
    mov    ecx, esp
    pushad
    sub    ecx, esp
    mov    edi, esp
    mov    ebx, [edi+64+4]   ; ctx
    mov    esi, [edi+64+8]   ; key
    mov    edx, esi          ; edx=key
    rep    movsb
    
    call   tf_init
    
    mov    edi, ebx          ; edi=keys
sk_l1:
    ; ecx/i = 0
    mov    esi, esp          ; esi=p/key_copy
sk_l2:
    call   round_h           ; A = mds(round_h(ctx, i++, p++));
    call   mds
    add    esi, 4            ; p++
    inc    ecx               ; i++
    xchg   eax, ebp          ; swap A and B
    test   cl, 1             ; if (i & 1) goto sk_l1
    jnz    sk_l2
    
    rol    ebp, 8            ; B = ROTL32(B, 8);
    add    eax, ebp          ; A += B;
    add    ebp, eax          ; B += A;
    stosd                    ; ctx->keys[i-2] = A;
    xchg   eax, ebp
    rol    eax, 9
    stosd                    ; ctx->keys[i-1] = ROTL32(B, 9);
    cmp    ecx, 40           ; i < 40
    jnz    sk_l1
    
    add    esi, 16           ; p += 4
    mov    cl, 4             ; for (i=0; i<4; i++) {
sk_l3:
    ; *p = reedsolomon(mk->v64[i]);
;;    call   reedsolomon

; in:  ebp
; out: eax = result
; uint32_t reedsolomon (uint64_t in)
reedsolomon:
    pushad
    mov    ebx, [edx]
    mov    edx, [edx+4]
    mov    cl, 88h
    jmp    rs_l1
rs_l0:
    xor    edx, ebx
rs_l1:
    rol    edx, 8
    mov    ah, dl
    shr    ah, 1
    jnb    rs_l2
    xor    ah, 0a6h
rs_l2:
    mov    al, dl
    add    al, al
    jnc    rs_l3
    xor    al, 04dh
rs_l3:
    xor    ah, al
    xor    dh, ah
    shl    eax, 16
    xor    edx, eax
    shr    cl, 1
    jnb    rs_l1
    jnz    rs_l0
    mov    [esp+_eax], edx
    popad
;;    ret

    mov    [esi], eax        ;
    add    edx, 8
    sub    esi, 8            ; p -= 2
    loop   sk_l3
    
    lodsd                    ; p++
    lodsd                    ; p++
sk_l4:                       ; for (i=0; i<256; i++) {
    call   round_h           ;   x.v32 = round_h(ctx, i, p);
    lea    edi, [ebx+sbox]   ;   sbp = &ctx->sbox[0];
sk_l5:                       ;   do {
    mov    [edi+ecx], al     ;     sbp[i] = x.v8[0];    
    add    edi, 256          ;     sbp += 256;
    shr    eax, 8            ;     x.v32 >>= 8;
    jnz    sk_l5             ;   } while (x.v32!=0);
    
    inc    cl                ; 
    jnz    sk_l4             ; }
    
    popad
    popad
    ret
    
    