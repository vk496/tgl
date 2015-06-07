/*
 This file is part of tgl-library

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

 Copyright Matthias Jentsch 2015
 */

#ifndef __TGL__TGL_CRYPT__
#define __TGL__TGL_CRYPT__

#include "config.h"

#ifdef HAVE_LIBOPENSSL
#  include <openssl/md5.h>
#  include <openssl/sha.h>
#  include <openssl/pem.h>
#  include <openssl/rand.h>
#  include <openssl/aes.h>
#  include <openssl/rsa.h>
#  include <openssl/err.h>

#  define TGLC_BN_CTX  BN_CTX
#  define TGLC_BIGNUM  BIGNUM
#  define TGLC_RSA     RSA
#  define TGLC_AES_KEY AES_KEY
#else
#  define TGLC_BN_CTX  void
#  define TGLC_BIGNUM  void
#  define TGLC_RSA     void
#  define TGLC_AES_KEY void
#endif

/*
#elseif HAVE_LIBGCRYPT
#  define TGLC_BN_CTX  void
#  define TGLC_BIGNUM  gcry_mpi_t
#  define TGLC_RSA     RSA
#  define TGLC_AES_KEY AES_KEY
*/

struct tgl_crypt_methods {

  // bignum
  TGLC_BN_CTX* (*BN_CTX_new) ();
  int (*BN_CTX_free) (TGLC_BN_CTX* ctx);
  TGLC_BIGNUM *(*BN_new) (void);
  void (*BN_init) (TGLC_BIGNUM *);
  void (*BN_free) (TGLC_BIGNUM *a);
  void (*BN_clear_free) (TGLC_BIGNUM *a);
  int (*BN_cmp) (TGLC_BIGNUM *a, TGLC_BIGNUM *b);
  int (*BN_is_prime) (const TGLC_BIGNUM *a, int checks, void (*callback) (int, int, void *), TGLC_BN_CTX *ctx, void *cb_arg);
  int (*BN_bn2bin) (const TGLC_BIGNUM *a, unsigned char *to);
  TGLC_BIGNUM * (*BN_bin2bn)(const unsigned char *s, int len, TGLC_BIGNUM *ret);
  int (*BN_set_word) (TGLC_BIGNUM *a, unsigned long w);
  unsigned long (*BN_get_word) (TGLC_BIGNUM *a);
  int (*BN_num_bytes) (const TGLC_BIGNUM *a);
  int (*BN_num_bits) (const TGLC_BIGNUM *a);
  int (*BN_sub) (TGLC_BIGNUM *r, const TGLC_BIGNUM *a, const TGLC_BIGNUM *b);
  int (*BN_div) (TGLC_BIGNUM *dv, TGLC_BIGNUM *rem, const TGLC_BIGNUM *a, const TGLC_BIGNUM *d, TGLC_BN_CTX *ctx);
  int (*BN_mod_exp) (TGLC_BIGNUM *r, TGLC_BIGNUM *a, const TGLC_BIGNUM *p, const TGLC_BIGNUM *m, TGLC_BN_CTX *ctx);
  void (*AES_ige_encrypt) (const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, const int enc);
  int (*AES_set_encrypt_key) (const unsigned char *userKey, const int bits, AES_KEY *key);
  int (*AES_set_decrypt_key) (const unsigned char *userKey, const int bits, AES_KEY *key);
  unsigned char* (*MD5) (const unsigned char *d, unsigned long n, unsigned char *md);
  unsigned char* (*SHA1) (const unsigned char *d, size_t n, unsigned char *md);
  unsigned char* (*SHA256) (const unsigned char *d, size_t n, unsigned char *md);
  TGLC_RSA (*PEM_read_RSAPublicKey) (FILE *fp, TGLC_RSA **x, pem_password_cb *cb, void *u);
  void (*RSA_free) (TGLC_RSA *rsa);
  void (*RAND_add) (const void *buf, int num, int entropy);
  int (*RAND_bytes) (unsigned char *buf, int num);
  int (*RAND_pseudo_bytes) (unsigned char *buf, int num);
  void (*ERR_print_errors_fp) (FILE *fp);
};

extern struct tgl_crypt_methods TGLCM;

#endif
