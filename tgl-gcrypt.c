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

#include "tgl-gcrypt.h"

#include <gcrypt.h>
#include <assert.h>

#ifdef VALGRIND_FIXES
#include "valgrind/memcheck.h"
#endif

// no context needed, but return a valid pointer to not fail assertions
TGLC_BN_CTX* BN_CTX_new () {
  return malloc (sizeof(int));
}
void BN_CTX_free (TGLC_BN_CTX* ctx) {
  free (ctx);
}

TGLC_BIGNUM *BN_new () {
  return gcry_mpi_snew (0);
}

void BN_free (TGLC_BIGNUM *a) {
  gcry_mpi_release (a);
}

void BN_clear_free (TGLC_BIGNUM *a) {
  // since 'a' is always allocated as secure mpi, it will be cleared by libgcrypt
  gcry_mpi_release (a);
}

int BN_cmp (const TGLC_BIGNUM *a, const TGLC_BIGNUM *b) {
  return gcry_mpi_cmp (a, b);
}

int BN_is_prime (const TGLC_BIGNUM *a, int checks, void (*callback) (int, int, void *), TGLC_BN_CTX *ctx, void *cb_arg) {
  assert (! callback && "callbacks not implemented");
  
  gcry_error_t err = gcry_prime_check (a, 0);
  assert (!err || err == GPG_ERR_NO_PRIME);
  return err == 0;
}

int BN_bn2bin (const TGLC_BIGNUM *a, unsigned char *to) {
  size_t nscanned;
  assert (! gcry_mpi_print (GCRYMPI_FMT_USG, to, TGLCM.TGLCM_BN_num_bytes(a), &nscanned, a));
  return (int)nscanned;
}

TGLC_BIGNUM *BN_bin2bn (const unsigned char *s, int len) {
  TGLC_BIGNUM *ret;
  size_t ns;
  assert (! gcry_mpi_scan (&ret, GCRYMPI_FMT_USG, s, len, &ns));
  assert ((int)ns == len);
  return ret;
}

int BN_set_word (TGLC_BIGNUM *a, unsigned long w) {
  gcry_mpi_t err = gcry_mpi_set_ui (a, w);
  assert (!err);
}

unsigned long BN_get_word (const TGLC_BIGNUM *a) {
  // TODO: think about way to implement this
}

int TGLCM_BN_num_bytes (const TGLC_BIGNUM *a) {
  return gcry_mpi_get_nbits (a) >> 3;
}

int BN_num_bits (const TGLC_BIGNUM *a) {
  return gcry_mpi_get_nbits (a);
}

int BN_sub (TGLC_BIGNUM *r, const TGLC_BIGNUM *a, const TGLC_BIGNUM *b) {
  gcry_mpi_sub (r, a, b);
}

int BN_div (TGLC_BIGNUM *dv, TGLC_BIGNUM *rem, const TGLC_BIGNUM *a, const TGLC_BIGNUM *d, TGLC_BN_CTX *ctx) {
  gcry_mpi_div (dv, rem, a, d, -1 /* round towards zero */);
  return TRUE;
}

int BN_mod_exp (TGLC_BIGNUM *r, const TGLC_BIGNUM *a, const TGLC_BIGNUM *p, const TGLC_BIGNUM *m, TGLC_BN_CTX *ctx) {
  gcry_mpi_powm (r, a, p, m);
  return TRUE;
}

// BN_num_bytes is a macro and cannot be pointed to
int TGLC_BN_num_bytes (const TGLC_BIGNUM *a) {
  return BN_num_bytes (a);
}

int MD5 (const unsigned char *d, unsigned long n, unsigned char *md) {
  assert (md);
  gcry_md_hash_buffer (GCRY_MD_M D5, md, d, n);
  return gcry_md_get_algo_dlen (GCRY_MD_MD5);
}

int SHA1 (const unsigned char *d, size_t n, unsigned char *md) {
  assert (md);
  gcry_md_hash_buffer (GCRY_MD_SHA1, md, d, n);
  return gcry_md_get_algo_dlen (GCRY_MD_SHA1);
}

int SHA256 (const unsigned char *d, size_t n, unsigned char *md) {
  assert (md);
  gcry_md_hash_buffer (GCRY_MD_SHA256, md, d, n);
  return gcry_md_get_algo_dlen (GCRY_MD_SHA256);
}

/* RSA */

TGLC_RSA *PEM_read_RSAPublicKey (FILE *fp, TGLC_RSA **x, pem_password_cb *cb, void *u) {
}

void RSA_free (TGLC_RSA *rsa) {
}

/* RAND */

void RAND_add (const void *buf, int num, double entropy) {
  assert (num > 0 && entropy < num);
  gcry_random_add_bytes (buf, num, 100 * entropy / num);
}

int RAND_bytes (unsigned char *buf, int num) {
  gcry_randomize (buf, num, GCRY_VERY_STRONG_RANDOM);
}

int RAND_pseudo_bytes (unsigned char *buf, int num) {
  gcry_randomize (buf, num, GCRY_STRONG_RANDOM);
}

void ERR_print_errors_fp (FILE *fp) {
}

int AES_set_encrypt_key (const unsigned char *userKey, const int bits, AES_KEY *key) {
  assert (! gcry_cipher_setkey (*key));
}
int AES_set_decrypt_key (const unsigned char *userKey, const int bits, AES_KEY *key)
}

void AES_ige_encrypt (const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, const int enc)  {
  // TODO: implement IGE
}

// implement cryptographic and BN functions using OpenSSL
struct tgl_crypt_methods TGLCM = {
  BN_CTX_new,
  BN_CTX_free,
  BN_new,
  BN_free,
  BN_clear_free,
  BN_cmp,
  BN_is_prime,
  BN_bn2bin,
  BN_bin2bn,
  BN_set_word,
  BN_get_word,
  TGLC_BN_num_bytes,
  BN_num_bits,
  BN_sub,
  BN_div,
  BN_mod_exp,
  AES_ige_encrypt,
  AES_set_encrypt_key,
  AES_set_decrypt_key,
  MD5,
  SHA1,
  SHA256,
  PEM_read_RSAPublicKey,
  RSA_free,
  RAND_add,
  RAND_bytes,
  RAND_pseudo_bytes,
  ERR_print_errors_fp
};

void tglt_secure_random (void *s, int l) {
  if (TGLCM.RAND_bytes (s, l) <= 0) {
    /*if (allow_weak_random) {
     TGLCM.RAND_pseudo_bytes (s, l);
     } else {*/
    assert (0 && "End of random. If you want, you can start with -w");
    //}
  } else {
#ifdef VALGRIND_FIXES
    VALGRIND_MAKE_MEM_DEFINED (s, l);
    VALGRIND_CHECK_MEM_IS_DEFINED (s, l);
#endif
  }
}
