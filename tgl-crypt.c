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

#include "tgl-crypt.h"

// BN_num_bytes is a macro and cannot be pointed to
int *TGLC_BN_num_bytes (const TGLC_BIGNUM *a) {
  return BN_num_bytes (a);
}

struct tgl_crypt_methods TGLCM = {
  BN_CTX_new,
  BN_CTX_free,
  BN_new,
  BN_init,
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
