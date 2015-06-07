#include "config.h"
#include "tgl-crypt.h"
#include "tgl.h"
#include "tools.h"

static unsigned long long gcd (unsigned long long a, unsigned long long b) {
  return b ? gcd (b, a % b) : a;
}

static int check_prime (struct tgl_state *TLS, TGLC_BIGNUM *p) {
  int r = TGLCM.BN_is_prime (p, BN_prime_checks, 0, TLS->BN_ctx, 0);
  ensure (r >= 0);
  return r;
}


// Complete set of checks see at https://core.telegram.org/mtproto/security_guidelines


// Checks that (p,g) is acceptable pair for DH
int tglmp_check_DH_params (struct tgl_state *TLS, TGLC_BIGNUM *p, int g) {
  if (g < 2 || g > 7) { return -1; }
  if (TGLCM.BN_num_bits (p) != 2048) { return -1; }
  
  TGLC_BIGNUM *t = TGLMC.BN_new ();
  
  TGLC_BIGNUM *dh_g = TGLMC.BN_new ();
  
  ensure (TGLCM.BN_set_word (dh_g, 4 * g));
  ensure (BN_mod (t, p, dh_g, TLS->BN_ctx));
  int x = TGLCM.BN_get_word (t);
  assert (x >= 0 && x < 4 * g);

  TGLCM.BN_free (dh_g);

  int res = 0;
  switch (g) {
  case 2:
    if (x != 7) { res = -1; }
    break;
  case 3:
    if (x % 3 != 2) { res = -1; }
    break;
  case 4:
    break;
  case 5:
    if (x % 5 != 1 && x % 5 != 4) { res = -1; }
    break;
  case 6:
    if (x != 19 && x != 23) { res = -1; }
    break;
  case 7:
    if (x % 7 != 3 && x % 7 != 5 && x % 7 != 6) { res = -1; }
    break;
  }

  if (res < 0 || !check_prime (TLS, p)) { 
    TGLCM.BN_free (t);
    return -1; 
  }

  TGLC_BIGNUM *b = TGLMC.BN_new ();
  ensure (TGLCM.BN_set_word (b, 2));
  ensure (TGLCM.BN_div (t, 0, p, b, TLS->BN_ctx));
  if (!check_prime (TLS, t)) { 
    res = -1;
  }
  TGLCM.BN_free (b);
  TGLCM.BN_free (t);
  return res;
}

// checks that g_a is acceptable for DH
int tglmp_check_g_a (struct tgl_state *TLS, TGLC_BIGNUM *p, TGLC_BIGNUM *g_a) {
  if (TGLCM.BN_num_bytes (g_a) > 256) {
    return -1;
  }
  if (TGLCM.BN_num_bits (g_a) < 2048 - 64) {
    return -1;
  }
  if (TGLCM.BN_cmp (p, g_a) <= 0) {
    return -1;
  }
  
  TGLC_BIGNUM *dif = TGLMC.BN_new ();
  TGLCM.BN_sub (dif, p, g_a);
  if (TGLCM.BN_num_bits (dif) < 2048 - 64) {
    TGLCM.BN_free (dif);
    return -1;
  }
  TGLCM.BN_free (dif);
  return 0;
}

static unsigned long long BN2ull (TGLC_BIGNUM *b) {
  if (sizeof (BN_ULONG) == 8) {
    return TGLCM.BN_get_word (b);
  } else {
    unsigned int tmp[2];
    memset (tmp, 0, 8);
    TGLCM.BN_bn2bin (b, (void *)tmp);
    return __builtin_bswap32 (tmp[0]) * (1ll << 32) | __builtin_bswap32 (tmp[1]);
  }
}

static void ull2BN (TGLC_BIGNUM *b, unsigned long long val) {
  if (sizeof (BN_ULONG) == 8 || val < (1ll << 32)) {
    TGLCM.BN_set_word (b, val);
  } else {
    unsigned int tmp[2];
    tmp[0] = __builtin_bswap32 (val >> 32);
    tmp[1] = __builtin_bswap32 ((unsigned)val);
    TGLCM.BN_bin2bn ((void *)tmp, 8, b);
  }
}

int bn_factorize (TGLC_BIGNUM *pq, TGLC_BIGNUM *p, TGLC_BIGNUM *q) {
  // Should work in any case
  // Rewrite this code
  unsigned long long what = BN2ull (pq);

  int it = 0;
  
  unsigned long long g = 0;
  int i;
  for (i = 0; i < 3 || it < 1000; i++) {
    int q = ((lrand48() & 15) + 17) % what;
    unsigned long long x = (long long)lrand48 () % (what - 1) + 1, y = x;
    int lim = 1 << (i + 18);
    int j;
    for (j = 1; j < lim; j++) {
      ++it;
      unsigned long long a = x, b = x, c = q;
      while (b) {
        if (b & 1) {
          c += a;
          if (c >= what) {
            c -= what;
          }
        }
        a += a;
        if (a >= what) {
          a -= what;
        }
        b >>= 1;
      }
      x = c;
      unsigned long long z = x < y ? what + x - y : x - y;
      g = gcd (z, what);
      if (g != 1) {
        break;
      }
      if (!(j & (j - 1))) {
        y = x;
      }
    }
    if (g > 1 && g < what) break;
  }

  assert (g > 1 && g < what);
  unsigned long long p1 = g;
  unsigned long long p2 = what / g;
  if (p1 > p2) {
    unsigned long long t = p1; p1 = p2; p2 = t;
  }
  ull2BN (p, p1);
  ull2BN (q, p2);
  return 0;
}
