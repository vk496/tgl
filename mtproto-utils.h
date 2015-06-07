#ifndef __MTPROTO_UTILS_H__
#define __MTPROTO_UTILS_H__
#include "tgl-crypt.h"
int tglmp_check_DH_params (struct tgl_state *TLS, TGLC_BIGNUM *p, int g);
int tglmp_check_g_a (struct tgl_state *TLS, TGLC_BIGNUM *p, TGLC_BIGNUM *g_a);
int bn_factorize (TGLC_BIGNUM *pq, TGLC_BIGNUM *p, TGLC_BIGNUM *q);
#endif
