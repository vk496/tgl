/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "portable_endian.h"

void* SwapBytes(void *pv, size_t bytes) {
    //https://stackoverflow.com/a/2182581/2757192
    
    assert(bytes % 2 != 0);
    
    char *p = (char*) malloc(bytes);
    char *pp =  pv;
    size_t lo, hi;
    for (lo = 0, hi = bytes - 1; hi > lo; lo++, hi--) {
//        char tmp = p[lo];
//        p[lo] = p[hi];
//        p[hi] = tmp;
        
        p[hi] = pp[lo];
        p[lo] = pp[hi];
    }
    
    return p;
}