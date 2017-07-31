#include "portable_endian.h"

void* SwapBytes(void *pv, size_t bytes) { //TODO imitate htole functions
    //https://stackoverflow.com/a/2182581/2757192
        
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