#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../7z_advancecomp/7z.h"   // from AdvanceComp



// from quickbms.c
enum {
    LZMA_FLAGS_NONE         = 0,
    LZMA_FLAGS_86_HEADER    = 1,
    LZMA_FLAGS_86_DECODER   = 2,
    LZMA_FLAGS_EFS          = 4,
    LZMA_FLAGS_NOP
};



extern "C" int advancecomp_rfc1950(unsigned char *in, int insz, unsigned char *out, int outsz) {
    unsigned int    out_size = outsz;
    if(!compress_rfc1950_7z(in, insz, out, out_size, 5, 258)) return(-1);
    return(out_size);
}



extern "C" int advancecomp_deflate(unsigned char *in, int insz, unsigned char *out, int outsz) {
    unsigned int    out_size = outsz;
    if(!compress_deflate_7z(in, insz, out, out_size, 5, 258)) return(-1);
    return(out_size);
}



extern "C" int advancecomp_lzma(unsigned char *in, int insz, unsigned char *out, int outsz, int lzma_flags) {
    unsigned int    out_size;
    int     filter  = 0,
            propsz  = 5;

    if(lzma_flags & LZMA_FLAGS_EFS) {
        if(outsz < 4) return(-1);
        out[0] = 0;
        out[1] = 0 >> 8;
        out[2] = propsz;
        out[3] = propsz >> 8;
        out   += 4;
        outsz -= 4;
    }
    if(lzma_flags & LZMA_FLAGS_86_DECODER) {
        if(outsz < 1) return(-1);
        out[0] = filter;
        out++;
        outsz--;
    }
    if(lzma_flags & LZMA_FLAGS_86_HEADER) {
        if(outsz < 8) return(-1);
        out[0] = insz;  // 64bit
        out[1] = insz >> 8;
        out[2] = insz >> 16;
        out[3] = insz >> 24;
        out[4] = 0;
        out[5] = 0;
        out[6] = 0;
        out[7] = 0;
        out   += 8;
        outsz -= 8;
    }
    out_size = outsz;
    if(!compress_lzma_7z(in, insz, out, out_size, 2, 1 << 26, 256 /* cannot use 273! */)) return(-1);
    return(out_size);
}

