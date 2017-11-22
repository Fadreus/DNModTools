#include "encryption/leverage_ssc.h"
u8 *mystrchrs(u8 *str, u8 *chrs);
QUICKBMS_int readbase(u8 *data, QUICKBMS_int size, QUICKBMS_int *readn);
int unhex(u8 *in, int insz, u8 *out, int outsz);
QUICKBMS_int getxx(u8 *tmp, QUICKBMS_int bytes);
QUICKBMS_int putxx(u8 *data, QUICKBMS_u_int num, QUICKBMS_int bytes);
QUICKBMS_int math_operations(QUICKBMS_int var1i, QUICKBMS_int op, QUICKBMS_int var2i, QUICKBMS_int sign);



// math
typedef struct {
    int     op;
    int     var2;
    int     sign;
    int     size;
    int     exact;
} math_context;

void math_setkey(math_context *ctx, u8 *key, u8 *ivec) {
    u8      *p;

    p = key;
    while(*p && (*p <= ' ')) p++;
            for(; *p; p++) {
                if(*p <= ' ') break;
                if(tolower(*p) == 'u') {          // unsigned
                    ctx->sign = 1;
                //} else if(tolower(*p) == 'i') {   // signed (default)
                    //ctx->sign = 0;
                } else if(!ctx->op) {            // operator
                    ctx->op = tolower(*p);
                }
            }

    while(*p && (*p <= ' ')) p++;
    ctx->var2 = readbase(p, 10, NULL);
    while(*p && (*p > ' ')) p++;

    ctx->size = 32;
    while(*p && (*p <= ' ')) p++;
    if(*p > ' ') ctx->size = readbase(p, 10, NULL);

    switch(ctx->size) {
        case 1:  ctx->size = 8;     break;
        case 2:  ctx->size = 16;    break;
        case 4:  ctx->size = 32;    break;
        default:                    break;
    }
    ctx->size /= 8;
    if(ctx->size <= 0) ctx->size = 0;
    if(ctx->size >  8) ctx->size = 8;

    if(ivec && ivec[0]) ctx->exact = readbase(ivec, 10, NULL);
}

void math_crypt(math_context *ctx, u8 *data, int datalen) {
    int     var1,
            i;
    u64     v8;
    u32     v4;
    u16     v2;
    u8      v1;

    if(ctx->size <= 0) return;
    datalen /= ctx->size;
    for(i = 0; i < datalen; i++) {
        if(ctx->exact) {
            #define math_crypt_bytes(X) { \
                v##X = getxx(data, X); \
                v##X = math_operations(v##X, ctx->op, ctx->var2 ? ctx->var2 : v##X, ctx->sign); \
                putxx(data, v##X, X); \
            }
            switch(ctx->size) {
                case 1: math_crypt_bytes(1) break;
                case 2: math_crypt_bytes(2) break;
                case 4: math_crypt_bytes(4) break;
                case 8: math_crypt_bytes(8) break;
                default: break;
            }
        } else {
            var1 = getxx(data, ctx->size);
            var1 = math_operations(var1, ctx->op, ctx->var2 ? ctx->var2 : var1, ctx->sign);
            putxx(data, var1, ctx->size);
        }
        data += ctx->size;
    }
}



// swap
typedef struct {
    int     size;
} swap_context;

void swap_setkey(swap_context *ctx, int num) {
    ctx->size = num;
    switch(ctx->size) {
        case 1:  ctx->size = 8;     break;
        case 2:  ctx->size = 16;    break;
        case 4:  ctx->size = 32;    break;
        default:                    break;
    }
    ctx->size /= 8;
    if(ctx->size <= 1) ctx->size = 1;
    if(ctx->size > 32) ctx->size = 32;
}

void swap_crypt(swap_context *ctx, u8 *data, int datalen) {
    int     i,
            j;
    u8      tmp[32],    // 256bit
            *p;

    if(ctx->size <= 1) return;
    if(ctx->size > sizeof(tmp)) ctx->size = sizeof(tmp);
    datalen /= ctx->size;
    for(i = 0; i < datalen; i++) {
        p = tmp + ctx->size;
        for(j = 0; j < ctx->size; j++) {
            p--;
            *p = data[j];
        }
        for(j = 0; j < ctx->size; j++) {
            data[j] = p[j];
        }
        data += ctx->size;
    }
}



// xor
typedef struct {
    u8      *key;
    int     keysz;
    int     keypos;
} xor_context;

void xor_setkey(xor_context *ctx, u8 *key, int keysz) {
    ctx->key    = malloc(keysz);    // "ctx->key = key" was good too
    memcpy(ctx->key, key, keysz);
    ctx->keysz  = keysz;
    ctx->keypos = 0;
}

void xor_crypt(xor_context *ctx, u8 *data, int datalen) {
    int     i;

    for(i = 0; i < datalen; i++) {
        if(ctx->keypos >= ctx->keysz) ctx->keypos = 0;
        data[i] ^= ctx->key[ctx->keypos];
        ctx->keypos++;
    }
}



// rot
typedef struct {
    u8      *key;
    int     keysz;
    int     keypos;
} rot_context;

void rot_setkey(rot_context *ctx, u8 *key, int keysz) {
    ctx->key    = malloc(keysz);    // "ctx->key = key" was good too
    memcpy(ctx->key, key, keysz);
    ctx->keysz  = keysz;
    ctx->keypos = 0;
}

void rot_decrypt(rot_context *ctx, u8 *data, int datalen) {
    int     i;

    for(i = 0; i < datalen; i++) {
        if(ctx->keypos >= ctx->keysz) ctx->keypos = 0;
        data[i] += ctx->key[ctx->keypos];
        ctx->keypos++;
    }
}

void rot_encrypt(rot_context *ctx, u8 *data, int datalen) {
    int     i;

    for(i = 0; i < datalen; i++) {
        if(ctx->keypos >= ctx->keysz) ctx->keypos = 0;
        data[i] -= ctx->key[ctx->keypos];
        ctx->keypos++;
    }
}



// rotate
typedef struct {
    int     num;
    int     size;
} rotate_context;

void rotate_setkey(rotate_context *ctx, u8 *key, u8 *ivec) {
    ctx->num  = readbase(key, 10, NULL);
    ctx->size = 8;
    if(ivec && ivec[0]) ctx->size = readbase(ivec, 10, NULL);
    if(ctx->size >= 8) ctx->size /= 8;
}

void rotate_crypt(rotate_context *ctx, u8 *data, int datalen, int decenc) {
    int     i,
            num;
    u64     v8;
    u32     v4;
    u16     v2;
    u8      v1;

    if(ctx->size <= 0) return;

    num = ctx->num;
    if(decenc) num = ctx->size - num;

    datalen /= ctx->size;
    for(i = 0; i < datalen; i++) {
        #define rotate_crypt_bytes(X) { \
            v##X = getxx(data, X); \
            v##X = (v##X  >> (num)) | (v##X  << ((X << 3) - num)); \
            putxx(data, v##X, X); \
        }
        switch(ctx->size) {
            case 1: rotate_crypt_bytes(1)   break;
            case 2: rotate_crypt_bytes(2)   break;
            case 4: rotate_crypt_bytes(4)   break;
            case 8: rotate_crypt_bytes(8)   break;
            default: break;
        }
        data += ctx->size;
    }
}



// incremental xor/rot
typedef struct {
    int     xor_rot;
    u32     byte;
    int     bytesz;
    int     inc;
} inc_context;

void inc_setkey(inc_context *ctx, int xor_rot, u32 byte, int inc) {
    ctx->xor_rot    = xor_rot;
    ctx->byte       = byte;
    if(byte > 0xffff) {
        ctx->bytesz = 4;
    } else if(byte > 0xff) {
        ctx->bytesz = 2;
    } else {
        ctx->bytesz = 1;
    }
    if(!inc) inc = 1;   // inc can be both positive and negative
    ctx->inc        = inc;
}

void inc_crypt(inc_context *ctx, u8 *data, int datalen, int decenc) {
    u32     var1;
    int     i;

    datalen /= ctx->bytesz;
    for(i = 0; i < datalen; i++) {
        var1 = getxx(data, ctx->bytesz);
        if(!ctx->xor_rot) { // XOR
            var1 ^= ctx->byte;
        } else {            // ROT
            if(!decenc) {
                var1 += ctx->byte;
            } else {
                var1 -= ctx->byte;
            }
        }
        putxx(data, var1, ctx->bytesz);
        ctx->byte += ctx->inc;
        data += ctx->bytesz;
    }
}



// charset
typedef struct {
    u8      key[256];
} charset_context;

void charset_setkey(charset_context *ctx, u8 *key, int keysz) {
    memset(ctx->key, 0, 256);
    if(keysz <= 0) return;
    if(keysz > 256) keysz = 256;
    memcpy(ctx->key, key, keysz);
}

void charset_decrypt(charset_context *ctx, u8 *data, int datalen) {
    int     i;

    for(i = 0; i < datalen; i++) {
        data[i] = ctx->key[data[i]];
    }
}

void charset_encrypt(charset_context *ctx, u8 *data, int datalen) {
    int     i,
            j,
            c;

    for(i = 0; i < datalen; i++) {
        c = data[i];
        for(j = 0; j < 256; j++) {
            if(ctx->key[j] == c) {
                c = j;
                break;
            }
        }
        data[i] = c;
    }
}



// ssc
typedef struct {
    u8      *key;
    int     keysz;
} ssc_context;

void ssc_setkey(ssc_context *ctx, u8 *key, int keysz) {
    ctx->key    = malloc(keysz);    // "ctx->key = key" was good too
    memcpy(ctx->key, key, keysz);
    ctx->keysz  = keysz;
}



// wincrypt
#ifdef WIN32
#include <wincrypt.h>

typedef struct {
    DWORD   num;
    char    *str;
} wincrypt_types;
wincrypt_types wincrypt_mspn1[] = { // blah
    { (DWORD)MS_DEF_DH_SCHANNEL_PROV,  "MS_DEF_DH_SCHANNEL_PROV" },
    { (DWORD)MS_DEF_DSS_DH_PROV,       "MS_DEF_DSS_DH_PROV" },
    { (DWORD)MS_DEF_DSS_PROV,          "MS_DEF_DSS_PROV" },
    { (DWORD)MS_DEF_PROV,              "MS_DEF_PROV" },
    { (DWORD)MS_DEF_RSA_SCHANNEL_PROV, "MS_DEF_RSA_SCHANNEL_PROV" },
    { (DWORD)MS_DEF_RSA_SIG_PROV,      "MS_DEF_RSA_SIG_PROV" },
    { (DWORD)MS_ENH_DSS_DH_PROV,       "MS_ENH_DSS_DH_PROV" },
#ifdef MS_ENH_RSA_AES_PROV
    { (DWORD)MS_ENH_RSA_AES_PROV,      "MS_ENH_RSA_AES_PROV" },
#endif
    { (DWORD)MS_ENHANCED_PROV,         "MS_ENHANCED_PROV" },
    { (DWORD)MS_SCARD_PROV,            "MS_SCARD_PROV" },
    { (DWORD)MS_STRONG_PROV,           "MS_STRONG_PROV" },
    { (DWORD)NULL,                     NULL }
};
wincrypt_types wincrypt_mspn2[] = { // blah
    { (DWORD)MS_DEF_DH_SCHANNEL_PROV,  MS_DEF_DH_SCHANNEL_PROV },
    { (DWORD)MS_DEF_DSS_DH_PROV,       MS_DEF_DSS_DH_PROV },
    { (DWORD)MS_DEF_DSS_PROV,          MS_DEF_DSS_PROV },
    { (DWORD)MS_DEF_PROV,              MS_DEF_PROV },
    { (DWORD)MS_DEF_RSA_SCHANNEL_PROV, MS_DEF_RSA_SCHANNEL_PROV },
    { (DWORD)MS_DEF_RSA_SIG_PROV,      MS_DEF_RSA_SIG_PROV },
    { (DWORD)MS_ENH_DSS_DH_PROV,       MS_ENH_DSS_DH_PROV },
#ifdef MS_ENH_RSA_AES_PROV
    { (DWORD)MS_ENH_RSA_AES_PROV,      MS_ENH_RSA_AES_PROV },
#endif
    { (DWORD)MS_ENHANCED_PROV,         MS_ENHANCED_PROV },
    { (DWORD)MS_SCARD_PROV,            MS_SCARD_PROV },
    { (DWORD)MS_STRONG_PROV,           MS_STRONG_PROV },
    { (DWORD)NULL,                     NULL }
};
wincrypt_types wincrypt_prov[] = {
    { 1,  "PROV_RSA_FULL" },
    { 2,  "PROV_RSA_SIG" },
    { 3,  "PROV_DSS" },
    { 4,  "PROV_FORTEZZA" },
    { 5,  "PROV_MS_EXCHANGE" },
    { 5,  "PROV_MS_MAIL" },
    { 6,  "PROV_SSL" },
    { 7,  "PROV_STT_MER" },
    { 8,  "PROV_STT_ACQ" },
    { 9,  "PROV_STT_BRND" },
    { 10, "PROV_STT_ROOT" },
    { 11, "PROV_STT_ISS" },
    { 12, "PROV_RSA_SCHANNEL" },
    { 13, "PROV_DSS_DH" },
    { 14, "PROV_EC_ECDSA_SIG" },
    { 15, "PROV_EC_ECNRA_SIG" },
    { 16, "PROV_EC_ECDSA_FULL" },
    { 17, "PROV_EC_ECNRA_FULL" },
    { 18, "PROV_DH_SCHANNEL" },
    { 20, "PROV_SPYRUS_LYNKS" },
    { 21, "PROV_RNG" },
    { 22, "PROV_INTEL_SEC" },
    { 24, "PROV_RSA_AES" },
    { 0,  NULL }
};
wincrypt_types wincrypt_calg[] = {
    { 0x00006603, "CALG_3DES" },
    { 0x00006609, "CALG_3DES_112" },
    { 0x00006611, "CALG_AES" },
    { 0x00006611, "CALG_AES" },
    { 0x0000660e, "CALG_AES_128" },
    { 0x0000660e, "CALG_AES_128" },
    { 0x0000660f, "CALG_AES_192" },
    { 0x0000660f, "CALG_AES_192" },
    { 0x00006610, "CALG_AES_256" },
    { 0x00006610, "CALG_AES_256" },
    { 0x0000aa03, "CALG_AGREEDKEY_ANY" },
    { 0x0000660c, "CALG_CYLINK_MEK" },
    { 0x00006601, "CALG_DES" },
    { 0x00006604, "CALG_DESX" },
    { 0x0000aa02, "CALG_DH_EPHEM" },
    { 0x0000aa01, "CALG_DH_SF" },
    { 0x00002200, "CALG_DSS_SIGN" },
    { 0x0000aa05, "CALG_ECDH" },
    { 0x0000aa05, "CALG_ECDH" },
    { 0x00002203, "CALG_ECDSA" },
    { 0x00002203, "CALG_ECDSA" },
    { 0x0000a001, "CALG_ECMQV" },
    { 0x0000800b, "CALG_HASH_REPLACE_OWF" },
    { 0x0000800b, "CALG_HASH_REPLACE_OWF" },
    { 0x0000a003, "CALG_HUGHES_MD5" },
    { 0x00008009, "CALG_HMAC" },
    { 0x0000aa04, "CALG_KEA_KEYX" },
    { 0x00008005, "CALG_MAC" },
    { 0x00008001, "CALG_MD2" },
    { 0x00008002, "CALG_MD4" },
    { 0x00008003, "CALG_MD5" },
    { 0x00002000, "CALG_NO_SIGN" },
    { 0xffffffff, "CALG_OID_INFO_CNG_ONLY" },
    { 0xfffffffe, "CALG_OID_INFO_PARAMETERS" },
    { 0x00004c04, "CALG_PCT1_MASTER" },
    { 0x00006602, "CALG_RC2" },
    { 0x00006801, "CALG_RC4" },
    { 0x0000660d, "CALG_RC5" },
    { 0x0000a400, "CALG_RSA_KEYX" },
    { 0x00002400, "CALG_RSA_SIGN" },
    { 0x00004c07, "CALG_SCHANNEL_ENC_KEY" },
    { 0x00004c03, "CALG_SCHANNEL_MAC_KEY" },
    { 0x00004c02, "CALG_SCHANNEL_MASTER_HASH" },
    { 0x00006802, "CALG_SEAL" },
    { 0x00008004, "CALG_SHA" },
    { 0x00008004, "CALG_SHA1" },
    { 0x0000800c, "CALG_SHA_256" },
    { 0x0000800c, "CALG_SHA_256" },
    { 0x0000800d, "CALG_SHA_384" },
    { 0x0000800d, "CALG_SHA_384" },
    { 0x0000800e, "CALG_SHA_512" },
    { 0x0000800e, "CALG_SHA_512" },
    { 0x0000660a, "CALG_SKIPJACK" },
    { 0x00004c05, "CALG_SSL2_MASTER" },
    { 0x00004c01, "CALG_SSL3_MASTER" },
    { 0x00008008, "CALG_SSL3_SHAMD5" },
    { 0x0000660b, "CALG_TEK" },
    { 0x00004c06, "CALG_TLS1_MASTER" },
    { 0x0000800a, "CALG_TLS1PRF" },
    { 0,          NULL }
};
typedef struct {
    HCRYPTPROV  hProv;
    HCRYPTHASH  hHash;
    HCRYPTKEY   hKey;
    u8          *mspn;
    DWORD       prov;
    DWORD       hash;
    DWORD       algo;
} wincrypt_context;

u8 *wincrypt_parameters(u8 *parameters, wincrypt_types *types, DWORD *ret) {
    DWORD   tmp;
    int     i,
            len,
            quote = 0;
    u8      *p,
            *pquote = NULL,
            *pret;

    if(!parameters) return(NULL);
    if(!parameters[0]) return(NULL);
    p = parameters;
    if((*p == '\"') || (*p == '\'')) {
        quote = 1;
        for(++p; *p; p++) {
            if((*p == '\"') || (*p == '\'')) {
                pquote = p;
                break;
            }
        }
    }
    p = mystrchrs(p, " \t,;");
    if(!p) p = parameters + strlen(parameters);
    pret = p;

    if(quote) {
        parameters++;
        p = pquote;
    }
    len = p - parameters;
    if(len <= 0) return(NULL);

    tmp = readbase(parameters, 10, NULL);
    for(i = 0; types[i].str; i++) {
        if(
            (!strnicmp(types[i].str, parameters, len) && !types[i].str[len])
         || (tmp == types[i].num)) {
            *ret = (DWORD)types[i].num;
            break;
        }
    }
    return(pret + 1);
}

int wincrypt_setkey(wincrypt_context *ctx, u8 *key, int keysz, u8 *parameters) {
    static const int    flags[] = {
                0,
                CRYPT_NEWKEYSET,
                CRYPT_MACHINE_KEYSET,
                CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET,
                -1
            };
    int     i;
    u8      *p;

    ctx->mspn = MS_DEF_PROV;
    ctx->prov = PROV_RSA_FULL;
    ctx->hash = CALG_MD5;
    ctx->algo = CALG_RC4;

    if(parameters) {
        p = parameters;
        p = wincrypt_parameters(p, wincrypt_calg, &ctx->hash);
        p = wincrypt_parameters(p, wincrypt_calg, &ctx->algo);
        p = wincrypt_parameters(p, wincrypt_prov, &ctx->prov);
            wincrypt_parameters(p, wincrypt_mspn1, (DWORD *)&ctx->mspn);    // don't increment p
        p = wincrypt_parameters(p, wincrypt_mspn2, (DWORD *)&ctx->mspn);
    }

    for(i = 0; flags[i] >= 0; i++) {
        if(CryptAcquireContext(
            &ctx->hProv,
            NULL,
            ctx->mspn,
            ctx->prov,
            flags[i])) break;
    }
    if(flags[i] < 0) return(-1);

    if(!CryptCreateHash(
        ctx->hProv,
        ctx->hash,
        0,  //ctx->hashkey,
        0,
        &ctx->hHash)) return(-1);

    if(!CryptHashData(
        ctx->hHash,
        key,
        keysz,
        0)) return(-1);
    return(0);
}

int wincrypt_decrypt(wincrypt_context *ctx, u8 *data, int datalen) {
    DWORD   len;

    if(datalen <= 0) return(0);
    len = datalen;

    if(!CryptDeriveKey(
        ctx->hProv,
        ctx->algo,
        ctx->hHash,
        0,
        &ctx->hKey)) return(-1);

    if(!CryptDecrypt(
        ctx->hKey,
        0,
        TRUE,
        0,
        data,
        &len)) return(-1);
    return(len);
}

int wincrypt_encrypt(wincrypt_context *ctx, u8 *data, int datalen) {
    DWORD   len;

    if(datalen <= 0) return(0);
    len = datalen;

    if(!CryptDeriveKey(
        ctx->hProv,
        ctx->algo,
        ctx->hHash,
        0,
        &ctx->hKey)) return(-1);

    if(!CryptEncrypt(
        ctx->hKey,
        0,
        TRUE,
        0,
        data,
        &len,
        datalen)) return(-1);
    return(len);
}
#else
typedef struct {
} wincrypt_context;
int wincrypt_setkey(wincrypt_context *ctx, u8 *key, int keysz, u8 *parameters) {
    return(-1);
}
int wincrypt_decrypt(wincrypt_context *ctx, u8 *data, int datalen) {
    return(-1);
}
int wincrypt_encrypt(wincrypt_context *ctx, u8 *data, int datalen) {
    return(-1);
}
#endif



// CryptUnprotect (mainly for thoroughness, not for real usage)
#ifdef WIN32
#include <windows.h>
typedef struct {
    u8      *entropy;
    int     entropy_size;
} cunprot_context;
int cunprot_setkey(cunprot_context *ctx, u8 *key, int keysz) {
    if(keysz > 0) {
        ctx->entropy      = key;
        ctx->entropy_size = keysz;
    } else {
        ctx->entropy      = NULL;
        ctx->entropy_size = 0;
    }
    return(0);
}
int cunprot_decrypt(cunprot_context *ctx, u8 *data, int datalen) {
    DATA_BLOB   DataIn,
                DataEntropy,
                DataOut;
    int         ret;

    DataIn.pbData = data;
    DataIn.cbData = datalen;
    if(ctx->entropy) {
        DataEntropy.pbData = ctx->entropy;
        DataEntropy.cbData = ctx->entropy_size;
    }

    if(!CryptUnprotectData(
      &DataIn,
      NULL,
      ctx->entropy ? &DataEntropy : NULL,
      NULL,
      NULL,
      0,
      &DataOut)) {
        DataIn.pbData = malloc(datalen + 1);
        DataIn.cbData = unhex(data, datalen, DataIn.pbData, datalen);
        ret = CryptUnprotectData(
          &DataIn,
          NULL,
          ctx->entropy ? &DataEntropy : NULL,
          NULL,
          NULL,
          0,
          &DataOut);
        free(DataIn.pbData);    // free it in any case
        if(!ret) return(-1);
    }

    if(datalen > DataOut.cbData) datalen = DataOut.cbData;
    memcpy(data, DataOut.pbData, datalen);
    if(DataOut.pbData) LocalFree(DataOut.pbData);
    return(datalen);
}
int cunprot_encrypt(cunprot_context *ctx, u8 *data, int datalen) {
    DATA_BLOB   DataIn,
                DataEntropy,
                DataOut;
    int         ret;

    DataIn.pbData = data;
    DataIn.cbData = datalen;
    if(ctx->entropy) {
        DataEntropy.pbData = ctx->entropy;
        DataEntropy.cbData = ctx->entropy_size;
    }

    if(!CryptProtectData(
      &DataIn,
      L"description",
      ctx->entropy ? &DataEntropy : NULL,
      NULL,
      NULL,
      0,
      &DataOut)) {
        DataIn.pbData = malloc(datalen + 1);
        DataIn.cbData = unhex(data, datalen, DataIn.pbData, datalen);
        ret = CryptProtectData(
          &DataIn,
          L"description",
          ctx->entropy ? &DataEntropy : NULL,
          NULL,
          NULL,
          0,
          &DataOut);
        free(DataIn.pbData);
        if(!ret) return(-1);
    }

    if(datalen > DataOut.cbData) datalen = DataOut.cbData;
    memcpy(data, DataOut.pbData, datalen);
    if(DataOut.pbData) LocalFree(DataOut.pbData);
    return(datalen);
}
#else
typedef struct {
} cunprot_context;
int cunprot_setkey(cunprot_context *ctx, u8 *key, int keysz) {
    return(-1);
}
int cunprot_decrypt(cunprot_context *ctx, u8 *data, int datalen) {
    return(-1);
}
int cunprot_encrypt(cunprot_context *ctx, u8 *data, int datalen) {
    return(-1);
}
#endif



// crc
typedef struct {
    u32     table[256];
    u32     poly;
    int     size;
    u32     init;
    u32     final;
    int     type;
    int     rever;
} crc_context;
#define CRC_BITMASK(SIZE)   ((u64)1 << (u64)(SIZE))
static u64 reflect(u64 v, int b) {
    u64     t;
    int     i;

    t = v;
    for(i = 0; i < b; i++) {
        if(t & (u64)1) {
            v |= CRC_BITMASK((b - 1) - (u64)i);
        } else {
            v &= (CRC_BITMASK((b - 1) ^ (u64)0xffffffffffffffffLL) - (u64)i);
        }
        t >>= (u64)1;
    }
    return(v);
}
inline u64 widmask(int size) {
    return((((u64)1 << (u64)(size - 1)) - (u64)1) << (u64)1) | (u64)1;
}
static u64 cm_tab(int inbyte, u64 poly, int size, int rever) {
    u64     r,
            topbit;
    int     i;

    topbit = CRC_BITMASK(size - 1);

    if(rever) inbyte = reflect(inbyte, 8);  // RefIn

    r = (u64)inbyte << (u64)(size - 8);

    for(i = 0; i < 8; i++) {
        if(r & topbit) {
            r = (r << (u64)1) ^ poly;
        } else {
            r <<= (u64)1;
        }
    }

    if(rever) r = reflect(r, size);         // RefOut

    return(r & widmask(size));
}
u32 crc_safe_limit(u32 crc, int size) { // in my tests this was NOT necessary, but I want to be sure
    if(size <= 8)  return(crc & 0xff);
    if(size <= 16) return(crc & 0xffff);
    if(size <= 32) return(crc & 0xffffffff);
    return(crc);    // in case of future u64 implementations
}
void make_crctable(u32 *output, u64 poly, int size, int rever) {
    //u64     num;
    u32     num;
    int     i;

    for(i = 0; i < 256; i++) {
        num = cm_tab(i, poly, size, rever);
        *output++ = crc_safe_limit(num, size);
    }
}
u16 in_cksum(u32 init, u8 *data, int len) {
    u32     sum;
    int     endian = 1; // big endian
    u16     crc,
            *p,
            *l;

    if(*(char *)&endian) endian = 0;
    sum = init;

    for(p = (u16 *)data, l = p + (len >> 1); p < l; p++) sum += *p;
    if(len & 1) sum += *p & (endian ? 0xff00 : 0xff);
    sum = (sum >> 16) + (sum & 0xffff);
    crc = sum + (sum >> 16);
    if(!endian) crc = (crc >> 8) | (crc << 8);
    return(crc);    // should be xored with 0xffff but this job is done later
}
u32 calc_crc(crc_context *ctx, u8 *data, int datalen) {
#define CALC_CRC_CYCLE(X) \
    for(i = 0; i < datalen; i++) { \
        crc = X; \
        crc = crc_safe_limit(crc, ctx->size); \
    }
    u32     crc;
    int     i;

    crc = ctx->init;    // Init
    if(!ctx->type) {
        CALC_CRC_CYCLE(ctx->table[(data[i] ^ crc) & 0xff] ^ (crc >> 8));
    } else if(ctx->type == 1) {
        CALC_CRC_CYCLE(ctx->table[(data[i] ^ (crc >> 24)) & 0xff] ^ (crc << 8));
    } else if(ctx->type == 2) {
        CALC_CRC_CYCLE(((crc << 8) | data[i]) ^ ctx->table[(crc >> 24) & 0xff]);
    } else if(ctx->type == 3) {
        CALC_CRC_CYCLE(((crc >> 1) + ((crc & 1) << (ctx->size - 1))) + *data);
    } else if(ctx->type == 4) {
        crc = in_cksum(crc, data, datalen);
    } else {
        printf("\nError: unsupported crc type %d\n", (i32)ctx->type);
        return(-1);
    }
    crc ^= ctx->final;  // XorOut
    return(crc_safe_limit(crc, ctx->size));
}

